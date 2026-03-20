"""
crawler.py - List and stream S3 objects, then scan them for sensitive data.
"""

import os
import re
import logging
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn,
    TaskProgressColumn, TimeElapsedColumn, MofNCompleteColumn,
)
from rich.markup import escape

from .parsers import is_supported, extract_text
from .detector import Detector, SEVERITY_COLORS

console = Console()
logger = logging.getLogger("s3spider")

# Lock for thread-safe console output and findings list appending
_lock = threading.Lock()

# ── Filename normalisation regexes (order matters — most specific first) ──────
_NORM_PATTERNS = [
    # UUID with dashes (must come BEFORE date patterns to avoid partial matches)
    (re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE), '{uuid}'),
    # 32-char hex (UUID without dashes)
    (re.compile(r'\b[0-9a-f]{32}\b', re.IGNORECASE), '{uuid}'),
    # Full ISO datetime / timestamps  e.g. 2024-01-15T10:30:00Z
    (re.compile(r'\d{4}[-_]\d{2}[-_]\d{2}[T_]\d{2}[-:]\d{2}[-:]\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'), '{datetime}'),
    # Date with separators: 2024-01-15  or  2024/01/15
    (re.compile(r'\d{4}[-/]\d{2}[-/]\d{2}'), '{date}'),
    # Compact date: 20240115
    (re.compile(r'\b\d{8}\b'), '{date}'),
    # Unix epoch timestamps (10 or 13 digits)
    (re.compile(r'\b1[0-9]{9,12}\b'), '{timestamp}'),
    # Long pure-numeric IDs (5+ digits)
    (re.compile(r'\b\d{5,}\b'), '{id}'),
    # Remaining hex strings (8+ chars)
    (re.compile(r'\b[0-9a-f]{8,}\b', re.IGNORECASE), '{hex}'),
]


# Compressed/binary file extensions that are never useful to scan and
# should be rejected at the listing phase (before any download occurs).
COMPRESSED_EXTENSIONS = {
    ".gz", ".gzip", ".bz2", ".xz", ".zst", ".zstd",
    ".tar", ".tgz", ".tar.gz", ".tar.bz2",
    ".zip", ".7z", ".rar",
}

# AWS-managed log prefixes that almost never contain credentials.
# Skipped by default; override with --include-awslogs.
# NOTE: Keep these specific — avoid short/generic names that collide with
# legitimate user folders (e.g. "config/").  CloudTrail & Config logs are
# already covered by the "AWSLogs/" umbrella prefix.
AWSLOGS_PREFIXES = (
    "AWSLogs/",
    "aws-logs/",
    "elasticloadbalancing/",
    "vpcflowlogs/",
)


def _normalize_filename(key: str) -> str:
    """
    Replace variable parts of a filename (dates, UUIDs, IDs, hex) with
    generic placeholders so that files following the same naming convention
    collapse to the same pattern.

    Only the *basename* (last path component) is normalised; the prefix/folder
    is kept verbatim so pattern grouping stays within each folder.
    """
    prefix, _, basename = key.rpartition("/")
    norm = basename
    for pattern, replacement in _NORM_PATTERNS:
        norm = pattern.sub(replacement, norm)
    return f"{prefix}/{norm}" if prefix else norm


def _group_keys_by_pattern(
    keys: list[tuple[str, int]],
    sample_threshold: int,
) -> tuple[list[tuple[str, int]], dict[str, list[tuple[str, int]]]]:
    """
    Split keys into:
      - scan_all:    keys that should always be scanned (unique patterns or
                     small groups below the threshold)
      - sample_groups: {pattern_str: [key_info, ...]} where each group has
                       >= sample_threshold members and will be sampled
    """
    # Group by (folder_prefix, normalised_filename_pattern)
    groups: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for ki in keys:
        key = ki[0]
        pattern = _normalize_filename(key)
        groups[pattern].append(ki)

    scan_all: list[tuple[str, int]] = []
    sample_groups: dict[str, list[tuple[str, int]]] = {}

    for pattern, members in groups.items():
        if len(members) >= sample_threshold:
            sample_groups[pattern] = members
        else:
            scan_all.extend(members)

    return scan_all, sample_groups


def crawl_bucket(
    session,
    bucket: dict,
    detector: Detector,
    max_size_mb: float = 10.0,
    threads: int = 5,
    download: bool = False,
    download_dir: str = "downloads",
    extensions: set | None = None,
    keywords_only: bool = False,
    exclude_prefixes: list[str] | None = None,
    include_awslogs: bool = False,
    sample_threshold: int = 10,
    no_sample: bool = False,
) -> list[dict]:
    """
    Crawl all objects in a bucket and return findings.

    Smart sampling: for any folder where many files share the same naming
    pattern, one representative is scanned first. If it's clean, the rest
    are skipped. Files with unique/different naming patterns are always scanned.

    Each finding dict:
    {
        profile, region, bucket_arn, bucket_name,
        s3_key, pattern_name, severity, line_number, line, match
    }
    """
    bucket_name = bucket["name"]
    region      = bucket["region"]
    bucket_arn  = bucket["arn"]
    profile     = bucket["profile"]
    max_bytes   = int(max_size_mb * 1024 * 1024)

    # Create a region-specific S3 client to avoid redirect issues
    s3 = session.client("s3", region_name=region if region != "unknown" else None)

    console.print(
        f"[bold cyan][*] Crawling:[/bold cyan] [white]{bucket_arn}[/white]  "
        f"[dim]({region})[/dim]"
    )

    # Build the full prefix exclusion list for this crawl
    active_exclude_prefixes: list[str] = list(exclude_prefixes or [])
    if not include_awslogs:
        active_exclude_prefixes.extend(AWSLOGS_PREFIXES)

    # ── Step 1: list all matching objects ────────────────────────────────────
    keys = _list_objects(s3, bucket_name, extensions, max_bytes, active_exclude_prefixes)

    if not keys:
        console.print(f"    [dim]No matching objects found in {bucket_name}[/dim]")
        return []

    all_findings: list[dict] = []

    # ── Step 2: smart pattern-based sampling ─────────────────────────────────
    if no_sample or sample_threshold <= 0:
        # No sampling — scan everything
        keys_to_scan = keys
        console.print(f"    [green]{len(keys_to_scan)} object(s) to scan (sampling disabled)[/green]")
    else:
        scan_all, sample_groups = _group_keys_by_pattern(keys, sample_threshold)

        total_sampled_skipped = 0

        for pattern, members in sample_groups.items():
            # Pick one representative (first member)
            representative = members[0]
            rep_key, rep_size = representative

            console.print(
                f"    [yellow][~] Pattern group:[/yellow] [dim]{escape(pattern)}[/dim]  "
                f"[dim]({len(members)} files)[/dim]"
            )

            # Sample the representative synchronously (before thread pool)
            sample_findings = _process_object(
                s3=s3,
                bucket_name=bucket_name,
                key=rep_key,
                size=rep_size,
                detector=detector,
                profile=profile,
                region=region,
                bucket_arn=bucket_arn,
                download=download,
                download_dir=download_dir,
                keywords_only=keywords_only,
            )

            if sample_findings:
                # Representative had findings — scan all members
                console.print(
                    f"    [red]  ↳ Sample had findings — scanning all {len(members)} file(s)[/red]"
                )
                scan_all.extend(members)
                with _lock:
                    all_findings.extend(sample_findings)
                    for finding in sample_findings:
                        _print_finding(finding)
            else:
                # Representative was clean — skip the rest
                skipped = len(members) - 1
                total_sampled_skipped += skipped
                console.print(
                    f"    [green]  ↳ Sample clean — skipping {skipped:,} similar file(s)[/green]"
                )

        if total_sampled_skipped:
            console.print(
                f"    [green]Sampling saved {total_sampled_skipped:,} download(s)[/green]"
            )

        keys_to_scan = scan_all
        console.print(f"    [green]{len(keys_to_scan)} object(s) remaining to scan[/green]")

    if not keys_to_scan:
        return all_findings

    # ── Step 3: scan remaining keys concurrently ─────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("    [progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(f"Scanning {bucket_name}", total=len(keys_to_scan))

        def process_key(key_info):
            key, size = key_info
            findings = _process_object(
                s3=s3,
                bucket_name=bucket_name,
                key=key,
                size=size,
                detector=detector,
                profile=profile,
                region=region,
                bucket_arn=bucket_arn,
                download=download,
                download_dir=download_dir,
                keywords_only=keywords_only,
            )
            progress.advance(task_id)
            return findings

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(process_key, ki): ki for ki in keys_to_scan}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with _lock:
                            all_findings.extend(result)
                            for finding in result:
                                _print_finding(finding)
                except Exception as e:
                    logger.debug(f"Error processing object: {e}")

    return all_findings


def _list_objects(
    s3,
    bucket_name: str,
    extensions: set | None,
    max_bytes: int,
    exclude_prefixes: list[str],
) -> list[tuple[str, int]]:
    """Paginate through all objects and return list of (key, size) tuples."""
    keys = []
    skipped_prefix: dict[str, int] = {}
    paginator = s3.get_paginator("list_objects_v2")
    try:
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                key  = obj["Key"]
                size = obj.get("Size", 0)

                # ── Reject compressed/archive files immediately ───────────────
                key_lower = key.lower()
                if any(key_lower.endswith(ext) for ext in COMPRESSED_EXTENSIONS):
                    logger.debug(f"Skipping compressed file: {key}")
                    continue

                # ── Reject excluded key prefixes (AWSLogs, custom, etc.) ──────
                # Case-sensitive check first (preserves built-in prefix casing),
                # then case-insensitive only for user-supplied --exclude-prefixes.
                matched_prefix = next(
                    (p for p in exclude_prefixes if key.startswith(p)),
                    None,
                )
                if matched_prefix is None:
                    # Case-insensitive fallback for user-supplied patterns only
                    matched_prefix = next(
                        (p for p in exclude_prefixes
                         if p not in AWSLOGS_PREFIXES and key_lower.startswith(p.lower())),
                        None,
                    )
                if matched_prefix:
                    skipped_prefix[matched_prefix] = skipped_prefix.get(matched_prefix, 0) + 1
                    continue

                # ── Skip oversized files ──────────────────────────────────────
                if size > max_bytes:
                    logger.debug(f"Skipping {key} — too large ({size / 1024 / 1024:.1f} MB)")
                    continue

                # ── Extension filter ──────────────────────────────────────────
                if extensions:
                    if not any(key_lower.endswith(ext) for ext in extensions):
                        continue
                else:
                    if not is_supported(key):
                        continue

                keys.append((key, size))
    except ClientError as e:
        logger.error(f"Error listing objects in {bucket_name}: {e}")

    # Report how many objects were skipped per prefix
    for prefix, count in sorted(skipped_prefix.items()):
        console.print(
            f"    [dim]Skipped {count:,} object(s) under prefix "
            f"[yellow]{prefix}[/yellow] (excluded)[/dim]"
        )

    return keys


def _process_object(
    s3,
    bucket_name: str,
    key: str,
    size: int,
    detector: Detector,
    profile: str,
    region: str,
    bucket_arn: str,
    download: bool,
    download_dir: str,
    keywords_only: bool = False,
) -> list[dict]:
    """Download (stream) and scan a single S3 object."""
    findings = []
    try:
        response = s3.get_object(Bucket=bucket_name, Key=key)
        data = response["Body"].read()
    except ClientError as e:
        logger.debug(f"Could not read s3://{bucket_name}/{key}: {e}")
        return findings

    # Optionally save to disk
    if download:
        _save_file(data, bucket_name, key, download_dir)

    # Extract text
    text = extract_text(data, key)
    if text is None:
        return findings

    # Scan for sensitive data
    raw_findings = detector.scan(text, keywords_only=keywords_only)
    for f in raw_findings:
        findings.append({
            "profile":      profile,
            "region":       region,
            "bucket_arn":   bucket_arn,
            "bucket_name":  bucket_name,
            "s3_key":       key,
            "s3_uri":       f"s3://{bucket_name}/{key}",
            "pattern_name": f["pattern_name"],
            "severity":     f["severity"],
            "line_number":  f["line_number"],
            "line":         f["line"],
            "match":        f["match"],
        })

    return findings


def _save_file(data: bytes, bucket_name: str, key: str, download_dir: str):
    """Save downloaded bytes to a local directory mirroring the S3 path."""
    try:
        local_path = Path(download_dir) / bucket_name / key
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as fh:
            fh.write(data)
        logger.debug(f"Saved: {local_path}")
    except Exception as e:
        logger.debug(f"Failed to save {key}: {e}")


def _print_finding(finding: dict):
    """Print a single finding to the console with Rich markup."""
    severity   = finding["severity"]
    color      = SEVERITY_COLORS.get(severity, "white")
    pattern    = finding["pattern_name"]
    s3_uri     = finding["s3_uri"]
    line_num   = finding["line_number"]
    line       = finding["line"]
    match_text = finding["match"]

    # Highlight the matched portion within the full line
    highlighted_line = escape(line).replace(
        escape(match_text),
        f"[bold {color}]{escape(match_text)}[/bold {color}]",
        1,
    )

    console.print(
        f"  [{color}][{severity.upper()}][/{color}] "
        f"[bold]{escape(pattern)}[/bold]  "
        f"[dim]{escape(s3_uri)}[/dim] [dim]line {line_num}[/dim]\n"
        f"    {highlighted_line}"
    )
