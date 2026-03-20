"""
crawler.py - List and stream S3 objects, then scan them for sensitive data.
"""

import os
import logging
import threading
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


# Compressed/binary file extensions that are never useful to scan and
# should be rejected at the listing phase (before any download occurs).
COMPRESSED_EXTENSIONS = {
    ".gz", ".gzip", ".bz2", ".xz", ".zst", ".zstd",
    ".tar", ".tgz", ".tar.gz", ".tar.bz2",
    ".zip", ".7z", ".rar",
}

# AWS-managed log prefixes that almost never contain credentials.
# Skipped by default; override with --include-awslogs.
AWSLOGS_PREFIXES = (
    "AWSLogs/",
    "aws-logs/",
    "elasticloadbalancing/",
    "vpcflowlogs/",
    "CloudTrail/",
    "Config/",
)


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
) -> list[dict]:
    """
    Crawl all objects in a bucket and return findings.

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

    console.print(f"    [green]{len(keys)} object(s) to scan[/green]")

    all_findings: list[dict] = []

    # ── Step 2: download + scan concurrently ─────────────────────────────────
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
        task_id = progress.add_task(f"Scanning {bucket_name}", total=len(keys))

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
            futures = {executor.submit(process_key, ki): ki for ki in keys}
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
                matched_prefix = next(
                    (p for p in exclude_prefixes if key.startswith(p) or key_lower.startswith(p.lower())),
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
