#!/usr/bin/env python3
"""
s3spider.py - S3 sensitive data scanner (MANSPIDER for S3)

Enumerates all S3 buckets accessible to one or more AWS profiles,
then crawls each bucket looking for sensitive data using regex patterns.
Findings are printed to the console in real time and written to an Excel report.
"""

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.rule import Rule
from rich.text import Text
from rich import box
from rich.table import Table
from rich.panel import Panel

# ── Local imports ──────────────────────────────────────────────────────────────
from scanner.buckets   import get_session, enumerate_buckets, display_buckets
from scanner.crawler   import crawl_bucket
from scanner.detector  import Detector
from scanner.reporter  import write_excel

console = Console()

BANNER = r"""
  ____  ____  ____        _     _           
 / ___|___ \ / ___|  _ __(_) __| | ___ _ __ 
 \___ \ __) |\___ \ | '_ \ |/ _` |/ _ \ '__|
  ___) / __/  ___) || |_) | | (_| |  __/ |   
 |____/_____||____/ | .__/|_|\__,_|\___|_|   
                    |_|                       
    S3 Sensitive Data Scanner  |  @s3spider
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="s3spider",
        description="Enumerate S3 buckets and scan for sensitive data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan using default AWS profile
  python s3spider.py

  # Scan using multiple profiles
  python s3spider.py --profiles dev-readonly prod-readonly

  # Scan only .env and .json files, download matches
  python s3spider.py --profiles dev --extensions .env .json --download

  # Search for specific keywords (like MANSPIDER -c)
  python s3spider.py --profiles dev --content password secret apikey

  # Keyword-only mode (skip built-in regex patterns)
  python s3spider.py --profiles dev --content password --content-only

  # Exclude buckets matching patterns + CloudTrail excluded by default
  python s3spider.py --profiles prod --exclude-buckets backup archive

  # Force-include CloudTrail buckets (excluded by default)
  python s3spider.py --profiles prod --include-cloudtrail

  # Use a custom patterns file
  python s3spider.py --profiles prod --patterns-file my_patterns.yaml

  # Limit file size and thread count
  python s3spider.py --profiles prod --max-size 5 --threads 10

  # Save report to a specific file
  python s3spider.py --profiles prod --output /tmp/findings.xlsx
        """,
    )

    parser.add_argument(
        "--profiles",
        nargs="+",
        metavar="PROFILE",
        default=None,
        help="AWS profile name(s) from ~/.aws/credentials. "
             "Defaults to the default profile / environment credentials.",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        metavar="EXT",
        default=None,
        help="File extensions to scan (e.g. .env .json .txt). "
             "Defaults to all supported extensions.",
    )
    parser.add_argument(
        "--content", "-c",
        nargs="+",
        metavar="WORD",
        default=None,
        help="Plain keyword(s) to search for in file contents (case-insensitive). "
             "Mirrors MANSPIDER's -c flag. E.g. --content password secret apikey",
    )
    parser.add_argument(
        "--content-only",
        action="store_true",
        help="Only run --content keyword searches; skip all built-in regex patterns.",
    )
    parser.add_argument(
        "--patterns-file",
        metavar="FILE",
        default=None,
        help="Path to a custom YAML patterns file (merged with built-in patterns).",
    )
    parser.add_argument(
        "--exclude-buckets",
        nargs="+",
        metavar="PATTERN",
        default=None,
        help="Skip buckets whose name contains any of these substrings (case-insensitive). "
             "E.g. --exclude-buckets backup archive temp",
    )
    parser.add_argument(
        "--include-cloudtrail",
        action="store_true",
        help="Include CloudTrail buckets in the scan (excluded by default because "
             "they are very large and rarely contain useful secrets).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        metavar="N",
        help="Number of concurrent download/scan threads per bucket (default: 5).",
    )
    parser.add_argument(
        "--max-size",
        type=float,
        default=10.0,
        metavar="MB",
        help="Maximum file size in MB to download and scan (default: 10).",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download matched files to ./downloads/<bucket>/<key>.",
    )
    parser.add_argument(
        "--download-dir",
        metavar="DIR",
        default="downloads",
        help="Directory to save downloaded files (default: ./downloads).",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Path for the Excel output report "
             "(default: s3spider_YYYYMMDD_HHMMSS.xlsx).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII art banner.",
    )

    return parser


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress noisy botocore debug logs unless explicitly verbose
    if not verbose:
        logging.getLogger("botocore").setLevel(logging.ERROR)
        logging.getLogger("boto3").setLevel(logging.ERROR)
        logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)

    # ── Banner ────────────────────────────────────────────────────────────────
    if not args.no_banner:
        console.print(f"[bold cyan]{BANNER}[/bold cyan]")

    # ── Profiles ──────────────────────────────────────────────────────────────
    profiles = args.profiles if args.profiles else [None]  # None = default profile

    # ── Extensions ────────────────────────────────────────────────────────────
    extensions = None
    if args.extensions:
        # Normalise: ensure each extension starts with a dot
        extensions = set(
            ext if ext.startswith(".") else f".{ext}"
            for ext in args.extensions
        )
        console.print(f"[dim][*] Extension filter: {', '.join(sorted(extensions))}[/dim]")

    # ── Output path ───────────────────────────────────────────────────────────
    if args.output:
        output_path = args.output
    else:
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"s3spider_{timestamp}.xlsx"

    # ── Validate --content-only usage ─────────────────────────────────────────
    if args.content_only and not args.content:
        console.print(
            "[bold red][!] --content-only requires at least one --content keyword.[/bold red]"
        )
        sys.exit(1)

    # ── Load detector ─────────────────────────────────────────────────────────
    # If --content-only, skip loading the built-in regex patterns entirely
    detector = Detector(no_default_patterns=args.content_only)

    if not args.content_only:
        if args.patterns_file:
            if not os.path.isfile(args.patterns_file):
                console.print(f"[bold red][!] Patterns file not found: {args.patterns_file}[/bold red]")
                sys.exit(1)
            detector.add_patterns_from_file(args.patterns_file)
            console.print(f"[dim][*] Loaded additional patterns from {args.patterns_file}[/dim]")

    if args.content:
        detector.add_keywords(args.content)
        console.print(
            f"[dim][*] Keyword search terms: {', '.join(repr(k) for k in args.content)}[/dim]"
        )

    if args.content_only:
        console.print(f"[dim][*] Mode: keyword-only (built-in regex patterns disabled)[/dim]")

    console.print(f"[dim][*] {len(detector.patterns)} detection pattern(s) loaded[/dim]")

    # ── Build bucket exclusion list ────────────────────────────────────────────
    exclude_patterns: list[str] = []
    if not args.include_cloudtrail:
        exclude_patterns.append("cloudtrail")
    if args.exclude_buckets:
        exclude_patterns.extend(args.exclude_buckets)

    if exclude_patterns:
        console.print(
            f"[dim][*] Bucket exclusions (name contains): "
            f"{', '.join(repr(p) for p in exclude_patterns)}[/dim]"
        )

    console.print()

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 1 — Enumerate buckets across all profiles
    # ══════════════════════════════════════════════════════════════════════════
    console.print(Rule("[bold cyan]Phase 1 — Bucket Enumeration[/bold cyan]"))
    console.print()

    all_buckets: list[dict] = []
    sessions_map: dict[str | None, object] = {}

    for profile in profiles:
        label = profile if profile else "default"
        console.print(f"[cyan][*] Authenticating profile:[/cyan] [white]{label}[/white]")

        session, account_id, caller_arn = get_session(profile)
        if session is None:
            continue

        console.print(
            f"    [green]✔ Authenticated[/green]  "
            f"Account: [white]{account_id}[/white]  "
            f"ARN: [dim]{caller_arn}[/dim]"
        )

        buckets = enumerate_buckets(session, label, account_id)
        all_buckets.extend(buckets)
        sessions_map[label] = session

    if not all_buckets:
        console.print("[bold red][!] No buckets found across any profile. Exiting.[/bold red]")
        sys.exit(0)

    # Display the bucket table and wait for the user to proceed
    display_buckets(all_buckets)

    # Filter to only readable buckets
    readable_buckets = [b for b in all_buckets if b["readable"]]
    if not readable_buckets:
        console.print("[bold yellow][!] No readable buckets found. Exiting.[/bold yellow]")
        sys.exit(0)

    # ── Apply bucket exclusions ───────────────────────────────────────────────
    if exclude_patterns:
        excluded = []
        kept = []
        for b in readable_buckets:
            name_lower = b["name"].lower()
            matched = next(
                (p for p in exclude_patterns if p.lower() in name_lower), None
            )
            if matched:
                excluded.append((b["name"], matched))
            else:
                kept.append(b)

        if excluded:
            for name, reason in excluded:
                console.print(
                    f"[dim][-] Skipping bucket [white]{name}[/white] "
                    f"(matches exclusion pattern '[yellow]{reason}[/yellow]')[/dim]"
                )
            console.print()
        readable_buckets = kept

    if not readable_buckets:
        console.print("[bold yellow][!] All readable buckets were excluded. Exiting.[/bold yellow]")
        sys.exit(0)

    console.print(
        f"[bold green][*] Proceeding to scan {len(readable_buckets)} readable bucket(s)...[/bold green]"
    )
    console.print()

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 2 — Crawl & Scan
    # ══════════════════════════════════════════════════════════════════════════
    console.print(Rule("[bold cyan]Phase 2 — Crawling & Scanning[/bold cyan]"))
    console.print()

    all_findings: list[dict] = []

    for bucket in readable_buckets:
        profile_label = bucket["profile"]
        session = sessions_map.get(profile_label)
        if session is None:
            continue

        findings = crawl_bucket(
            session=session,
            bucket=bucket,
            detector=detector,
            max_size_mb=args.max_size,
            threads=args.threads,
            download=args.download,
            download_dir=args.download_dir,
            extensions=extensions,
            keywords_only=args.content_only,
        )
        all_findings.extend(findings)
        console.print()

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 3 — Summary & Report
    # ══════════════════════════════════════════════════════════════════════════
    console.print(Rule("[bold cyan]Phase 3 — Summary[/bold cyan]"))
    console.print()

    if not all_findings:
        console.print(
            Panel(
                "[green]No sensitive data found across all scanned buckets.[/green]",
                title="[bold green]Scan Complete[/bold green]",
                border_style="green",
            )
        )
        sys.exit(0)

    # Console summary table
    _print_summary_table(all_findings)

    # Write Excel report
    console.print(f"\n[bold cyan][*] Writing Excel report:[/bold cyan] [white]{output_path}[/white]")
    write_excel(all_findings, output_path)
    console.print(f"[bold green][✔] Report saved:[/bold green] [white]{output_path}[/white]")

    if args.download:
        console.print(
            f"[bold green][✔] Downloaded files saved to:[/bold green] [white]{args.download_dir}[/white]"
        )

    console.print()


def _print_summary_table(findings: list[dict]):
    """Print a final summary table of all findings grouped by severity."""
    from collections import Counter

    severity_counts = Counter(f["severity"] for f in findings)
    severity_colors = {
        "critical": "bold red",
        "high":     "red",
        "medium":   "yellow",
        "low":      "dim white",
    }

    table = Table(
        title="[bold cyan]Findings Summary[/bold cyan]",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("Count", justify="right")
    table.add_column("Pattern", no_wrap=False)

    # Also collect per-pattern counts
    pattern_counts = Counter(
        (f["severity"], f["pattern_name"]) for f in findings
    )

    printed_sev = set()
    for sev in ["critical", "high", "medium", "low"]:
        color = severity_colors.get(sev, "white")
        patterns_for_sev = [
            (pname, cnt)
            for (s, pname), cnt in sorted(
                pattern_counts.items(), key=lambda x: -x[1]
            )
            if s == sev
        ]
        if not patterns_for_sev:
            continue

        for i, (pname, cnt) in enumerate(patterns_for_sev):
            sev_label = f"[{color}]{sev.upper()}[/{color}]" if i == 0 else ""
            count_str = str(severity_counts[sev]) if i == 0 else ""
            table.add_row(sev_label, count_str, f"{pname} ({cnt})")

    console.print(table)
    console.print(
        f"\n[bold white]Total findings: [bold cyan]{len(findings)}[/bold cyan]  |  "
        f"Buckets affected: [bold cyan]{len(set(f['bucket_arn'] for f in findings))}[/bold cyan][/bold white]"
    )


if __name__ == "__main__":
    main()
