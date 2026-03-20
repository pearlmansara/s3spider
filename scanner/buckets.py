"""
buckets.py - Enumerate and validate S3 bucket access for a given boto3 session.
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


def get_session(profile: str):
    """Create a boto3 session for the given profile."""
    try:
        session = boto3.Session(profile_name=profile)
        # Verify credentials exist
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity.get("Account", "unknown")
        arn = identity.get("Arn", "unknown")
        return session, account_id, arn
    except ProfileNotFound:
        console.print(f"[bold red][!] Profile '{profile}' not found in ~/.aws/credentials[/bold red]")
        return None, None, None
    except NoCredentialsError:
        console.print(f"[bold red][!] No credentials found for profile '{profile}'[/bold red]")
        return None, None, None
    except ClientError as e:
        console.print(f"[bold red][!] Auth error for profile '{profile}': {e}[/bold red]")
        return None, None, None


def enumerate_buckets(session, profile: str, account_id: str):
    """
    List all S3 buckets accessible to the session.
    Returns a list of dicts: {name, region, arn, readable}
    """
    s3 = session.client("s3")
    buckets = []

    try:
        response = s3.list_buckets()
        raw_buckets = response.get("Buckets", [])
    except ClientError as e:
        console.print(f"[bold red][!] Could not list buckets for profile '{profile}': {e}[/bold red]")
        return buckets

    for bucket in raw_buckets:
        name = bucket["Name"]
        region = _get_bucket_region(s3, name)
        arn = f"arn:aws:s3:::{name}"
        readable = _check_read_access(s3, name)
        buckets.append({
            "profile": profile,
            "name": name,
            "region": region or "unknown",
            "arn": arn,
            "account_id": account_id,
            "readable": readable,
        })

    return buckets


def _get_bucket_region(s3_client, bucket_name: str) -> str:
    """Return the region of a bucket, or None on error."""
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        loc = response.get("LocationConstraint")
        # us-east-1 returns None from LocationConstraint
        return loc if loc else "us-east-1"
    except ClientError:
        return "unknown"


def _check_read_access(s3_client, bucket_name: str) -> bool:
    """Check if we can list objects in the bucket (basic read access test)."""
    try:
        s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        return True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "AllAccessDisabled"):
            return False
        # NoSuchBucket or other errors — treat as not readable
        return False


def display_buckets(all_buckets: list):
    """Print a Rich table of discovered buckets grouped by profile."""
    if not all_buckets:
        console.print("[yellow][-] No buckets found.[/yellow]")
        return

    table = Table(
        title="[bold cyan]Discovered S3 Buckets[/bold cyan]",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("Profile", style="cyan", no_wrap=True)
    table.add_column("Bucket Name", style="white", no_wrap=True)
    table.add_column("Region", style="blue")
    table.add_column("ARN", style="dim white")
    table.add_column("Readable", justify="center")

    for b in all_buckets:
        readable_str = "[green]✔ Yes[/green]" if b["readable"] else "[red]✘ No[/red]"
        table.add_row(
            b["profile"],
            b["name"],
            b["region"],
            b["arn"],
            readable_str,
        )

    console.print()
    console.print(table)
    console.print()

    total = len(all_buckets)
    readable = sum(1 for b in all_buckets if b["readable"])
    console.print(
        f"[bold green][*] Found {total} bucket(s) across all profiles — "
        f"{readable} readable, {total - readable} denied.[/bold green]"
    )
    console.print()
