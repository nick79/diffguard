"""Baseline management CLI subcommands."""

import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from diffguard.baseline import BaselineEntry, load_baseline, save_baseline
from diffguard.config import load_config
from diffguard.exceptions import BaselineError, ConfigError

baseline_app = typer.Typer(name="baseline", help="Manage baseline suppressions.")

_FINDING_ID_RE = re.compile(r"^[a-z]+[0-9]*-[0-9a-f]{16}$")

_SCAN_CACHE_PATH = Path(".diffguard") / "last_scan.json"


def _resolve_baseline_path() -> Path:
    """Load config and return the resolved baseline path."""
    try:
        config = load_config()
    except ConfigError:
        config = None

    baseline_path = ".diffguard-baseline.json"
    if config is not None:
        baseline_path = config.baseline_path

    return Path(baseline_path)


def _validate_finding_id(finding_id: str) -> None:
    """Validate finding ID format, exit 2 on invalid."""
    if not _FINDING_ID_RE.match(finding_id):
        typer.echo(
            f"Error: Invalid finding ID format: '{finding_id}'. "
            f"Expected format: <prefix>-<16 hex chars> (e.g., cwe89-a1b2c3d4e5f6a7b8)",
            err=True,
        )
        raise typer.Exit(code=2)


def _utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_scan_cache() -> list[dict[str, str]] | None:
    """Load scan cache from .diffguard/last_scan.json, or None if unavailable."""
    if not _SCAN_CACHE_PATH.exists():
        return None
    try:
        raw = _SCAN_CACHE_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
        findings = data.get("findings")
        if isinstance(findings, list):
            return findings
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _find_in_cache(finding_id: str, cache: list[dict[str, str]]) -> dict[str, str] | None:
    """Find a finding in the scan cache by ID."""
    for entry in cache:
        if entry.get("finding_id") == finding_id:
            return entry
    return None


@baseline_app.command("add")
def baseline_add(
    finding_id: str = typer.Argument(default="", help="Finding ID to suppress"),
    reason: str = typer.Option("", "--reason", "-r", help="Reason for suppression"),
    cwe: str = typer.Option("", "--cwe", help="CWE identifier (e.g., CWE-89)"),
    all_low: bool = typer.Option(False, "--all-low", help="Add all Low/Info findings from last scan"),
) -> None:
    """Add a finding to the baseline."""
    baseline_path = _resolve_baseline_path()

    if all_low:
        _add_all_low(baseline_path, reason)
        return

    if not finding_id:
        typer.echo("Error: Missing finding ID argument.", err=True)
        raise typer.Exit(code=2)

    _validate_finding_id(finding_id)

    try:
        entries = load_baseline(baseline_path)
    except BaselineError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    for entry in entries:
        if entry.finding_id == finding_id:
            typer.echo(f"Finding '{finding_id}' is already in the baseline.")
            raise typer.Exit(code=0)

    # Try to enrich from scan cache
    file_path: str | None = None
    cache = _load_scan_cache()
    if cache is not None:
        cached = _find_in_cache(finding_id, cache)
        if cached is not None:
            if not cwe and cached.get("cwe_id"):
                cwe = cached["cwe_id"]
            if cached.get("file_path"):
                file_path = cached["file_path"]

    # Interactive reason prompt if TTY and no reason provided
    if not reason and sys.stdin.isatty():
        reason = typer.prompt("Reason for suppression", default="")

    new_entry = BaselineEntry(
        finding_id=finding_id,
        cwe_id=cwe,
        code_hash="",
        reason=reason,
        added_at=_utc_now_iso(),
        file_path=file_path,
    )
    entries.append(new_entry)

    try:
        save_baseline(entries, baseline_path)
    except BaselineError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    typer.echo(f"Added '{finding_id}' to baseline.")


def _add_all_low(baseline_path: Path, reason: str) -> None:
    """Add all Low/Info findings from the last scan to the baseline."""
    cache = _load_scan_cache()
    if cache is None:
        typer.echo("Error: No scan cache found. Run a scan first.", err=True)
        raise typer.Exit(code=2)

    low_findings = [f for f in cache if f.get("severity", "").lower() in ("low", "info")]

    if not low_findings:
        typer.echo("No Low/Info findings in last scan.")
        raise typer.Exit(code=0)

    try:
        entries = load_baseline(baseline_path)
    except BaselineError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    existing_ids = {e.finding_id for e in entries}
    added = 0

    for f in low_findings:
        fid = f.get("finding_id", "")
        if not fid or fid in existing_ids:
            continue
        entries.append(
            BaselineEntry(
                finding_id=fid,
                cwe_id=f.get("cwe_id", ""),
                code_hash="",
                reason=reason or "Bulk-added low/info finding",
                added_at=_utc_now_iso(),
                file_path=f.get("file_path") or None,
            )
        )
        existing_ids.add(fid)
        added += 1

    try:
        save_baseline(entries, baseline_path)
    except BaselineError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    typer.echo(f"Added {added} Low/Info finding(s) to baseline.")


@baseline_app.command("remove")
def baseline_remove(
    finding_id: str = typer.Argument(help="Finding ID to remove from baseline"),
) -> None:
    """Remove a finding from the baseline."""
    baseline_path = _resolve_baseline_path()
    _validate_finding_id(finding_id)

    try:
        entries = load_baseline(baseline_path)
    except BaselineError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    remaining = [e for e in entries if e.finding_id != finding_id]

    if len(remaining) == len(entries):
        typer.echo(f"Error: Finding '{finding_id}' not found in baseline.", err=True)
        raise typer.Exit(code=2)

    try:
        save_baseline(remaining, baseline_path)
    except BaselineError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    typer.echo(f"Removed '{finding_id}' from baseline.")


@baseline_app.command("list")
def baseline_list() -> None:
    """List all baselined findings."""
    baseline_path = _resolve_baseline_path()

    try:
        entries = load_baseline(baseline_path)
    except BaselineError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    if not entries:
        typer.echo("No baselined findings.")
        raise typer.Exit(code=0)

    console = Console()
    table = Table(title="Baselined Findings")
    table.add_column("Finding ID", style="cyan")
    table.add_column("CWE", style="yellow")
    table.add_column("File", style="green")
    table.add_column("Reason")
    table.add_column("Added At", style="dim")

    for entry in entries:
        table.add_row(
            entry.finding_id,
            entry.cwe_id or "",
            entry.file_path or "",
            entry.reason,
            entry.added_at,
        )

    console.print(table)
