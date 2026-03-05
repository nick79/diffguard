"""CLI entry point for Diffguard."""

import asyncio
import contextlib
import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

from diffguard import __version__
from diffguard.baseline_cli import baseline_app
from diffguard.config import DiffguardConfig, load_config
from diffguard.exceptions import ConfigError, DiffguardError, GitError, ReportWriteError
from diffguard.git import get_branch_name, get_commit_hash, get_staged_diff, is_git_repo, parse_diff
from diffguard.llm import AnalysisResult, OpenAIClient, build_user_prompt, estimate_tokens
from diffguard.llm.analyzer import FileAnalysisError, analyze_files
from diffguard.llm.response import Finding  # noqa: TC001
from diffguard.output.json_report import ReportMetadata, generate_report, print_report, write_report
from diffguard.output.terminal import (
    build_stats,
    create_progress_spinner,
    print_findings_grouped,
    print_no_findings,
    print_summary,
)
from diffguard.pipeline import PreparedContext, analyze_staged_changes, prepare_file_contexts
from diffguard.severity import should_block

app = typer.Typer(
    name="diffguard",
    help="LLM-powered security review of staged git diffs.\n\nExit codes: 0 = pass, 1 = blocking findings, 2 = error.",
    no_args_is_help=False,
)
app.add_typer(baseline_app, name="baseline")


def _version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"diffguard {__version__}")
        raise typer.Exit()


def _validate_git_repo() -> None:
    """Exit with code 2 if not inside a git repository."""
    if not is_git_repo():
        typer.echo("Error: Not a git repository.", err=True)
        typer.echo("Run diffguard from within a git repository.", err=True)
        raise typer.Exit(code=2)


def _validate_api_key() -> None:
    """Exit with code 2 if OPENAI_API_KEY is missing or blank."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key.strip():
        typer.echo("Error: OPENAI_API_KEY environment variable is not set.", err=True)
        typer.echo("Set it with: export OPENAI_API_KEY=sk-your-key-here", err=True)
        raise typer.Exit(code=2) from None


def _get_staged_diff_text() -> str:
    """Get staged diff text, exiting on error or empty diff."""
    try:
        raw_diff = get_staged_diff()
    except GitError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    if not raw_diff.strip():
        typer.echo("No staged changes to analyze.")
        typer.echo("Stage changes with: git add <files>")
        raise typer.Exit(code=0)

    return raw_diff


def _error_to_dict(error: FileAnalysisError) -> dict[str, str]:
    """Serialize a FileAnalysisError to a JSON-compatible dict."""
    return {
        "file_path": error.file_path,
        "error": error.error,
        "error_type": error.error_type,
    }


def _serialize_dry_run(token_estimates: list[tuple[str, int]], total: int) -> dict[str, Any]:
    """Serialize dry-run token estimates to a JSON-compatible dict."""
    return {
        "dry_run": True,
        "files": [{"path": path, "estimated_tokens": tokens} for path, tokens in token_estimates],
        "total_estimated_tokens": total,
    }


def _write_json_file(data: dict[str, Any], path: Path) -> None:
    """Write JSON data to a file, creating parent directories as needed."""
    try:
        write_report(data, path)
    except ReportWriteError:
        typer.echo(f"Error: Permission denied writing to {path}", err=True)
        raise typer.Exit(code=2) from None


def _compute_token_estimates(prepared: PreparedContext) -> list[tuple[str, int]]:
    """Compute per-file token estimates from prepared contexts."""
    estimates: list[tuple[str, int]] = []
    for ctx in prepared.code_contexts:
        prompt = build_user_prompt(ctx)
        tokens = estimate_tokens(prompt)
        estimates.append((ctx.file_path, tokens))
    return estimates


def _cwe_to_prefix(cwe: str) -> str:
    """Convert a CWE identifier to a lowercase prefix (e.g., 'CWE-89' -> 'cwe89')."""
    return cwe.lower().replace("-", "")


def _save_scan_cache(findings: list[Finding]) -> None:
    """Save findings to .diffguard/last_scan.json for baseline CLI enrichment."""
    cache_dir = Path(".diffguard")
    cache_dir.mkdir(exist_ok=True)
    cache_data = {
        "scan_time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": [
            {
                "finding_id": _cwe_to_prefix(f.cwe_id or "unknown")
                + "-"
                + hashlib.sha256(f"{_cwe_to_prefix(f.cwe_id or 'unknown')}:{f.what}".encode()).hexdigest()[:16],
                "cwe_id": f.cwe_id or "",
                "what": f.what,
                "file_path": f.file_path or "",
                "severity": f.severity.value,
            }
            for f in findings
        ],
    }
    with contextlib.suppress(OSError):
        (cache_dir / "last_scan.json").write_text(json.dumps(cache_data, indent=2), encoding="utf-8")


def _print_results(
    result: AnalysisResult,
    console: Console,
    *,
    files_analyzed: int,
    blocking: bool,
) -> None:
    """Print analysis results to the terminal using rich formatting."""
    stats = build_stats(result.findings, files_analyzed)

    if result.findings:
        print_findings_grouped(result.findings, console)
        console.print()
        print_summary(stats, console)
        if blocking:
            console.print("[bold red]Blocking issues found — commit should be rejected.[/bold red]")
        console.print()
        console.print("[dim]To suppress a finding: diffguard baseline add <finding-id>[/dim]")
    else:
        print_no_findings(stats, console)

    if result.errors:
        for error in result.errors:
            typer.echo(f"Warning: Error analyzing {error.file_path}: {error.error}", err=True)


def _route_output(
    result: AnalysisResult,
    *,
    json_output: bool,
    output: Path | None,
    console: Console,
    metadata: ReportMetadata,
    blocking: bool,
) -> None:
    """Route analysis results to the appropriate output destinations."""
    if not json_output and not output:
        _print_results(result, console, files_analyzed=metadata.files_analyzed, blocking=blocking)
        if blocking:
            raise typer.Exit(code=1)
        return

    report = generate_report(result.findings, metadata)
    if result.errors:
        report["errors"] = [_error_to_dict(e) for e in result.errors]

    if json_output:
        print_report(report)
    if output:
        _write_json_file(report, output)
        if not json_output:
            _print_results(result, console, files_analyzed=metadata.files_analyzed, blocking=blocking)
            console.print(f"Report saved to {output}")
    if blocking:
        raise typer.Exit(code=1)


def _handle_dry_run(
    prepared: PreparedContext,
    *,
    verbose: bool,
    json_output: bool,
    output: Path | None,
) -> None:
    """Handle the --dry-run flow with token estimates."""
    token_estimates = _compute_token_estimates(prepared)
    total_tokens = sum(t for _, t in token_estimates)

    if json_output or output:
        data = _serialize_dry_run(token_estimates, total_tokens)
        if json_output:
            typer.echo(json.dumps(data, indent=2))
        if output:
            _write_json_file(data, output)
            if not json_output:
                typer.echo(f"Report saved to {output}")
        raise typer.Exit(code=0)

    typer.echo(f"Would analyze {len(prepared.code_contexts)} file(s):")
    for i, _ctx in enumerate(prepared.code_contexts):
        file_path, tokens = token_estimates[i]
        if verbose:
            region_lines = sum(r.end_line - r.start_line + 1 for r in prepared.file_contexts[i].regions)
            scope_count = len(prepared.file_contexts[i].scopes)
            typer.echo(f"  {file_path} (~{tokens} tokens, {region_lines} region lines, {scope_count} scope(s))")
        else:
            typer.echo(f"  {file_path} (~{tokens} tokens)")
    typer.echo(f"Total estimated tokens: {total_tokens}")
    raise typer.Exit(code=0)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Detailed output with timing and token info")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be analyzed without calling the LLM")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Output findings as JSON to stdout")] = False,
    output: Annotated[Path | None, typer.Option("--output", help="Write JSON report to file")] = None,
    _version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version and exit"),
    ] = False,
) -> None:
    """LLM-powered security review of staged git diffs.

    Exit codes: 0 = pass, 1 = blocking findings, 2 = error.
    """
    if ctx.invoked_subcommand is not None:
        return
    try:
        asyncio.run(_run(verbose=verbose, dry_run=dry_run, json_output=json_output, output=output))
    except KeyboardInterrupt:
        typer.echo("\nInterrupted", err=True)
        raise typer.Exit(code=130) from None


async def _run_verbose_analysis(
    prepared: PreparedContext,
    client: OpenAIClient,
    config: DiffguardConfig,
    *,
    json_output: bool,
) -> tuple[AnalysisResult, int, float]:
    """Run analysis in verbose mode with timing and token info."""
    token_estimates = _compute_token_estimates(prepared)
    files_analyzed = len(prepared.code_contexts)
    if not json_output:
        typer.echo(f"Analyzing {files_analyzed} file(s)...")
        for file_path, tokens in token_estimates:
            fc = next(fc for fc in prepared.file_contexts if fc.file_path == file_path)
            region_lines = sum(r.end_line - r.start_line + 1 for r in fc.regions)
            scope_count = len(fc.scopes)
            typer.echo(f"  {file_path} (~{tokens} tokens, {region_lines} region lines, {scope_count} scope(s))")

    start = time.monotonic()
    result = await analyze_files(
        prepared.code_contexts,
        client,
        max_concurrent=config.max_concurrent_api_calls,
        timeout_per_file=float(config.timeout),
    )
    result.errors.extend(prepared.errors)
    elapsed = time.monotonic() - start

    if not json_output:
        typer.echo(f"Analysis completed in {elapsed:.1f}s")

    return result, files_analyzed, elapsed


async def _run(
    *,
    verbose: bool,
    dry_run: bool,
    json_output: bool,
    output: Path | None,
) -> None:
    """Run the analysis pipeline."""
    _validate_git_repo()

    try:
        config = load_config()
    except ConfigError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    if not dry_run:
        _validate_api_key()

    raw_diff = _get_staged_diff_text()

    diff_files = parse_diff(raw_diff)
    if not diff_files:
        typer.echo("No staged changes to analyze.")
        typer.echo("Stage changes with: git add <files>")
        raise typer.Exit(code=0)

    # Suppress rich output when --json is active
    console = Console(stderr=json_output)

    if dry_run or verbose:
        prepared = prepare_file_contexts(diff_files, config)

    if dry_run:
        _handle_dry_run(prepared, verbose=verbose, json_output=json_output, output=output)
        return  # _handle_dry_run raises typer.Exit, but guard return for clarity

    client = OpenAIClient(model=config.model, timeout=config.timeout)

    try:
        if verbose:
            result, files_analyzed, elapsed = await _run_verbose_analysis(
                prepared, client, config, json_output=json_output
            )
        else:
            elapsed = None
            if not json_output:
                with create_progress_spinner(console):
                    result = await analyze_staged_changes(diff_files, config, client)
            else:
                result = await analyze_staged_changes(diff_files, config, client)
            files_analyzed = len(diff_files)
    except DiffguardError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    _save_scan_cache(result.findings)

    blocking = should_block(result.findings, config)

    report_metadata = ReportMetadata(
        files_analyzed=files_analyzed,
        analysis_time_seconds=elapsed,
        commit_hash=get_commit_hash(),
        branch_name=get_branch_name(),
    )

    _route_output(
        result,
        json_output=json_output,
        output=output,
        console=console,
        metadata=report_metadata,
        blocking=blocking,
    )
