"""CLI entry point for Diffguard."""

import asyncio
import contextlib
import hashlib
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

from diffguard import __version__
from diffguard.baseline import BaselineEntry, filter_suppressed, get_suppressed, load_baseline
from diffguard.baseline_cli import baseline_app
from diffguard.config import DiffguardConfig, load_config
from diffguard.exceptions import BaselineError, ConfigError, DiffguardError, GitError, ReportWriteError
from diffguard.git import DiffFile, get_branch_name, get_commit_hash, get_staged_diff, is_git_repo, parse_diff
from diffguard.llm import SYSTEM_PROMPT, AnalysisResult, OpenAIClient, build_user_prompt, estimate_tokens
from diffguard.llm.analyzer import FileAnalysisError, analyze_files
from diffguard.llm.response import Finding  # noqa: TC001
from diffguard.output.json_report import ReportMetadata, generate_report, print_report, write_report
from diffguard.output.terminal import (
    AnalysisProgress,
    build_stats,
    format_file_done,
    format_file_error,
    friendly_error_message,
    print_findings_grouped,
    print_no_findings,
    print_summary,
)
from diffguard.pipeline import PreparedContext, analyze_staged_changes, filter_by_confidence, prepare_file_contexts
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
        typer.echo("Error: Not a git repository. Run diffguard from within a git project.", err=True)
        raise typer.Exit(code=2)


def _validate_api_key() -> None:
    """Exit with code 2 if OPENAI_API_KEY is missing or blank."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key.strip():
        typer.echo("Error: Invalid API key. Check OPENAI_API_KEY environment variable.", err=True)
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
        typer.echo("No staged changes to analyze. Stage files with 'git add' first.")
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
    """Compute per-file token estimates from prepared contexts.

    Each file estimate includes the system prompt overhead so the total
    reflects actual API usage.
    """
    system_tokens = estimate_tokens(SYSTEM_PROMPT)
    estimates: list[tuple[str, int]] = []
    for ctx in prepared.code_contexts:
        prompt = build_user_prompt(ctx)
        tokens = estimate_tokens(prompt) + system_tokens
        estimates.append((ctx.file_path, tokens))
    return estimates


def _cwe_to_prefix(cwe: str) -> str:
    """Convert a CWE identifier to a lowercase prefix (e.g., 'CWE-89' -> 'cwe89')."""
    return cwe.lower().replace("-", "")


def _compute_finding_id(finding: Finding) -> str:
    """Compute a stable finding ID from CWE, file path, and line range.

    Uses stable attributes (not LLM-generated text) so the ID remains
    consistent across runs even when the LLM varies its descriptions.
    """
    prefix = _cwe_to_prefix(finding.cwe_id or "unknown")
    parts = [prefix]
    if finding.file_path:
        parts.append(finding.file_path)
    if finding.line_range:
        parts.append(str(finding.line_range[0]))
    if len(parts) == 1:
        parts.append(finding.what)
    hash_input = ":".join(parts)
    return f"{prefix}-{hashlib.sha256(hash_input.encode()).hexdigest()[:16]}"


def _save_scan_cache(findings: list[Finding]) -> None:
    """Save findings to .diffguard/last_scan.json for baseline CLI enrichment."""
    cache_dir = Path(".diffguard")
    cache_dir.mkdir(exist_ok=True)
    cache_data = {
        "scan_time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": [
            {
                "finding_id": _compute_finding_id(f),
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


def _load_baseline_safe(config: DiffguardConfig) -> list[BaselineEntry]:
    """Load baseline entries, returning empty list on error with a warning."""
    try:
        return load_baseline(Path(config.baseline_path))
    except BaselineError as exc:
        typer.echo(f"Warning: Could not load baseline: {exc}", err=True)
        return []


def _build_finding_ids(findings: list[Finding]) -> dict[Finding, str]:
    """Build a mapping of findings to their computed IDs."""
    return {f: _compute_finding_id(f) for f in findings}


def _print_errors(errors: list[FileAnalysisError]) -> None:
    """Print file analysis errors with user-friendly messages."""
    for error in errors:
        msg = friendly_error_message(error.error_type, error.error)
        typer.echo(f"Warning: {format_file_error(error.file_path, msg)}", err=True)


def _print_results(
    result: AnalysisResult,
    console: Console,
    *,
    files_analyzed: int,
    blocking: bool,
    suppressed_count: int = 0,
    elapsed: float | None = None,
) -> None:
    """Print analysis results to the terminal using rich formatting."""
    stats = build_stats(result.findings, files_analyzed, suppressed_count=suppressed_count)

    if result.findings:
        finding_ids = _build_finding_ids(result.findings)
        print_findings_grouped(result.findings, console, finding_ids=finding_ids)
        console.print()
        print_summary(stats, console, elapsed=elapsed)
        if blocking:
            console.print("[bold red]Blocking issues found — commit should be rejected.[/bold red]")
        console.print()
        console.print("[dim]To suppress a finding: diffguard baseline add <finding-id>[/dim]")
    else:
        print_no_findings(stats, console, elapsed=elapsed)

    _print_errors(result.errors)


def _route_output(
    result: AnalysisResult,
    *,
    json_output: bool,
    output: Path | None,
    console: Console,
    metadata: ReportMetadata,
    blocking: bool,
    suppressed_count: int = 0,
    elapsed: float | None = None,
) -> None:
    """Route analysis results to the appropriate output destinations."""
    if not json_output and not output:
        _print_results(
            result,
            console,
            files_analyzed=metadata.files_analyzed,
            blocking=blocking,
            suppressed_count=suppressed_count,
            elapsed=elapsed,
        )
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
            _print_results(
                result,
                console,
                files_analyzed=metadata.files_analyzed,
                blocking=blocking,
                suppressed_count=suppressed_count,
                elapsed=elapsed,
            )
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


def _handle_errors_non_interactive(errors: list[FileAnalysisError], *, fail_on_error: bool) -> None:
    """In non-TTY mode, abort on errors unless fail_on_error is False."""
    if not errors:
        return
    if fail_on_error:
        _print_errors(errors)
        typer.echo("Error: Analysis failed for one or more files. Aborting.", err=True)
        raise typer.Exit(code=2)
    # Lenient mode: warn and continue
    for error in errors:
        msg = friendly_error_message(error.error_type, error.error)
        typer.echo(f"Warning: Skipping {error.file_path}: {msg}", err=True)


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

    file_start_times: dict[str, float] = {}
    file_findings: dict[str, int] = {}

    def _verbose_callback(file_path: str, _completed: int, _total: int) -> None:
        file_findings.setdefault(file_path, 0)

    start = time.monotonic()

    # Track per-file timing using a wrapper
    for ctx in prepared.code_contexts:
        file_start_times[ctx.file_path] = time.monotonic()

    result = await analyze_files(
        prepared.code_contexts,
        client,
        max_concurrent=config.max_concurrent_api_calls,
        timeout_per_file=float(config.timeout),
        on_progress=_verbose_callback,
    )
    result.findings = filter_by_confidence(result.findings, config.min_confidence)
    result.errors.extend(prepared.errors)
    elapsed = time.monotonic() - start

    if not json_output:
        # Show per-file results
        error_files = {e.file_path for e in result.errors}
        findings_per_file: dict[str, int] = {}
        for f in result.findings:
            findings_per_file[f.file_path or ""] = findings_per_file.get(f.file_path or "", 0) + 1

        for ctx in prepared.code_contexts:
            if ctx.file_path in error_files:
                error = next(e for e in result.errors if e.file_path == ctx.file_path)
                msg = friendly_error_message(error.error_type, error.error)
                typer.echo(format_file_error(ctx.file_path, msg))
            else:
                count = findings_per_file.get(ctx.file_path, 0)
                file_elapsed = elapsed / max(files_analyzed, 1)  # approximate per-file
                typer.echo(format_file_done(ctx.file_path, file_elapsed, count))

        typer.echo(f"Analysis completed in {elapsed:.1f}s")

    return result, files_analyzed, elapsed


async def _run_default_analysis(
    diff_files: list[DiffFile],
    config: DiffguardConfig,
    client: OpenAIClient,
    console: Console,
    *,
    json_output: bool,
) -> tuple[AnalysisResult, int, float]:
    """Run analysis in default (non-verbose) mode with progress bar."""
    start = time.monotonic()
    total_files = len(diff_files)
    if not json_output:
        with AnalysisProgress(console, total_files) as progress:
            result = await analyze_staged_changes(diff_files, config, client, on_progress=progress.update)
    else:
        result = await analyze_staged_changes(diff_files, config, client)
    elapsed = time.monotonic() - start
    return result, total_files, elapsed


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
        typer.echo("No staged changes to analyze. Stage files with 'git add' first.")
        raise typer.Exit(code=0)

    # Suppress rich output when --json is active
    console = Console(stderr=json_output)

    if dry_run or verbose:
        prepared = prepare_file_contexts(diff_files, config)

    if dry_run:
        _handle_dry_run(prepared, verbose=verbose, json_output=json_output, output=output)
        return  # _handle_dry_run raises typer.Exit, but guard return for clarity

    client = OpenAIClient(model=config.model, timeout=config.timeout, temperature=config.temperature)

    try:
        if verbose:
            result, files_analyzed, elapsed = await _run_verbose_analysis(
                prepared, client, config, json_output=json_output
            )
        else:
            result, files_analyzed, elapsed = await _run_default_analysis(
                diff_files, config, client, console, json_output=json_output
            )
    except DiffguardError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    # In non-TTY mode, abort on errors if configured
    if not sys.stdout.isatty() and not json_output:
        _handle_errors_non_interactive(result.errors, fail_on_error=config.fail_on_error)

    _save_scan_cache(result.findings)

    baseline = _load_baseline_safe(config)
    suppressed = get_suppressed(result.findings, baseline)
    active_findings = filter_suppressed(result.findings, baseline)
    suppressed_count = len(suppressed)

    if verbose and not json_output and suppressed_count > 0:
        for finding in suppressed:
            typer.echo(f"  Suppressed: {finding.cwe_id or 'unknown'} \u2014 {finding.what}", err=True)

    result.findings = active_findings
    blocking = should_block(result.findings, config)

    report_metadata = ReportMetadata(
        files_analyzed=files_analyzed,
        analysis_time_seconds=elapsed,
        commit_hash=get_commit_hash(),
        branch_name=get_branch_name(),
        suppressed_count=suppressed_count,
    )

    _route_output(
        result,
        json_output=json_output,
        output=output,
        console=console,
        metadata=report_metadata,
        blocking=blocking,
        suppressed_count=suppressed_count,
        elapsed=elapsed,
    )
