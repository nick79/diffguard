"""CLI entry point for Diffguard."""

import asyncio
import json
import os
import time
from pathlib import Path  # noqa: TC003 — typer needs Path at runtime
from typing import Annotated, Any

import typer

from diffguard import __version__
from diffguard.config import load_config
from diffguard.exceptions import ConfigError, GitError
from diffguard.git import get_staged_diff, is_git_repo, parse_diff
from diffguard.llm import AnalysisResult, Finding, OpenAIClient, build_user_prompt, estimate_tokens
from diffguard.llm.analyzer import FileAnalysisError, analyze_files
from diffguard.pipeline import PreparedContext, analyze_staged_changes, prepare_file_contexts

app = typer.Typer(
    name="diffguard",
    help="LLM-powered security review of staged git diffs.",
    no_args_is_help=False,
)


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
    """Exit with code 1 if OPENAI_API_KEY is missing or blank."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key.strip():
        typer.echo("Error: OPENAI_API_KEY environment variable is not set.", err=True)
        typer.echo("Set it with: export OPENAI_API_KEY=sk-your-key-here", err=True)
        raise typer.Exit(code=1) from None


def _get_staged_diff_text() -> str:
    """Get staged diff text, exiting on error or empty diff."""
    try:
        raw_diff = get_staged_diff()
    except GitError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    if not raw_diff.strip():
        typer.echo("No staged changes to analyze.")
        typer.echo("Stage changes with: git add <files>")
        raise typer.Exit(code=0)

    return raw_diff


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Serialize a Finding to a JSON-compatible dict."""
    d: dict[str, Any] = {
        "what": finding.what,
        "why": finding.why,
        "how_to_fix": finding.how_to_fix,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
    }
    if finding.cwe_id is not None:
        d["cwe_id"] = finding.cwe_id
    if finding.owasp_category is not None:
        d["owasp_category"] = finding.owasp_category
    if finding.line_range is not None:
        d["line_range"] = {"start": finding.line_range[0], "end": finding.line_range[1]}
    if finding.file_path is not None:
        d["file_path"] = finding.file_path
    return d


def _error_to_dict(error: FileAnalysisError) -> dict[str, str]:
    """Serialize a FileAnalysisError to a JSON-compatible dict."""
    return {
        "file_path": error.file_path,
        "error": error.error,
        "error_type": error.error_type,
    }


def _serialize_result(result: AnalysisResult) -> dict[str, Any]:
    """Serialize an AnalysisResult to a JSON-compatible dict."""
    data: dict[str, Any] = {
        "findings": [_finding_to_dict(f) for f in result.findings],
    }
    if result.errors:
        data["errors"] = [_error_to_dict(e) for e in result.errors]
    return data


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
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n")
    except OSError as exc:
        typer.echo(f"Error: Permission denied writing to {path}", err=True)
        raise typer.Exit(code=1) from exc


def _compute_token_estimates(prepared: PreparedContext) -> list[tuple[str, int]]:
    """Compute per-file token estimates from prepared contexts."""
    estimates: list[tuple[str, int]] = []
    for ctx in prepared.code_contexts:
        prompt = build_user_prompt(ctx)
        tokens = estimate_tokens(prompt)
        estimates.append((ctx.file_path, tokens))
    return estimates


def _print_results(result: AnalysisResult) -> None:
    """Print analysis results to the terminal."""
    if result.findings:
        typer.echo(f"Found {len(result.findings)} security issue(s).")
        for finding in result.findings:
            typer.echo(f"  [{finding.severity.value}] {finding.what} ({finding.file_path})")
    else:
        typer.echo("No security issues found.")

    if result.errors:
        for error in result.errors:
            typer.echo(f"Warning: Error analyzing {error.file_path}: {error.error}", err=True)


def _has_critical_or_high(result: AnalysisResult) -> bool:
    """Check if any finding has Critical or High severity."""
    from diffguard.llm import SeverityLevel  # noqa: PLC0415

    return any(f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) for f in result.findings)


def _route_output(
    result: AnalysisResult,
    *,
    json_output: bool,
    output: Path | None,
) -> None:
    """Route analysis results to the appropriate output destinations."""
    if not json_output and not output:
        _print_results(result)
        return

    data = _serialize_result(result)
    if json_output:
        typer.echo(json.dumps(data, indent=2))
    if output:
        _write_json_file(data, output)
        if not json_output:
            _print_results(result)
            typer.echo(f"Report saved to {output}")
    if json_output and _has_critical_or_high(result):
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


@app.command()
def main(
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
    """LLM-powered security review of staged git diffs."""
    try:
        asyncio.run(_run(verbose=verbose, dry_run=dry_run, json_output=json_output, output=output))
    except KeyboardInterrupt:
        typer.echo("\nInterrupted", err=True)
        raise typer.Exit(code=130) from None


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
        raise typer.Exit(code=1) from None

    if not dry_run:
        _validate_api_key()

    raw_diff = _get_staged_diff_text()

    diff_files = parse_diff(raw_diff)
    if not diff_files:
        typer.echo("No staged changes to analyze.")
        typer.echo("Stage changes with: git add <files>")
        raise typer.Exit(code=0)

    if dry_run or verbose:
        prepared = prepare_file_contexts(diff_files, config)

    if dry_run:
        _handle_dry_run(prepared, verbose=verbose, json_output=json_output, output=output)
        return  # _handle_dry_run raises typer.Exit, but guard return for clarity

    client = OpenAIClient(model=config.model, timeout=config.timeout)

    if verbose:
        token_estimates = _compute_token_estimates(prepared)
        if not json_output:
            typer.echo(f"Analyzing {len(prepared.code_contexts)} file(s)...")
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
    else:
        result = await analyze_staged_changes(diff_files, config, client)

    _route_output(result, json_output=json_output, output=output)
