"""CLI entry point for Diffguard."""

import asyncio
import os
from pathlib import Path  # noqa: TC003 — typer needs Path at runtime
from typing import Annotated

import typer

from diffguard import __version__
from diffguard.config import load_config
from diffguard.exceptions import ConfigError, GitError
from diffguard.git import get_staged_diff, is_git_repo, parse_diff
from diffguard.llm import AnalysisResult, OpenAIClient
from diffguard.pipeline import analyze_staged_changes

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

    if dry_run:
        typer.echo(f"Would analyze {len(diff_files)} file(s):")
        for df in diff_files:
            typer.echo(f"  {df.path}")
        raise typer.Exit(code=0)

    client = OpenAIClient(model=config.model, timeout=config.timeout)
    result = await analyze_staged_changes(diff_files, config, client)
    _print_results(result)

    # Flags for future tasks (Task 12, 13, 14)
    _ = verbose
    _ = json_output
    _ = output
