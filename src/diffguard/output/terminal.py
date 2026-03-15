"""Rich terminal output for security findings."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from diffguard.llm.response import Finding, SeverityLevel

if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.console import Console
    from rich.status import Status

__all__ = [
    "AnalysisProgress",
    "AnalysisStats",
    "build_stats",
    "create_progress_spinner",
    "format_file_done",
    "format_file_error",
    "format_line_range",
    "friendly_error_message",
    "print_finding_detail",
    "print_findings",
    "print_findings_grouped",
    "print_no_findings",
    "print_summary",
    "shorten_path",
    "truncate",
]

SEVERITY_STYLES: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "bold red",
    SeverityLevel.HIGH: "red",
    SeverityLevel.MEDIUM: "yellow",
    SeverityLevel.LOW: "blue",
    SeverityLevel.INFO: "dim",
}

_SEVERITY_ORDER = [
    SeverityLevel.CRITICAL,
    SeverityLevel.HIGH,
    SeverityLevel.MEDIUM,
    SeverityLevel.LOW,
    SeverityLevel.INFO,
]

# Mapping from FileAnalysisError.error_type to user-friendly messages.
_ERROR_TYPE_MESSAGES: dict[str, str] = {
    "LLMTimeoutError": "Request timed out. The OpenAI API did not respond in time. Try again or check your network.",
    "TimeoutError": "Request timed out. The OpenAI API did not respond in time. Try again or check your network.",
    "LLMRateLimitError": "Rate limit exceeded. Wait and retry, or check your API plan.",
    "LLMAuthenticationError": "Invalid API key. Check OPENAI_API_KEY environment variable.",
    "LLMConnectionError": "Failed to connect to OpenAI API. Check your network connection.",
    "LLMServerError": "OpenAI API server error. Try again later.",
    "LLMModelNotFoundError": "Model not found. Check your model configuration.",
    "LLMContextLengthError": "Input too large for model context window. Try reducing file size.",
}


@dataclass
class AnalysisStats:
    """Display metadata for analysis results."""

    files_analyzed: int
    findings_count: int
    severity_counts: dict[SeverityLevel, int] = field(default_factory=dict)
    suppressed_count: int = 0


class AnalysisProgress:
    """Rich progress display for multi-file analysis.

    When the console is not a terminal (piped output), all display
    operations are silently skipped.
    """

    def __init__(self, console: Console, total_files: int) -> None:
        self._console = console
        self._total = total_files
        self._is_terminal = console.is_terminal
        self._progress: Progress | None = None
        self._task_id: object = None

    def __enter__(self) -> AnalysisProgress:
        if not self._is_terminal:
            return self
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("[dim]{task.fields[current_file]}"),
            TimeElapsedColumn(),
            console=self._console,
            transient=True,
        )
        self._progress.start()
        self._task_id = self._progress.add_task("Analyzing...", total=self._total, current_file="")
        return self

    def __exit__(self, *_args: object) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None

    def update(self, file_path: str, completed: int, _total: int) -> None:
        """Update progress bar after a file completes."""
        if self._progress is not None and self._task_id is not None:
            self._progress.update(self._task_id, completed=completed, current_file=file_path)  # type: ignore[arg-type]

    @property
    def callback(self) -> Callable[[str, int, int], None]:
        """Return a callback compatible with ``analyze_files(on_progress=...)``."""
        return self.update


def format_file_done(file_path: str, elapsed: float, findings_count: int) -> str:
    """Format a verbose per-file completion line."""
    return f"  \u2713 {file_path} ({elapsed:.1f}s, {findings_count} finding(s))"


def format_file_error(file_path: str, error: str) -> str:
    """Format a verbose per-file error line."""
    return f"  \u2717 {file_path} (error: {error})"


def friendly_error_message(error_type: str, error: str) -> str:
    """Map an error type to a user-friendly message, falling back to the raw error."""
    return _ERROR_TYPE_MESSAGES.get(error_type, error)


def format_line_range(line_range: tuple[int, int] | None) -> str:
    """Format a line range for display.

    Returns "42" for (42, 42), "42-45" for (42, 45), "" for None.
    """
    if line_range is None:
        return ""
    start, end = line_range
    if start == end:
        return str(start)
    return f"{start}-{end}"


def truncate(text: str, max_len: int) -> str:
    """Truncate text with '...' if over max_len."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def shorten_path(path: str, max_len: int) -> str:
    """Shorten a file path for display.

    Shows '.../parent/file.py' if path too long.
    """
    if len(path) <= max_len:
        return path
    parts = path.split("/")
    if len(parts) <= 2:
        return truncate(path, max_len)
    short = f".../{parts[-2]}/{parts[-1]}"
    if len(short) <= max_len:
        return short
    return f".../{parts[-1]}"


def build_stats(findings: list[Finding], files_analyzed: int, *, suppressed_count: int = 0) -> AnalysisStats:
    """Create AnalysisStats from a findings list."""
    severity_counts: dict[SeverityLevel, int] = defaultdict(int)
    for finding in findings:
        severity_counts[finding.severity] += 1
    return AnalysisStats(
        files_analyzed=files_analyzed,
        findings_count=len(findings),
        severity_counts=dict(severity_counts),
        suppressed_count=suppressed_count,
    )


def print_findings(findings: list[Finding], console: Console) -> None:
    """Print findings as a rich table with colored severity."""
    table = Table(title="Security Findings", show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("File", max_width=40)
    table.add_column("Line", width=8)
    table.add_column("Description", min_width=30)

    for finding in findings:
        style = SEVERITY_STYLES.get(finding.severity, "")
        severity_text = Text(finding.severity.value, style=style)
        file_path = shorten_path(finding.file_path or "", 40)
        line = format_line_range(finding.line_range)
        description = truncate(finding.what, 80)
        table.add_row(severity_text, file_path, line, description)

    console.print(table)


def print_finding_detail(finding: Finding, console: Console, *, finding_id: str | None = None) -> None:
    """Print a detailed panel for a single finding."""
    style = SEVERITY_STYLES.get(finding.severity, "")
    lines: list[str] = [
        f"[bold]What:[/bold] {finding.what}",
        f"[bold]Why:[/bold] {finding.why}",
        f"[bold]How to fix:[/bold] {finding.how_to_fix}",
    ]
    if finding.cwe_id:
        lines.append(f"[bold]CWE:[/bold] {finding.cwe_id}")
    if finding.owasp_category:
        lines.append(f"[bold]OWASP:[/bold] {finding.owasp_category}")
    lines.append(f"[bold]Confidence:[/bold] {finding.confidence.value}")
    if finding_id:
        lines.append(f"[bold]ID:[/bold] [dim]{finding_id}[/dim]")

    title = f"{finding.severity.value}: {truncate(finding.what, 60)}"
    content = "\n".join(lines)
    console.print(Panel(content, title=title, border_style=style))


def print_findings_grouped(
    findings: list[Finding],
    console: Console,
    *,
    finding_ids: dict[Finding, str] | None = None,
) -> None:
    """Print findings grouped by file path."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        key = finding.file_path or "(unknown)"
        groups[key].append(finding)

    ids = finding_ids or {}

    for file_path, group in groups.items():
        console.print()
        console.print(f"[bold]{file_path}[/bold]")

        table = Table(show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("Line", width=8)
        table.add_column("Description", min_width=30)

        for finding in group:
            style = SEVERITY_STYLES.get(finding.severity, "")
            severity_text = Text(finding.severity.value, style=style)
            line = format_line_range(finding.line_range)
            description = truncate(finding.what, 80)
            table.add_row(severity_text, line, description)

        console.print(table)

        for finding in group:
            print_finding_detail(finding, console, finding_id=ids.get(finding))


def print_no_findings(stats: AnalysisStats, console: Console, *, elapsed: float | None = None) -> None:
    """Print a success message when no findings exist."""
    suffix = ""
    if stats.suppressed_count > 0:
        suffix = f" ({stats.suppressed_count} suppressed)"
    elapsed_part = f" in {elapsed:.1f}s" if elapsed is not None else ""
    console.print(
        f"[green]\u2714 Analyzed {stats.files_analyzed} file(s){elapsed_part}"
        f" \u2014 No security issues found{suffix}[/green]"
    )


def print_summary(stats: AnalysisStats, console: Console, *, elapsed: float | None = None) -> None:
    """Print summary statistics for the analysis."""
    suppressed_suffix = ""
    if stats.suppressed_count > 0:
        suppressed_suffix = f" ({stats.suppressed_count} suppressed)"
    elapsed_part = f" in {elapsed:.1f}s" if elapsed is not None else ""
    console.print(
        f"Analyzed {stats.files_analyzed} file(s){elapsed_part},"
        f" found {stats.findings_count} issue(s){suppressed_suffix}"
    )

    parts: list[str] = []
    for severity in _SEVERITY_ORDER:
        count = stats.severity_counts.get(severity, 0)
        if count > 0:
            style = SEVERITY_STYLES[severity]
            parts.append(f"[{style}]{count} {severity.value}[/{style}]")

    if parts:
        console.print(", ".join(parts))


def create_progress_spinner(console: Console) -> Status:
    """Return a rich Status context manager for analysis progress."""
    return console.status("[bold blue]Analyzing staged changes...", spinner="dots")
