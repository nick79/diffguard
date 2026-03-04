"""Terminal output formatting for Diffguard."""

from diffguard.output.terminal import (
    AnalysisStats,
    build_stats,
    create_progress_spinner,
    format_line_range,
    print_finding_detail,
    print_findings,
    print_findings_grouped,
    print_no_findings,
    print_summary,
    shorten_path,
    truncate,
)

__all__ = [
    "AnalysisStats",
    "build_stats",
    "create_progress_spinner",
    "format_line_range",
    "print_finding_detail",
    "print_findings",
    "print_findings_grouped",
    "print_no_findings",
    "print_summary",
    "shorten_path",
    "truncate",
]
