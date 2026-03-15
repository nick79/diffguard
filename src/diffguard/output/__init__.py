"""Output formatting for Diffguard."""

from diffguard.output.json_report import (
    ReportMetadata,
    generate_report,
    print_report,
    write_report,
)
from diffguard.output.terminal import (
    AnalysisProgress,
    AnalysisStats,
    build_stats,
    create_progress_spinner,
    format_file_done,
    format_file_error,
    format_line_range,
    friendly_error_message,
    print_finding_detail,
    print_findings,
    print_findings_grouped,
    print_no_findings,
    print_summary,
    shorten_path,
    truncate,
)

__all__ = [
    "AnalysisProgress",
    "AnalysisStats",
    "ReportMetadata",
    "build_stats",
    "create_progress_spinner",
    "format_file_done",
    "format_file_error",
    "format_line_range",
    "friendly_error_message",
    "generate_report",
    "print_finding_detail",
    "print_findings",
    "print_findings_grouped",
    "print_no_findings",
    "print_report",
    "print_summary",
    "shorten_path",
    "truncate",
    "write_report",
]
