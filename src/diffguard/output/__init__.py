"""Output formatting for Diffguard."""

from diffguard.output.json_report import (
    ReportMetadata,
    generate_report,
    print_report,
    write_report,
)
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
    "ReportMetadata",
    "build_stats",
    "create_progress_spinner",
    "format_line_range",
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
