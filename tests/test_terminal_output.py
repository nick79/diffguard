"""Tests for rich terminal output formatting."""

import re
from io import StringIO

from rich.console import Console

from diffguard.llm.response import ConfidenceLevel, Finding, SeverityLevel
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

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return _ANSI_RE.sub("", text)


def _make_console() -> tuple[Console, StringIO]:
    """Create a console that captures output."""
    output = StringIO()
    console = Console(file=output, force_terminal=True, width=120)
    return console, output


def _make_finding(
    *,
    what: str = "SQL Injection",
    why: str = "User input in query",
    how_to_fix: str = "Use parameterized queries",
    severity: SeverityLevel = SeverityLevel.HIGH,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    cwe_id: str | None = "CWE-89",
    owasp_category: str | None = "A03:2025-Injection",
    line_range: tuple[int, int] | None = (42, 45),
    file_path: str | None = "src/api/users.py",
) -> Finding:
    return Finding(
        what=what,
        why=why,
        how_to_fix=how_to_fix,
        severity=severity,
        confidence=confidence,
        cwe_id=cwe_id,
        owasp_category=owasp_category,
        line_range=line_range,
        file_path=file_path,
    )


class TestFormatLineRange:
    def test_none_returns_empty(self) -> None:
        assert format_line_range(None) == ""

    def test_single_line(self) -> None:
        assert format_line_range((42, 42)) == "42"

    def test_range(self) -> None:
        assert format_line_range((42, 45)) == "42-45"


class TestTruncate:
    def test_short_text_unchanged(self) -> None:
        assert truncate("hello", 10) == "hello"

    def test_exact_length_unchanged(self) -> None:
        assert truncate("hello", 5) == "hello"

    def test_long_text_truncated(self) -> None:
        result = truncate("a" * 100, 20)
        assert len(result) == 20
        assert result.endswith("...")

    def test_truncated_content_preserved(self) -> None:
        result = truncate("abcdefghij", 7)
        assert result == "abcd..."


class TestShortenPath:
    def test_short_path_unchanged(self) -> None:
        assert shorten_path("src/api.py", 40) == "src/api.py"

    def test_long_path_shortened(self) -> None:
        path = "very/deeply/nested/directory/structure/file.py"
        result = shorten_path(path, 30)
        assert result.startswith("...")
        assert "file.py" in result

    def test_shows_parent_and_file(self) -> None:
        path = "a/b/c/d/e/config.py"
        result = shorten_path(path, 18)
        assert result == ".../e/config.py"

    def test_single_component_truncated(self) -> None:
        path = "very_long_filename_that_exceeds_limit.py"
        result = shorten_path(path, 20)
        assert len(result) <= 20


class TestBuildStats:
    def test_empty_findings(self) -> None:
        stats = build_stats([], files_analyzed=5)
        assert stats.files_analyzed == 5
        assert stats.findings_count == 0
        assert stats.severity_counts == {}

    def test_counts_severities(self) -> None:
        findings = [
            _make_finding(severity=SeverityLevel.CRITICAL),
            _make_finding(severity=SeverityLevel.HIGH),
            _make_finding(severity=SeverityLevel.HIGH),
            _make_finding(severity=SeverityLevel.LOW),
        ]
        stats = build_stats(findings, files_analyzed=3)
        assert stats.findings_count == 4
        assert stats.severity_counts[SeverityLevel.CRITICAL] == 1
        assert stats.severity_counts[SeverityLevel.HIGH] == 2
        assert stats.severity_counts[SeverityLevel.LOW] == 1
        assert SeverityLevel.MEDIUM not in stats.severity_counts


class TestPrintFindings:
    def test_table_has_column_headers(self) -> None:
        console, output = _make_console()
        findings = [_make_finding()]
        print_findings(findings, console)
        text = output.getvalue()
        assert "Severity" in text
        assert "File" in text
        assert "Line" in text
        assert "Description" in text

    def test_all_findings_shown(self) -> None:
        console, output = _make_console()
        findings = [_make_finding(what=f"Finding {i}", severity=s) for i, s in enumerate(SeverityLevel)]
        print_findings(findings, console)
        text = output.getvalue()
        for i in range(len(SeverityLevel)):
            assert f"Finding {i}" in text

    def test_severity_text_present(self) -> None:
        console, output = _make_console()
        findings = [_make_finding(severity=SeverityLevel.CRITICAL)]
        print_findings(findings, console)
        assert "Critical" in output.getvalue()

    def test_file_path_shown(self) -> None:
        console, output = _make_console()
        findings = [_make_finding(file_path="src/api/users.py")]
        print_findings(findings, console)
        assert "src/api/users.py" in output.getvalue()

    def test_line_range_shown(self) -> None:
        console, output = _make_console()
        findings = [_make_finding(line_range=(42, 45))]
        print_findings(findings, console)
        assert "42-45" in output.getvalue()

    def test_single_line_shown(self) -> None:
        console, output = _make_console()
        findings = [_make_finding(line_range=(42, 42))]
        print_findings(findings, console)
        text = output.getvalue()
        assert "42" in text
        assert "42-42" not in text

    def test_description_truncated_in_table(self) -> None:
        console, output = _make_console()
        long_desc = "A" * 200
        findings = [_make_finding(what=long_desc)]
        print_findings(findings, console)
        text = _strip_ansi(output.getvalue())
        assert long_desc not in text
        assert "…" in text or "..." in text

    def test_long_path_shortened_in_table(self) -> None:
        console, output = _make_console()
        long_path = "/".join(["dir"] * 10) + "/file.py"
        findings = [_make_finding(file_path=long_path)]
        print_findings(findings, console)
        text = output.getvalue()
        assert "file.py" in text

    def test_none_file_path_handled(self) -> None:
        console, output = _make_console()
        findings = [_make_finding(file_path=None)]
        print_findings(findings, console)
        assert "SQL Injection" in output.getvalue()

    def test_none_line_range_handled(self) -> None:
        console, output = _make_console()
        findings = [_make_finding(line_range=None)]
        print_findings(findings, console)
        assert "SQL Injection" in output.getvalue()


class TestPrintFindingDetail:
    def test_shows_what_why_fix(self) -> None:
        console, output = _make_console()
        finding = _make_finding()
        print_finding_detail(finding, console)
        text = output.getvalue()
        assert "SQL Injection" in text
        assert "User input in query" in text
        assert "Use parameterized queries" in text

    def test_shows_cwe_and_owasp(self) -> None:
        console, output = _make_console()
        finding = _make_finding(cwe_id="CWE-89", owasp_category="A03:2025-Injection")
        print_finding_detail(finding, console)
        text = output.getvalue()
        assert "CWE-89" in text
        assert "A03:2025-Injection" in text

    def test_shows_confidence(self) -> None:
        console, output = _make_console()
        finding = _make_finding(confidence=ConfidenceLevel.LOW)
        print_finding_detail(finding, console)
        assert "Low" in output.getvalue()

    def test_omits_cwe_when_none(self) -> None:
        console, output = _make_console()
        finding = _make_finding(cwe_id=None)
        print_finding_detail(finding, console)
        assert "CWE:" not in output.getvalue()

    def test_omits_owasp_when_none(self) -> None:
        console, output = _make_console()
        finding = _make_finding(owasp_category=None)
        print_finding_detail(finding, console)
        assert "OWASP:" not in output.getvalue()

    def test_panel_has_severity_in_title(self) -> None:
        console, output = _make_console()
        finding = _make_finding(severity=SeverityLevel.CRITICAL)
        print_finding_detail(finding, console)
        text = output.getvalue()
        assert "Critical" in text


class TestPrintFindingsGrouped:
    def test_groups_by_file(self) -> None:
        console, output = _make_console()
        findings = [
            _make_finding(file_path="src/api.py", what="Issue A"),
            _make_finding(file_path="src/api.py", what="Issue B"),
            _make_finding(file_path="src/db.py", what="Issue C"),
        ]
        print_findings_grouped(findings, console)
        text = output.getvalue()
        assert "src/api.py" in text
        assert "src/db.py" in text
        assert "Issue A" in text
        assert "Issue B" in text
        assert "Issue C" in text

    def test_shows_detail_panels(self) -> None:
        console, output = _make_console()
        findings = [_make_finding(what="SQL Injection", why="Dangerous")]
        print_findings_grouped(findings, console)
        text = output.getvalue()
        assert "Dangerous" in text

    def test_handles_none_file_path(self) -> None:
        console, output = _make_console()
        findings = [_make_finding(file_path=None)]
        print_findings_grouped(findings, console)
        text = _strip_ansi(output.getvalue())
        assert "(unknown)" in text


class TestPrintNoFindings:
    def test_shows_checkmark(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(files_analyzed=5, findings_count=0)
        print_no_findings(stats, console)
        text = output.getvalue()
        assert "✔" in text

    def test_shows_file_count(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(files_analyzed=5, findings_count=0)
        print_no_findings(stats, console)
        text = output.getvalue()
        assert "5" in text

    def test_shows_no_issues_message(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(files_analyzed=3, findings_count=0)
        print_no_findings(stats, console)
        text = output.getvalue()
        assert "No security issues found" in text


class TestPrintSummary:
    def test_shows_file_and_finding_counts(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(files_analyzed=5, findings_count=3, severity_counts={})
        print_summary(stats, console)
        text = output.getvalue()
        assert "5" in text
        assert "3" in text

    def test_shows_severity_breakdown(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(
            files_analyzed=5,
            findings_count=3,
            severity_counts={
                SeverityLevel.CRITICAL: 1,
                SeverityLevel.HIGH: 2,
            },
        )
        print_summary(stats, console)
        text = _strip_ansi(output.getvalue())
        assert "1 Critical" in text
        assert "2 High" in text

    def test_omits_zero_counts(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(
            files_analyzed=5,
            findings_count=1,
            severity_counts={SeverityLevel.LOW: 1},
        )
        print_summary(stats, console)
        text = _strip_ansi(output.getvalue())
        assert "Critical" not in text
        assert "High" not in text
        assert "1 Low" in text

    def test_no_breakdown_when_no_findings(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(files_analyzed=3, findings_count=0, severity_counts={})
        print_summary(stats, console)
        text = _strip_ansi(output.getvalue())
        assert "0 issue" in text


class TestProgressSpinner:
    def test_returns_status_context_manager(self) -> None:
        console, _ = _make_console()
        spinner = create_progress_spinner(console)
        assert hasattr(spinner, "__enter__")
        assert hasattr(spinner, "__exit__")


class TestNonTTYOutput:
    def test_no_ansi_when_not_terminal(self) -> None:
        output = StringIO()
        console = Console(file=output, force_terminal=False, width=120)
        findings = [_make_finding(severity=SeverityLevel.CRITICAL)]
        print_findings(findings, console)
        text = output.getvalue()
        assert "\x1b[" not in text
        assert "Critical" in text

    def test_ansi_present_when_terminal(self) -> None:
        output = StringIO()
        console = Console(file=output, force_terminal=True, width=120)
        findings = [_make_finding(severity=SeverityLevel.CRITICAL)]
        print_findings(findings, console)
        text = output.getvalue()
        assert "\x1b[" in text


class TestNarrowTerminal:
    def test_renders_without_error_at_narrow_width(self) -> None:
        output = StringIO()
        console = Console(file=output, force_terminal=True, width=40)
        findings = [_make_finding()]
        print_findings(findings, console)
        text = _strip_ansi(output.getvalue())
        assert "SQL" in text
