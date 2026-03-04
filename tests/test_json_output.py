"""Tests for JSON report generation, writing, and printing."""

import json
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 — used at runtime by tmp_path fixture type hints
from typing import Any

import pytest

from diffguard import __version__
from diffguard.exceptions import ReportWriteError
from diffguard.llm.response import ConfidenceLevel, Finding, SeverityLevel
from diffguard.output.json_report import (
    ReportMetadata,
    generate_report,
    print_report,
    write_report,
)


def _make_finding(
    severity: SeverityLevel = SeverityLevel.HIGH,
    *,
    cwe_id: str | None = "CWE-89",
    owasp_category: str | None = "A05:2025-Injection",
    line_range: tuple[int, int] | None = (42, 45),
    file_path: str | None = "src/db.py",
) -> Finding:
    return Finding(
        what="SQL Injection",
        why="Unsafe query construction",
        how_to_fix="Use parameterized queries",
        severity=severity,
        confidence=ConfidenceLevel.HIGH,
        cwe_id=cwe_id,
        owasp_category=owasp_category,
        line_range=line_range,
        file_path=file_path,
    )


def _make_metadata(**kwargs: Any) -> ReportMetadata:
    defaults: dict[str, Any] = {"files_analyzed": 5}
    defaults.update(kwargs)
    return ReportMetadata(**defaults)


class TestGenerateReport:
    def test_contains_version(self) -> None:
        report = generate_report([], _make_metadata())
        assert report["version"] == __version__

    def test_contains_timestamp(self) -> None:
        report = generate_report([], _make_metadata())
        ts = report["timestamp"]
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None

    def test_contains_findings_array(self) -> None:
        findings = [_make_finding(), _make_finding(SeverityLevel.LOW), _make_finding(SeverityLevel.CRITICAL)]
        report = generate_report(findings, _make_metadata())
        assert len(report["findings"]) == 3

    def test_finding_structure(self) -> None:
        finding = _make_finding()
        report = generate_report([finding], _make_metadata())
        f = report["findings"][0]
        assert f["what"] == "SQL Injection"
        assert f["why"] == "Unsafe query construction"
        assert f["how_to_fix"] == "Use parameterized queries"
        assert f["severity"] == "High"
        assert f["confidence"] == "High"
        assert f["cwe_id"] == "CWE-89"
        assert f["owasp_category"] == "A05:2025-Injection"
        assert f["line_range"] == {"start": 42, "end": 45}
        assert f["file_path"] == "src/db.py"

    def test_summary_section(self) -> None:
        findings = [
            _make_finding(SeverityLevel.CRITICAL),
            _make_finding(SeverityLevel.HIGH),
            _make_finding(SeverityLevel.HIGH),
            _make_finding(SeverityLevel.LOW),
        ]
        report = generate_report(findings, _make_metadata())
        summary = report["summary"]
        assert summary["total"] == 4
        assert summary["Critical"] == 1
        assert summary["High"] == 2
        assert summary["Medium"] == 0
        assert summary["Low"] == 1
        assert summary["Info"] == 0

    def test_metadata_section(self) -> None:
        meta = _make_metadata(analysis_time_seconds=3.5)
        report = generate_report([], meta)
        assert report["metadata"]["files_analyzed"] == 5
        assert report["metadata"]["analysis_time_seconds"] == 3.5

    def test_empty_findings(self) -> None:
        report = generate_report([], _make_metadata())
        assert report["findings"] == []
        assert report["summary"]["total"] == 0
        for level in SeverityLevel:
            assert report["summary"][level.value] == 0

    def test_git_info_in_metadata(self) -> None:
        meta = _make_metadata(commit_hash="abc123", branch_name="feature/auth")
        report = generate_report([], meta)
        assert report["metadata"]["commit_hash"] == "abc123"
        assert report["metadata"]["branch_name"] == "feature/auth"

    def test_schema_version(self) -> None:
        report = generate_report([], _make_metadata())
        assert report["schema_version"] == "1.0"

    def test_metadata_omits_none_values(self) -> None:
        meta = _make_metadata()
        report = generate_report([], meta)
        assert "analysis_time_seconds" not in report["metadata"]
        assert "commit_hash" not in report["metadata"]
        assert "branch_name" not in report["metadata"]


class TestWriteReport:
    def test_creates_file(self, tmp_path: Path) -> None:
        report = generate_report([], _make_metadata())
        out = tmp_path / "report.json"
        write_report(report, out)
        assert out.exists()

    def test_pretty_printed(self, tmp_path: Path) -> None:
        report = generate_report([], _make_metadata())
        out = tmp_path / "report.json"
        write_report(report, out)
        content = out.read_text()
        assert "\n" in content
        assert "  " in content

    def test_utf8_encoding(self, tmp_path: Path) -> None:
        finding = Finding(
            what="Уязвимость инъекции",
            why="危険な入力",
            how_to_fix="使用参数化查询",
            severity=SeverityLevel.MEDIUM,
            confidence=ConfidenceLevel.MEDIUM,
        )
        report = generate_report([finding], _make_metadata())
        out = tmp_path / "report.json"
        write_report(report, out)
        content = out.read_text(encoding="utf-8")
        assert "Уязвимость" in content
        assert "危険" in content

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        report = generate_report([], _make_metadata())
        out = tmp_path / "reports" / "2024" / "jan" / "report.json"
        write_report(report, out)
        assert out.exists()

    def test_permission_error_raises_report_write_error(self, tmp_path: Path) -> None:
        report = generate_report([], _make_metadata())
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)
        out = readonly_dir / "subdir" / "report.json"

        with pytest.raises(ReportWriteError):
            write_report(report, out)

        readonly_dir.chmod(0o755)

    def test_file_ends_with_newline(self, tmp_path: Path) -> None:
        report = generate_report([], _make_metadata())
        out = tmp_path / "report.json"
        write_report(report, out)
        assert out.read_text().endswith("\n")


class TestPrintReport:
    def test_prints_to_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = generate_report([], _make_metadata())
        print_report(report)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "findings" in data

    def test_compact_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = generate_report([], _make_metadata())
        print_report(report, compact=True)
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert len(lines) == 1

    def test_pretty_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = generate_report([], _make_metadata())
        print_report(report, compact=False)
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert len(lines) > 1

    def test_output_is_valid_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = generate_report([_make_finding()], _make_metadata())
        print_report(report)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["findings"][0]["what"] == "SQL Injection"

    def test_no_trailing_comma(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = generate_report([_make_finding()], _make_metadata())
        print_report(report)
        captured = capsys.readouterr()
        assert ",\n}" not in captured.out
        assert ",\n]" not in captured.out


class TestReportValues:
    def test_line_range_as_object(self) -> None:
        finding = _make_finding(line_range=(10, 15))
        report = generate_report([finding], _make_metadata())
        assert report["findings"][0]["line_range"] == {"start": 10, "end": 15}

    def test_severity_as_string(self) -> None:
        finding = _make_finding(SeverityLevel.CRITICAL)
        report = generate_report([finding], _make_metadata())
        assert report["findings"][0]["severity"] == "Critical"

    def test_none_values_omitted(self) -> None:
        finding = _make_finding(cwe_id=None, owasp_category=None, line_range=None, file_path=None)
        report = generate_report([finding], _make_metadata())
        f = report["findings"][0]
        assert "cwe_id" not in f
        assert "owasp_category" not in f
        assert "line_range" not in f
        assert "file_path" not in f

    def test_timestamp_is_utc(self) -> None:
        report = generate_report([], _make_metadata())
        ts = report["timestamp"]
        assert ts.endswith("+00:00")
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo == UTC

    def test_report_round_trips_through_json(self) -> None:
        findings = [_make_finding(), _make_finding(SeverityLevel.LOW, cwe_id=None)]
        report = generate_report(findings, _make_metadata(analysis_time_seconds=2.1))
        serialized = json.dumps(report, indent=2, ensure_ascii=False)
        deserialized = json.loads(serialized)
        assert deserialized["findings"][0]["what"] == "SQL Injection"
        assert deserialized["metadata"]["analysis_time_seconds"] == 2.1
