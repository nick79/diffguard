"""Tests for baseline file loading and saving."""

from __future__ import annotations

import json
import stat
from typing import TYPE_CHECKING

import pytest

from diffguard.baseline import (
    BaselineEntry,
    filter_suppressed,
    get_suppressed,
    is_suppressed,
    load_baseline,
    save_baseline,
)
from diffguard.exceptions import BaselineError
from diffguard.llm.response import ConfidenceLevel, Finding, SeverityLevel

if TYPE_CHECKING:
    from pathlib import Path

SAMPLE_BASELINE_JSON = """
{
  "version": "1.0",
  "entries": [
    {
      "finding_id": "cwe89-abc123",
      "cwe_id": "CWE-89",
      "code_hash": "abc123def456",
      "file_path": "src/db.py",
      "reason": "False positive - input is sanitized upstream",
      "added_at": "2025-01-15T10:30:00Z"
    },
    {
      "finding_id": "cwe79-def456",
      "cwe_id": "CWE-79",
      "code_hash": "def456ghi789",
      "file_path": "src/views.py",
      "reason": "Output is escaped by template engine",
      "added_at": "2025-01-16T14:20:00Z"
    }
  ]
}
"""

INVALID_BASELINE_JSON = "{ not valid json }"
WRONG_SCHEMA_BASELINE = '{"findings": []}'
EMPTY_BASELINE = '{"version": "1.0", "entries": []}'


def _make_finding(
    *,
    cwe_id: str | None = "CWE-89",
    file_path: str | None = "src/db.py",
    what: str = "SQL Injection",
) -> Finding:
    return Finding(
        what=what,
        why="Test reason",
        how_to_fix="Test fix",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        cwe_id=cwe_id,
        file_path=file_path,
    )


@pytest.fixture
def baseline_file(tmp_path: Path) -> Path:
    path = tmp_path / ".diffguard-baseline.json"
    path.write_text(SAMPLE_BASELINE_JSON)
    return path


@pytest.fixture
def sample_entries() -> list[BaselineEntry]:
    return [
        BaselineEntry(
            finding_id="cwe89-abc123",
            cwe_id="CWE-89",
            code_hash="abc123def456",
            reason="False positive",
            added_at="2025-01-15T10:30:00Z",
        ),
    ]


class TestBaselineEntryFields:
    def test_has_all_required_fields(self) -> None:
        entry = BaselineEntry(
            finding_id="cwe89-abc123",
            cwe_id="CWE-89",
            code_hash="abc123def456",
            reason="False positive",
            added_at="2025-01-15T10:30:00Z",
        )
        assert entry.finding_id == "cwe89-abc123"
        assert entry.cwe_id == "CWE-89"
        assert entry.code_hash == "abc123def456"
        assert entry.reason == "False positive"
        assert entry.added_at == "2025-01-15T10:30:00Z"
        assert entry.file_path is None

    def test_optional_file_path(self) -> None:
        entry = BaselineEntry(
            finding_id="cwe89-abc123",
            cwe_id="CWE-89",
            code_hash="abc123def456",
            reason="False positive",
            added_at="2025-01-15T10:30:00Z",
            file_path="src/db.py",
        )
        assert entry.file_path == "src/db.py"

    def test_is_frozen(self) -> None:
        entry = BaselineEntry(
            finding_id="cwe89-abc123",
            cwe_id="CWE-89",
            code_hash="abc123def456",
            reason="False positive",
            added_at="2025-01-15T10:30:00Z",
        )
        with pytest.raises(AttributeError):
            entry.finding_id = "changed"  # type: ignore[misc]


class TestLoadBaseline:
    def test_loads_two_entries(self, baseline_file: Path) -> None:
        entries = load_baseline(baseline_file)
        assert len(entries) == 2

    def test_all_fields_populated(self, baseline_file: Path) -> None:
        entries = load_baseline(baseline_file)
        entry = entries[0]
        assert entry.finding_id == "cwe89-abc123"
        assert entry.cwe_id == "CWE-89"
        assert entry.code_hash == "abc123def456"
        assert entry.file_path == "src/db.py"
        assert entry.reason == "False positive - input is sanitized upstream"
        assert entry.added_at == "2025-01-15T10:30:00Z"

    def test_returns_empty_list_when_file_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "nonexistent.json"
        assert load_baseline(path) == []

    def test_empty_file_returns_empty_list(self, tmp_path: Path) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        path.write_text("")
        assert load_baseline(path) == []

    def test_whitespace_only_file_returns_empty_list(self, tmp_path: Path) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        path.write_text("   \n\n  ")
        assert load_baseline(path) == []

    def test_invalid_json_raises_baseline_error(self, tmp_path: Path) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        path.write_text(INVALID_BASELINE_JSON)
        with pytest.raises(BaselineError, match="Invalid JSON"):
            load_baseline(path)

    def test_wrong_schema_raises_baseline_error(self, tmp_path: Path) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        path.write_text(WRONG_SCHEMA_BASELINE)
        with pytest.raises(BaselineError, match="expected object with 'entries' key"):
            load_baseline(path)

    def test_missing_required_field_raises_baseline_error(self, tmp_path: Path) -> None:
        data = {"version": "1.0", "entries": [{"cwe_id": "CWE-89", "code_hash": "abc"}]}
        path = tmp_path / ".diffguard-baseline.json"
        path.write_text(json.dumps(data))
        with pytest.raises(BaselineError, match=r"missing required field.*finding_id"):
            load_baseline(path)

    def test_extra_fields_ignored(self, tmp_path: Path) -> None:
        data = {
            "version": "1.0",
            "entries": [
                {
                    "finding_id": "cwe89-abc123",
                    "cwe_id": "CWE-89",
                    "code_hash": "abc123def456",
                    "reason": "False positive",
                    "added_at": "2025-01-15T10:30:00Z",
                    "extra_field": "should be ignored",
                    "another_extra": 42,
                }
            ],
        }
        path = tmp_path / ".diffguard-baseline.json"
        path.write_text(json.dumps(data))
        entries = load_baseline(path)
        assert len(entries) == 1
        assert entries[0].finding_id == "cwe89-abc123"

    def test_permission_denied_raises_baseline_error(self, tmp_path: Path) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        path.write_text(SAMPLE_BASELINE_JSON)
        path.chmod(0o000)
        try:
            with pytest.raises(BaselineError, match="Permission denied"):
                load_baseline(path)
        finally:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def test_empty_entries_array(self, tmp_path: Path) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        path.write_text(EMPTY_BASELINE)
        assert load_baseline(path) == []


class TestSaveBaseline:
    def test_creates_file(self, tmp_path: Path, sample_entries: list[BaselineEntry]) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        save_baseline(sample_entries, path)
        assert path.exists()

    def test_valid_json(self, tmp_path: Path, sample_entries: list[BaselineEntry]) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        save_baseline(sample_entries, path)
        data = json.loads(path.read_text())
        assert isinstance(data, dict)
        assert "entries" in data

    def test_pretty_printed(self, tmp_path: Path, sample_entries: list[BaselineEntry]) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        save_baseline(sample_entries, path)
        content = path.read_text()
        assert "\n" in content
        assert "  " in content

    def test_preserves_all_fields(self, tmp_path: Path) -> None:
        entries = [
            BaselineEntry(
                finding_id="cwe89-abc123",
                cwe_id="CWE-89",
                code_hash="abc123def456",
                reason="False positive - input validated",
                added_at="2025-01-15T10:30:00Z",
                file_path="src/db.py",
            ),
        ]
        path = tmp_path / ".diffguard-baseline.json"
        save_baseline(entries, path)
        reloaded = load_baseline(path)
        assert len(reloaded) == 1
        assert reloaded[0].finding_id == entries[0].finding_id
        assert reloaded[0].cwe_id == entries[0].cwe_id
        assert reloaded[0].code_hash == entries[0].code_hash
        assert reloaded[0].reason == entries[0].reason
        assert reloaded[0].added_at == entries[0].added_at
        assert reloaded[0].file_path == entries[0].file_path

    def test_creates_parent_directory(self, tmp_path: Path, sample_entries: list[BaselineEntry]) -> None:
        path = tmp_path / ".diffguard" / "baseline.json"
        save_baseline(sample_entries, path)
        assert path.exists()

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        old_entries = [
            BaselineEntry(
                finding_id="old-id",
                cwe_id="CWE-79",
                code_hash="old_hash",
                reason="Old reason",
                added_at="2025-01-01T00:00:00Z",
            ),
        ]
        save_baseline(old_entries, path)

        new_entries = [
            BaselineEntry(
                finding_id="new-id",
                cwe_id="CWE-89",
                code_hash="new_hash",
                reason="New reason",
                added_at="2025-01-02T00:00:00Z",
            ),
        ]
        save_baseline(new_entries, path)

        reloaded = load_baseline(path)
        assert len(reloaded) == 1
        assert reloaded[0].finding_id == "new-id"

    def test_atomic_write_no_corruption(self, tmp_path: Path, sample_entries: list[BaselineEntry]) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        save_baseline(sample_entries, path)
        content = path.read_text()
        data = json.loads(content)
        assert data["version"] == "1.0"

    def test_includes_version(self, tmp_path: Path, sample_entries: list[BaselineEntry]) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        save_baseline(sample_entries, path)
        data = json.loads(path.read_text())
        assert data["version"] == "1.0"

    def test_trailing_newline(self, tmp_path: Path, sample_entries: list[BaselineEntry]) -> None:
        path = tmp_path / ".diffguard-baseline.json"
        save_baseline(sample_entries, path)
        content = path.read_text()
        assert content.endswith("\n")


class TestIsSuppressed:
    def test_match_by_finding_id(self) -> None:
        baseline = [
            BaselineEntry(
                finding_id="cwe89-a93ce531a288e825",
                cwe_id="CWE-89",
                code_hash="abc123",
                reason="False positive",
                added_at="2025-01-15T10:30:00Z",
                file_path="src/db.py",
            ),
        ]
        finding = _make_finding(cwe_id="CWE-89", file_path="src/db.py")
        assert is_suppressed(finding, baseline) is True

    def test_no_match(self) -> None:
        baseline = [
            BaselineEntry(
                finding_id="cwe79-xyz",
                cwe_id="CWE-79",
                code_hash="xyz789",
                reason="Escaped",
                added_at="2025-01-15T10:30:00Z",
                file_path="src/views.py",
            ),
        ]
        finding = _make_finding(cwe_id="CWE-89", file_path="src/db.py")
        assert is_suppressed(finding, baseline) is False

    def test_no_match_same_cwe_different_what(self) -> None:
        baseline = [
            BaselineEntry(
                finding_id="cwe89-0000000000000000",
                cwe_id="CWE-89",
                code_hash="abc123",
                reason="False positive",
                added_at="2025-01-15T10:30:00Z",
                file_path="src/db.py",
            ),
        ]
        finding = _make_finding(cwe_id="CWE-89", file_path="src/db.py")
        assert is_suppressed(finding, baseline) is False

    def test_empty_baseline(self) -> None:
        finding = _make_finding()
        assert is_suppressed(finding, []) is False

    def test_finding_without_cwe(self) -> None:
        baseline = [
            BaselineEntry(
                finding_id="cwe89-abc",
                cwe_id="CWE-89",
                code_hash="abc123",
                reason="FP",
                added_at="2025-01-15T10:30:00Z",
            ),
        ]
        finding = _make_finding(cwe_id=None, file_path=None)
        assert is_suppressed(finding, baseline) is False


class TestSameCweSameFileOnlyOneMatches:
    def test_only_matching_finding_suppressed(self) -> None:
        finding_a = _make_finding(cwe_id="CWE-89", file_path="src/db.py", what="SQL Injection")
        finding_b = _make_finding(cwe_id="CWE-89", file_path="src/db.py", what="Second SQL Injection")
        baseline = [
            BaselineEntry(
                finding_id="cwe89-a93ce531a288e825",
                cwe_id="CWE-89",
                code_hash="abc123",
                reason="FP",
                added_at="2025-01-15T10:30:00Z",
                file_path="src/db.py",
            ),
        ]
        assert is_suppressed(finding_a, baseline) is True
        assert is_suppressed(finding_b, baseline) is False

    def test_filter_keeps_non_matching_same_cwe(self) -> None:
        finding_a = _make_finding(cwe_id="CWE-89", file_path="src/db.py", what="SQL Injection")
        finding_b = _make_finding(cwe_id="CWE-89", file_path="src/db.py", what="Second SQL Injection")
        baseline = [
            BaselineEntry(
                finding_id="cwe89-a93ce531a288e825",
                cwe_id="CWE-89",
                code_hash="abc123",
                reason="FP",
                added_at="2025-01-15T10:30:00Z",
                file_path="src/db.py",
            ),
        ]
        active = filter_suppressed([finding_a, finding_b], baseline)
        assert len(active) == 1
        assert active[0].what == "Second SQL Injection"

        suppressed = get_suppressed([finding_a, finding_b], baseline)
        assert len(suppressed) == 1
        assert suppressed[0].what == "SQL Injection"


class TestFilterSuppressed:
    def test_filters_suppressed_findings(self) -> None:
        baseline = [
            BaselineEntry(
                finding_id="cwe89-a93ce531a288e825",
                cwe_id="CWE-89",
                code_hash="abc123",
                reason="FP",
                added_at="2025-01-15T10:30:00Z",
                file_path="src/db.py",
            ),
            BaselineEntry(
                finding_id="cwe79-85fea705d69897cf",
                cwe_id="CWE-79",
                code_hash="def456",
                reason="Escaped",
                added_at="2025-01-16T14:20:00Z",
                file_path="src/views.py",
            ),
        ]
        findings = [
            _make_finding(cwe_id="CWE-89", file_path="src/db.py"),
            _make_finding(cwe_id="CWE-79", file_path="src/views.py"),
            _make_finding(cwe_id="CWE-22", file_path="src/files.py", what="Path Traversal"),
            _make_finding(cwe_id="CWE-502", file_path="src/api.py", what="Deserialization"),
            _make_finding(cwe_id="CWE-78", file_path="src/cmd.py", what="Command Injection"),
        ]
        result = filter_suppressed(findings, baseline)
        assert len(result) == 3
        assert all(f.cwe_id not in ("CWE-89", "CWE-79") for f in result)


class TestGetSuppressed:
    def test_returns_suppressed_findings(self) -> None:
        baseline = [
            BaselineEntry(
                finding_id="cwe89-a93ce531a288e825",
                cwe_id="CWE-89",
                code_hash="abc123",
                reason="FP",
                added_at="2025-01-15T10:30:00Z",
                file_path="src/db.py",
            ),
            BaselineEntry(
                finding_id="cwe79-85fea705d69897cf",
                cwe_id="CWE-79",
                code_hash="def456",
                reason="Escaped",
                added_at="2025-01-16T14:20:00Z",
                file_path="src/views.py",
            ),
        ]
        findings = [
            _make_finding(cwe_id="CWE-89", file_path="src/db.py"),
            _make_finding(cwe_id="CWE-79", file_path="src/views.py"),
            _make_finding(cwe_id="CWE-22", file_path="src/files.py", what="Path Traversal"),
            _make_finding(cwe_id="CWE-502", file_path="src/api.py", what="Deserialization"),
            _make_finding(cwe_id="CWE-78", file_path="src/cmd.py", what="Command Injection"),
        ]
        result = get_suppressed(findings, baseline)
        assert len(result) == 2


class TestBaselineTimestampFormat:
    def test_iso_8601_utc_format(self, baseline_file: Path) -> None:
        entries = load_baseline(baseline_file)
        for entry in entries:
            assert entry.added_at.endswith("Z")
            assert "T" in entry.added_at
