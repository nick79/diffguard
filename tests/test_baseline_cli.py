"""Tests for baseline CLI subcommands."""

import json
from pathlib import Path  # noqa: TC003
from unittest.mock import patch

import pytest  # noqa: TC002
from typer.testing import CliRunner

from diffguard.baseline import BaselineEntry, load_baseline, save_baseline
from diffguard.cli import app
from diffguard.config import DiffguardConfig

runner = CliRunner()

VALID_FINDING_ID = "cwe89-a1b2c3d4e5f6a7b8"
VALID_FINDING_ID_2 = "cwe79-1234567890abcdef"


def _make_baseline(tmp_path: Path, entries: list[BaselineEntry]) -> Path:
    """Create a baseline file with the given entries."""
    baseline_path = tmp_path / ".diffguard-baseline.json"
    save_baseline(entries, baseline_path)
    return baseline_path


def _make_scan_cache(tmp_path: Path, findings: list[dict[str, str]]) -> None:
    """Create a scan cache file."""
    cache_dir = tmp_path / ".diffguard"
    cache_dir.mkdir(exist_ok=True)
    cache_data = {
        "scan_time": "2026-03-06T18:00:00Z",
        "findings": findings,
    }
    (cache_dir / "last_scan.json").write_text(json.dumps(cache_data, indent=2))


def _make_entry(
    finding_id: str = VALID_FINDING_ID,
    cwe_id: str = "CWE-89",
    reason: str = "false positive",
) -> BaselineEntry:
    return BaselineEntry(
        finding_id=finding_id,
        cwe_id=cwe_id,
        code_hash="",
        reason=reason,
        added_at="2026-03-06T18:00:00Z",
        file_path="test.py",
    )


class TestBaselineHelp:
    def test_baseline_help_shows_commands(self) -> None:
        result = runner.invoke(app, ["baseline", "--help"])
        assert result.exit_code == 0
        assert "add" in result.output
        assert "remove" in result.output
        assert "list" in result.output

    def test_baseline_help_shows_description(self) -> None:
        result = runner.invoke(app, ["baseline", "--help"])
        assert "baseline" in result.output.lower()


class TestBaselineAdd:
    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_adds_finding_to_new_baseline(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["baseline", "add", VALID_FINDING_ID, "--reason", "false positive"])
        assert result.exit_code == 0
        assert "Added" in result.output
        entries = load_baseline(tmp_path / ".diffguard-baseline.json")
        assert len(entries) == 1
        assert entries[0].finding_id == VALID_FINDING_ID

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_appends_to_existing_baseline(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_baseline(tmp_path, [_make_entry()])
        result = runner.invoke(app, ["baseline", "add", VALID_FINDING_ID_2, "--reason", "also ok"])
        assert result.exit_code == 0
        entries = load_baseline(tmp_path / ".diffguard-baseline.json")
        assert len(entries) == 2

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_duplicate_warns_and_exits_zero(
        self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _make_baseline(tmp_path, [_make_entry()])
        result = runner.invoke(app, ["baseline", "add", VALID_FINDING_ID, "--reason", "dup"])
        assert result.exit_code == 0
        assert "already in the baseline" in result.output

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_stores_reason(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["baseline", "add", VALID_FINDING_ID, "--reason", "tested and safe"])
        assert result.exit_code == 0
        entries = load_baseline(tmp_path / ".diffguard-baseline.json")
        assert entries[0].reason == "tested and safe"

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_stores_cwe(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["baseline", "add", VALID_FINDING_ID, "--cwe", "CWE-89"])
        assert result.exit_code == 0
        entries = load_baseline(tmp_path / ".diffguard-baseline.json")
        assert entries[0].cwe_id == "CWE-89"

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_stores_utc_timestamp(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["baseline", "add", VALID_FINDING_ID, "--reason", "test"])
        entries = load_baseline(tmp_path / ".diffguard-baseline.json")
        assert entries[0].added_at.endswith("Z")

    def test_invalid_id_format_exits_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["baseline", "add", "bad-id"])
        assert result.exit_code == 2
        assert "Invalid finding ID format" in result.output

    def test_missing_id_exits_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["baseline", "add"])
        assert result.exit_code == 2


class TestBaselineAddFromCache:
    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_enriches_from_scan_cache(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_scan_cache(
            tmp_path,
            [
                {
                    "finding_id": VALID_FINDING_ID,
                    "cwe_id": "CWE-89",
                    "what": "SQL injection",
                    "file_path": "app.py",
                    "severity": "High",
                }
            ],
        )
        result = runner.invoke(app, ["baseline", "add", VALID_FINDING_ID, "--reason", "ok"])
        assert result.exit_code == 0
        entries = load_baseline(tmp_path / ".diffguard-baseline.json")
        assert entries[0].cwe_id == "CWE-89"
        assert entries[0].file_path == "app.py"

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_cwe_flag_overrides_cache(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_scan_cache(
            tmp_path,
            [
                {
                    "finding_id": VALID_FINDING_ID,
                    "cwe_id": "CWE-89",
                    "what": "SQL injection",
                    "file_path": "app.py",
                    "severity": "High",
                }
            ],
        )
        result = runner.invoke(app, ["baseline", "add", VALID_FINDING_ID, "--cwe", "CWE-79", "--reason", "ok"])
        assert result.exit_code == 0
        entries = load_baseline(tmp_path / ".diffguard-baseline.json")
        assert entries[0].cwe_id == "CWE-79"


class TestBaselineAddAllLow:
    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_adds_all_low_and_info(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_scan_cache(
            tmp_path,
            [
                {
                    "finding_id": VALID_FINDING_ID,
                    "cwe_id": "CWE-89",
                    "what": "a",
                    "file_path": "a.py",
                    "severity": "Low",
                },
                {
                    "finding_id": VALID_FINDING_ID_2,
                    "cwe_id": "CWE-79",
                    "what": "b",
                    "file_path": "b.py",
                    "severity": "Info",
                },
                {
                    "finding_id": "cwe78-0000000000000001",
                    "cwe_id": "CWE-78",
                    "what": "c",
                    "file_path": "c.py",
                    "severity": "High",
                },
            ],
        )
        result = runner.invoke(app, ["baseline", "add", "--all-low"])
        assert result.exit_code == 0
        assert "2" in result.output
        entries = load_baseline(tmp_path / ".diffguard-baseline.json")
        assert len(entries) == 2

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_no_scan_cache_exits_2(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["baseline", "add", "--all-low"])
        assert result.exit_code == 2
        assert "No scan cache found" in result.output

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_no_low_findings_exits_0(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_scan_cache(
            tmp_path,
            [
                {
                    "finding_id": VALID_FINDING_ID,
                    "cwe_id": "CWE-89",
                    "what": "a",
                    "file_path": "a.py",
                    "severity": "High",
                },
            ],
        )
        result = runner.invoke(app, ["baseline", "add", "--all-low"])
        assert result.exit_code == 0
        assert "No Low/Info" in result.output

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_skips_duplicates(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_baseline(tmp_path, [_make_entry(finding_id=VALID_FINDING_ID)])
        _make_scan_cache(
            tmp_path,
            [
                {
                    "finding_id": VALID_FINDING_ID,
                    "cwe_id": "CWE-89",
                    "what": "a",
                    "file_path": "a.py",
                    "severity": "Low",
                },
                {
                    "finding_id": VALID_FINDING_ID_2,
                    "cwe_id": "CWE-79",
                    "what": "b",
                    "file_path": "b.py",
                    "severity": "Low",
                },
            ],
        )
        result = runner.invoke(app, ["baseline", "add", "--all-low"])
        assert result.exit_code == 0
        assert "1" in result.output
        entries = load_baseline(tmp_path / ".diffguard-baseline.json")
        assert len(entries) == 2


class TestBaselineRemove:
    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_removes_entry(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_baseline(tmp_path, [_make_entry(), _make_entry(finding_id=VALID_FINDING_ID_2)])
        result = runner.invoke(app, ["baseline", "remove", VALID_FINDING_ID])
        assert result.exit_code == 0
        assert "Removed" in result.output
        entries = load_baseline(tmp_path / ".diffguard-baseline.json")
        assert len(entries) == 1
        assert entries[0].finding_id == VALID_FINDING_ID_2

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_not_found_exits_2(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_baseline(tmp_path, [_make_entry()])
        result = runner.invoke(app, ["baseline", "remove", VALID_FINDING_ID_2])
        assert result.exit_code == 2
        assert "not found" in result.output

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_keeps_file_on_last_entry(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_baseline(tmp_path, [_make_entry()])
        result = runner.invoke(app, ["baseline", "remove", VALID_FINDING_ID])
        assert result.exit_code == 0
        baseline_path = tmp_path / ".diffguard-baseline.json"
        assert baseline_path.exists()
        entries = load_baseline(baseline_path)
        assert len(entries) == 0

    def test_invalid_id_exits_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["baseline", "remove", "not-valid"])
        assert result.exit_code == 2


class TestBaselineList:
    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_shows_entries(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_baseline(tmp_path, [_make_entry()])
        result = runner.invoke(app, ["baseline", "list"])
        assert result.exit_code == 0
        assert "Baselined Findings" in result.output
        assert "cwe89" in result.output

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_empty_baseline_message(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["baseline", "list"])
        assert result.exit_code == 0
        assert "No baselined findings" in result.output

    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig())
    def test_shows_multiple_entries(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        _make_baseline(
            tmp_path,
            [
                _make_entry(),
                _make_entry(finding_id=VALID_FINDING_ID_2, cwe_id="CWE-79", reason="also fine"),
            ],
        )
        result = runner.invoke(app, ["baseline", "list"])
        assert result.exit_code == 0
        assert "cwe89" in result.output
        assert "cwe79" in result.output


class TestBaselinePathConfig:
    @patch("diffguard.baseline_cli.load_config", return_value=DiffguardConfig(baseline_path="custom/baseline.json"))
    def test_uses_custom_path(self, _mock: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["baseline", "add", VALID_FINDING_ID, "--reason", "custom path"])
        assert result.exit_code == 0
        entries = load_baseline(tmp_path / "custom" / "baseline.json")
        assert len(entries) == 1
