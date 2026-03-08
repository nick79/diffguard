"""Tests for CLI entry point."""

import json
import os
import tomllib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from diffguard import __version__
from diffguard.baseline import BaselineEntry
from diffguard.cli import app
from diffguard.config import DiffguardConfig
from diffguard.exceptions import BaselineError, ConfigError, GitError
from diffguard.git import DiffFile, DiffHunk
from diffguard.llm import AnalysisResult, ConfidenceLevel, Finding, SeverityLevel

runner = CliRunner()


def _make_diff_file() -> DiffFile:
    """Create a simple diff file for testing."""
    return DiffFile(
        old_path="test.py",
        new_path="test.py",
        hunks=[
            DiffHunk(
                old_start=1,
                old_count=3,
                new_start=1,
                new_count=3,
                lines=[("+", "print('hello')")],
            )
        ],
    )


def _make_finding() -> Finding:
    """Create a sample security finding."""
    return Finding(
        what="SQL Injection",
        why="User input in query",
        how_to_fix="Use parameterized queries",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        cwe_id="CWE-89",
        file_path="test.py",
        line_range=(1, 3),
    )


class TestCLIHelp:
    def test_runs_without_error(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_shows_description(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "security review" in result.output.lower()

    def test_shows_verbose_option(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "--verbose" in result.output

    def test_shows_dry_run_option(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "--dry-run" in result.output

    def test_shows_json_option(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "--json" in result.output

    def test_shows_output_option(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "--output" in result.output


class TestCLIVersion:
    def test_shows_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_version_contains_diffguard(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert "diffguard" in result.output


class TestGitRepoValidation:
    @patch("diffguard.cli.is_git_repo", return_value=False)
    def test_fails_outside_git_repo(self, _mock_git: MagicMock) -> None:
        result = runner.invoke(app)
        assert result.exit_code == 2

    @patch("diffguard.cli.is_git_repo", return_value=False)
    def test_shows_error_message(self, _mock_git: MagicMock) -> None:
        result = runner.invoke(app)
        assert "Not a git repository" in result.output

    @patch("diffguard.cli.is_git_repo", return_value=False)
    def test_shows_helpful_hint(self, _mock_git: MagicMock) -> None:
        result = runner.invoke(app)
        output_lower = result.output.lower()
        assert "git repository" in output_lower


class TestNoStagedChanges:
    @patch("diffguard.cli.get_staged_diff", return_value="")
    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_exits_with_zero(self, _mock_git: MagicMock, _mock_config: MagicMock, _mock_diff: MagicMock) -> None:
        result = runner.invoke(app)
        assert result.exit_code == 0

    @patch("diffguard.cli.get_staged_diff", return_value="")
    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_shows_no_staged_message(
        self, _mock_git: MagicMock, _mock_config: MagicMock, _mock_diff: MagicMock
    ) -> None:
        result = runner.invoke(app)
        assert "No staged changes" in result.output

    @patch("diffguard.cli.get_staged_diff", return_value="")
    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_shows_git_add_hint(self, _mock_git: MagicMock, _mock_config: MagicMock, _mock_diff: MagicMock) -> None:
        result = runner.invoke(app)
        assert "git add" in result.output


class TestAsyncEntryPoint:
    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_pipeline_runs_with_staged_changes(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult()

        result = runner.invoke(app)

        assert result.exit_code == 0
        mock_analyze.assert_awaited_once()

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_displays_findings(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding()])

        result = runner.invoke(app)

        assert "1 issue" in result.output
        assert "SQL Injection" in result.output

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_displays_no_findings_message(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult()

        result = runner.invoke(app)

        assert "No security issues found" in result.output


class TestConfigLoading:
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.get_staged_diff", return_value="")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_loads_config(
        self,
        _mock_git: MagicMock,
        _mock_diff: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        mock_config.return_value = DiffguardConfig()
        result = runner.invoke(app)

        assert result.exit_code == 0
        mock_config.assert_called_once()

    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.get_staged_diff", return_value="")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_uses_default_when_no_config(
        self,
        _mock_git: MagicMock,
        _mock_diff: MagicMock,
        _mock_config: MagicMock,
    ) -> None:
        result = runner.invoke(app)

        assert result.exit_code == 0

    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    def test_handles_config_error(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
    ) -> None:
        mock_config.side_effect = ConfigError("Invalid TOML syntax")
        result = runner.invoke(app)

        assert result.exit_code == 2
        assert "Invalid TOML syntax" in result.output


class TestAPIKeyValidation:
    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_fails_without_api_key(
        self,
        _mock_git: MagicMock,
        _mock_config: MagicMock,
    ) -> None:
        result = runner.invoke(app)

        assert result.exit_code == 2
        assert "OPENAI_API_KEY" in result.output

    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "   "})
    def test_fails_with_blank_api_key(
        self,
        _mock_git: MagicMock,
        _mock_config: MagicMock,
    ) -> None:
        result = runner.invoke(app)

        assert result.exit_code == 2
        assert "OPENAI_API_KEY" in result.output

    @patch("diffguard.cli.get_staged_diff", return_value="")
    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_dry_run_skips_api_key_check(
        self,
        _mock_git: MagicMock,
        _mock_config: MagicMock,
        _mock_diff: MagicMock,
    ) -> None:
        result = runner.invoke(app, ["--dry-run"])

        assert result.exit_code == 0
        assert "OPENAI_API_KEY" not in result.output


class TestKeyboardInterrupt:
    @patch("diffguard.cli.is_git_repo", side_effect=KeyboardInterrupt)
    def test_graceful_shutdown(self, _mock_git: MagicMock) -> None:
        result = runner.invoke(app)

        assert result.exit_code == 130

    @patch("diffguard.cli.is_git_repo", side_effect=KeyboardInterrupt)
    def test_shows_interrupted_message(self, _mock_git: MagicMock) -> None:
        result = runner.invoke(app)

        assert "Interrupted" in result.output


class TestGitError:
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_handles_git_error(
        self,
        _mock_git: MagicMock,
        _mock_config: MagicMock,
        mock_diff: MagicMock,
    ) -> None:
        mock_diff.side_effect = GitError("git diff failed")
        result = runner.invoke(app)

        assert result.exit_code == 2
        assert "git diff failed" in result.output


def _make_baseline_entry(finding_id: str = "cwe89-a93ce531a288e825", cwe_id: str = "CWE-89") -> BaselineEntry:
    """Create a baseline entry matching _make_finding's CWE and file_path."""
    return BaselineEntry(
        finding_id=finding_id,
        cwe_id=cwe_id,
        code_hash="abc123",
        reason="False positive",
        added_at="2025-01-15T10:30:00Z",
        file_path="test.py",
    )


def _scan_patches() -> list[MagicMock | AsyncMock]:
    """Return the common patch stack for a scan that produces findings."""
    return []


class TestBaselineIntegration:
    """Tests for baseline suppression during scan."""

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.load_baseline")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_baseline_loaded_during_scan(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        mock_load_baseline: MagicMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding()])
        mock_load_baseline.return_value = []

        runner.invoke(app)

        mock_load_baseline.assert_called_once()

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.load_baseline")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_finding_id_shown_in_output(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        mock_load_baseline: MagicMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding()])
        mock_load_baseline.return_value = []

        result = runner.invoke(app)

        assert "cwe89-a93ce531a288e825" in result.output

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.load_baseline")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_suppressed_findings_excluded_from_output(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        mock_load_baseline: MagicMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding()])
        mock_load_baseline.return_value = [_make_baseline_entry()]

        result = runner.invoke(app)

        assert result.exit_code == 0
        assert "SQL Injection" not in result.output

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.load_baseline")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_suppressed_findings_excluded_from_exit_code(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        mock_load_baseline: MagicMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        critical_finding = Finding(
            what="Remote Code Execution",
            why="Unsafe eval",
            how_to_fix="Remove eval",
            severity=SeverityLevel.CRITICAL,
            confidence=ConfidenceLevel.HIGH,
            cwe_id="CWE-94",
            file_path="test.py",
        )
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[critical_finding])
        mock_load_baseline.return_value = [
            _make_baseline_entry(finding_id="cwe94-1ff2d90c0662f624", cwe_id="CWE-94"),
        ]

        result = runner.invoke(app)

        assert result.exit_code == 0

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.load_baseline")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_partial_suppression_blocking_remains(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        mock_load_baseline: MagicMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        sql_finding = _make_finding()
        xss_finding = Finding(
            what="Cross-Site Scripting",
            why="Unescaped output",
            how_to_fix="Escape output",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            cwe_id="CWE-79",
            file_path="views.py",
        )
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[sql_finding, xss_finding])
        mock_load_baseline.return_value = [_make_baseline_entry()]

        result = runner.invoke(app)

        assert result.exit_code == 1
        assert "Cross-Site Scripting" in result.output

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.load_baseline")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_summary_shows_suppressed_count(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        mock_load_baseline: MagicMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        xss_finding = Finding(
            what="Cross-Site Scripting",
            why="Unescaped output",
            how_to_fix="Escape output",
            severity=SeverityLevel.MEDIUM,
            confidence=ConfidenceLevel.MEDIUM,
            cwe_id="CWE-79",
            file_path="views.py",
        )
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding(), xss_finding])
        mock_load_baseline.return_value = [_make_baseline_entry()]

        result = runner.invoke(app)

        assert "1 suppressed" in result.output

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.load_baseline")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_no_baseline_file_works_normally(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        mock_load_baseline: MagicMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding()])
        mock_load_baseline.return_value = []

        result = runner.invoke(app)

        assert result.exit_code == 1
        assert "SQL Injection" in result.output

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.load_baseline")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_json_output_includes_suppressed_count(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        mock_load_baseline: MagicMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        xss_finding = Finding(
            what="Cross-Site Scripting",
            why="Unescaped output",
            how_to_fix="Escape output",
            severity=SeverityLevel.MEDIUM,
            confidence=ConfidenceLevel.MEDIUM,
            cwe_id="CWE-79",
            file_path="views.py",
        )
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding(), xss_finding])
        mock_load_baseline.return_value = [_make_baseline_entry()]

        result = runner.invoke(app, ["--json"])

        report = json.loads(result.output)
        assert report["summary"]["suppressed"] == 1
        assert report["metadata"]["suppressed_count"] == 1

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.load_baseline")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_baseline_load_error_is_non_fatal(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        mock_load_baseline: MagicMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding()])
        mock_load_baseline.side_effect = BaselineError("Invalid JSON")

        result = runner.invoke(app)

        assert result.exit_code == 1
        assert "SQL Injection" in result.output
        assert "Could not load baseline" in result.output

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch("diffguard.cli.load_baseline")
    @patch("diffguard.cli.analyze_staged_changes", new_callable=AsyncMock)
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff")
    @patch("diffguard.cli.load_config")
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_all_findings_suppressed_shows_no_issues(
        self,
        _mock_git: MagicMock,
        mock_config: MagicMock,
        mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_client_cls: MagicMock,
        mock_analyze: AsyncMock,
        mock_load_baseline: MagicMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_config.return_value = DiffguardConfig()
        mock_diff.return_value = "diff --git a/test.py b/test.py\n"
        mock_parse.return_value = [_make_diff_file()]
        mock_client_cls.return_value = MagicMock()
        mock_analyze.return_value = AnalysisResult(findings=[_make_finding()])
        mock_load_baseline.return_value = [_make_baseline_entry()]

        result = runner.invoke(app)

        assert result.exit_code == 0
        assert "No security issues found" in result.output
        assert "1 suppressed" in result.output


class TestEntryPoint:
    def test_script_entry_registered(self) -> None:
        """Verify pyproject.toml has the console_scripts entry."""
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text())
        scripts = data.get("project", {}).get("scripts", {})
        assert "diffguard" in scripts
        assert scripts["diffguard"] == "diffguard.cli:app"
