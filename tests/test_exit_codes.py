"""Tests for exit codes and commit gating."""

import contextlib
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from diffguard.cli import app
from diffguard.config import DEFAULT_THRESHOLDS, DiffguardConfig, ThresholdAction
from diffguard.exceptions import ConfigError, GitError, LLMServerError, LLMTimeoutError
from diffguard.git import DiffFile, DiffHunk
from diffguard.llm import AnalysisResult, ConfidenceLevel, Finding, SeverityLevel
from diffguard.severity import should_block

runner = CliRunner()


def _make_diff_file() -> DiffFile:
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


def _make_finding(
    severity: SeverityLevel,
    *,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> Finding:
    return Finding(
        what=f"{severity.value} issue",
        why="Test reason",
        how_to_fix="Fix it",
        severity=severity,
        confidence=confidence,
        cwe_id="CWE-79",
        file_path="test.py",
        line_range=(1, 3),
    )


def _patch_full_pipeline(
    findings: list[Finding] | None = None,
    config: DiffguardConfig | None = None,
) -> list[contextlib.AbstractContextManager[Any]]:
    """Return a list of context managers that mock the full pipeline."""
    if findings is None:
        findings = []
    if config is None:
        config = DiffguardConfig()
    return [
        patch("diffguard.cli.is_git_repo", return_value=True),
        patch("diffguard.cli.load_config", return_value=config),
        patch("diffguard.cli.get_staged_diff", return_value="diff --git a/test.py b/test.py\n"),
        patch("diffguard.cli.parse_diff", return_value=[_make_diff_file()]),
        patch("diffguard.cli.OpenAIClient"),
        patch(
            "diffguard.cli.analyze_staged_changes",
            new_callable=AsyncMock,
            return_value=AnalysisResult(findings=findings),
        ),
        patch("diffguard.cli.get_commit_hash", return_value="abc123"),
        patch("diffguard.cli.get_branch_name", return_value="main"),
        patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}),
    ]


class TestExitZeroNoFindings:
    def test_exit_0_no_findings(self) -> None:
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=[]):
                stack.enter_context(p)
            result = runner.invoke(app)
        assert result.exit_code == 0

    def test_exit_0_only_allowed_findings(self) -> None:
        findings = [
            _make_finding(SeverityLevel.LOW),
            _make_finding(SeverityLevel.INFO),
        ]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings):
                stack.enter_context(p)
            result = runner.invoke(app)
        assert result.exit_code == 0

    def test_exit_0_only_warn_findings(self) -> None:
        findings = [_make_finding(SeverityLevel.MEDIUM)]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings):
                stack.enter_context(p)
            result = runner.invoke(app)
        assert result.exit_code == 0

    def test_warn_findings_still_printed(self) -> None:
        findings = [_make_finding(SeverityLevel.MEDIUM)]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings):
                stack.enter_context(p)
            result = runner.invoke(app)
        assert result.exit_code == 0
        assert "Medium issue" in result.output


class TestExitOneBlockingFindings:
    def test_exit_1_critical_finding(self) -> None:
        findings = [_make_finding(SeverityLevel.CRITICAL)]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings):
                stack.enter_context(p)
            result = runner.invoke(app)
        assert result.exit_code == 1

    def test_exit_1_high_finding(self) -> None:
        findings = [_make_finding(SeverityLevel.HIGH)]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings):
                stack.enter_context(p)
            result = runner.invoke(app)
        assert result.exit_code == 1

    def test_exit_1_mixed_findings(self) -> None:
        findings = [
            _make_finding(SeverityLevel.CRITICAL),
            _make_finding(SeverityLevel.MEDIUM),
            _make_finding(SeverityLevel.LOW),
        ]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings):
                stack.enter_context(p)
            result = runner.invoke(app)
        assert result.exit_code == 1

    def test_exit_1_shows_blocking_message(self) -> None:
        findings = [_make_finding(SeverityLevel.CRITICAL)]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings):
                stack.enter_context(p)
            result = runner.invoke(app)
        assert result.exit_code == 1
        assert "Blocking issues found" in result.output


class TestExitTwoErrors:
    @patch("diffguard.cli.is_git_repo", return_value=False)
    def test_exit_2_not_git_repo(self, _mock: MagicMock) -> None:
        result = runner.invoke(app)
        assert result.exit_code == 2

    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_exit_2_missing_api_key(self, _mock_git: MagicMock, _mock_config: MagicMock) -> None:
        result = runner.invoke(app)
        assert result.exit_code == 2

    @patch("diffguard.cli.load_config", side_effect=ConfigError("bad config"))
    @patch("diffguard.cli.is_git_repo", return_value=True)
    def test_exit_2_config_error(self, _mock_git: MagicMock, _mock_config: MagicMock) -> None:
        result = runner.invoke(app)
        assert result.exit_code == 2

    @patch("diffguard.cli.get_staged_diff", side_effect=GitError("git failed"))
    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_exit_2_git_error(self, _mock_git: MagicMock, _mock_config: MagicMock, _mock_diff: MagicMock) -> None:
        result = runner.invoke(app)
        assert result.exit_code == 2

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch(
        "diffguard.cli.analyze_staged_changes",
        new_callable=AsyncMock,
        side_effect=LLMServerError("Internal server error"),
    )
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff", return_value="diff --git a/test.py b/test.py\n")
    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_exit_2_llm_server_error(
        self,
        _mock_git: MagicMock,
        _mock_config: MagicMock,
        _mock_diff: MagicMock,
        mock_parse: MagicMock,
        _mock_client: MagicMock,
        _mock_analyze: AsyncMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        result = runner.invoke(app)
        assert result.exit_code == 2

    @patch("diffguard.cli.get_branch_name", return_value="main")
    @patch("diffguard.cli.get_commit_hash", return_value="abc123")
    @patch(
        "diffguard.cli.analyze_staged_changes",
        new_callable=AsyncMock,
        side_effect=LLMTimeoutError("Timed out"),
    )
    @patch("diffguard.cli.OpenAIClient")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff", return_value="diff --git a/test.py b/test.py\n")
    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"})
    def test_exit_2_llm_timeout(
        self,
        _mock_git: MagicMock,
        _mock_config: MagicMock,
        _mock_diff: MagicMock,
        mock_parse: MagicMock,
        _mock_client: MagicMock,
        _mock_analyze: AsyncMock,
        _mock_commit: MagicMock,
        _mock_branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        result = runner.invoke(app)
        assert result.exit_code == 2


class TestShouldBlock:
    def test_returns_true_for_blocking(self) -> None:
        config = DiffguardConfig()
        findings = [_make_finding(SeverityLevel.CRITICAL)]
        assert should_block(findings, config) is True

    def test_returns_false_for_warn_and_allow(self) -> None:
        config = DiffguardConfig()
        findings = [_make_finding(SeverityLevel.MEDIUM), _make_finding(SeverityLevel.LOW)]
        assert should_block(findings, config) is False

    def test_returns_false_for_empty(self) -> None:
        config = DiffguardConfig()
        assert should_block([], config) is False


class TestCustomThresholdsAffectExitCode:
    def test_custom_medium_block_exits_1(self) -> None:
        config = DiffguardConfig(thresholds={**DEFAULT_THRESHOLDS, SeverityLevel.MEDIUM: ThresholdAction.BLOCK})
        findings = [_make_finding(SeverityLevel.MEDIUM)]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings, config=config):
                stack.enter_context(p)
            result = runner.invoke(app)
        assert result.exit_code == 1

    def test_permissive_critical_still_blocks(self) -> None:
        config = DiffguardConfig(thresholds={**DEFAULT_THRESHOLDS, SeverityLevel.HIGH: ThresholdAction.WARN})
        findings = [_make_finding(SeverityLevel.CRITICAL)]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings, config=config):
                stack.enter_context(p)
            result = runner.invoke(app)
        assert result.exit_code == 1


class TestDryRunAlwaysExitsZero:
    @patch("diffguard.cli.prepare_file_contexts")
    @patch("diffguard.cli.parse_diff")
    @patch("diffguard.cli.get_staged_diff", return_value="diff --git a/test.py b/test.py\n")
    @patch("diffguard.cli.load_config", return_value=DiffguardConfig())
    @patch("diffguard.cli.is_git_repo", return_value=True)
    @patch.dict(os.environ, {}, clear=True)
    def test_dry_run_exits_0(
        self,
        _mock_git: MagicMock,
        _mock_config: MagicMock,
        _mock_diff: MagicMock,
        mock_parse: MagicMock,
        mock_prepared: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        prepared = MagicMock()
        prepared.code_contexts = []
        prepared.file_contexts = []
        mock_prepared.return_value = prepared
        result = runner.invoke(app, ["--dry-run"])
        assert result.exit_code == 0


class TestJsonOutputWithExitCode:
    def test_json_with_blocking_exits_1(self) -> None:
        findings = [_make_finding(SeverityLevel.CRITICAL)]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings):
                stack.enter_context(p)
            result = runner.invoke(app, ["--json"])
        assert result.exit_code == 1

    def test_json_without_blocking_exits_0(self) -> None:
        findings = [_make_finding(SeverityLevel.LOW)]
        with contextlib.ExitStack() as stack:
            for p in _patch_full_pipeline(findings=findings):
                stack.enter_context(p)
            result = runner.invoke(app, ["--json"])
        assert result.exit_code == 0


class TestExitCodeDocumented:
    def test_help_mentions_exit_codes(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "0" in result.output
        assert "1" in result.output
        assert "2" in result.output
