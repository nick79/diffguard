"""Tests for progress indicators and UX polish."""

import os
import re
from io import StringIO
from unittest.mock import AsyncMock, MagicMock, patch

from rich.console import Console
from typer.testing import CliRunner

from diffguard.ast.languages import Language
from diffguard.cli import app
from diffguard.config import DiffguardConfig
from diffguard.context import Region
from diffguard.git import DiffFile, DiffHunk
from diffguard.llm import AnalysisResult, CodeContext, ConfidenceLevel, DiffLine, Finding, SeverityLevel
from diffguard.llm.analyzer import FileAnalysisError
from diffguard.llm.prompts import ScopeContext
from diffguard.output.terminal import (
    AnalysisProgress,
    AnalysisStats,
    format_file_done,
    format_file_error,
    friendly_error_message,
    print_no_findings,
    print_summary,
)
from diffguard.pipeline import FileContext, PreparedContext

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_DIFF_TEXT = "diff --git a/test.py b/test.py\n"


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _make_console(*, is_terminal: bool = True) -> tuple[Console, StringIO]:
    output = StringIO()
    console = Console(file=output, force_terminal=is_terminal, width=120)
    return console, output


def _make_diff_file(path: str = "test.py") -> DiffFile:
    return DiffFile(
        old_path=path,
        new_path=path,
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
    severity: SeverityLevel = SeverityLevel.HIGH,
    file_path: str = "test.py",
) -> Finding:
    return Finding(
        what="SQL Injection",
        why="User input in query",
        how_to_fix="Use parameterized queries",
        severity=severity,
        confidence=ConfidenceLevel.HIGH,
        cwe_id="CWE-89",
        file_path=file_path,
        line_range=(1, 3),
    )


def _make_prepared() -> PreparedContext:
    fc = FileContext(
        file_path="test.py",
        language=Language.PYTHON,
        source_lines=["print('hello')", "x = 1", "y = 2"],
        regions=[Region(start_line=1, end_line=3)],
        diff_lines=[DiffLine(line_num=1, change_type="+", content="print('hello')")],
        scopes=[ScopeContext(type="function", name="main", start_line=1, end_line=3, source="def main(): ...")],
    )
    cc = CodeContext(
        file_path="test.py",
        diff_lines=[DiffLine(line_num=1, change_type="+", content="print('hello')")],
        expanded_region="print('hello')\nx = 1\ny = 2",
        region_start_line=1,
        scopes=[ScopeContext(type="function", name="main", start_line=1, end_line=3, source="def main(): ...")],
    )
    return PreparedContext(file_contexts=[fc], code_contexts=[cc])


# Common patch targets
_GIT = "diffguard.cli.is_git_repo"
_CONFIG = "diffguard.cli.load_config"
_DIFF = "diffguard.cli.get_staged_diff"
_PARSE = "diffguard.cli.parse_diff"
_ANALYZE = "diffguard.cli.analyze_staged_changes"
_PREPARE = "diffguard.cli.prepare_file_contexts"
_ANALYZE_FILES = "diffguard.cli.analyze_files"
_CLIENT = "diffguard.cli.OpenAIClient"
_COMMIT = "diffguard.cli.get_commit_hash"
_BRANCH = "diffguard.cli.get_branch_name"
_ENV = {"OPENAI_API_KEY": "test-key"}


# ---------------------------------------------------------------------------
# AnalysisProgress
# ---------------------------------------------------------------------------


class TestAnalysisProgress:
    def test_creates_context_manager(self) -> None:
        console, _ = _make_console()
        progress = AnalysisProgress(console, 5)
        assert hasattr(progress, "__enter__")
        assert hasattr(progress, "__exit__")

    def test_provides_callback(self) -> None:
        console, _ = _make_console()
        progress = AnalysisProgress(console, 3)
        assert callable(progress.callback)

    def test_enter_exit_without_error(self) -> None:
        console, _ = _make_console()
        with AnalysisProgress(console, 3) as progress:
            progress.update("file.py", 1, 3)

    def test_non_tty_suppresses_display(self) -> None:
        console, output = _make_console(is_terminal=False)
        with AnalysisProgress(console, 3) as progress:
            progress.update("file.py", 1, 3)
        # Non-TTY should produce no progress output
        assert output.getvalue() == ""

    def test_update_accepts_file_path(self) -> None:
        console, _ = _make_console()
        with AnalysisProgress(console, 2) as progress:
            progress.update("src/api.py", 1, 2)
            progress.update("src/db.py", 2, 2)


# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------


class TestFormatFileDone:
    def test_includes_checkmark(self) -> None:
        line = format_file_done("file.py", 1.2, 0)
        assert "\u2713" in line

    def test_includes_file_path(self) -> None:
        line = format_file_done("src/api/handler.py", 1.2, 0)
        assert "src/api/handler.py" in line

    def test_includes_elapsed(self) -> None:
        line = format_file_done("file.py", 1.234, 0)
        assert "1.2s" in line

    def test_includes_findings_count(self) -> None:
        line = format_file_done("file.py", 0.5, 3)
        assert "3 finding(s)" in line

    def test_zero_findings(self) -> None:
        line = format_file_done("file.py", 0.5, 0)
        assert "0 finding(s)" in line


class TestFormatFileError:
    def test_includes_cross_mark(self) -> None:
        line = format_file_error("file.py", "timeout")
        assert "\u2717" in line

    def test_includes_file_path(self) -> None:
        line = format_file_error("src/api.py", "timeout")
        assert "src/api.py" in line

    def test_includes_error_message(self) -> None:
        line = format_file_error("file.py", "rate limit")
        assert "rate limit" in line


# ---------------------------------------------------------------------------
# Friendly error messages
# ---------------------------------------------------------------------------


class TestFriendlyErrorMessage:
    def test_timeout_error(self) -> None:
        msg = friendly_error_message("LLMTimeoutError", "raw error")
        assert "timed out" in msg.lower()

    def test_rate_limit_error(self) -> None:
        msg = friendly_error_message("LLMRateLimitError", "raw error")
        assert "rate limit" in msg.lower()

    def test_auth_error(self) -> None:
        msg = friendly_error_message("LLMAuthenticationError", "raw error")
        assert "api key" in msg.lower()

    def test_connection_error(self) -> None:
        msg = friendly_error_message("LLMConnectionError", "raw error")
        assert "network" in msg.lower()

    def test_server_error(self) -> None:
        msg = friendly_error_message("LLMServerError", "raw error")
        assert "server error" in msg.lower()

    def test_unknown_error_uses_raw(self) -> None:
        msg = friendly_error_message("UnknownError", "something went wrong")
        assert msg == "something went wrong"


# ---------------------------------------------------------------------------
# Summary with elapsed time
# ---------------------------------------------------------------------------


class TestSummaryWithElapsed:
    def test_summary_includes_elapsed(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(
            files_analyzed=5,
            findings_count=3,
            severity_counts={SeverityLevel.HIGH: 2, SeverityLevel.CRITICAL: 1},
        )
        print_summary(stats, console, elapsed=3.2)
        text = _strip_ansi(output.getvalue())
        assert "5 file(s)" in text
        assert "3.2s" in text
        assert "3 issue(s)" in text

    def test_summary_without_elapsed(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(files_analyzed=5, findings_count=3, severity_counts={})
        print_summary(stats, console)
        text = _strip_ansi(output.getvalue())
        assert "5 file(s)" in text
        assert " in " not in text  # no timing

    def test_summary_shows_severity_breakdown(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(
            files_analyzed=5,
            findings_count=3,
            severity_counts={SeverityLevel.CRITICAL: 1, SeverityLevel.HIGH: 2},
        )
        print_summary(stats, console, elapsed=1.0)
        text = _strip_ansi(output.getvalue())
        assert "1 Critical" in text
        assert "2 High" in text

    def test_no_findings_with_elapsed(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(files_analyzed=5, findings_count=0)
        print_no_findings(stats, console, elapsed=2.5)
        text = _strip_ansi(output.getvalue())
        assert "2.5s" in text
        assert "No security issues found" in text

    def test_no_findings_without_elapsed(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(files_analyzed=3, findings_count=0)
        print_no_findings(stats, console)
        text = output.getvalue()
        assert "No security issues found" in text


# ---------------------------------------------------------------------------
# Non-TTY behavior
# ---------------------------------------------------------------------------


class TestNonTTYBehavior:
    def test_no_progress_when_piped(self) -> None:
        console, output = _make_console(is_terminal=False)
        with AnalysisProgress(console, 5) as progress:
            for i in range(5):
                progress.update(f"file{i}.py", i + 1, 5)
        assert output.getvalue() == ""


# ---------------------------------------------------------------------------
# Verbose mode file-by-file status
# ---------------------------------------------------------------------------


class TestVerboseFileStatus:
    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE_FILES, new_callable=AsyncMock)
    @patch(_PREPARE)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_verbose_shows_per_file_done(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_prepare: MagicMock,
        mock_af: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()
        mock_af.return_value = AnalysisResult()

        result = runner.invoke(app, ["--verbose"])

        assert result.exit_code == 0
        assert "\u2713" in result.output
        assert "finding(s)" in result.output

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE_FILES, new_callable=AsyncMock)
    @patch(_PREPARE)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig(fail_on_error=False))
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_verbose_shows_per_file_error(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_prepare: MagicMock,
        mock_af: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()
        mock_af.return_value = AnalysisResult(
            errors=[FileAnalysisError(file_path="test.py", error="timed out", error_type="LLMTimeoutError")]
        )

        result = runner.invoke(app, ["--verbose"])

        assert result.exit_code == 0
        assert "\u2717" in result.output
        assert "timed out" in result.output.lower()

    @patch(_BRANCH, return_value="main")
    @patch(_COMMIT, return_value="abc123")
    @patch(_ANALYZE_FILES, new_callable=AsyncMock)
    @patch(_PREPARE)
    @patch(_CLIENT)
    @patch(_PARSE)
    @patch(_DIFF, return_value=_DIFF_TEXT)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_GIT, return_value=True)
    @patch.dict(os.environ, _ENV)
    def test_verbose_shows_elapsed_time(
        self,
        _git: MagicMock,
        _cfg: MagicMock,
        _diff: MagicMock,
        mock_parse: MagicMock,
        _client: MagicMock,
        mock_prepare: MagicMock,
        mock_af: AsyncMock,
        _commit: MagicMock,
        _branch: MagicMock,
    ) -> None:
        mock_parse.return_value = [_make_diff_file()]
        mock_prepare.return_value = _make_prepared()
        mock_af.return_value = AnalysisResult()

        result = runner.invoke(app, ["--verbose"])

        assert result.exit_code == 0
        assert "completed in" in result.output.lower()


# ---------------------------------------------------------------------------
# Error messages for common errors
# ---------------------------------------------------------------------------


class TestClearErrorMessages:
    def test_not_a_git_repo(self) -> None:
        with patch(_GIT, return_value=False):
            result = runner.invoke(app, [])
        assert result.exit_code == 2
        assert "Not a git repository" in result.output

    @patch(_GIT, return_value=True)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_api_key(self, _git: MagicMock, _cfg: MagicMock) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code == 2
        assert "API key" in result.output or "OPENAI_API_KEY" in result.output

    @patch(_GIT, return_value=True)
    @patch(_CONFIG, return_value=DiffguardConfig())
    @patch(_DIFF, return_value="")
    @patch.dict(os.environ, {}, clear=True)
    def test_no_staged_changes(self, _git: MagicMock, _cfg: MagicMock, _diff: MagicMock) -> None:
        result = runner.invoke(app, ["--dry-run"])
        assert result.exit_code == 0
        assert "No staged changes" in result.output
        assert "git add" in result.output


class TestFailOnErrorConfig:
    def test_default_is_true(self) -> None:
        config = DiffguardConfig()
        assert config.fail_on_error is True

    def test_can_be_set_to_false(self) -> None:
        config = DiffguardConfig(fail_on_error=False)
        assert config.fail_on_error is False


# ---------------------------------------------------------------------------
# Success message (already exists, verify it still works)
# ---------------------------------------------------------------------------


class TestSuccessMessage:
    def test_checkmark_when_no_findings(self) -> None:
        console, output = _make_console()
        stats = AnalysisStats(files_analyzed=5, findings_count=0)
        print_no_findings(stats, console)
        text = output.getvalue()
        assert "\u2714" in text
        assert "No security issues found" in text
