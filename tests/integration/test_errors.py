"""Integration tests for error handling scenarios."""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from diffguard.cli import app
from diffguard.exceptions import (
    LLMAuthenticationError,
    LLMRateLimitError,
    LLMServerError,
    LLMTimeoutError,
)

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

runner = CliRunner()

# ---------------------------------------------------------------------------
# Patch targets
# ---------------------------------------------------------------------------
_CLIENT = "diffguard.cli.OpenAIClient"
_COMMIT = "diffguard.cli.get_commit_hash"
_BRANCH = "diffguard.cli.get_branch_name"

# ---------------------------------------------------------------------------
# Code samples
# ---------------------------------------------------------------------------
VALID_PYTHON = """\
def valid_function():
    return "hello"
"""

VALID_PYTHON_B = """\
def another():
    return 42
"""

FINDING_HIGH: dict[str, Any] = {
    "what": "SQL Injection",
    "why": "User input in query",
    "how_to_fix": "Use parameterized queries",
    "severity": "High",
    "confidence": "High",
    "cwe_id": "CWE-89",
    "line_range": {"start": 2, "end": 2},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_client(
    *,
    findings: list[dict[str, Any]] | None = None,
    error: Exception | None = None,
    error_for_file: str | None = None,
    malformed_response: str | None = None,
) -> MagicMock:
    """Build a mock that replaces the OpenAIClient class."""
    mock_cls = MagicMock()
    mock_instance = AsyncMock()

    if error is not None and error_for_file is not None:

        async def _mixed(prompt: str) -> str:
            if error_for_file in prompt:
                raise error
            return json.dumps({"findings": findings or []})

        mock_instance.analyze = AsyncMock(side_effect=_mixed)
    elif error is not None:
        mock_instance.analyze = AsyncMock(side_effect=error)
    elif malformed_response is not None:
        mock_instance.analyze = AsyncMock(return_value=malformed_response)
    else:
        mock_instance.analyze = AsyncMock(
            return_value=json.dumps({"findings": findings or []}),
        )

    mock_cls.return_value = mock_instance
    return mock_cls


def _pipeline_patches(mock_client: MagicMock) -> contextlib.ExitStack:
    """Return a single context manager that mocks the pipeline boundaries."""
    stack = contextlib.ExitStack()
    stack.enter_context(patch(_CLIENT, mock_client))
    stack.enter_context(patch(_COMMIT, return_value="abc123"))
    stack.enter_context(patch(_BRANCH, return_value="main"))
    return stack


# ---------------------------------------------------------------------------
# Not a git repo
# ---------------------------------------------------------------------------


class TestNotAGitRepo:
    """Running outside a git repository."""

    def test_exit_code_two(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Exit code is 2 when not in a git repo."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app)
        assert result.exit_code == 2

    def test_error_message(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Error message mentions 'not a git repository'."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app)
        assert "not a git repository" in result.output.lower()

    def test_suggestion(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Error message suggests running from within a git project."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app)
        assert "git project" in result.output.lower() or "git repository" in result.output.lower()


# ---------------------------------------------------------------------------
# No staged changes
# ---------------------------------------------------------------------------


class TestNoStagedChanges:
    """Git repo with nothing staged."""

    def test_exit_code_zero(
        self,
        fake_git_repo: Path,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 0 — not an error."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)
        assert result.exit_code == 0

    def test_message(
        self,
        fake_git_repo: Path,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Output says 'No staged changes to analyze'."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)
        assert "No staged changes" in result.output

    def test_suggestion(
        self,
        fake_git_repo: Path,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Output suggests staging files with git add."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)
        assert "git add" in result.output.lower()


# ---------------------------------------------------------------------------
# Missing API key
# ---------------------------------------------------------------------------


class TestMissingApiKey:
    """OPENAI_API_KEY not set."""

    def test_exit_code_two(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 2 when API key is missing."""
        monkeypatch.chdir(fake_git_repo)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 2

    def test_error_message(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error message mentions OPENAI_API_KEY."""
        monkeypatch.chdir(fake_git_repo)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert "OPENAI_API_KEY" in result.output

    def test_instructions(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error message explains how to set the key."""
        monkeypatch.chdir(fake_git_repo)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert "export OPENAI_API_KEY" in result.output

    def test_dry_run_works_without_key(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--dry-run does not require an API key."""
        monkeypatch.chdir(fake_git_repo)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--dry-run"])

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# LLM errors
# ---------------------------------------------------------------------------


class TestLlmTimeoutError:
    """LLM raises timeout error."""

    def test_exit_code_two(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 2 on timeout."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(error=LLMTimeoutError("Request timed out"))
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 2

    def test_message_mentions_timeout(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error message mentions timeout."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(error=LLMTimeoutError("Request timed out"))
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert "timed out" in result.output.lower()


class TestLlmRateLimitError:
    """LLM raises rate limit error."""

    def test_exit_code_two(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 2 on rate limit."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(error=LLMRateLimitError("Rate limit exceeded"))
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 2

    def test_message_mentions_rate_limit(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error message mentions rate limit."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(error=LLMRateLimitError("Rate limit exceeded"))
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert "rate limit" in result.output.lower()


class TestLlmAuthError:
    """LLM raises authentication error."""

    def test_exit_code_two(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 2 on auth error."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(error=LLMAuthenticationError("Invalid key"))
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 2

    def test_message_mentions_api_key(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error message mentions invalid API key."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(error=LLMAuthenticationError("Invalid key"))
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert "api key" in result.output.lower() or "invalid" in result.output.lower()


class TestLlmServerError:
    """LLM raises server error."""

    def test_exit_code_two(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 2 on server error."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(error=LLMServerError("Internal server error"))
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 2

    def test_message_mentions_server_error(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error message mentions server error."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(error=LLMServerError("Internal server error"))
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert "server error" in result.output.lower()


# ---------------------------------------------------------------------------
# Malformed LLM response
# ---------------------------------------------------------------------------


class TestMalformedResponse:
    """LLM returns invalid JSON."""

    def test_exit_code_two(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 2 on malformed response (non-TTY)."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(malformed_response="{ totally not valid json !!!")
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 2

    def test_message_mentions_parsing(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error message mentions parsing or invalid response."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        mock_client = _make_mock_client(malformed_response="{ totally not valid json !!!")
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        lower = result.output.lower()
        assert "json" in lower or "pars" in lower or "invalid" in lower or "malformed" in lower


# ---------------------------------------------------------------------------
# Config errors
# ---------------------------------------------------------------------------


class TestConfigSyntaxError:
    """Invalid TOML syntax in .diffguard.toml."""

    def test_exit_code_two(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 2 on config syntax error."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})
        (fake_git_repo / ".diffguard.toml").write_text("invalid [ toml syntax")

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 2

    def test_message(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error message mentions TOML/config issue."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})
        (fake_git_repo / ".diffguard.toml").write_text("invalid [ toml syntax")

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        lower = result.output.lower()
        assert "toml" in lower or "config" in lower


class TestConfigValidationError:
    """Invalid values in .diffguard.toml."""

    def test_exit_code_two(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 2 on config validation error."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})
        (fake_git_repo / ".diffguard.toml").write_text("hunk_expansion_lines = -5\n")

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 2

    def test_message(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error message mentions the invalid field."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})
        (fake_git_repo / ".diffguard.toml").write_text("hunk_expansion_lines = -5\n")

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        lower = result.output.lower()
        assert "hunk_expansion_lines" in lower or "invalid" in lower


# ---------------------------------------------------------------------------
# File read errors (graceful degradation)
# ---------------------------------------------------------------------------


class TestFileReadError:
    """Files that cannot be read are skipped gracefully.

    Uses ``fail_on_error = false`` in config so errors don't abort in non-TTY.
    """

    def test_other_files_still_analyzed(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        config_file: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unreadable file is skipped; other files are still analysed."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        config_file({"fail_on_error": False})
        stage_files(
            {
                "good.py": VALID_PYTHON,
                "bad.py": VALID_PYTHON_B,
                "also_good.py": VALID_PYTHON,
            }
        )
        # Make one file unreadable after staging
        (fake_git_repo / "bad.py").chmod(0o000)

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        # Restore permissions for cleanup
        (fake_git_repo / "bad.py").chmod(0o644)

        # The other files should still be analyzed (LLM called at least for those)
        assert mock_client.return_value.analyze.await_count >= 1
        assert result.exit_code == 0

    def test_exit_based_on_findings_not_read_error(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        config_file: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit code is based on findings, not on read errors."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        config_file({"fail_on_error": False})
        stage_files(
            {
                "good.py": VALID_PYTHON,
                "bad.py": VALID_PYTHON_B,
            }
        )
        (fake_git_repo / "bad.py").chmod(0o000)

        mock_client = _make_mock_client(findings=[FINDING_HIGH])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        (fake_git_repo / "bad.py").chmod(0o644)

        # Exit 1 because of finding, not exit 2 because of read error
        assert result.exit_code == 1


class TestAllFilesFilteredOut:
    """When all files are non-analyzable (e.g. only sensitive files staged)."""

    def test_exit_zero(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 0 when all staged files are excluded."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        # Stage only sensitive files that get filtered out
        stage_files({".env": "SECRET=abc", ".env.local": "KEY=xyz"})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Output file permission error
# ---------------------------------------------------------------------------


class TestOutputFilePermissionError:
    """Cannot write to output path."""

    def test_exit_code_two(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exit 2 when output file cannot be written."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        # Create a read-only directory so file creation fails
        readonly_dir = fake_git_repo / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o555)

        report_path = readonly_dir / "report.json"
        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--output", str(report_path)])

        readonly_dir.chmod(0o755)

        assert result.exit_code == 2

    def test_permission_error_message(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Error message mentions permission denied."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": VALID_PYTHON})

        readonly_dir = fake_git_repo / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o555)

        report_path = readonly_dir / "report.json"
        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--output", str(report_path)])

        readonly_dir.chmod(0o755)

        assert "permission" in result.output.lower() or "denied" in result.output.lower()
