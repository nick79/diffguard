"""Integration tests for CLI flags: --verbose, --dry-run, --json, --output, and combinations."""

from __future__ import annotations

import contextlib
import json
import re
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from diffguard.cli import app

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

runner = CliRunner()

# ---------------------------------------------------------------------------
# Patch targets (only LLM + git metadata)
# ---------------------------------------------------------------------------
_CLIENT = "diffguard.cli.OpenAIClient"
_COMMIT = "diffguard.cli.get_commit_hash"
_BRANCH = "diffguard.cli.get_branch_name"

# ---------------------------------------------------------------------------
# Code samples
# ---------------------------------------------------------------------------
PYTHON_SAMPLE = """\
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
"""

PYTHON_SAMPLE_B = """\
def process(data):
    return eval(data)
"""

PYTHON_SAMPLE_C = """\
def hello():
    return "hello world"
"""

# ---------------------------------------------------------------------------
# Finding dicts
# Note: severity_map remaps CWE-89 → HIGH, CWE-78 → CRITICAL
# ---------------------------------------------------------------------------
FINDING_SQL: dict[str, Any] = {
    "what": "SQL Injection vulnerability",
    "why": "User input directly interpolated into SQL query",
    "how_to_fix": "Use parameterized queries",
    "severity": "High",
    "confidence": "High",
    "cwe_id": "CWE-89",
    "owasp_category": "A03:2021-Injection",
    "line_range": {"start": 2, "end": 2},
}

FINDING_EVAL: dict[str, Any] = {
    "what": "Code Injection via eval",
    "why": "eval() on untrusted input",
    "how_to_fix": "Use ast.literal_eval or remove eval",
    "severity": "Critical",
    "confidence": "High",
    "cwe_id": "CWE-94",
    "owasp_category": "A03:2021-Injection",
    "line_range": {"start": 2, "end": 2},
}


# ---------------------------------------------------------------------------
# Helpers (same pattern as test_full_workflow.py)
# ---------------------------------------------------------------------------


def _make_mock_client(
    *,
    findings: list[dict[str, Any]] | None = None,
    per_file: dict[str, list[dict[str, Any]]] | None = None,
    error: Exception | None = None,
    error_for_file: str | None = None,
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
    elif per_file is not None:

        async def _per_file(prompt: str) -> str:
            for fp, ff in per_file.items():
                if fp in prompt:
                    return json.dumps({"findings": ff})
            return json.dumps({"findings": []})

        mock_instance.analyze = AsyncMock(side_effect=_per_file)
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


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# ---------------------------------------------------------------------------
# --verbose flag
# ---------------------------------------------------------------------------


class TestVerboseFlag:
    """--verbose shows timing, file count, context details, and per-file status."""

    def test_shows_elapsed_time(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Output includes 'Analysis completed in X.Xs'."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--verbose"])

        assert result.exit_code == 0
        assert "completed in" in result.output.lower()

    def test_shows_file_count(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Output includes 'Analyzing N file(s)'."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"a.py": PYTHON_SAMPLE, "b.py": PYTHON_SAMPLE_B, "c.py": PYTHON_SAMPLE_C})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--verbose"])

        assert "Analyzing 3 file(s)" in result.output

    def test_shows_context_details(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verbose output shows region lines and scope counts."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--verbose"])

        assert "region lines" in result.output
        assert "scope(s)" in result.output

    def test_shows_token_estimates(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verbose output shows per-file token estimates."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--verbose"])

        assert "tokens" in result.output.lower()

    def test_shows_per_file_status(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Each completed file shows a checkmark with finding count."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"a.py": PYTHON_SAMPLE, "b.py": PYTHON_SAMPLE_B, "c.py": PYTHON_SAMPLE_C})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--verbose"])

        # Each file gets a ✓ line with finding count
        assert "\u2713" in result.output
        assert "finding(s)" in result.output


# ---------------------------------------------------------------------------
# --dry-run flag
# ---------------------------------------------------------------------------


class TestDryRun:
    """--dry-run lists files and tokens without calling the LLM."""

    def test_lists_all_files(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """All staged file paths appear in dry-run output."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"a.py": PYTHON_SAMPLE, "b.py": PYTHON_SAMPLE_B, "c.py": PYTHON_SAMPLE_C})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--dry-run"])

        assert result.exit_code == 0
        assert "a.py" in result.output
        assert "b.py" in result.output
        assert "c.py" in result.output

    def test_shows_token_estimates(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Per-file and total token estimates are shown."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--dry-run"])

        assert "tokens" in result.output.lower()
        assert "Total estimated tokens:" in result.output

    def test_no_llm_calls(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The LLM client's analyze is never called."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app, ["--dry-run"])

        mock_client.return_value.analyze.assert_not_awaited()

    def test_shows_would_analyze_message(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Output includes 'would analyze N file(s)'."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"a.py": PYTHON_SAMPLE, "b.py": PYTHON_SAMPLE_B})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--dry-run"])

        assert "would analyze" in result.output.lower()


# ---------------------------------------------------------------------------
# --json flag
# ---------------------------------------------------------------------------


class TestJsonOutput:
    """--json produces pure JSON on stdout."""

    def test_only_json_on_stdout(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """stdout contains only valid JSON, no extra text."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[FINDING_SQL])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json"])

        # Must parse as JSON without stripping anything
        data = json.loads(result.output)
        assert isinstance(data, dict)

    def test_no_ansi_escape_codes(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No ANSI escape codes in JSON output."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[FINDING_SQL])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json"])

        assert not _ANSI_RE.search(result.output)

    def test_findings_included(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """JSON findings array has the correct number of items."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"a.py": PYTHON_SAMPLE, "b.py": PYTHON_SAMPLE_B})

        mock_client = _make_mock_client(
            per_file={
                "a.py": [FINDING_SQL],
                "b.py": [FINDING_EVAL],
            },
        )
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json"])

        data = json.loads(result.output)
        assert len(data["findings"]) == 2


# ---------------------------------------------------------------------------
# --output flag
# ---------------------------------------------------------------------------


class TestOutputFile:
    """--output writes a JSON report to disk."""

    def test_file_created(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The output file is created."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        report_path = fake_git_repo / "results.json"
        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--output", str(report_path)])

        assert result.exit_code == 0
        assert report_path.exists()

    def test_valid_json_content(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Written file contains valid JSON with the same structure as --json."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        report_path = fake_git_repo / "results.json"
        mock_client = _make_mock_client(findings=[FINDING_SQL])
        with _pipeline_patches(mock_client):
            runner.invoke(app, ["--output", str(report_path)])

        data = json.loads(report_path.read_text())
        assert "schema_version" in data
        assert "findings" in data
        assert "summary" in data

    def test_terminal_output_still_shown(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without --json, terminal still shows normal output alongside the file."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        report_path = fake_git_repo / "results.json"
        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--output", str(report_path)])

        # Terminal should show the normal success message and report-saved confirmation
        assert "Report saved to" in result.output


# ---------------------------------------------------------------------------
# Combined flags
# ---------------------------------------------------------------------------


class TestCombinedFlags:
    """Flag combinations work correctly."""

    def test_verbose_dry_run(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--verbose --dry-run shows detailed breakdown with region/scope info."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--verbose", "--dry-run"])

        assert result.exit_code == 0
        assert "region lines" in result.output
        assert "scope(s)" in result.output
        assert "tokens" in result.output.lower()

    def test_verbose_json(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--verbose --json produces JSON only (--json suppresses verbose terminal)."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[FINDING_SQL])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--verbose", "--json"])

        # Output must be valid JSON (verbose text should not appear on stdout)
        data = json.loads(result.output)
        assert "findings" in data

    def test_json_output_file(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--json --output writes same JSON to stdout and file."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        report_path = fake_git_repo / "report.json"
        mock_client = _make_mock_client(findings=[FINDING_SQL])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json", "--output", str(report_path)])

        stdout_data = json.loads(result.output)
        file_data = json.loads(report_path.read_text())
        assert stdout_data["findings"] == file_data["findings"]

    def test_dry_run_json(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--dry-run --json produces dry-run info as JSON."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--dry-run", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["dry_run"] is True
        assert "total_estimated_tokens" in data
        assert "files" in data

    def test_verbose_dry_run_output(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--verbose --dry-run --output saves JSON and shows verbose dry-run."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        report_path = fake_git_repo / "plan.json"
        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--verbose", "--dry-run", "--output", str(report_path)])

        assert result.exit_code == 0
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert data["dry_run"] is True


# ---------------------------------------------------------------------------
# Short flags
# ---------------------------------------------------------------------------


class TestShortFlags:
    """-v is equivalent to --verbose."""

    def test_short_v_same_as_verbose(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """-v produces verbose output with timing."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["-v"])

        assert result.exit_code == 0
        assert "completed in" in result.output.lower()


# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------


class TestHelpText:
    """--help lists all flags with descriptions."""

    def test_all_flags_in_help(self) -> None:
        """All flags appear in help output."""
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "--verbose" in result.output
        assert "--dry-run" in result.output
        assert "--json" in result.output
        assert "--output" in result.output
        assert "-v" in result.output
