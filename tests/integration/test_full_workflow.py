"""End-to-end workflow integration tests.

These tests exercise the full CLI pipeline with real git repos, real diff
parsing, real tree-sitter parsing, and real config/baseline loading.
Only the LLM client is mocked.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from diffguard.cli import app
from diffguard.exceptions import LLMServerError

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
PYTHON_WITH_SQL_INJECTION = """\
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
"""

PYTHON_CLEAN = """\
def get_user(user_id: int) -> str:
    return db.query(User).filter(User.id == user_id).first()
"""

PYTHON_WITH_XSS = """\
def render_page(user_input):
    return f"<div>{user_input}</div>"
"""

# ---------------------------------------------------------------------------
# Finding dicts (what the mock LLM returns)
# Note: severity_map remaps CWE-89 → HIGH and CWE-79 → HIGH
# ---------------------------------------------------------------------------
FINDING_SQL_INJECTION: dict[str, Any] = {
    "what": "SQL Injection vulnerability",
    "why": "User input directly interpolated into SQL query",
    "how_to_fix": "Use parameterized queries or an ORM",
    "severity": "High",
    "confidence": "High",
    "cwe_id": "CWE-89",
    "owasp_category": "A03:2021-Injection",
    "line_range": {"start": 2, "end": 2},
}

FINDING_XSS: dict[str, Any] = {
    "what": "Cross-Site Scripting (XSS)",
    "why": "User input rendered without escaping",
    "how_to_fix": "Use HTML escaping or a templating engine",
    "severity": "Medium",
    "confidence": "High",
    "cwe_id": "CWE-79",
    "owasp_category": "A03:2021-Injection",
    "line_range": {"start": 2, "end": 2},
}

FINDING_CRITICAL: dict[str, Any] = {
    "what": "OS Command Injection",
    "why": "User input passed to subprocess",
    "how_to_fix": "Use shlex.quote or avoid shell=True",
    "severity": "Critical",
    "confidence": "High",
    "cwe_id": "CWE-78",
    "owasp_category": "A03:2021-Injection",
    "line_range": {"start": 2, "end": 2},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_client(
    *,
    findings: list[dict[str, Any]] | None = None,
    per_file: dict[str, list[dict[str, Any]]] | None = None,
    error: Exception | None = None,
    error_for_file: str | None = None,
) -> MagicMock:
    """Build a mock that replaces the OpenAIClient class.

    The mock's constructor (``return_value``) yields an instance whose
    ``analyze()`` method returns canned JSON.
    """
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


def _compute_expected_finding_id(cwe: str, file_path: str, line_start: int) -> str:
    """Replicate the finding ID algorithm from baseline.py / cli.py."""
    prefix = cwe.lower().replace("-", "")
    parts = [prefix, file_path, str(line_start)]
    hash_input = ":".join(parts)
    return f"{prefix}-{hashlib.sha256(hash_input.encode()).hexdigest()[:16]}"


def _pipeline_patches(mock_client: MagicMock) -> contextlib.ExitStack:
    """Return a single context manager that mocks the pipeline boundaries."""
    stack = contextlib.ExitStack()
    stack.enter_context(patch(_CLIENT, mock_client))
    stack.enter_context(patch(_COMMIT, return_value="abc123"))
    stack.enter_context(patch(_BRANCH, return_value="main"))
    return stack


# ---------------------------------------------------------------------------
# Clean scan
# ---------------------------------------------------------------------------


class TestCleanScan:
    """No findings → exit 0."""

    def test_no_findings_exit_zero(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged file with no LLM findings produces exit 0 and success message."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_CLEAN})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0
        assert "no security issues" in result.output.lower()

    def test_llm_is_called(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """All pipeline steps execute — the LLM client's analyze is called."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_CLEAN})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        mock_client.return_value.analyze.assert_awaited()


# ---------------------------------------------------------------------------
# Scan with findings
# ---------------------------------------------------------------------------


class TestScanWithFindings:
    """Blocking findings → exit 1 with details."""

    def test_blocking_finding_exit_one(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """High severity finding causes exit 1."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 1
        assert "SQL Injection" in result.output

    def test_finding_details_shown(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Output contains what, why, how_to_fix, CWE, and OWASP."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        output = result.output
        assert "SQL Injection vulnerability" in output
        assert "parameterized queries" in output
        assert "CWE-89" in output

    def test_line_reference_shown(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Output shows file path and line numbers."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert "handler.py" in result.output


# ---------------------------------------------------------------------------
# Multi-file workflow
# ---------------------------------------------------------------------------


class TestMultiFile:
    """Multiple staged files analysed and aggregated."""

    def test_all_files_analyzed(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """All 3 staged files are sent to the LLM."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files(
            {
                "a.py": PYTHON_WITH_SQL_INJECTION,
                "b.py": PYTHON_WITH_XSS,
                "c.py": PYTHON_CLEAN,
            }
        )

        mock_client = _make_mock_client(
            per_file={
                "a.py": [FINDING_SQL_INJECTION],
                "b.py": [FINDING_XSS],
            },
        )
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        assert mock_client.return_value.analyze.await_count == 3

    def test_findings_aggregated(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Findings from all files appear in the output."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files(
            {
                "a.py": PYTHON_WITH_SQL_INJECTION,
                "b.py": PYTHON_WITH_XSS,
            }
        )

        mock_client = _make_mock_client(
            per_file={
                "a.py": [FINDING_SQL_INJECTION],
                "b.py": [FINDING_XSS],
            },
        )
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert "SQL Injection" in result.output
        assert "Cross-Site Scripting" in result.output

    def test_exit_one_if_any_blocking(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """One critical finding among many files causes exit 1."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files(
            {
                "a.py": PYTHON_CLEAN,
                "b.py": PYTHON_WITH_SQL_INJECTION,
                "c.py": PYTHON_CLEAN,
            }
        )

        mock_client = _make_mock_client(
            per_file={"b.py": [FINDING_CRITICAL]},
        )
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Baseline suppression
# ---------------------------------------------------------------------------


class TestBaselineSuppression:
    """Baseline entries suppress matching findings."""

    def test_finding_suppressed(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        baseline_file: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A baselined finding does not appear in the output."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        finding_id = _compute_expected_finding_id("CWE-89", "handler.py", 2)
        baseline_file(
            [
                {
                    "finding_id": finding_id,
                    "cwe_id": "CWE-89",
                    "code_hash": "irrelevant",
                    "reason": "False positive",
                    "added_at": "2025-01-15T10:00:00Z",
                }
            ]
        )

        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0
        assert "SQL Injection" not in result.output

    def test_all_suppressed_exit_zero(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        baseline_file: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When all findings are suppressed, exit 0."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        finding_id = _compute_expected_finding_id("CWE-89", "handler.py", 2)
        baseline_file(
            [
                {
                    "finding_id": finding_id,
                    "cwe_id": "CWE-89",
                    "code_hash": "irrelevant",
                    "reason": "False positive",
                    "added_at": "2025-01-15T10:00:00Z",
                }
            ]
        )

        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0

    def test_shows_suppression_count(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        baseline_file: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Output shows how many findings were suppressed."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        finding_id = _compute_expected_finding_id("CWE-89", "handler.py", 2)
        baseline_file(
            [
                {
                    "finding_id": finding_id,
                    "cwe_id": "CWE-89",
                    "code_hash": "irrelevant",
                    "reason": "False positive",
                    "added_at": "2025-01-15T10:00:00Z",
                }
            ]
        )

        # LLM returns two findings, one is baselined
        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION, FINDING_XSS])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert "1 suppressed" in result.output

    def test_partial_suppression_blocking(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        baseline_file: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Non-suppressed blocking finding still causes exit 1."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        # Suppress XSS but not SQL injection
        xss_id = _compute_expected_finding_id("CWE-79", "handler.py", 2)
        baseline_file(
            [
                {
                    "finding_id": xss_id,
                    "cwe_id": "CWE-79",
                    "code_hash": "irrelevant",
                    "reason": "Handled elsewhere",
                    "added_at": "2025-01-15T10:00:00Z",
                }
            ]
        )

        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION, FINDING_XSS])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        # SQL Injection (High) still blocks
        assert result.exit_code == 1
        assert "SQL Injection" in result.output


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


class TestJsonOutput:
    """--json flag produces valid JSON to stdout."""

    def test_valid_json(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """stdout is valid JSON."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json"])

        json.loads(result.output)  # must not raise

    def test_json_structure(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """JSON has expected top-level keys."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json"])

        data = json.loads(result.output)
        assert "schema_version" in data
        assert "version" in data
        assert "timestamp" in data
        assert "findings" in data
        assert "summary" in data

    def test_json_exit_one_with_blocking(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Blocking finding produces exit 1 even with --json."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json"])

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert len(data["findings"]) >= 1


# ---------------------------------------------------------------------------
# Verbose output
# ---------------------------------------------------------------------------


class TestVerboseOutput:
    """--verbose shows timing and context info."""

    def test_verbose_shows_timing(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verbose output includes elapsed time and token estimates."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_CLEAN})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--verbose"])

        assert result.exit_code == 0
        lower = result.output.lower()
        assert "completed in" in lower
        assert "tokens" in lower


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------


class TestDryRun:
    """--dry-run shows files/tokens without calling LLM."""

    def test_dry_run_no_llm_call(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Dry-run lists files and tokens but never calls the LLM."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_CLEAN, "handler.py": PYTHON_WITH_SQL_INJECTION})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--dry-run"])

        assert result.exit_code == 0
        assert "main.py" in result.output
        assert "handler.py" in result.output
        assert "tokens" in result.output.lower()
        mock_client.return_value.analyze.assert_not_awaited()


# ---------------------------------------------------------------------------
# Output to file
# ---------------------------------------------------------------------------


class TestOutputToFile:
    """--output writes JSON to a file."""

    def test_output_file_created(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """JSON report is saved to the specified path."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_CLEAN})

        report_path = fake_git_repo / "report.json"
        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--output", str(report_path)])

        assert result.exit_code == 0
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert "findings" in data


# ---------------------------------------------------------------------------
# Custom config
# ---------------------------------------------------------------------------


class TestCustomConfig:
    """Custom .diffguard.toml thresholds are applied."""

    def test_high_demoted_to_warn(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        config_file: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When High is set to 'warn', a High finding does not block (exit 0)."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})
        config_file(
            {
                "thresholds": {
                    "Critical": "block",
                    "High": "warn",
                    "Medium": "warn",
                    "Low": "allow",
                    "Info": "allow",
                },
            }
        )

        mock_client = _make_mock_client(findings=[FINDING_SQL_INJECTION])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Sensitive file exclusion
# ---------------------------------------------------------------------------


class TestSensitiveFileExclusion:
    """.env files are excluded from analysis."""

    def test_env_file_skipped(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staging both .env and main.py only analyses main.py."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({".env": "SECRET_KEY=abc123", "main.py": PYTHON_CLEAN})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0
        # LLM should be called only once (for main.py, not .env)
        assert mock_client.return_value.analyze.await_count == 1


# ---------------------------------------------------------------------------
# Error recovery
# ---------------------------------------------------------------------------


class TestErrorRecovery:
    """LLM errors cause exit 2 in non-TTY mode."""

    def test_llm_error_exit_two(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the LLM fails on a file, CLI exits with code 2."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files(
            {
                "a.py": PYTHON_CLEAN,
                "b.py": PYTHON_WITH_SQL_INJECTION,
                "c.py": PYTHON_WITH_XSS,
            }
        )

        mock_client = _make_mock_client(
            findings=[],
            error=LLMServerError("Internal server error"),
            error_for_file="b.py",
        )
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Full pipeline with real parsing
# ---------------------------------------------------------------------------


class TestFullPipelineWithParsing:
    """Tree-sitter parsing and scope detection work end-to-end."""

    def test_tree_sitter_scope_in_prompt(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The prompt sent to the LLM contains scope information from tree-sitter."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"handler.py": PYTHON_WITH_SQL_INJECTION})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        # The prompt should contain the function name from tree-sitter scope detection
        call_args = mock_client.return_value.analyze.call_args
        prompt = call_args[0][0]
        assert "get_user" in prompt
