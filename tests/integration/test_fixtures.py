"""Tests verifying that integration test fixtures work correctly."""

from __future__ import annotations

import json
import os
import subprocess
import tomllib
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

from diffguard.exceptions import LLMTimeoutError

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# fake_git_repo
# ---------------------------------------------------------------------------


class TestFakeGitRepo:
    """Verify the fake_git_repo fixture."""

    def test_has_git_directory(self, fake_git_repo: Path) -> None:
        """Repo contains a .git directory."""
        assert (fake_git_repo / ".git").is_dir()

    def test_git_commands_work(self, fake_git_repo: Path) -> None:
        """Standard git commands succeed inside the repo."""
        result = subprocess.run(
            ["git", "status"],
            cwd=fake_git_repo,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0

    def test_user_email_configured(self, fake_git_repo: Path) -> None:
        """Git user.email is set so commits can be created."""
        result = subprocess.run(
            ["git", "config", "user.email"],
            cwd=fake_git_repo,
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == "test@test.com"

    def test_user_name_configured(self, fake_git_repo: Path) -> None:
        """Git user.name is set so commits can be created."""
        result = subprocess.run(
            ["git", "config", "user.name"],
            cwd=fake_git_repo,
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == "Test User"


# ---------------------------------------------------------------------------
# stage_files
# ---------------------------------------------------------------------------


class TestStageFiles:
    """Verify the stage_files fixture."""

    def test_single_file(self, stage_files: Any) -> None:
        """A single file is created with the right content and staged."""
        repo = stage_files({"hello.py": "print('hello')\n"})
        assert (repo / "hello.py").read_text() == "print('hello')\n"

    def test_multiple_files(self, stage_files: Any) -> None:
        """Multiple files are all created and staged."""
        repo = stage_files({"a.py": "a = 1", "b.py": "b = 2", "c.py": "c = 3"})
        assert (repo / "a.py").exists()
        assert (repo / "b.py").exists()
        assert (repo / "c.py").exists()

    def test_nested_paths(self, stage_files: Any) -> None:
        """Intermediate directories are created for nested paths."""
        repo = stage_files({"src/api/handler.py": "handler code"})
        assert (repo / "src" / "api" / "handler.py").read_text() == "handler code"

    def test_files_appear_in_staged_diff(self, stage_files: Any, fake_git_repo: Path) -> None:
        """Staged files show up in ``git diff --cached``."""
        stage_files({"main.py": "x = 1\n"})
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            cwd=fake_git_repo,
            capture_output=True,
            text=True,
            check=True,
        )
        assert "main.py" in result.stdout


# ---------------------------------------------------------------------------
# mock_llm_client
# ---------------------------------------------------------------------------

FINDING_DICT: dict[str, Any] = {
    "what": "SQL Injection",
    "why": "User input in query",
    "how_to_fix": "Use parameterized queries",
    "severity": "High",
    "confidence": "High",
    "cwe_id": "CWE-89",
    "owasp_category": "A03:2021",
    "line_range": {"start": 5, "end": 5},
}

FINDING_DICT_XSS: dict[str, Any] = {
    "what": "XSS",
    "why": "Unescaped output",
    "how_to_fix": "Escape HTML",
    "severity": "Medium",
    "confidence": "Medium",
    "cwe_id": "CWE-79",
}


class TestMockLlmClient:
    """Verify the mock_llm_client fixture."""

    @pytest.mark.asyncio
    async def test_returns_findings(self, mock_llm_client: Any) -> None:
        """Client returns the configured findings list."""
        client = mock_llm_client(findings=[FINDING_DICT])
        raw = await client.analyze("some prompt")
        data = json.loads(raw)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["what"] == "SQL Injection"

    @pytest.mark.asyncio
    async def test_returns_empty(self, mock_llm_client: Any) -> None:
        """Client returns empty findings when none are given."""
        client = mock_llm_client(findings=[])
        raw = await client.analyze("some prompt")
        data = json.loads(raw)
        assert data["findings"] == []

    @pytest.mark.asyncio
    async def test_per_file_responses(self, mock_llm_client: Any) -> None:
        """Client returns different findings depending on which file is in the prompt."""
        client = mock_llm_client(
            per_file={
                "handler.py": [FINDING_DICT],
                "utils.py": [],
            }
        )
        raw_handler = await client.analyze("...handler.py...")
        raw_utils = await client.analyze("...utils.py...")

        assert len(json.loads(raw_handler)["findings"]) == 1
        assert len(json.loads(raw_utils)["findings"]) == 0

    @pytest.mark.asyncio
    async def test_per_file_unknown_returns_empty(self, mock_llm_client: Any) -> None:
        """Per-file client returns empty findings for unrecognised file paths."""
        client = mock_llm_client(per_file={"handler.py": [FINDING_DICT]})
        raw = await client.analyze("...other_file.py...")
        assert json.loads(raw)["findings"] == []

    @pytest.mark.asyncio
    async def test_raises_error(self, mock_llm_client: Any) -> None:
        """Client raises the configured exception."""
        client = mock_llm_client(error=LLMTimeoutError("boom"))
        with pytest.raises(LLMTimeoutError, match="boom"):
            await client.analyze("prompt")

    def test_client_is_async_mock(self, mock_llm_client: Any) -> None:
        """Returned client is an AsyncMock so callers can assert on calls."""
        client = mock_llm_client(findings=[])
        assert isinstance(client.analyze, AsyncMock)


# ---------------------------------------------------------------------------
# mock_llm_response
# ---------------------------------------------------------------------------


class TestMockLlmResponse:
    """Verify the mock_llm_response helper fixture."""

    def test_serialises_findings(self, mock_llm_response: Any) -> None:
        """Produces valid JSON with a findings array."""
        raw = mock_llm_response([FINDING_DICT, FINDING_DICT_XSS])
        data = json.loads(raw)
        assert len(data["findings"]) == 2

    def test_empty_findings(self, mock_llm_response: Any) -> None:
        """Produces valid JSON for an empty findings list."""
        raw = mock_llm_response([])
        data = json.loads(raw)
        assert data["findings"] == []


# ---------------------------------------------------------------------------
# mock_env
# ---------------------------------------------------------------------------


class TestMockEnv:
    """Verify the mock_env fixture."""

    def test_sets_env_var(self, mock_env: Any) -> None:
        """Environment variable is set for the duration of the test."""
        mock_env({"OPENAI_API_KEY": "sk-test-integration"})
        assert os.environ["OPENAI_API_KEY"] == "sk-test-integration"

    def test_env_restored_after_yield(self) -> None:
        """Previous test's OPENAI_API_KEY is no longer present (or has its original value)."""
        assert os.environ.get("OPENAI_API_KEY") != "sk-test-integration"


# ---------------------------------------------------------------------------
# config_file
# ---------------------------------------------------------------------------


class TestConfigFile:
    """Verify the config_file fixture."""

    def test_creates_toml(self, config_file: Any, fake_git_repo: Path) -> None:
        """A .diffguard.toml is written in the repo root."""
        path = config_file({"model": "gpt-4o", "timeout": 60})
        assert path == fake_git_repo / ".diffguard.toml"
        assert path.exists()

    def test_content_is_valid_toml(self, config_file: Any) -> None:
        """Written file is parseable as TOML."""
        path = config_file({"model": "gpt-4o", "max_concurrent_api_calls": 3})
        data = tomllib.loads(path.read_text())
        assert data["model"] == "gpt-4o"
        assert data["max_concurrent_api_calls"] == 3

    def test_subtable_support(self, config_file: Any) -> None:
        """Nested dicts produce TOML sub-tables."""
        path = config_file(
            {
                "model": "gpt-4o",
                "thresholds": {"Critical": "block", "High": "block"},
            }
        )
        data = tomllib.loads(path.read_text())
        assert data["thresholds"]["Critical"] == "block"

    def test_list_values(self, config_file: Any) -> None:
        """List values are serialised as TOML arrays."""
        path = config_file({"sensitive_patterns": ["*.env", "*.pem"]})
        data = tomllib.loads(path.read_text())
        assert data["sensitive_patterns"] == ["*.env", "*.pem"]


# ---------------------------------------------------------------------------
# baseline_file
# ---------------------------------------------------------------------------

BASELINE_ENTRY: dict[str, Any] = {
    "finding_id": "cwe89-abc123",
    "cwe_id": "CWE-89",
    "code_hash": "deadbeef",
    "reason": "False positive",
    "added_at": "2025-01-15T10:00:00Z",
}


class TestBaselineFile:
    """Verify the baseline_file fixture."""

    def test_creates_json(self, baseline_file: Any, fake_git_repo: Path) -> None:
        """A .diffguard-baseline.json is written in the repo root."""
        path = baseline_file([BASELINE_ENTRY])
        assert path == fake_git_repo / ".diffguard-baseline.json"
        assert path.exists()

    def test_content_is_valid_json(self, baseline_file: Any) -> None:
        """Written file is valid JSON with version and entries."""
        path = baseline_file([BASELINE_ENTRY])
        data = json.loads(path.read_text())
        assert data["version"] == "1.0"
        assert len(data["entries"]) == 1
        assert data["entries"][0]["finding_id"] == "cwe89-abc123"

    def test_empty_entries(self, baseline_file: Any) -> None:
        """An empty entries list produces valid JSON."""
        path = baseline_file([])
        data = json.loads(path.read_text())
        assert data["entries"] == []


# ---------------------------------------------------------------------------
# Fixture chaining
# ---------------------------------------------------------------------------


class TestFixtureChaining:
    """Verify that fixtures compose correctly."""

    @pytest.mark.asyncio
    async def test_all_fixtures_together(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_llm_client: Any,
        mock_env: Any,
        config_file: Any,
        baseline_file: Any,
    ) -> None:
        """All fixtures can be used in a single test without conflicts."""
        mock_env({"OPENAI_API_KEY": "sk-test-chain"})
        stage_files({"app.py": "x = 1\n"})
        config_file({"model": "gpt-4o"})
        baseline_file([BASELINE_ENTRY])

        client = mock_llm_client(findings=[FINDING_DICT])
        raw = await client.analyze("prompt")
        data = json.loads(raw)

        assert (fake_git_repo / "app.py").exists()
        assert (fake_git_repo / ".diffguard.toml").exists()
        assert (fake_git_repo / ".diffguard-baseline.json").exists()
        assert os.environ["OPENAI_API_KEY"] == "sk-test-chain"
        assert len(data["findings"]) == 1

    @pytest.mark.asyncio
    async def test_async_context(self, mock_llm_client: Any) -> None:
        """Fixtures work correctly inside an async test."""
        client = mock_llm_client(findings=[FINDING_DICT])
        raw = await client.analyze("async prompt")
        data = json.loads(raw)
        assert data["findings"][0]["cwe_id"] == "CWE-89"
