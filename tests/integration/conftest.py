"""Shared fixtures for integration tests."""

from __future__ import annotations

import json
import os
import subprocess
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


@pytest.fixture
def fake_git_repo(tmp_path: Path) -> Path:
    """Create a temporary git repository with user config."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, capture_output=True, check=True)
    return repo


@pytest.fixture
def stage_files(fake_git_repo: Path) -> Any:
    """Factory to create and stage files in the fake repo.

    Usage::

        stage_files({"src/api/handler.py": "content", "main.py": "print('hi')"})

    Returns the repo path for convenience.
    """

    def _stage(files: dict[str, str]) -> Path:
        for rel_path, content in files.items():
            file_path = fake_git_repo / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            subprocess.run(["git", "add", rel_path], cwd=fake_git_repo, capture_output=True, check=True)
        return fake_git_repo

    return _stage


@pytest.fixture
def mock_llm_response() -> Any:
    """Factory that serialises finding dicts into the JSON format the LLM returns."""

    def _build(findings: list[dict[str, Any]]) -> str:
        return json.dumps({"findings": findings})

    return _build


@pytest.fixture
def mock_llm_client() -> Any:
    """Factory that returns an ``AsyncMock`` satisfying the ``LLMClient`` protocol.

    Modes:

    * **uniform findings** - ``mock_llm_client(findings=[...])``
      Every ``analyze()`` call returns the same findings list.

    * **per-file findings** - ``mock_llm_client(per_file={"a.py": [...], "b.py": []})``
      Returns different findings based on which file path appears in the prompt.

    * **error** - ``mock_llm_client(error=LLMTimeoutError("boom"))``
      Every ``analyze()`` call raises the given exception.

    Returns the mock client instance (not the class).
    """

    def _build(
        *,
        findings: list[dict[str, Any]] | None = None,
        per_file: dict[str, list[dict[str, Any]]] | None = None,
        error: Exception | None = None,
    ) -> AsyncMock:
        client = AsyncMock()

        if error is not None:
            client.analyze = AsyncMock(side_effect=error)
        elif per_file is not None:

            async def _per_file_analyze(prompt: str) -> str:
                for file_path, file_findings in per_file.items():
                    if file_path in prompt:
                        return json.dumps({"findings": file_findings})
                return json.dumps({"findings": []})

            client.analyze = AsyncMock(side_effect=_per_file_analyze)
        else:
            response = json.dumps({"findings": findings or []})
            client.analyze = AsyncMock(return_value=response)

        return client

    return _build


@pytest.fixture
def mock_env() -> Generator[Any]:
    """Set environment variables for the test, then restore the original env.

    Usage::

        mock_env({"OPENAI_API_KEY": "sk-test-123"})
    """
    original = os.environ.copy()

    def _set(env_vars: dict[str, str]) -> None:
        os.environ.update(env_vars)

    yield _set

    os.environ.clear()
    os.environ.update(original)


@pytest.fixture
def config_file(fake_git_repo: Path) -> Any:
    """Create a ``.diffguard.toml`` in the fake repo from a dict of settings.

    Only supports flat key/value pairs and simple ``[thresholds]`` sub-table.
    """

    def _create(settings: dict[str, Any]) -> Path:
        config_path = fake_git_repo / ".diffguard.toml"
        config_path.write_text(_dict_to_toml(settings))
        return config_path

    return _create


@pytest.fixture
def baseline_file(fake_git_repo: Path) -> Any:
    """Create a ``.diffguard-baseline.json`` in the fake repo.

    ``entries`` should be a list of dicts matching BaselineEntry fields.
    """

    def _create(entries: list[dict[str, Any]]) -> Path:
        data = {"version": "1.0", "entries": entries}
        path = fake_git_repo / ".diffguard-baseline.json"
        path.write_text(json.dumps(data, indent=2))
        return path

    return _create


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dict_to_toml(d: dict[str, Any]) -> str:
    """Minimal dict-to-TOML serialiser for flat configs with one optional sub-table."""
    lines: list[str] = []
    subtables: dict[str, dict[str, Any]] = {}

    for key, value in d.items():
        if isinstance(value, dict):
            subtables[key] = value
        else:
            lines.append(f"{key} = {_toml_value(value)}")

    for table_name, table_dict in subtables.items():
        lines.append(f"\n[{table_name}]")
        for k, v in table_dict.items():
            lines.append(f"{k} = {_toml_value(v)}")

    return "\n".join(lines) + "\n"


def _toml_value(v: Any) -> str:
    """Format a Python value as a TOML literal."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(v)
    if isinstance(v, str):
        return f'"{v}"'
    if isinstance(v, list):
        inner = ", ".join(_toml_value(item) for item in v)
        return f"[{inner}]"
    return f'"{v}"'
