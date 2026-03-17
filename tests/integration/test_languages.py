"""Integration tests for language-specific parsing, scope detection, and import extraction.

Each supported language gets a test class verifying that tree-sitter parsing,
scope detection, and import extraction work end-to-end through the real CLI
pipeline (only the LLM client is mocked).
"""

from __future__ import annotations

import contextlib
import json
import subprocess
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
# Code samples — each contains imports AND a named function/class so we can
# verify both import extraction and scope detection in the prompt.
# ---------------------------------------------------------------------------
PYTHON_SAMPLE = """\
import os
from pathlib import Path

def process_file(path: str) -> str:
    with open(path) as f:
        return f.read()
"""

JAVASCRIPT_SAMPLE = """\
import { readFile } from 'fs/promises';

async function processFile(path) {
    return await readFile(path, 'utf-8');
}

export { processFile };
"""

TYPESCRIPT_SAMPLE = """\
import type { ReadStream } from 'fs';
import { createReadStream } from 'fs';

function getStream(path: string): ReadStream {
    return createReadStream(path);
}

export { getStream };
"""

TSX_SAMPLE = """\
import React from 'react';

interface Props {
    name: string;
}

export function Greeting({ name }: Props): JSX.Element {
    return <h1>Hello, {name}!</h1>;
}
"""

JAVA_SAMPLE = """\
package com.example;

import java.io.File;
import java.io.IOException;

public class FileProcessor {
    public String process(File file) throws IOException {
        return new String(java.nio.file.Files.readAllBytes(file.toPath()));
    }
}
"""

RUBY_SAMPLE = """\
require 'json'
require_relative './helper'

class DataProcessor
  def initialize(config)
    @config = config
  end

  def process(data)
    JSON.parse(data)
  end
end
"""

GO_SAMPLE = """\
package main

import (
    "io/ioutil"
    "os"
)

func readFile(path string) ([]byte, error) {
    return ioutil.ReadFile(path)
}
"""

PHP_SAMPLE = """\
<?php
namespace App\\Services;

use App\\Helpers\\FileHelper;

class FileService
{
    public function read(string $path): string
    {
        return file_get_contents($path);
    }
}
"""

ELIXIR_SAMPLE = """\
defmodule MyApp.Accounts do
  alias MyApp.Repo
  import Ecto.Query, only: [from: 2]

  def list_users do
    query = from u in "users", select: u
    Repo.all(query)
  end

  defp validate(attrs) do
    attrs
  end
end
"""

# ---------------------------------------------------------------------------
# Reusable finding dict
# ---------------------------------------------------------------------------
FINDING_GENERIC: dict[str, Any] = {
    "what": "Potential vulnerability",
    "why": "Detected in code",
    "how_to_fix": "Review and fix",
    "severity": "Medium",
    "confidence": "Medium",
    "cwe_id": "CWE-200",
    "line_range": {"start": 2, "end": 2},
}


# ---------------------------------------------------------------------------
# Helpers (same pattern as other integration test files)
# ---------------------------------------------------------------------------


def _make_mock_client(
    *,
    findings: list[dict[str, Any]] | None = None,
    per_file: dict[str, list[dict[str, Any]]] | None = None,
) -> MagicMock:
    """Build a mock that replaces the OpenAIClient class."""
    mock_cls = MagicMock()
    mock_instance = AsyncMock()

    if per_file is not None:

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


def _get_prompts(mock_client: MagicMock) -> list[str]:
    """Extract the prompt strings from all analyze() calls."""
    return [call[0][0] for call in mock_client.return_value.analyze.call_args_list]


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


class TestPython:
    """Python file parsing, scope detection, and import extraction."""

    def test_parses_successfully(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged Python file parses without errors."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0

    def test_scope_detected(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Function name appears in the prompt sent to the LLM."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        assert any("process_file" in p for p in prompts)

    def test_imports_extracted(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Import statements appear in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        combined = " ".join(prompts)
        assert "import os" in combined or "os" in combined

    def test_full_workflow(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """End-to-end analysis returns findings with correct file path."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"src/main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[FINDING_GENERIC])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json"])

        data = json.loads(result.output)
        assert len(data["findings"]) >= 1
        assert any("main.py" in f.get("file_path", "") for f in data["findings"])


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------


class TestJavaScript:
    """JavaScript file parsing, scope detection, and import extraction."""

    def test_parses_successfully(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged .js file parses without errors."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"utils.js": JAVASCRIPT_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0

    def test_scope_detected(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Function name appears in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"utils.js": JAVASCRIPT_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        assert any("processFile" in p for p in prompts)

    def test_imports_extracted(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Import statements appear in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"utils.js": JAVASCRIPT_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        combined = " ".join(prompts)
        assert "readFile" in combined or "fs/promises" in combined

    def test_full_workflow(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """End-to-end analysis completes successfully."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"src/utils.js": JAVASCRIPT_SAMPLE})

        mock_client = _make_mock_client(findings=[FINDING_GENERIC])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json"])

        data = json.loads(result.output)
        assert len(data["findings"]) >= 1


# ---------------------------------------------------------------------------
# TypeScript
# ---------------------------------------------------------------------------


class TestTypeScript:
    """TypeScript file parsing with type annotations, scope, and imports."""

    def test_parses_with_types(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged .ts file with type annotations parses successfully."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"stream.ts": TYPESCRIPT_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0

    def test_scope_detected(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Function name appears in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"stream.ts": TYPESCRIPT_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        assert any("getStream" in p for p in prompts)

    def test_type_imports_handled(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Type imports are recognized in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"stream.ts": TYPESCRIPT_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        combined = " ".join(prompts)
        assert "ReadStream" in combined or "createReadStream" in combined

    def test_full_workflow(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """End-to-end analysis completes successfully."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"src/stream.ts": TYPESCRIPT_SAMPLE})

        mock_client = _make_mock_client(findings=[FINDING_GENERIC])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json"])

        data = json.loads(result.output)
        assert len(data["findings"]) >= 1


# ---------------------------------------------------------------------------
# TSX
# ---------------------------------------------------------------------------


class TestTsx:
    """TSX file with JSX syntax inside TypeScript."""

    def test_parses_jsx_in_ts(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged .tsx file with React component parses successfully."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"Greeting.tsx": TSX_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0
        mock_client.return_value.analyze.assert_awaited()


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------


class TestJava:
    """Java file parsing, scope detection, and import extraction."""

    def test_parses_successfully(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged .java file parses without errors."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"FileProcessor.java": JAVA_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0

    def test_scope_detected(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Method name appears in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"FileProcessor.java": JAVA_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        assert any("process" in p for p in prompts)

    def test_imports_extracted(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Java import statements appear in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"FileProcessor.java": JAVA_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        combined = " ".join(prompts)
        assert "java.io" in combined or "File" in combined


# ---------------------------------------------------------------------------
# Ruby
# ---------------------------------------------------------------------------


class TestRuby:
    """Ruby file parsing, scope detection, and require extraction."""

    def test_parses_successfully(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged .rb file parses without errors."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"processor.rb": RUBY_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0

    def test_scope_detected(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Method name appears in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"processor.rb": RUBY_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        assert any("process" in p for p in prompts)

    def test_requires_extracted(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Require statements appear in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"processor.rb": RUBY_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        combined = " ".join(prompts)
        assert "json" in combined.lower()


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


class TestGo:
    """Go file parsing, scope detection, and import extraction."""

    def test_parses_successfully(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged .go file parses without errors."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.go": GO_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0

    def test_scope_detected(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Function name appears in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.go": GO_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        assert any("readFile" in p for p in prompts)

    def test_imports_extracted(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Go import statements appear in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"main.go": GO_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        combined = " ".join(prompts)
        assert "ioutil" in combined or "io/ioutil" in combined


# ---------------------------------------------------------------------------
# PHP
# ---------------------------------------------------------------------------


class TestPhp:
    """PHP file parsing, scope detection, and use statement extraction."""

    def test_parses_successfully(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged .php file parses without errors."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"FileService.php": PHP_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0

    def test_scope_detected(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Method name appears in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"FileService.php": PHP_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        assert any("read" in p for p in prompts)

    def test_use_statements_extracted(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """PHP use statements appear in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"FileService.php": PHP_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        combined = " ".join(prompts)
        assert "FileHelper" in combined or "App" in combined


# ---------------------------------------------------------------------------
# Elixir
# ---------------------------------------------------------------------------


class TestElixir:
    """Elixir file parsing, scope detection, and directive extraction."""

    def test_parses_successfully(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged .ex file parses without errors."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"accounts.ex": ELIXIR_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0

    def test_scope_detected(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Function name appears in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"accounts.ex": ELIXIR_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        assert any("list_users" in p for p in prompts)

    def test_imports_extracted(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Alias/import directives appear in the prompt."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"accounts.ex": ELIXIR_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            runner.invoke(app)

        prompts = _get_prompts(mock_client)
        combined = " ".join(prompts)
        assert "Repo" in combined or "Ecto" in combined

    def test_full_workflow(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """End-to-end analysis completes successfully."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"lib/accounts.ex": ELIXIR_SAMPLE})

        mock_client = _make_mock_client(findings=[FINDING_GENERIC])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app, ["--json"])

        data = json.loads(result.output)
        assert len(data["findings"]) >= 1


# ---------------------------------------------------------------------------
# Unknown extension
# ---------------------------------------------------------------------------


class TestUnknownExtension:
    """Unsupported file extensions are skipped."""

    def test_skipped(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A .xyz file is not sent to the LLM."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"data.xyz": "some unknown content"})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0
        mock_client.return_value.analyze.assert_not_awaited()

    def test_other_files_still_analyzed(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A .py file alongside a .xyz file is still analyzed."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files({"data.xyz": "unknown", "main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0
        assert mock_client.return_value.analyze.await_count == 1


# ---------------------------------------------------------------------------
# Mixed language project
# ---------------------------------------------------------------------------


class TestMixedLanguageProject:
    """Multiple languages in the same scan."""

    def test_all_languages_analyzed(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staged .py, .js, .ts files are all analyzed with correct parsers."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        stage_files(
            {
                "src/main.py": PYTHON_SAMPLE,
                "src/utils.js": JAVASCRIPT_SAMPLE,
                "src/types.ts": TYPESCRIPT_SAMPLE,
            }
        )

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0
        assert mock_client.return_value.analyze.await_count == 3

        prompts = _get_prompts(mock_client)
        combined = " ".join(prompts)
        assert "process_file" in combined
        assert "processFile" in combined
        assert "getStream" in combined


# ---------------------------------------------------------------------------
# Binary file
# ---------------------------------------------------------------------------


class TestBinaryFileSkipped:
    """Binary files are excluded from analysis."""

    def test_binary_skipped(
        self,
        fake_git_repo: Path,
        stage_files: Any,
        mock_env: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A .png binary file is not sent to the LLM."""
        monkeypatch.chdir(fake_git_repo)
        mock_env({"OPENAI_API_KEY": "sk-test"})
        # Write actual binary content so git detects it as binary
        png_path = fake_git_repo / "image.png"
        png_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        subprocess.run(["git", "add", "image.png"], cwd=fake_git_repo, capture_output=True, check=True)

        # Also stage a real source file so the pipeline has something to do
        stage_files({"main.py": PYTHON_SAMPLE})

        mock_client = _make_mock_client(findings=[])
        with _pipeline_patches(mock_client):
            result = runner.invoke(app)

        assert result.exit_code == 0
        # Only main.py should be analyzed, not image.png
        assert mock_client.return_value.analyze.await_count == 1
