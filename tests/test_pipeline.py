"""Tests for the core analysis pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest

from diffguard.config import DiffguardConfig
from diffguard.context import Region
from diffguard.git import DiffFile, DiffHunk
from diffguard.llm import (
    AnalysisResult,
    CodeContext,
    DiffLine,
    Finding,
    ScopeContext,
    SymbolDef,
)
from diffguard.llm.response import ConfidenceLevel, SeverityLevel
from diffguard.pipeline import FileContext, _build_diff_lines, _file_context_to_code_context, analyze_staged_changes

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PYTHON_SOURCE = """\
import os

def hello(name: str) -> str:
    return f"Hello, {name}!"

def main() -> None:
    print(hello("world"))
"""

PYTHON_LINES = PYTHON_SOURCE.splitlines()


def _make_diff_file(
    path: str = "src/app.py",
    *,
    is_new_file: bool = False,
    is_deleted: bool = False,
    is_binary: bool = False,
    hunks: list[DiffHunk] | None = None,
) -> DiffFile:
    """Create a DiffFile for testing."""
    if hunks is None:
        hunks = [
            DiffHunk(
                old_start=3,
                old_count=2,
                new_start=3,
                new_count=2,
                lines=[("+", '    return f"Hello, {name}!"'), (" ", "")],
            )
        ]
    return DiffFile(
        old_path=path,
        new_path=path,
        hunks=hunks,
        is_new_file=is_new_file,
        is_deleted=is_deleted,
        is_binary=is_binary,
    )


def _make_finding(file_path: str = "src/app.py") -> Finding:
    """Create a sample Finding for testing."""
    return Finding(
        what="Test vulnerability",
        why="Test reason",
        how_to_fix="Test fix",
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        file_path=file_path,
    )


def _default_config() -> DiffguardConfig:
    """Create a default config for testing."""
    return DiffguardConfig()


# ---------------------------------------------------------------------------
# TestBuildDiffLines
# ---------------------------------------------------------------------------


class TestBuildDiffLines:
    """Tests for _build_diff_lines helper."""

    def test_tracks_line_numbers_for_additions(self) -> None:
        diff_file = _make_diff_file(
            hunks=[
                DiffHunk(
                    old_start=1,
                    old_count=3,
                    new_start=1,
                    new_count=4,
                    lines=[
                        (" ", "line 1"),
                        ("+", "new line"),
                        (" ", "line 2"),
                        (" ", "line 3"),
                    ],
                )
            ]
        )
        result = _build_diff_lines(diff_file)
        assert len(result) == 4
        assert result[0] == DiffLine(line_num=1, change_type=" ", content="line 1")
        assert result[1] == DiffLine(line_num=2, change_type="+", content="new line")
        assert result[2] == DiffLine(line_num=3, change_type=" ", content="line 2")
        assert result[3] == DiffLine(line_num=4, change_type=" ", content="line 3")

    def test_removals_do_not_advance_counter(self) -> None:
        diff_file = _make_diff_file(
            hunks=[
                DiffHunk(
                    old_start=1,
                    old_count=3,
                    new_start=1,
                    new_count=1,
                    lines=[
                        (" ", "kept"),
                        ("-", "removed1"),
                        ("-", "removed2"),
                    ],
                )
            ]
        )
        result = _build_diff_lines(diff_file)
        assert len(result) == 3
        assert result[0].line_num == 1
        assert result[0].change_type == " "
        # Removals get the current line_num but don't advance it
        assert result[1].line_num == 2
        assert result[1].change_type == "-"
        assert result[2].line_num == 2
        assert result[2].change_type == "-"

    def test_multiple_hunks(self) -> None:
        diff_file = _make_diff_file(
            hunks=[
                DiffHunk(old_start=1, old_count=1, new_start=1, new_count=1, lines=[("+", "a")]),
                DiffHunk(old_start=10, old_count=1, new_start=10, new_count=1, lines=[("+", "b")]),
            ]
        )
        result = _build_diff_lines(diff_file)
        assert len(result) == 2
        assert result[0].line_num == 1
        assert result[1].line_num == 10


# ---------------------------------------------------------------------------
# TestFileContextToCodeContext
# ---------------------------------------------------------------------------


class TestFileContextToCodeContext:
    """Tests for _file_context_to_code_context conversion."""

    def test_builds_expanded_region_from_source_lines(self) -> None:
        fc = FileContext(
            file_path="test.py",
            language=__import__("diffguard.ast.languages", fromlist=["Language"]).Language.PYTHON,
            source_lines=["line1", "line2", "line3", "line4", "line5"],
            regions=[Region(start_line=2, end_line=4)],
            diff_lines=[DiffLine(line_num=3, change_type="+", content="line3")],
        )
        ctx = _file_context_to_code_context(fc)
        assert ctx.file_path == "test.py"
        assert ctx.region_start_line == 2
        assert ctx.expanded_region == "line2\nline3\nline4"

    def test_empty_regions_returns_empty_expanded_region(self) -> None:
        fc = FileContext(
            file_path="test.py",
            language=__import__("diffguard.ast.languages", fromlist=["Language"]).Language.PYTHON,
            source_lines=["line1"],
            regions=[],
            diff_lines=[],
        )
        ctx = _file_context_to_code_context(fc)
        assert ctx.expanded_region == ""
        assert ctx.region_start_line == 1

    def test_multiple_regions_uses_min_max(self) -> None:
        fc = FileContext(
            file_path="test.py",
            language=__import__("diffguard.ast.languages", fromlist=["Language"]).Language.PYTHON,
            source_lines=[f"line{i}" for i in range(1, 11)],
            regions=[Region(start_line=2, end_line=3), Region(start_line=7, end_line=9)],
            diff_lines=[],
        )
        ctx = _file_context_to_code_context(fc)
        assert ctx.region_start_line == 2
        # Covers lines 2-9 (indices 1-8)
        assert ctx.expanded_region == "\n".join(f"line{i}" for i in range(2, 10))

    def test_preserves_scopes_and_symbols(self) -> None:
        scope = ScopeContext(type="function", name="foo", start_line=1, end_line=5, source="def foo(): ...")
        sym = SymbolDef(name="bar", code="def bar(): ...", file="other.py")
        fc = FileContext(
            file_path="test.py",
            language=__import__("diffguard.ast.languages", fromlist=["Language"]).Language.PYTHON,
            source_lines=["x = 1"],
            regions=[Region(start_line=1, end_line=1)],
            diff_lines=[],
            scopes=[scope],
            symbols={"bar": sym},
        )
        ctx = _file_context_to_code_context(fc)
        assert ctx.scopes == [scope]
        assert ctx.symbols == {"bar": sym}


# ---------------------------------------------------------------------------
# TestPipelineSingleFile
# ---------------------------------------------------------------------------


class TestPipelineSingleFile:
    """Single .py file produces findings."""

    @pytest.mark.asyncio
    async def test_single_file_returns_findings(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_file = src_dir / "app.py"
        app_file.write_text(PYTHON_SOURCE)

        diff_file = _make_diff_file("src/app.py")
        finding = _make_finding("src/app.py")
        config = _default_config()

        mock_client = AsyncMock()
        mock_client.analyze.return_value = (
            '{"findings": [{"what": "Test vulnerability", "why": "Test reason",'
            ' "how_to_fix": "Test fix", "severity": "Medium", "confidence": "High"}]}'
        )

        result = await analyze_staged_changes([diff_file], config, mock_client, project_root=tmp_path)

        assert len(result.findings) >= 1
        assert result.findings[0].what == finding.what
        assert not result.errors


# ---------------------------------------------------------------------------
# TestPipelineMultipleFiles
# ---------------------------------------------------------------------------


class TestPipelineMultipleFiles:
    """Multiple .py files are all analyzed and findings aggregated."""

    @pytest.mark.asyncio
    async def test_multiple_files_aggregated(self, tmp_path: Path) -> None:
        for name in ("a.py", "b.py", "c.py"):
            (tmp_path / name).write_text(PYTHON_SOURCE)

        diff_files = [_make_diff_file(name) for name in ("a.py", "b.py", "c.py")]
        config = _default_config()

        call_count = 0

        async def mock_analyze(_prompt: str) -> str:
            nonlocal call_count
            call_count += 1
            return (
                '{"findings": [{"what": "Issue", "why": "reason",'
                ' "how_to_fix": "fix", "severity": "Low", "confidence": "Medium"}]}'
            )

        mock_client = AsyncMock()
        mock_client.analyze.side_effect = mock_analyze

        result = await analyze_staged_changes(diff_files, config, mock_client, project_root=tmp_path)

        assert call_count == 3
        assert len(result.findings) == 3
        assert not result.errors


# ---------------------------------------------------------------------------
# TestPipelineSkipsNonSource
# ---------------------------------------------------------------------------


class TestPipelineSkipsNonSource:
    """Non-source files (.json, .md, .png) are skipped; only .py is analyzed."""

    @pytest.mark.asyncio
    async def test_non_source_files_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_SOURCE)
        (tmp_path / "config.json").write_text("{}")
        (tmp_path / "README.md").write_text("# README")
        (tmp_path / "logo.png").write_bytes(b"\x89PNG")

        diff_files = [
            _make_diff_file("app.py"),
            _make_diff_file("config.json"),
            _make_diff_file("README.md"),
            _make_diff_file("logo.png"),
        ]
        config = _default_config()

        mock_client = AsyncMock()
        mock_client.analyze.return_value = '{"findings": []}'

        result = await analyze_staged_changes(diff_files, config, mock_client, project_root=tmp_path)

        # Only app.py should be analyzed
        assert mock_client.analyze.call_count == 1
        assert not result.errors


# ---------------------------------------------------------------------------
# TestPipelineSkipsSensitive
# ---------------------------------------------------------------------------


class TestPipelineSkipsSensitive:
    """Sensitive files (.env) are excluded; .py files are analyzed."""

    @pytest.mark.asyncio
    async def test_env_file_excluded(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_SOURCE)
        (tmp_path / ".env").write_text("SECRET=abc")

        diff_files = [
            _make_diff_file("app.py"),
            _make_diff_file(".env"),
        ]
        config = _default_config()

        mock_client = AsyncMock()
        mock_client.analyze.return_value = '{"findings": []}'

        result = await analyze_staged_changes(diff_files, config, mock_client, project_root=tmp_path)

        # .env is not a recognized source language, so it's filtered by language detection
        # Even if it were, it would be caught by sensitive file filter
        assert mock_client.analyze.call_count == 1
        assert not result.errors


# ---------------------------------------------------------------------------
# TestPipelineSkipsBinary
# ---------------------------------------------------------------------------


class TestPipelineSkipsBinary:
    """Binary files (is_binary=True) are skipped."""

    @pytest.mark.asyncio
    async def test_binary_file_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_SOURCE)

        diff_files = [
            _make_diff_file("app.py"),
            _make_diff_file("image.py", is_binary=True),
        ]
        config = _default_config()

        mock_client = AsyncMock()
        mock_client.analyze.return_value = '{"findings": []}'

        result = await analyze_staged_changes(diff_files, config, mock_client, project_root=tmp_path)

        assert mock_client.analyze.call_count == 1
        assert not result.errors


# ---------------------------------------------------------------------------
# TestPipelineNewFiles
# ---------------------------------------------------------------------------


class TestPipelineNewFiles:
    """New files (is_new_file=True) get full file region and flag passed through."""

    @pytest.mark.asyncio
    async def test_new_file_full_region(self, tmp_path: Path) -> None:
        (tmp_path / "new.py").write_text(PYTHON_SOURCE)

        diff_file = _make_diff_file(
            "new.py",
            is_new_file=True,
            hunks=[
                DiffHunk(
                    old_start=0,
                    old_count=0,
                    new_start=1,
                    new_count=len(PYTHON_LINES),
                    lines=[("+", line) for line in PYTHON_LINES],
                )
            ],
        )
        config = _default_config()

        captured_contexts: list[CodeContext] = []

        async def capture_analyze(contexts: list[CodeContext], _client: object, **_kwargs: object) -> AnalysisResult:
            captured_contexts.extend(contexts)
            return AnalysisResult()

        mock_client = AsyncMock()

        with patch("diffguard.pipeline.analyze_files", side_effect=capture_analyze):
            await analyze_staged_changes([diff_file], config, mock_client, project_root=tmp_path)

        assert len(captured_contexts) == 1
        ctx = captured_contexts[0]
        # New file: region covers full file
        assert ctx.region_start_line == 1
        region_lines = ctx.expanded_region.splitlines()
        assert len(region_lines) == len(PYTHON_LINES)


# ---------------------------------------------------------------------------
# TestPipelineDeletedFiles
# ---------------------------------------------------------------------------


class TestPipelineDeletedFiles:
    """Deleted files (is_deleted=True) are skipped."""

    @pytest.mark.asyncio
    async def test_deleted_file_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_SOURCE)

        diff_files = [
            _make_diff_file("app.py"),
            _make_diff_file("old.py", is_deleted=True),
        ]
        config = _default_config()

        mock_client = AsyncMock()
        mock_client.analyze.return_value = '{"findings": []}'

        result = await analyze_staged_changes(diff_files, config, mock_client, project_root=tmp_path)

        assert mock_client.analyze.call_count == 1
        assert not result.errors


# ---------------------------------------------------------------------------
# TestPipelinePartialFailures
# ---------------------------------------------------------------------------


class TestPipelinePartialFailures:
    """Context build error on one file doesn't prevent others from being analyzed."""

    @pytest.mark.asyncio
    async def test_context_error_recorded_others_succeed(self, tmp_path: Path) -> None:
        (tmp_path / "good.py").write_text(PYTHON_SOURCE)
        # bad.py doesn't exist on disk → ContextError when reading

        diff_files = [
            _make_diff_file("good.py"),
            _make_diff_file("missing.py"),
        ]
        config = _default_config()

        mock_client = AsyncMock()
        mock_client.analyze.return_value = (
            '{"findings": [{"what": "Issue", "why": "reason",'
            ' "how_to_fix": "fix", "severity": "Low", "confidence": "Low"}]}'
        )

        result = await analyze_staged_changes(diff_files, config, mock_client, project_root=tmp_path)

        # good.py should succeed
        assert mock_client.analyze.call_count == 1
        assert len(result.findings) == 1
        # missing.py should have an error
        assert len(result.errors) == 1
        assert result.errors[0].file_path == "missing.py"
        assert result.errors[0].error_type == "ContextError"


# ---------------------------------------------------------------------------
# TestPipelineEmptyResult
# ---------------------------------------------------------------------------


class TestPipelineEmptyResult:
    """Only non-source files → empty findings, no errors."""

    @pytest.mark.asyncio
    async def test_all_non_source_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "config.json").write_text("{}")
        (tmp_path / "README.md").write_text("# README")

        diff_files = [
            _make_diff_file("config.json"),
            _make_diff_file("README.md"),
        ]
        config = _default_config()

        mock_client = AsyncMock()

        result = await analyze_staged_changes(diff_files, config, mock_client, project_root=tmp_path)

        assert result.findings == []
        assert result.errors == []
        mock_client.analyze.assert_not_called()


# ---------------------------------------------------------------------------
# TestPipelineConcurrency
# ---------------------------------------------------------------------------


class TestPipelineConcurrency:
    """max_concurrent_api_calls is forwarded to analyze_files."""

    @pytest.mark.asyncio
    async def test_max_concurrent_forwarded(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(PYTHON_SOURCE)

        diff_file = _make_diff_file("app.py")
        config = DiffguardConfig(max_concurrent_api_calls=3, timeout=60)

        captured_kwargs: dict[str, object] = {}

        async def capture_analyze(_contexts: list[CodeContext], _client: object, **kwargs: object) -> AnalysisResult:
            captured_kwargs.update(kwargs)
            return AnalysisResult()

        mock_client = AsyncMock()

        with patch("diffguard.pipeline.analyze_files", side_effect=capture_analyze):
            await analyze_staged_changes([diff_file], config, mock_client, project_root=tmp_path)

        assert captured_kwargs["max_concurrent"] == 3
        assert captured_kwargs["timeout_per_file"] == 60.0
