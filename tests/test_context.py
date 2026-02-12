"""Tests for hunk expansion and region merging."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from diffguard.context import Region, build_file_regions, expand_hunk, merge_regions, read_file_lines
from diffguard.exceptions import ContextError
from diffguard.git import DiffFile, DiffHunk

# === Inline fixtures ===

# Standard hunk: starts at line 10, spans 5 new lines (10-14)
STANDARD_HUNK = DiffHunk(old_start=8, old_count=3, new_start=10, new_count=5)

# Hunk near start of file: starts at line 2, spans 3 new lines (2-4)
NEAR_START_HUNK = DiffHunk(old_start=1, old_count=2, new_start=2, new_count=3)

# Hunk near end of file: starts at line 95, spans 4 new lines (95-98)
NEAR_END_HUNK = DiffHunk(old_start=90, old_count=3, new_start=95, new_count=4)

# Hunk at line 1: starts at line 1, spans 2 new lines (1-2)
AT_START_HUNK = DiffHunk(old_start=1, old_count=1, new_start=1, new_count=2)

# Single-line hunk: starts at line 50, spans 1 new line
SINGLE_LINE_HUNK = DiffHunk(old_start=48, old_count=1, new_start=50, new_count=1)

# Pure deletion hunk: new_count=0 (no lines on new side)
DELETION_HUNK = DiffHunk(old_start=20, old_count=3, new_start=20, new_count=0)


# === Tests: expand_hunk ===


class TestExpandHunkStandard:
    """Standard expansion with default lines."""

    def test_standard_expansion_start(self) -> None:
        region = expand_hunk(STANDARD_HUNK, expansion=3)
        assert region.start_line == 7  # 10 - 3

    def test_standard_expansion_end(self) -> None:
        region = expand_hunk(STANDARD_HUNK, expansion=3)
        assert region.end_line == 17  # 14 + 3


class TestExpandHunkConfigurable:
    """Expansion is configurable."""

    def test_expansion_of_5(self) -> None:
        region = expand_hunk(STANDARD_HUNK, expansion=5)
        assert region.start_line == 5  # 10 - 5
        assert region.end_line == 19  # 14 + 5

    def test_expansion_of_10(self) -> None:
        region = expand_hunk(STANDARD_HUNK, expansion=10)
        assert region.start_line == 1  # max(1, 10-10)
        assert region.end_line == 24  # 14 + 10


class TestExpandHunkClampStart:
    """Expansion clamps to line 1 at start of file."""

    def test_clamp_to_line_1(self) -> None:
        region = expand_hunk(AT_START_HUNK, expansion=5)
        assert region.start_line == 1


class TestExpandHunkClampEnd:
    """Expansion clamps to file_length at end of file."""

    def test_clamp_to_file_length(self) -> None:
        region = expand_hunk(NEAR_END_HUNK, expansion=5, file_length=100)
        assert region.end_line == 100  # min(100, 98+5=103)


class TestExpandHunkClampBoth:
    """Expansion clamps both ends for small file."""

    def test_clamp_both_ends(self) -> None:
        region = expand_hunk(AT_START_HUNK, expansion=50, file_length=10)
        assert region.start_line == 1
        assert region.end_line == 10


class TestExpandHunkZeroExpansion:
    """Zero expansion returns exact hunk range."""

    def test_zero_expansion(self) -> None:
        region = expand_hunk(STANDARD_HUNK, expansion=0)
        assert region.start_line == 10
        assert region.end_line == 14  # 10 + 5 - 1


class TestExpandHunkSingleLine:
    """Single-line hunk and pure deletion hunk."""

    def test_single_line_hunk(self) -> None:
        region = expand_hunk(SINGLE_LINE_HUNK, expansion=3)
        assert region.start_line == 47  # 50 - 3
        assert region.end_line == 53  # 50 + 3

    def test_pure_deletion_hunk_uses_min_count_of_1(self) -> None:
        region = expand_hunk(DELETION_HUNK, expansion=3)
        # new_count=0 -> clamped to 1, so hunk_end = 20 + 1 - 1 = 20
        assert region.start_line == 17  # 20 - 3
        assert region.end_line == 23  # 20 + 3


# === Tests: merge_regions ===


class TestMergeOverlapping:
    """Overlapping regions are merged."""

    def test_overlapping_regions_merge(self) -> None:
        regions = [Region(start_line=1, end_line=10), Region(start_line=5, end_line=15)]
        result = merge_regions(regions)
        assert len(result) == 1
        assert result[0].start_line == 1
        assert result[0].end_line == 15


class TestMergeAdjacent:
    """Adjacent regions (touching) are merged."""

    def test_adjacent_regions_merge(self) -> None:
        regions = [Region(start_line=1, end_line=10), Region(start_line=11, end_line=20)]
        result = merge_regions(regions)
        assert len(result) == 1
        assert result[0].start_line == 1
        assert result[0].end_line == 20


class TestMergeGapOfOne:
    """Regions with a gap of 1 line are NOT merged."""

    def test_gap_of_one_not_merged(self) -> None:
        regions = [Region(start_line=1, end_line=10), Region(start_line=12, end_line=20)]
        result = merge_regions(regions)
        assert len(result) == 2


class TestMergeNonOverlapping:
    """Non-overlapping regions stay separate."""

    def test_non_overlapping_stay_separate(self) -> None:
        regions = [Region(start_line=1, end_line=5), Region(start_line=20, end_line=25)]
        result = merge_regions(regions)
        assert len(result) == 2
        assert result[0].start_line == 1
        assert result[0].end_line == 5
        assert result[1].start_line == 20
        assert result[1].end_line == 25


class TestMergeUnsorted:
    """Unsorted input is handled correctly."""

    def test_unsorted_input_sorted_and_merged(self) -> None:
        regions = [Region(start_line=20, end_line=30), Region(start_line=1, end_line=10)]
        result = merge_regions(regions)
        assert len(result) == 2
        assert result[0].start_line == 1
        assert result[1].start_line == 20


class TestMergeFullyContained:
    """Fully contained region is absorbed."""

    def test_contained_region_absorbed(self) -> None:
        regions = [Region(start_line=1, end_line=20), Region(start_line=5, end_line=10)]
        result = merge_regions(regions)
        assert len(result) == 1
        assert result[0].start_line == 1
        assert result[0].end_line == 20


class TestMergeSingle:
    """Single region returns copy."""

    def test_single_region_returns_copy(self) -> None:
        original = Region(start_line=5, end_line=15)
        result = merge_regions([original])
        assert len(result) == 1
        assert result[0].start_line == 5
        assert result[0].end_line == 15
        assert result[0] is not original


class TestMergeEmpty:
    """Empty list returns empty list."""

    def test_empty_list_returns_empty(self) -> None:
        result = merge_regions([])
        assert result == []


class TestMergeChain:
    """Chain of overlapping regions all merge into one."""

    def test_chain_merge(self) -> None:
        regions = [
            Region(start_line=1, end_line=10),
            Region(start_line=10, end_line=20),
            Region(start_line=20, end_line=30),
        ]
        result = merge_regions(regions)
        assert len(result) == 1
        assert result[0].start_line == 1
        assert result[0].end_line == 30


# === Tests: read_file_lines ===


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """Create a sample file with 100 lines."""
    p = tmp_path / "sample.py"
    lines = [f"line {i}" for i in range(1, 101)]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


class TestReadFileLinesValid:
    """Read valid file returns correct lines."""

    def test_reads_100_lines(self, sample_file: Path) -> None:
        lines = read_file_lines(sample_file)
        assert len(lines) == 100

    def test_first_line_content(self, sample_file: Path) -> None:
        lines = read_file_lines(sample_file)
        assert lines[0] == "line 1"

    def test_last_line_content(self, sample_file: Path) -> None:
        lines = read_file_lines(sample_file)
        assert lines[99] == "line 100"


class TestReadFileLinesEmpty:
    """Empty file returns empty list."""

    def test_empty_file_returns_empty_list(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.py"
        p.write_text("", encoding="utf-8")
        lines = read_file_lines(p)
        assert lines == []


class TestReadFileLinesNotFound:
    """Missing file raises FileNotFoundError."""

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "nonexistent.py"
        with pytest.raises(FileNotFoundError):
            read_file_lines(p)


class TestReadFileLinesBinary:
    """Binary file raises ContextError."""

    def test_binary_file_raises_context_error(self, tmp_path: Path) -> None:
        p = tmp_path / "binary.dat"
        p.write_bytes(b"\x00\x01\x02\x03binary content")
        with pytest.raises(ContextError, match="Binary file"):
            read_file_lines(p)


class TestReadFileLinesPreservesContent:
    """File content is preserved (tabs, spaces, indentation)."""

    def test_preserves_tabs_and_spaces(self, tmp_path: Path) -> None:
        p = tmp_path / "indented.py"
        content = "def foo():\n\tif True:\n\t\tpass\n    spaces\n"
        p.write_text(content, encoding="utf-8")
        lines = read_file_lines(p)
        assert lines[0] == "def foo():"
        assert lines[1] == "\tif True:"
        assert lines[2] == "\t\tpass"
        assert lines[3] == "    spaces"


class TestReadFileLinesMixedEndings:
    """Mixed line endings handled correctly."""

    def test_mixed_line_endings(self, tmp_path: Path) -> None:
        p = tmp_path / "mixed.txt"
        # Write raw bytes to preserve exact line endings
        p.write_bytes(b"unix\nwindows\r\nold_mac\rend")
        lines = read_file_lines(p)
        assert lines == ["unix", "windows", "old_mac", "end"]


# === Tests: build_file_regions ===


class TestNewFileEntireRegion:
    """New file returns entire file as single region."""

    def test_new_file_returns_full_region(self) -> None:
        diff_file = DiffFile(
            old_path="/dev/null",
            new_path="src/new.py",
            is_new_file=True,
            hunks=[DiffHunk(old_start=0, old_count=0, new_start=1, new_count=50)],
        )
        result = build_file_regions(diff_file, file_length=50, expansion=3)
        assert len(result) == 1
        assert result[0].start_line == 1
        assert result[0].end_line == 50

    def test_deleted_file_returns_empty(self) -> None:
        diff_file = DiffFile(
            old_path="src/old.py",
            new_path="src/old.py",
            is_deleted=True,
            hunks=[DiffHunk(old_start=1, old_count=5, new_start=0, new_count=0)],
        )
        result = build_file_regions(diff_file, file_length=100, expansion=3)
        assert result == []

    def test_binary_file_returns_empty(self) -> None:
        diff_file = DiffFile(
            old_path="image.png",
            new_path="image.png",
            is_binary=True,
        )
        result = build_file_regions(diff_file, file_length=0, expansion=3)
        assert result == []

    def test_no_hunks_returns_empty(self) -> None:
        diff_file = DiffFile(
            old_path="script.sh",
            new_path="script.sh",
            mode_changed=True,
        )
        result = build_file_regions(diff_file, file_length=50, expansion=3)
        assert result == []

    def test_multiple_hunks_expanded_and_merged(self) -> None:
        diff_file = DiffFile(
            old_path="src/app.py",
            new_path="src/app.py",
            hunks=[
                DiffHunk(old_start=5, old_count=3, new_start=5, new_count=4),  # new: 5-8
                DiffHunk(old_start=20, old_count=2, new_start=21, new_count=3),  # new: 21-23
            ],
        )
        # expansion=3: first -> 2-11, second -> 18-26. Gap of 6 -> no merge
        result = build_file_regions(diff_file, file_length=100, expansion=3)
        assert len(result) == 2
        assert result[0].start_line == 2
        assert result[0].end_line == 11
        assert result[1].start_line == 18
        assert result[1].end_line == 26
