"""Hunk expansion and region merging for building LLM context."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from diffguard.exceptions import ContextError

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from pathlib import Path

    from diffguard.git import DiffFile, DiffHunk


@dataclass
class Region:
    """A contiguous range of lines in a source file (1-indexed, inclusive)."""

    start_line: int
    end_line: int


def expand_hunk(hunk: DiffHunk, expansion: int, file_length: int | None = None) -> Region:
    """Expand a diff hunk by N surrounding lines into a Region.

    Uses new-file side line numbers (since we read the current file version).

    Args:
        hunk: The diff hunk to expand.
        expansion: Number of lines to add above and below.
        file_length: Total lines in the file. Used to clamp the end.

    Returns:
        A Region covering the expanded hunk range.
    """
    hunk_start = hunk.new_start
    hunk_end = hunk.new_start + max(hunk.new_count, 1) - 1

    start = hunk_start - expansion
    end = hunk_end + expansion

    start = max(1, start)
    if file_length is not None:
        end = min(file_length, end)

    return Region(start_line=start, end_line=end)


def merge_regions(regions: list[Region]) -> list[Region]:
    """Merge overlapping or adjacent regions into non-overlapping regions.

    Adjacent regions (gap of 0) are merged. Regions with a gap of 1+ are kept separate.

    Args:
        regions: List of regions to merge (not mutated).

    Returns:
        New list of merged Region objects, sorted by start_line.
    """
    if len(regions) <= 1:
        return [Region(start_line=r.start_line, end_line=r.end_line) for r in regions]

    sorted_regions = sorted(regions, key=lambda r: r.start_line)
    merged: list[Region] = [Region(start_line=sorted_regions[0].start_line, end_line=sorted_regions[0].end_line)]

    for region in sorted_regions[1:]:
        current = merged[-1]
        if region.start_line <= current.end_line + 1:
            current.end_line = max(current.end_line, region.end_line)
        else:
            merged.append(Region(start_line=region.start_line, end_line=region.end_line))

    return merged


def read_file_lines(path: Path) -> list[str]:
    """Read a file and return its lines.

    Args:
        path: Path to the file to read.

    Returns:
        List of lines (without line terminators).

    Raises:
        FileNotFoundError: If the file does not exist.
        ContextError: If the file appears to be binary.
    """
    if not path.is_file():
        msg = f"File not found: {path}"
        raise FileNotFoundError(msg)

    content = path.read_bytes()

    if b"\x00" in content[:8192]:
        msg = f"Binary file cannot be read as text: {path}"
        raise ContextError(msg)

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        logger.warning("File contains malformed UTF-8, lossy decoding applied: %s", path)
        text = content.decode("utf-8", errors="replace")
    return text.splitlines()


def build_file_regions(diff_file: DiffFile, file_length: int, expansion: int) -> list[Region]:
    """Build expanded and merged regions for a single diff file.

    Args:
        diff_file: The parsed diff file.
        file_length: Total number of lines in the current file.
        expansion: Number of context lines to add around each hunk.

    Returns:
        List of merged Region objects covering the relevant code.
    """
    if diff_file.is_new_file:
        return [Region(start_line=1, end_line=file_length)]

    if diff_file.is_deleted or diff_file.is_binary or not diff_file.hunks:
        return []

    expanded = [expand_hunk(hunk, expansion, file_length) for hunk in diff_file.hunks]
    return merge_regions(expanded)
