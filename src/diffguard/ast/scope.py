"""Scope detection and context extraction for changed code."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from diffguard.ast.languages import Language

if TYPE_CHECKING:
    from tree_sitter import Tree


@dataclass
class Scope:
    """An enclosing code scope (function, class, method).

    Line numbers are 1-indexed and inclusive.
    """

    type: str
    name: str
    start_line: int
    end_line: int


def find_enclosing_scope(tree: Tree, line: int, language: Language) -> Scope | None:
    """Find the innermost scope containing a 1-indexed line number.

    Args:
        tree: Parsed tree-sitter AST.
        line: 1-indexed line number to find scope for.
        language: Programming language of the source.

    Returns:
        The innermost Scope containing the line, or None if at module level.
    """
    if line < 1:
        return None

    match language:
        case Language.PYTHON:
            from diffguard.ast.python import find_python_scope  # noqa: PLC0415

            return find_python_scope(tree, line)
        case _:
            return None


def extract_scope_context(
    scope: Scope,
    source_lines: list[str],
    limit: int = 200,
    *,
    is_new_file: bool = False,
) -> str:
    """Extract the source code for a scope, truncating if over the line limit.

    Args:
        scope: The scope to extract.
        source_lines: All lines of the source file (0-indexed list).
        limit: Maximum lines to include before truncation.
        is_new_file: If True, skip truncation entirely.

    Returns:
        The scope's source code as a string, with truncation marker appended if needed.
    """
    start_idx = max(0, scope.start_line - 1)
    end_idx = min(len(source_lines), scope.end_line)
    scope_lines = source_lines[start_idx:end_idx]
    total = len(scope_lines)

    if is_new_file or total <= limit:
        return "\n".join(scope_lines)

    truncated_count = total - limit
    kept = scope_lines[:limit]
    return "\n".join(kept) + f"\n... [truncated {truncated_count} lines]"
