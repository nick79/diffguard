"""Core analysis pipeline: filtering, context building, and LLM orchestration."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from diffguard.ast import (
    Language,
    detect_language,
    extract_imports,
    extract_scope_context,
    find_enclosing_scope,
    find_used_symbols,
    is_first_party,
    parse_file,
    resolve_symbol_definition,
)
from diffguard.context import Region, build_file_regions, read_file_lines
from diffguard.exceptions import ContextError, UnsupportedLanguageError
from diffguard.exclusions import filter_sensitive_files
from diffguard.llm import (
    AnalysisResult,
    CodeContext,
    DiffLine,
    FileAnalysisError,
    LLMClient,
    ScopeContext,
    SymbolDef,
    analyze_files,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from tree_sitter import Tree

    from diffguard.config import DiffguardConfig
    from diffguard.git import DiffFile

logger = logging.getLogger(__name__)

__all__ = [
    "FileContext",
    "analyze_staged_changes",
]


@dataclass
class FileContext:
    """Intermediate representation combining all gathered data for a file."""

    file_path: str
    language: Language
    source_lines: list[str]
    regions: list[Region]
    diff_lines: list[DiffLine]
    scopes: list[ScopeContext] = field(default_factory=list)
    symbols: dict[str, SymbolDef] = field(default_factory=dict)
    is_new_file: bool = False


async def analyze_staged_changes(
    diff_files: list[DiffFile],
    config: DiffguardConfig,
    client: LLMClient,
    *,
    project_root: Path | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> AnalysisResult:
    """Run the full analysis pipeline on staged diff files.

    Filters files, builds rich code context, then delegates to the LLM analyzer.

    Args:
        diff_files: Parsed diff files from git.
        config: Diffguard configuration.
        client: LLM client for API calls.
        project_root: Project root directory for file resolution. Defaults to cwd.
        on_progress: Optional callback called with (completed, total) after each file.

    Returns:
        AnalysisResult with findings and any errors.
    """
    root = project_root or Path.cwd()
    analyzable = _filter_analyzable_files(diff_files, config)

    if not analyzable:
        return AnalysisResult()

    file_contexts: list[FileContext] = []
    build_errors: list[FileAnalysisError] = []

    for diff_file, language in analyzable:
        try:
            file_ctx = _build_file_context(diff_file, language, config, root)
            file_contexts.append(file_ctx)
        except (ContextError, OSError) as exc:
            logger.error("Error building context for '%s': %s", diff_file.path, exc)
            build_errors.append(
                FileAnalysisError(
                    file_path=diff_file.path,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
            )

    code_contexts = [_file_context_to_code_context(fc) for fc in file_contexts]

    result = await analyze_files(
        code_contexts,
        client,
        max_concurrent=config.max_concurrent_api_calls,
        timeout_per_file=float(config.timeout),
        on_progress=on_progress,
    )

    result.errors.extend(build_errors)
    return result


def _filter_analyzable_files(
    diff_files: list[DiffFile],
    config: DiffguardConfig,
) -> list[tuple[DiffFile, Language]]:
    """Filter diff files to only those that can be analyzed.

    Order (cheapest first):
    1. Skip binary files
    2. Skip deleted files
    3. Skip non-source files (language detection fails)
    4. Skip sensitive files (.env, keys, etc.)
    """
    result: list[tuple[DiffFile, Language]] = []
    non_binary_non_deleted: list[DiffFile] = []

    for df in diff_files:
        if df.is_binary:
            logger.debug("Skipping binary file: %s", df.path)
            continue
        if df.is_deleted:
            logger.debug("Skipping deleted file: %s", df.path)
            continue
        non_binary_non_deleted.append(df)

    # Detect language before sensitive filtering (cheap check)
    with_language: list[tuple[DiffFile, Language]] = []
    for df in non_binary_non_deleted:
        lang = detect_language(df.path)
        if lang is None:
            logger.debug("Skipping non-source file: %s", df.path)
            continue
        with_language.append((df, lang))

    # Filter sensitive files
    remaining_files = [df for df, _ in with_language]
    filter_result = filter_sensitive_files(remaining_files, config)
    kept_paths = {df.path for df in filter_result.kept}

    for df, lang in with_language:
        if df.path in kept_paths:
            result.append((df, lang))
        else:
            logger.debug("Skipping sensitive file: %s", df.path)

    return result


def _build_file_context(
    diff_file: DiffFile,
    language: Language,
    config: DiffguardConfig,
    project_root: Path,
) -> FileContext:
    """Build complete file context for a single diff file.

    Raises:
        ContextError: If the file cannot be read.
        OSError: If filesystem operations fail.
    """
    file_path = project_root / diff_file.path
    source_lines = read_file_lines(file_path)
    regions = build_file_regions(diff_file, len(source_lines), config.hunk_expansion_lines)
    diff_lines = _build_diff_lines(diff_file)

    # Parse AST — catch UnsupportedLanguageError so file continues without AST
    tree: Tree | None = None
    try:
        source_text = "\n".join(source_lines)
        tree = parse_file(source_text, language)
    except UnsupportedLanguageError:
        logger.debug("No grammar for %s, skipping AST analysis: %s", language.name, diff_file.path)

    scopes: list[ScopeContext] = []
    symbols: dict[str, SymbolDef] = {}

    if tree is not None:
        scopes = _build_scopes(tree, diff_lines, language, source_lines, config.scope_size_limit, diff_file.is_new_file)
        symbols = _build_symbols(tree, regions, language, source_lines, project_root, file_path, config)

    return FileContext(
        file_path=diff_file.path,
        language=language,
        source_lines=source_lines,
        regions=regions,
        diff_lines=diff_lines,
        scopes=scopes,
        symbols=symbols,
        is_new_file=diff_file.is_new_file,
    )


def _build_diff_lines(diff_file: DiffFile) -> list[DiffLine]:
    """Build DiffLine list from hunk lines, tracking new-file line numbers.

    '+' and ' ' (context) lines advance the new-file line counter.
    '-' lines do not advance the counter (they only exist in the old file).
    """
    result: list[DiffLine] = []
    for hunk in diff_file.hunks:
        line_num = hunk.new_start
        for marker, content in hunk.lines:
            match marker:
                case "+":
                    result.append(DiffLine(line_num=line_num, change_type="+", content=content))
                    line_num += 1
                case "-":
                    result.append(DiffLine(line_num=line_num, change_type="-", content=content))
                case " ":
                    result.append(DiffLine(line_num=line_num, change_type=" ", content=content))
                    line_num += 1
    return result


def _build_scopes(
    tree: Tree,
    diff_lines: list[DiffLine],
    language: Language,
    source_lines: list[str],
    scope_limit: int,
    is_new_file: bool,
) -> list[ScopeContext]:
    """Find enclosing scopes for changed lines, deduplicated."""
    changed_lines = [dl.line_num for dl in diff_lines if dl.change_type in ("+", "-")]
    seen: set[tuple[str, str, int, int]] = set()
    scopes: list[ScopeContext] = []

    for line in changed_lines:
        scope = find_enclosing_scope(tree, line, language)
        if scope is None:
            continue
        key = (scope.type, scope.name, scope.start_line, scope.end_line)
        if key in seen:
            continue
        seen.add(key)
        source = extract_scope_context(scope, source_lines, scope_limit, is_new_file=is_new_file)
        scopes.append(
            ScopeContext(
                type=scope.type,
                name=scope.name,
                start_line=scope.start_line,
                end_line=scope.end_line,
                source=source,
            )
        )

    return scopes


def _build_symbols(
    tree: Tree,
    regions: list[Region],
    language: Language,
    _source_lines: list[str],
    project_root: Path,
    current_file: Path,
    config: DiffguardConfig,
) -> dict[str, SymbolDef]:
    """Find used symbols in regions and resolve first-party definitions."""
    if language != Language.PYTHON:
        return {}

    all_symbols: set[str] = set()
    for region in regions:
        all_symbols |= find_used_symbols(tree, region.start_line, region.end_line, exclude_builtins=True)

    if not all_symbols:
        return {}

    imports = extract_imports(tree)
    result: dict[str, SymbolDef] = {}

    for symbol in sorted(all_symbols):
        try:
            resolved_path = resolve_symbol_definition(symbol, imports, project_root, current_file)
            if resolved_path is None:
                continue
            if not is_first_party(str(resolved_path), project_root, config.third_party_patterns):
                continue

            resolved_lines = read_file_lines(resolved_path)
            resolved_source = "\n".join(resolved_lines)
            resolved_tree = parse_file(resolved_source, language)
            if resolved_tree is None:
                continue

            code = _extract_symbol_code(symbol, resolved_tree, resolved_lines, config.scope_size_limit)
            if code is None:
                continue

            relative_path = str(resolved_path.relative_to(project_root))
            result[symbol] = SymbolDef(name=symbol, code=code, file=relative_path)
        except (ContextError, UnsupportedLanguageError, OSError, ValueError):
            logger.debug("Could not resolve symbol '%s': skipping", symbol)

    return result


def _extract_symbol_code(
    symbol: str,
    tree: Tree,
    source_lines: list[str],
    limit: int,
) -> str | None:
    """Walk top-level AST definitions for a matching name, extract source."""
    for child in tree.root_node.children:
        node = child
        # Handle decorated definitions
        if child.type == "decorated_definition":
            for inner in child.children:
                if inner.type in ("function_definition", "class_definition"):
                    node = inner
                    break
            else:
                continue

        if node.type not in ("function_definition", "class_definition"):
            continue

        name_node = node.child_by_field_name("name")
        if name_node is None or name_node.text is None:
            continue
        if str(name_node.text, "utf-8") != symbol:
            continue

        from diffguard.ast.scope import Scope  # noqa: PLC0415

        # Use the decorated definition's range if present
        start_row = int(child.start_point.row)
        end_row = int(node.end_point.row)
        scope = Scope(type=node.type, name=symbol, start_line=start_row + 1, end_line=end_row + 1)
        return extract_scope_context(scope, source_lines, limit)

    return None


def _file_context_to_code_context(file_ctx: FileContext) -> CodeContext:
    """Convert a FileContext to a CodeContext for the LLM prompt."""
    if not file_ctx.regions:
        return CodeContext(
            file_path=file_ctx.file_path,
            diff_lines=file_ctx.diff_lines,
            expanded_region="",
            region_start_line=1,
            scopes=file_ctx.scopes,
            symbols=file_ctx.symbols,
        )

    region_start = min(r.start_line for r in file_ctx.regions)
    region_end = max(r.end_line for r in file_ctx.regions)

    start_idx = max(0, region_start - 1)
    end_idx = min(len(file_ctx.source_lines), region_end)
    expanded_region = "\n".join(file_ctx.source_lines[start_idx:end_idx])

    return CodeContext(
        file_path=file_ctx.file_path,
        diff_lines=file_ctx.diff_lines,
        expanded_region=expanded_region,
        region_start_line=region_start,
        scopes=file_ctx.scopes,
        symbols=file_ctx.symbols,
    )
