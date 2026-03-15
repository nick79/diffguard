"""AST parsing and language detection for diffguard."""

from __future__ import annotations

from typing import TYPE_CHECKING

from diffguard.ast.languages import Language, detect_language
from diffguard.ast.parser import clear_parser_cache, get_parser, parse_file
from diffguard.ast.python import Import
from diffguard.ast.scope import Scope, extract_scope_context, find_enclosing_scope

if TYPE_CHECKING:
    from pathlib import Path

    from tree_sitter import Tree

__all__ = [
    "Import",
    "Language",
    "Scope",
    "clear_parser_cache",
    "detect_language",
    "extract_imports",
    "extract_scope_context",
    "find_enclosing_scope",
    "find_used_symbols",
    "get_parser",
    "is_first_party",
    "parse_file",
    "resolve_symbol_definition",
]


def extract_imports(tree: Tree, language: Language) -> list[Import]:  # noqa: PLR0911
    """Extract import statements from a parsed AST.

    Dispatches to the language-specific implementation. Returns an empty
    list for languages without import extraction support.
    """
    match language:
        case Language.PYTHON:
            from diffguard.ast.python import extract_python_imports  # noqa: PLC0415

            return extract_python_imports(tree)
        case Language.JAVASCRIPT:
            from diffguard.ast.javascript import extract_javascript_imports  # noqa: PLC0415

            return extract_javascript_imports(tree)
        case Language.TYPESCRIPT:
            from diffguard.ast.typescript import extract_typescript_imports  # noqa: PLC0415

            return extract_typescript_imports(tree)
        case Language.JAVA:
            from diffguard.ast.java import extract_java_imports  # noqa: PLC0415

            return extract_java_imports(tree)
        case Language.RUBY:
            from diffguard.ast.ruby import extract_ruby_imports  # noqa: PLC0415

            return extract_ruby_imports(tree)
        case Language.GO:
            from diffguard.ast.go import extract_go_imports  # noqa: PLC0415

            return extract_go_imports(tree)
        case Language.PHP:
            from diffguard.ast.php import extract_php_imports  # noqa: PLC0415

            return extract_php_imports(tree)
        case Language.ELIXIR:
            from diffguard.ast.elixir import extract_elixir_imports  # noqa: PLC0415

            return extract_elixir_imports(tree)
        case _:
            return []


def find_used_symbols(  # noqa: PLR0911
    tree: Tree,
    start_line: int,
    end_line: int,
    language: Language,
    *,
    exclude_builtins: bool = False,
) -> set[str]:
    """Find externally-referenced symbols in a line range (1-indexed, inclusive).

    Dispatches to the language-specific implementation. Returns an empty
    set for languages without symbol detection support.
    """
    match language:
        case Language.PYTHON:
            from diffguard.ast.python import find_python_used_symbols  # noqa: PLC0415

            return find_python_used_symbols(tree, start_line, end_line, exclude_builtins=exclude_builtins)
        case Language.JAVASCRIPT:
            from diffguard.ast.javascript import find_javascript_used_symbols  # noqa: PLC0415

            return find_javascript_used_symbols(tree, start_line, end_line, exclude_builtins=exclude_builtins)
        case Language.TYPESCRIPT:
            from diffguard.ast.typescript import find_typescript_used_symbols  # noqa: PLC0415

            return find_typescript_used_symbols(tree, start_line, end_line, exclude_builtins=exclude_builtins)
        case Language.JAVA:
            from diffguard.ast.java import find_java_used_symbols  # noqa: PLC0415

            return find_java_used_symbols(tree, start_line, end_line, exclude_builtins=exclude_builtins)
        case Language.RUBY:
            from diffguard.ast.ruby import find_ruby_used_symbols  # noqa: PLC0415

            return find_ruby_used_symbols(tree, start_line, end_line, exclude_builtins=exclude_builtins)
        case Language.GO:
            from diffguard.ast.go import find_go_used_symbols  # noqa: PLC0415

            return find_go_used_symbols(tree, start_line, end_line, exclude_builtins=exclude_builtins)
        case Language.PHP:
            from diffguard.ast.php import find_php_used_symbols  # noqa: PLC0415

            return find_php_used_symbols(tree, start_line, end_line, exclude_builtins=exclude_builtins)
        case Language.ELIXIR:
            from diffguard.ast.elixir import find_elixir_used_symbols  # noqa: PLC0415

            return find_elixir_used_symbols(tree, start_line, end_line, exclude_builtins=exclude_builtins)
        case _:
            return set()


def is_first_party(  # noqa: PLR0911
    module_or_path: str,
    project_root: Path,
    third_party_patterns: list[str] | None,
    language: Language,
    *,
    is_relative: bool = False,
) -> bool:
    """Determine whether an import is first-party project code.

    Dispatches to the language-specific implementation. Returns False
    for languages without first-party detection support.
    """
    match language:
        case Language.PYTHON:
            from diffguard.ast.python import is_python_first_party  # noqa: PLC0415

            return is_python_first_party(module_or_path, project_root, third_party_patterns, is_relative=is_relative)
        case Language.JAVASCRIPT:
            from diffguard.ast.javascript import is_first_party_js  # noqa: PLC0415

            return is_first_party_js(module_or_path, project_root, third_party_patterns, is_relative=is_relative)
        case Language.TYPESCRIPT:
            from diffguard.ast.typescript import is_first_party_ts  # noqa: PLC0415

            return is_first_party_ts(module_or_path, project_root, third_party_patterns, is_relative=is_relative)
        case Language.JAVA:
            from diffguard.ast.java import is_first_party_java  # noqa: PLC0415

            return is_first_party_java(module_or_path, project_root, third_party_patterns, is_relative=is_relative)
        case Language.RUBY:
            from diffguard.ast.ruby import is_first_party_ruby  # noqa: PLC0415

            return is_first_party_ruby(module_or_path, project_root, third_party_patterns, is_relative=is_relative)
        case Language.GO:
            from diffguard.ast.go import is_first_party_go  # noqa: PLC0415

            return is_first_party_go(module_or_path, project_root, third_party_patterns, is_relative=is_relative)
        case Language.PHP:
            from diffguard.ast.php import is_first_party_php  # noqa: PLC0415

            return is_first_party_php(module_or_path, project_root, third_party_patterns, is_relative=is_relative)
        case Language.ELIXIR:
            from diffguard.ast.elixir import is_first_party_elixir  # noqa: PLC0415

            return is_first_party_elixir(module_or_path, project_root, third_party_patterns, is_relative=is_relative)
        case _:
            return False


def resolve_symbol_definition(  # noqa: PLR0911
    symbol: str,
    imports: list[Import],
    project_root: Path,
    current_file: Path | None,
    language: Language,
) -> Path | None:
    """Resolve an imported symbol name to a file path in the project.

    Dispatches to the language-specific implementation. Returns None
    for languages without symbol resolution support.
    """
    match language:
        case Language.PYTHON:
            from diffguard.ast.python import resolve_python_symbol_definition  # noqa: PLC0415

            return resolve_python_symbol_definition(symbol, imports, project_root, current_file)
        case Language.JAVASCRIPT:
            from diffguard.ast.javascript import resolve_javascript_symbol  # noqa: PLC0415

            return resolve_javascript_symbol(symbol, imports, project_root, current_file)
        case Language.TYPESCRIPT:
            from diffguard.ast.typescript import resolve_typescript_symbol  # noqa: PLC0415

            return resolve_typescript_symbol(symbol, imports, project_root, current_file)
        case Language.JAVA:
            from diffguard.ast.java import resolve_java_symbol  # noqa: PLC0415

            return resolve_java_symbol(symbol, imports, project_root, current_file)
        case Language.RUBY:
            from diffguard.ast.ruby import resolve_ruby_symbol  # noqa: PLC0415

            return resolve_ruby_symbol(symbol, imports, project_root, current_file)
        case Language.GO:
            from diffguard.ast.go import resolve_go_symbol  # noqa: PLC0415

            return resolve_go_symbol(symbol, imports, project_root, current_file)
        case Language.PHP:
            from diffguard.ast.php import resolve_php_symbol  # noqa: PLC0415

            return resolve_php_symbol(symbol, imports, project_root, current_file)
        case Language.ELIXIR:
            from diffguard.ast.elixir import resolve_elixir_symbol  # noqa: PLC0415

            return resolve_elixir_symbol(symbol, imports, project_root, current_file)
        case _:
            return None
