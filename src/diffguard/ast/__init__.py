"""AST parsing and language detection for diffguard."""

from diffguard.ast.languages import Language, detect_language
from diffguard.ast.parser import clear_parser_cache, get_parser, parse_file
from diffguard.ast.python import Import, extract_imports, find_used_symbols, is_first_party, resolve_symbol_definition
from diffguard.ast.scope import Scope, extract_scope_context, find_enclosing_scope

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
