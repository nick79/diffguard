"""AST parsing and language detection for diffguard."""

from diffguard.ast.languages import Language, detect_language
from diffguard.ast.parser import get_parser, parse_file
from diffguard.ast.scope import Scope, extract_scope_context, find_enclosing_scope

__all__ = [
    "Language",
    "Scope",
    "detect_language",
    "extract_scope_context",
    "find_enclosing_scope",
    "get_parser",
    "parse_file",
]
