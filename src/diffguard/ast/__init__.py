"""AST parsing and language detection for diffguard."""

from diffguard.ast.languages import Language, detect_language
from diffguard.ast.parser import get_parser, parse_file

__all__ = ["Language", "detect_language", "get_parser", "parse_file"]
