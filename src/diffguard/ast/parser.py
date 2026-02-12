"""Tree-sitter parser creation, caching, and source file parsing."""

import logging

from tree_sitter import Language as TSLanguage
from tree_sitter import Parser, Tree

from diffguard.ast.languages import Language
from diffguard.exceptions import UnsupportedLanguageError

logger = logging.getLogger(__name__)

_parser_cache: dict[Language, Parser] = {}


def _load_language(language: Language) -> TSLanguage:
    """Load the tree-sitter grammar for a language.

    Raises UnsupportedLanguageError if no grammar is installed.
    """
    match language:
        case Language.PYTHON:
            import tree_sitter_python  # noqa: PLC0415

            return TSLanguage(tree_sitter_python.language())
        case _:
            raise UnsupportedLanguageError(f"No tree-sitter grammar installed for {language.value}")


def clear_parser_cache() -> None:
    """Clear the cached tree-sitter parsers (useful for testing)."""
    _parser_cache.clear()


def get_parser(language: Language) -> Parser:
    """Return a cached tree-sitter Parser for the given language.

    Creates and caches the parser on first call; returns the same
    instance on subsequent calls for the same language.

    Raises UnsupportedLanguageError if no grammar is available.
    """
    if language in _parser_cache:
        return _parser_cache[language]

    ts_language = _load_language(language)
    parser = Parser()
    parser.language = ts_language
    _parser_cache[language] = parser
    return parser


def _is_severely_malformed(tree: Tree) -> bool:
    """Check whether a parse tree represents severely malformed input.

    Returns True only when the root has errors AND every named child
    of the root is an ERROR node — meaning the parser could not recover
    any meaningful structure at all.
    """
    if not tree.root_node.has_error:
        return False

    named_children = tree.root_node.named_children
    if not named_children:
        return True

    return all(child.type == "ERROR" for child in named_children)


def parse_file(source: str, language: Language) -> Tree | None:
    """Parse source code into a tree-sitter Tree.

    Returns None (with a warning log) when the source is severely
    malformed and no meaningful AST structure could be recovered.
    Partial parse errors (e.g. a single syntax mistake) still return
    a Tree with ERROR nodes embedded in an otherwise valid structure.
    """
    parser = get_parser(language)
    tree = parser.parse(bytes(source, "utf-8"))

    if tree is None:
        return None

    if _is_severely_malformed(tree):
        logger.warning("Severely malformed source; no usable AST produced for %s content", language.value)
        return None

    return tree
