"""Tests for tree-sitter integration: language detection, parser caching, and file parsing."""

import logging

import pytest

from diffguard.ast import Language, detect_language, get_parser, parse_file
from diffguard.ast.parser import _parser_cache
from diffguard.exceptions import UnsupportedLanguageError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_PYTHON = """\
def greet(name: str) -> str:
    return f"Hello, {name}!"

class Calculator:
    def add(self, a: int, b: int) -> int:
        return a + b
"""

SYNTAX_ERROR_PYTHON = """\
def broken(x:
    return x
"""

EMPTY_SOURCE = ""

COMMENTS_ONLY_PYTHON = """\
# This is a comment
# Another comment

# Yet another comment
"""

UNICODE_PYTHON = """\
def grüße(名前: str) -> str:
    return f"こんにちは、{名前}!"
"""


# ---------------------------------------------------------------------------
# TestParseFile — AC1, AC2, AC3, AC4, AC5, AC15, AC16
# ---------------------------------------------------------------------------


class TestParseFile:
    """Test parse_file() for valid, malformed, empty, and edge-case sources."""

    def test_valid_python_produces_module_root(self) -> None:
        """AC1: Valid Python source produces a tree with root node type 'module'."""
        tree = parse_file(VALID_PYTHON, Language.PYTHON)
        assert tree is not None
        assert tree.root_node.type == "module"

    def test_valid_python_has_children(self) -> None:
        """AC1: Valid Python tree contains function and class definitions."""
        tree = parse_file(VALID_PYTHON, Language.PYTHON)
        assert tree is not None
        child_types = [child.type for child in tree.root_node.named_children]
        assert "function_definition" in child_types
        assert "class_definition" in child_types

    def test_syntax_error_returns_tree_with_errors(self) -> None:
        """AC2: Source with syntax errors returns a tree (not None) containing ERROR nodes."""
        tree = parse_file(SYNTAX_ERROR_PYTHON, Language.PYTHON)
        assert tree is not None
        assert tree.root_node.has_error

    def test_syntax_error_preserves_recoverable_structure(self) -> None:
        """AC2: Partial parse preserves recoverable structure alongside errors."""
        tree = parse_file(SYNTAX_ERROR_PYTHON, Language.PYTHON)
        assert tree is not None
        # The parser should recover at least some named children that aren't ERROR
        named_types = [child.type for child in tree.root_node.named_children]
        non_error = [t for t in named_types if t != "ERROR"]
        assert len(non_error) > 0

    def test_severely_malformed_returns_none(self) -> None:
        """AC3: Severely malformed input (no recoverable structure) returns None."""
        garbage = "}{}{][][))))(((({{{{}}}}>>><<<\x00\x01\x02\x03"
        tree = parse_file(garbage, Language.PYTHON)
        assert tree is None

    def test_severely_malformed_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """AC3: Severely malformed input logs a warning."""
        garbage = "}{}{][][))))(((({{{{}}}}>>><<<\x00\x01\x02\x03"
        with caplog.at_level(logging.WARNING, logger="diffguard.ast.parser"):
            parse_file(garbage, Language.PYTHON)
        assert any("malformed" in record.message.lower() for record in caplog.records)

    def test_empty_source_returns_valid_tree(self) -> None:
        """AC4: Empty string produces a valid tree (not None)."""
        tree = parse_file(EMPTY_SOURCE, Language.PYTHON)
        assert tree is not None
        assert tree.root_node.type == "module"

    def test_comments_only_returns_valid_tree(self) -> None:
        """AC5: Source with only comments produces a valid tree."""
        tree = parse_file(COMMENTS_ONLY_PYTHON, Language.PYTHON)
        assert tree is not None
        assert tree.root_node.type == "module"

    def test_preserves_node_positions(self) -> None:
        """AC15: Parsed tree preserves byte offsets and line/column positions."""
        source = "def foo():\n    pass\n"
        tree = parse_file(source, Language.PYTHON)
        assert tree is not None
        func = tree.root_node.named_children[0]
        assert func.type == "function_definition"
        assert func.start_point.row == 0
        assert func.start_point.column == 0
        assert func.end_point.row == 1
        assert func.start_byte == 0
        assert func.end_byte == len(source.encode("utf-8")) - 1  # excludes trailing newline

    def test_unicode_source(self) -> None:
        """AC16: Unicode identifiers and string content are parsed correctly."""
        tree = parse_file(UNICODE_PYTHON, Language.PYTHON)
        assert tree is not None
        assert tree.root_node.type == "module"
        # The function definition should be parsed
        child_types = [child.type for child in tree.root_node.named_children]
        assert "function_definition" in child_types


# ---------------------------------------------------------------------------
# TestDetectLanguage — AC6, AC7, AC8, AC9, AC10, AC11, AC12
# ---------------------------------------------------------------------------


class TestDetectLanguage:
    """Test detect_language() extension mapping and edge cases."""

    def test_python_extension(self) -> None:
        """AC6: .py extension maps to Language.PYTHON."""
        assert detect_language("src/main.py") == Language.PYTHON

    def test_pyi_extension(self) -> None:
        """AC7: .pyi extension maps to Language.PYTHON."""
        assert detect_language("stubs/types.pyi") == Language.PYTHON

    def test_case_insensitive(self) -> None:
        """AC8: Extension matching is case-insensitive."""
        assert detect_language("script.PY") == Language.PYTHON
        assert detect_language("module.Py") == Language.PYTHON
        assert detect_language("lib.pY") == Language.PYTHON

    def test_unknown_extension_returns_none(self) -> None:
        """AC9: Unknown extension returns None."""
        assert detect_language("data.csv") is None
        assert detect_language("image.png") is None

    def test_no_extension_returns_none(self) -> None:
        """AC10: File with no extension returns None."""
        assert detect_language("Makefile") is None
        assert detect_language("Dockerfile") is None

    def test_hidden_file_with_extension(self) -> None:
        """AC11: Hidden file with known extension is detected."""
        assert detect_language(".hidden.py") == Language.PYTHON

    def test_double_extension(self) -> None:
        """AC12: Double extension uses the last suffix."""
        assert detect_language("file.test.py") == Language.PYTHON
        assert detect_language("file.py.bak") is None

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("app.js", Language.JAVASCRIPT),
            ("app.mjs", Language.JAVASCRIPT),
            ("app.cjs", Language.JAVASCRIPT),
            ("component.jsx", Language.JAVASCRIPT),
            ("app.ts", Language.TYPESCRIPT),
            ("app.mts", Language.TYPESCRIPT),
            ("app.cts", Language.TYPESCRIPT),
            ("component.tsx", Language.TYPESCRIPT),
            ("Main.java", Language.JAVA),
            ("script.rb", Language.RUBY),
            ("main.go", Language.GO),
            ("index.php", Language.PHP),
        ],
    )
    def test_all_supported_extensions(self, path: str, expected: Language) -> None:
        """All mapped extensions resolve to the correct language."""
        assert detect_language(path) == expected


# ---------------------------------------------------------------------------
# TestGetParser — AC13, AC14
# ---------------------------------------------------------------------------


class TestGetParser:
    """Test get_parser() caching and unsupported language errors."""

    def setup_method(self) -> None:
        """Clear parser cache between tests."""
        _parser_cache.clear()

    def test_returns_parser_for_python(self) -> None:
        """get_parser returns a working Parser for Python."""
        parser = get_parser(Language.PYTHON)
        tree = parser.parse(b"x = 1")
        assert tree is not None
        assert tree.root_node.type == "module"

    def test_cached_same_instance(self) -> None:
        """AC13: Repeated calls return the same Parser instance."""
        parser1 = get_parser(Language.PYTHON)
        parser2 = get_parser(Language.PYTHON)
        assert parser1 is parser2

    def test_unsupported_language_raises(self) -> None:
        """AC14: Requesting a parser for an uninstalled grammar raises UnsupportedLanguageError."""
        with pytest.raises(UnsupportedLanguageError, match="javascript"):
            get_parser(Language.JAVASCRIPT)
