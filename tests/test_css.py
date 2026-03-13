"""Tests for CSS & preprocessor file analysis support."""

from __future__ import annotations

import pytest

from diffguard.ast import Language, detect_language, get_parser
from diffguard.exceptions import UnsupportedLanguageError
from diffguard.pipeline import _SYMBOL_NODE_CONFIGS

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


class TestCssLanguageDetection:
    """Test detect_language() for CSS and preprocessor extensions."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("static/style.css", Language.CSS),
            ("src/styles/main.scss", Language.CSS),
            ("styles/theme.sass", Language.CSS),
            ("assets/variables.less", Language.CSS),
        ],
    )
    def test_css_extensions_detected(self, path: str, expected: Language) -> None:
        """All CSS/preprocessor extensions resolve to Language.CSS."""
        assert detect_language(path) == expected

    def test_case_insensitive_css(self) -> None:
        """CSS extension matching is case-insensitive."""
        assert detect_language("style.CSS") == Language.CSS
        assert detect_language("style.Scss") == Language.CSS
        assert detect_language("style.SASS") == Language.CSS
        assert detect_language("style.Less") == Language.CSS


# ---------------------------------------------------------------------------
# Pipeline pass-through (no AST enrichment)
# ---------------------------------------------------------------------------


class TestCssPipelinePassThrough:
    """Verify CSS files skip AST enrichment gracefully."""

    def test_css_not_in_symbol_node_configs(self) -> None:
        """CSS is not in the pipeline's symbol node config (no AST extraction)."""
        assert Language.CSS not in _SYMBOL_NODE_CONFIGS

    def test_css_parser_raises_unsupported(self) -> None:
        """Requesting a parser for CSS raises UnsupportedLanguageError."""
        with pytest.raises(UnsupportedLanguageError, match="css"):
            get_parser(Language.CSS)
