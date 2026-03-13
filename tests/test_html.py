"""Tests for HTML & template file analysis support."""

from __future__ import annotations

import pytest

from diffguard.ast import Language, detect_language, get_parser
from diffguard.exceptions import UnsupportedLanguageError
from diffguard.exclusions import is_generated_file
from diffguard.pipeline import _SYMBOL_NODE_CONFIGS

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


class TestHtmlLanguageDetection:
    """Test detect_language() for HTML and template extensions."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("templates/index.html", Language.HTML),
            ("public/page.htm", Language.HTML),
            ("views/partial.ejs", Language.HTML),
            ("views/layout.hbs", Language.HTML),
            ("templates/page.handlebars", Language.HTML),
            ("views/base.njk", Language.HTML),
            ("templates/page.nunjucks", Language.HTML),
            ("views/layout.pug", Language.HTML),
            ("app/views/show.erb", Language.HTML),
            ("templates/base.jinja", Language.HTML),
            ("templates/base.jinja2", Language.HTML),
            ("partials/card.mustache", Language.HTML),
        ],
    )
    def test_template_extensions_detected(self, path: str, expected: Language) -> None:
        """All HTML/template extensions resolve to Language.HTML."""
        assert detect_language(path) == expected

    def test_case_insensitive_html(self) -> None:
        """HTML extension matching is case-insensitive."""
        assert detect_language("page.HTML") == Language.HTML
        assert detect_language("page.Html") == Language.HTML
        assert detect_language("page.HTM") == Language.HTML

    def test_blade_php_detected_as_html(self) -> None:
        """Blade templates (.blade.php) are detected as HTML, not PHP."""
        assert detect_language("resources/views/welcome.blade.php") == Language.HTML

    def test_blade_php_case_insensitive(self) -> None:
        """Blade compound extension is case-insensitive."""
        assert detect_language("views/page.BLADE.PHP") == Language.HTML
        assert detect_language("views/page.Blade.Php") == Language.HTML

    def test_regular_php_still_detected(self) -> None:
        """Regular .php files are still detected as PHP."""
        assert detect_language("app/Http/Controllers/UserController.php") == Language.PHP
        assert detect_language("index.php") == Language.PHP

    def test_nested_blade_path(self) -> None:
        """Blade template in nested directory."""
        assert detect_language("resources/views/admin/dashboard.blade.php") == Language.HTML


# ---------------------------------------------------------------------------
# Generated file detection (minified HTML)
# ---------------------------------------------------------------------------


class TestHtmlGeneratedFileDetection:
    """Test is_generated_file() for minified HTML."""

    def test_minified_html_skipped(self) -> None:
        """HTML file with avg line length > 500 is detected as generated."""
        long_line = "x" * 1000
        assert is_generated_file("dist/index.html", [long_line], Language.HTML) is True

    def test_normal_html_not_skipped(self) -> None:
        """Normal HTML file is not detected as generated."""
        lines = [
            "<!DOCTYPE html>",
            "<html>",
            "<head><title>Test</title></head>",
            "<body>",
            "<h1>Hello</h1>",
            "</body>",
            "</html>",
        ]
        assert is_generated_file("index.html", lines, Language.HTML) is False

    def test_empty_html_not_skipped(self) -> None:
        """Empty HTML file is not detected as generated."""
        assert is_generated_file("empty.html", [], Language.HTML) is False

    def test_template_minified_skipped(self) -> None:
        """Minified template file is also detected."""
        long_line = "<div>" + "a" * 600 + "</div>"
        assert is_generated_file("views/page.ejs", [long_line], Language.HTML) is True


# ---------------------------------------------------------------------------
# Pipeline pass-through (no AST enrichment)
# ---------------------------------------------------------------------------


class TestHtmlPipelinePassThrough:
    """Verify HTML files skip AST enrichment gracefully."""

    def test_html_not_in_symbol_node_configs(self) -> None:
        """HTML is not in the pipeline's symbol node config (no AST extraction)."""
        assert Language.HTML not in _SYMBOL_NODE_CONFIGS

    def test_html_parser_raises_unsupported(self) -> None:
        """Requesting a parser for HTML raises UnsupportedLanguageError."""
        with pytest.raises(UnsupportedLanguageError, match="html"):
            get_parser(Language.HTML)
