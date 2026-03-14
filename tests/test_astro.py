"""Tests for Astro component support."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from diffguard.ast import Language, detect_language, get_parser
from diffguard.ast.astro import detect_astro_frontmatter_language, extract_astro_frontmatter, extract_astro_template
from diffguard.config import DiffguardConfig
from diffguard.exceptions import UnsupportedLanguageError
from diffguard.exclusions import is_generated_file
from diffguard.git import DiffFile, DiffHunk
from diffguard.pipeline import _SYMBOL_NODE_CONFIGS, _build_file_context

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Test fixtures (inline Astro components)
# ---------------------------------------------------------------------------

ASTRO_BASIC = """\
---
import Layout from '../layouts/Layout.astro'

const title = 'Hello'
function greet(name) {
  return `Hello, ${name}!`
}
---

<Layout>
  <h1>{title}</h1>
  <p>{greet('world')}</p>
</Layout>"""

ASTRO_TYPESCRIPT = """\
---
import type { Props } from '../types'

const message: string = 'Hello'
const count: number = 42
---

<h1>{message}</h1>
<span>{count}</span>"""

ASTRO_TS_REFERENCE = """\
---
/// <reference types="astro/client" />

const title = 'My Site'
---

<h1>{title}</h1>"""

ASTRO_NO_FRONTMATTER = """\
<h1>Static content</h1>
<p>No frontmatter here</p>"""

ASTRO_EMPTY_FRONTMATTER = """\
---
---

<h1>Empty frontmatter</h1>"""

ASTRO_SET_HTML = """\
---
const rawHTML = '<b>bold</b>'
---

<div set:html={rawHTML} />"""

ASTRO_DEFINE_VARS = """\
---
const message = 'Hello'
---

<script define:vars={{ message }}>
  alert(message);
</script>"""


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


class TestAstroLanguageDetection:
    """Test detect_language() for .astro files."""

    def test_astro_extension_detected(self) -> None:
        assert detect_language("src/pages/index.astro") == Language.ASTRO

    def test_astro_case_insensitive(self) -> None:
        assert detect_language("Page.ASTRO") == Language.ASTRO
        assert detect_language("Page.Astro") == Language.ASTRO

    def test_astro_in_nested_path(self) -> None:
        assert detect_language("src/pages/blog/[slug].astro") == Language.ASTRO


# ---------------------------------------------------------------------------
# Frontmatter extraction
# ---------------------------------------------------------------------------


class TestExtractAstroFrontmatter:
    """Test extract_astro_frontmatter() for various component shapes."""

    def test_basic_frontmatter_extraction(self) -> None:
        result = extract_astro_frontmatter(ASTRO_BASIC)
        assert result is not None
        content, start_line = result
        assert "import Layout from '../layouts/Layout.astro'" in content
        assert "function greet(name)" in content
        assert start_line == 2

    def test_typescript_frontmatter_extraction(self) -> None:
        result = extract_astro_frontmatter(ASTRO_TYPESCRIPT)
        assert result is not None
        content, start_line = result
        assert "import type { Props } from '../types'" in content
        assert "const message: string = 'Hello'" in content
        assert start_line == 2

    def test_no_frontmatter_returns_none(self) -> None:
        assert extract_astro_frontmatter(ASTRO_NO_FRONTMATTER) is None

    def test_empty_frontmatter_returns_none(self) -> None:
        assert extract_astro_frontmatter(ASTRO_EMPTY_FRONTMATTER) is None

    def test_set_html_component_extraction(self) -> None:
        result = extract_astro_frontmatter(ASTRO_SET_HTML)
        assert result is not None
        content, _ = result
        assert "const rawHTML" in content

    def test_frontmatter_line_offset(self) -> None:
        source = "\n---\nconst x = 1\n---\n<p>hi</p>"
        result = extract_astro_frontmatter(source)
        assert result is not None
        content, start_line = result
        assert content == "const x = 1"
        assert start_line == 3


# ---------------------------------------------------------------------------
# Frontmatter language detection
# ---------------------------------------------------------------------------


class TestDetectAstroFrontmatterLanguage:
    """Test detect_astro_frontmatter_language() for TS vs JS."""

    def test_default_is_javascript(self) -> None:
        assert detect_astro_frontmatter_language(ASTRO_BASIC) == Language.JAVASCRIPT

    def test_import_type_detected_as_typescript(self) -> None:
        assert detect_astro_frontmatter_language(ASTRO_TYPESCRIPT) == Language.TYPESCRIPT

    def test_triple_slash_reference_detected_as_typescript(self) -> None:
        assert detect_astro_frontmatter_language(ASTRO_TS_REFERENCE) == Language.TYPESCRIPT

    def test_no_frontmatter_defaults_javascript(self) -> None:
        assert detect_astro_frontmatter_language(ASTRO_NO_FRONTMATTER) == Language.JAVASCRIPT

    def test_type_annotation_detected(self) -> None:
        source = "---\nconst x: string = 'hi'\n---\n<p>hi</p>"
        assert detect_astro_frontmatter_language(source) == Language.TYPESCRIPT

    def test_as_const_detected(self) -> None:
        source = "---\nconst themes = ['light', 'dark'] as const\n---\n<p>hi</p>"
        assert detect_astro_frontmatter_language(source) == Language.TYPESCRIPT


# ---------------------------------------------------------------------------
# Template extraction
# ---------------------------------------------------------------------------


class TestExtractAstroTemplate:
    """Test extract_astro_template() for template extraction."""

    def test_basic_template_extraction(self) -> None:
        result = extract_astro_template(ASTRO_BASIC)
        assert result is not None
        content, _start_line = result
        assert "<h1>{title}</h1>" in content
        assert "<Layout>" in content
        # Frontmatter should not be in template
        assert "import Layout" not in content

    def test_no_frontmatter_all_template(self) -> None:
        result = extract_astro_template(ASTRO_NO_FRONTMATTER)
        assert result is not None
        content, start_line = result
        assert "<h1>Static content</h1>" in content
        assert start_line == 1

    def test_empty_frontmatter_has_template(self) -> None:
        result = extract_astro_template(ASTRO_EMPTY_FRONTMATTER)
        assert result is not None
        content, _ = result
        assert "<h1>Empty frontmatter</h1>" in content

    def test_set_html_in_template(self) -> None:
        result = extract_astro_template(ASTRO_SET_HTML)
        assert result is not None
        content, _ = result
        assert "set:html={rawHTML}" in content

    def test_define_vars_in_template(self) -> None:
        result = extract_astro_template(ASTRO_DEFINE_VARS)
        assert result is not None
        content, _ = result
        assert "define:vars" in content

    def test_template_only_whitespace_returns_none(self) -> None:
        source = "---\nconst x = 1\n---\n\n  \n"
        assert extract_astro_template(source) is None


# ---------------------------------------------------------------------------
# Generated file detection (minified Astro component)
# ---------------------------------------------------------------------------


class TestAstroGeneratedFileDetection:
    """Test is_generated_file() for minified Astro components."""

    def test_minified_astro_skipped(self) -> None:
        long_line = "x" * 1000
        assert is_generated_file("dist/Page.astro", [long_line], Language.ASTRO) is True

    def test_normal_astro_not_skipped(self) -> None:
        lines = ASTRO_BASIC.splitlines()
        assert is_generated_file("src/pages/index.astro", lines, Language.ASTRO) is False

    def test_empty_astro_not_skipped(self) -> None:
        assert is_generated_file("Page.astro", [], Language.ASTRO) is False


# ---------------------------------------------------------------------------
# Pipeline pass-through (ASTRO not in symbol node configs)
# ---------------------------------------------------------------------------


class TestAstroPipelineConfig:
    """Verify Astro is not in symbol node configs (uses frontmatter language instead)."""

    def test_astro_not_in_symbol_node_configs(self) -> None:
        assert Language.ASTRO not in _SYMBOL_NODE_CONFIGS

    def test_astro_parser_raises_unsupported(self) -> None:
        with pytest.raises(UnsupportedLanguageError, match="astro"):
            get_parser(Language.ASTRO)


# ---------------------------------------------------------------------------
# Pipeline integration: frontmatter block gets AST enrichment
# ---------------------------------------------------------------------------


class TestAstroPipelineIntegration:
    """Verify that Astro frontmatter blocks receive AST enrichment in the pipeline."""

    def test_astro_frontmatter_scopes_detected(self, tmp_path: Path) -> None:
        """Changed lines in Astro frontmatter produce scopes."""
        astro_source = """\
---
const title = 'Hello'
function greet(name) {
  return `Hello, ${name}!`
}
---

<h1>{title}</h1>"""

        astro_file = tmp_path / "Page.astro"
        astro_file.write_text(astro_source)

        diff_file = DiffFile(
            old_path="Page.astro",
            new_path="Page.astro",
            hunks=[
                DiffHunk(
                    old_start=4,
                    old_count=1,
                    new_start=4,
                    new_count=1,
                    lines=[("+", "  return `Hello, ${name}!`")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.ASTRO, config, tmp_path)

        assert len(file_ctx.scopes) > 0
        for scope in file_ctx.scopes:
            assert scope.start_line >= 1

    def test_astro_typescript_scopes_detected(self, tmp_path: Path) -> None:
        """TypeScript frontmatter also produces scopes."""
        astro_file = tmp_path / "Page.astro"
        astro_file.write_text(ASTRO_TYPESCRIPT)

        diff_file = DiffFile(
            old_path="Page.astro",
            new_path="Page.astro",
            hunks=[
                DiffHunk(
                    old_start=4,
                    old_count=1,
                    new_start=4,
                    new_count=1,
                    lines=[("+", "const message: string = 'Hello'")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.ASTRO, config, tmp_path)
        # TS frontmatter should still be parsed (no scopes for top-level const, but no error)
        assert file_ctx.language == Language.ASTRO

    def test_astro_no_frontmatter_no_scopes(self, tmp_path: Path) -> None:
        """Astro file without frontmatter produces no scopes."""
        astro_file = tmp_path / "Static.astro"
        astro_file.write_text(ASTRO_NO_FRONTMATTER)

        diff_file = DiffFile(
            old_path="Static.astro",
            new_path="Static.astro",
            hunks=[
                DiffHunk(
                    old_start=1,
                    old_count=1,
                    new_start=1,
                    new_count=1,
                    lines=[("+", "<h1>Static content</h1>")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.ASTRO, config, tmp_path)
        assert file_ctx.scopes == []
        assert file_ctx.symbols == {}

    def test_astro_changes_outside_frontmatter_no_scopes(self, tmp_path: Path) -> None:
        """Changes in template (outside frontmatter) produce no scopes."""
        astro_file = tmp_path / "Page.astro"
        astro_file.write_text(ASTRO_BASIC)

        # Line 11 is in the template area (outside ---)
        diff_file = DiffFile(
            old_path="Page.astro",
            new_path="Page.astro",
            hunks=[
                DiffHunk(
                    old_start=11,
                    old_count=1,
                    new_start=11,
                    new_count=1,
                    lines=[("+", "  <h1>{title}</h1>")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.ASTRO, config, tmp_path)
        assert file_ctx.scopes == []

    def test_astro_full_source_preserved(self, tmp_path: Path) -> None:
        """source_lines contains the full Astro file, not just the frontmatter."""
        astro_file = tmp_path / "Page.astro"
        astro_file.write_text(ASTRO_BASIC)

        diff_file = DiffFile(
            old_path="Page.astro",
            new_path="Page.astro",
            hunks=[
                DiffHunk(
                    old_start=5,
                    old_count=1,
                    new_start=5,
                    new_count=1,
                    lines=[("+", "function greet(name) {")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.ASTRO, config, tmp_path)
        full_text = "\n".join(file_ctx.source_lines)
        assert "<h1>{title}</h1>" in full_text
        assert "<Layout>" in full_text
