"""Tests for Svelte Single File Component support."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from diffguard.ast import Language, detect_language, get_parser
from diffguard.ast.svelte import detect_svelte_script_language, extract_svelte_script, extract_svelte_template
from diffguard.config import DiffguardConfig
from diffguard.exceptions import UnsupportedLanguageError
from diffguard.exclusions import is_generated_file
from diffguard.git import DiffFile, DiffHunk
from diffguard.pipeline import _SYMBOL_NODE_CONFIGS, _build_file_context

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Test fixtures (inline Svelte components)
# ---------------------------------------------------------------------------

SVELTE_BASIC = """\
<script>
import { onMount } from 'svelte'

let count = 0
function increment() {
  count += 1
}
</script>

<h1>Count: {count}</h1>
<button on:click={increment}>+1</button>

<style>
h1 { color: red; }
</style>"""

SVELTE_TYPESCRIPT = """\
<script lang="ts">
import { onMount } from 'svelte'

let count: number = 0
function increment(): void {
  count += 1
}
</script>

<h1>Count: {count}</h1>
<button on:click={increment}>+1</button>"""

SVELTE_CONTEXT_MODULE = """\
<script context="module">
export const prerender = true
</script>

<script>
let name = 'world'
</script>

<h1>Hello {name}!</h1>"""

SVELTE_NO_SCRIPT = """\
<h1>Static content</h1>
<p>No script here</p>

<style>
h1 { margin: 0; }
</style>"""

SVELTE_NO_TEMPLATE = """\
<script>
export default {}
</script>"""

SVELTE_HTML_RAW = """\
<script>
let userInput = '<b>bold</b>'
</script>

{@html userInput}

<style>
p { color: blue; }
</style>"""


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


class TestSvelteLanguageDetection:
    """Test detect_language() for .svelte files."""

    def test_svelte_extension_detected(self) -> None:
        assert detect_language("src/components/App.svelte") == Language.SVELTE

    def test_svelte_case_insensitive(self) -> None:
        assert detect_language("App.SVELTE") == Language.SVELTE
        assert detect_language("App.Svelte") == Language.SVELTE

    def test_svelte_in_nested_path(self) -> None:
        assert detect_language("src/routes/admin/Dashboard.svelte") == Language.SVELTE


# ---------------------------------------------------------------------------
# Script extraction
# ---------------------------------------------------------------------------


class TestExtractSvelteScript:
    """Test extract_svelte_script() for various component shapes."""

    def test_basic_script_extraction(self) -> None:
        result = extract_svelte_script(SVELTE_BASIC)
        assert result is not None
        content, start_line = result
        assert "import { onMount } from 'svelte'" in content
        assert "function increment()" in content
        assert start_line == 2

    def test_typescript_script_extraction(self) -> None:
        result = extract_svelte_script(SVELTE_TYPESCRIPT)
        assert result is not None
        content, start_line = result
        assert "let count: number = 0" in content
        assert "function increment(): void" in content
        assert start_line == 2

    def test_context_module_extraction(self) -> None:
        """context='module' script is the first <script> found."""
        result = extract_svelte_script(SVELTE_CONTEXT_MODULE)
        assert result is not None
        content, start_line = result
        assert "export const prerender = true" in content
        assert start_line == 2

    def test_no_script_returns_none(self) -> None:
        assert extract_svelte_script(SVELTE_NO_SCRIPT) is None

    def test_script_only_component(self) -> None:
        result = extract_svelte_script(SVELTE_NO_TEMPLATE)
        assert result is not None
        content, _ = result
        assert "export default {}" in content


# ---------------------------------------------------------------------------
# Script language detection
# ---------------------------------------------------------------------------


class TestDetectSvelteScriptLanguage:
    """Test detect_svelte_script_language() for TS vs JS."""

    def test_default_is_javascript(self) -> None:
        assert detect_svelte_script_language(SVELTE_BASIC) == Language.JAVASCRIPT

    def test_lang_ts_detected(self) -> None:
        assert detect_svelte_script_language(SVELTE_TYPESCRIPT) == Language.TYPESCRIPT

    def test_no_script_defaults_javascript(self) -> None:
        assert detect_svelte_script_language(SVELTE_NO_SCRIPT) == Language.JAVASCRIPT

    def test_lang_typescript_full_word(self) -> None:
        source = '<script lang="typescript">\nlet x = 1\n</script>'
        assert detect_svelte_script_language(source) == Language.TYPESCRIPT

    def test_lang_single_quotes(self) -> None:
        source = "<script lang='ts'>\nlet x = 1\n</script>"
        assert detect_svelte_script_language(source) == Language.TYPESCRIPT

    def test_context_module_no_lang(self) -> None:
        assert detect_svelte_script_language(SVELTE_CONTEXT_MODULE) == Language.JAVASCRIPT


# ---------------------------------------------------------------------------
# Template extraction
# ---------------------------------------------------------------------------


class TestExtractSvelteTemplate:
    """Test extract_svelte_template() for template extraction."""

    def test_basic_template_extraction(self) -> None:
        result = extract_svelte_template(SVELTE_BASIC)
        assert result is not None
        content, _start_line = result
        assert "<h1>Count: {count}</h1>" in content
        assert "<button" in content
        # Script and style content should not be in template
        assert "import { onMount }" not in content
        assert "color: red" not in content

    def test_no_template_returns_none(self) -> None:
        """Script-only component with no template content returns None."""
        assert extract_svelte_template(SVELTE_NO_TEMPLATE) is None

    def test_template_with_html_directive(self) -> None:
        result = extract_svelte_template(SVELTE_HTML_RAW)
        assert result is not None
        content, _ = result
        assert "{@html userInput}" in content

    def test_no_script_all_template(self) -> None:
        result = extract_svelte_template(SVELTE_NO_SCRIPT)
        assert result is not None
        content, start_line = result
        assert "<h1>Static content</h1>" in content
        assert start_line == 1


# ---------------------------------------------------------------------------
# Generated file detection (minified SFC)
# ---------------------------------------------------------------------------


class TestSvelteGeneratedFileDetection:
    """Test is_generated_file() for minified Svelte components."""

    def test_minified_svelte_skipped(self) -> None:
        long_line = "x" * 1000
        assert is_generated_file("dist/App.svelte", [long_line], Language.SVELTE) is True

    def test_normal_svelte_not_skipped(self) -> None:
        lines = SVELTE_BASIC.splitlines()
        assert is_generated_file("src/App.svelte", lines, Language.SVELTE) is False

    def test_empty_svelte_not_skipped(self) -> None:
        assert is_generated_file("App.svelte", [], Language.SVELTE) is False


# ---------------------------------------------------------------------------
# Pipeline pass-through (SVELTE not in symbol node configs)
# ---------------------------------------------------------------------------


class TestSveltePipelineConfig:
    """Verify Svelte is not in symbol node configs (uses script language instead)."""

    def test_svelte_not_in_symbol_node_configs(self) -> None:
        assert Language.SVELTE not in _SYMBOL_NODE_CONFIGS

    def test_svelte_parser_raises_unsupported(self) -> None:
        with pytest.raises(UnsupportedLanguageError, match="svelte"):
            get_parser(Language.SVELTE)


# ---------------------------------------------------------------------------
# Pipeline integration: script block gets AST enrichment
# ---------------------------------------------------------------------------


class TestSveltePipelineIntegration:
    """Verify that Svelte script blocks receive AST enrichment in the pipeline."""

    def test_svelte_script_scopes_detected(self, tmp_path: Path) -> None:
        """Changed lines in a Svelte script block produce scopes."""
        svelte_source = """\
<script>
let count = 0
function increment() {
  count += 1
}
</script>

<h1>Count: {count}</h1>"""

        svelte_file = tmp_path / "Counter.svelte"
        svelte_file.write_text(svelte_source)

        # Change is on line 4 of the full file (inside increment function)
        diff_file = DiffFile(
            old_path="Counter.svelte",
            new_path="Counter.svelte",
            hunks=[
                DiffHunk(
                    old_start=4,
                    old_count=1,
                    new_start=4,
                    new_count=1,
                    lines=[("+", "  count += 1")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.SVELTE, config, tmp_path)

        # Scopes should be detected from the script block
        assert len(file_ctx.scopes) > 0
        # Scope line numbers should be in full-file coordinates
        for scope in file_ctx.scopes:
            assert scope.start_line >= 1

    def test_svelte_typescript_scopes_detected(self, tmp_path: Path) -> None:
        """TypeScript script blocks also produce scopes."""
        svelte_file = tmp_path / "Counter.svelte"
        svelte_file.write_text(SVELTE_TYPESCRIPT)

        diff_file = DiffFile(
            old_path="Counter.svelte",
            new_path="Counter.svelte",
            hunks=[
                DiffHunk(
                    old_start=5,
                    old_count=1,
                    new_start=5,
                    new_count=1,
                    lines=[("+", "function increment(): void {")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.SVELTE, config, tmp_path)
        assert len(file_ctx.scopes) > 0

    def test_svelte_no_script_no_scopes(self, tmp_path: Path) -> None:
        """Svelte file without script block produces no scopes."""
        svelte_file = tmp_path / "Static.svelte"
        svelte_file.write_text(SVELTE_NO_SCRIPT)

        diff_file = DiffFile(
            old_path="Static.svelte",
            new_path="Static.svelte",
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
        file_ctx = _build_file_context(diff_file, Language.SVELTE, config, tmp_path)
        assert file_ctx.scopes == []
        assert file_ctx.symbols == {}

    def test_svelte_changes_outside_script_no_scopes(self, tmp_path: Path) -> None:
        """Changes in template (outside script) produce no scopes."""
        svelte_file = tmp_path / "App.svelte"
        svelte_file.write_text(SVELTE_BASIC)

        # Change is on line 10 (template area, outside <script>)
        diff_file = DiffFile(
            old_path="App.svelte",
            new_path="App.svelte",
            hunks=[
                DiffHunk(
                    old_start=10,
                    old_count=1,
                    new_start=10,
                    new_count=1,
                    lines=[("+", "<h1>Count: {count}</h1>")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.SVELTE, config, tmp_path)
        assert file_ctx.scopes == []

    def test_svelte_full_source_preserved(self, tmp_path: Path) -> None:
        """source_lines contains the full Svelte file, not just the script block."""
        svelte_file = tmp_path / "App.svelte"
        svelte_file.write_text(SVELTE_BASIC)

        diff_file = DiffFile(
            old_path="App.svelte",
            new_path="App.svelte",
            hunks=[
                DiffHunk(
                    old_start=4,
                    old_count=1,
                    new_start=4,
                    new_count=1,
                    lines=[("+", "function increment() {")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.SVELTE, config, tmp_path)
        # source_lines should contain the full file including template and <style>
        full_text = "\n".join(file_ctx.source_lines)
        assert "<h1>Count: {count}</h1>" in full_text
        assert "<style>" in full_text
