"""Tests for Vue Single File Component support."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from diffguard.ast import Language, detect_language, get_parser
from diffguard.ast.vue import detect_vue_script_language, extract_vue_script, extract_vue_template
from diffguard.config import DiffguardConfig
from diffguard.exceptions import UnsupportedLanguageError
from diffguard.exclusions import is_generated_file
from diffguard.git import DiffFile, DiffHunk
from diffguard.pipeline import _SYMBOL_NODE_CONFIGS, _build_file_context

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Test fixtures (inline SFCs)
# ---------------------------------------------------------------------------

VUE_BASIC = """\
<template>
  <div>
    <h1>{{ msg }}</h1>
  </div>
</template>

<script>
import { ref } from 'vue'

export default {
  setup() {
    const msg = ref('Hello')
    return { msg }
  }
}
</script>

<style scoped>
h1 { color: red; }
</style>"""

VUE_TYPESCRIPT = """\
<template>
  <div>{{ count }}</div>
</template>

<script lang="ts">
import { defineComponent, ref } from 'vue'

export default defineComponent({
  setup() {
    const count = ref<number>(0)
    return { count }
  }
})
</script>"""

VUE_SCRIPT_SETUP = """\
<template>
  <button @click="increment">{{ count }}</button>
</template>

<script setup>
import { ref } from 'vue'

const count = ref(0)
function increment() {
  count.value++
}
</script>"""

VUE_SCRIPT_SETUP_TS = """\
<template>
  <span>{{ name }}</span>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const name = ref<string>('World')
</script>"""

VUE_NO_SCRIPT = """\
<template>
  <div>Static content</div>
</template>

<style>
div { margin: 0; }
</style>"""

VUE_NO_TEMPLATE = """\
<script>
export default {
  render(h) {
    return h('div', 'Hello')
  }
}
</script>"""


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


class TestVueLanguageDetection:
    """Test detect_language() for .vue files."""

    def test_vue_extension_detected(self) -> None:
        assert detect_language("src/components/App.vue") == Language.VUE

    def test_vue_case_insensitive(self) -> None:
        assert detect_language("App.VUE") == Language.VUE
        assert detect_language("App.Vue") == Language.VUE

    def test_vue_in_nested_path(self) -> None:
        assert detect_language("src/views/admin/Dashboard.vue") == Language.VUE


# ---------------------------------------------------------------------------
# Script extraction
# ---------------------------------------------------------------------------


class TestExtractVueScript:
    """Test extract_vue_script() for various SFC shapes."""

    def test_basic_script_extraction(self) -> None:
        result = extract_vue_script(VUE_BASIC)
        assert result is not None
        content, start_line = result
        assert "import { ref } from 'vue'" in content
        assert "export default {" in content
        assert start_line == 8

    def test_typescript_script_extraction(self) -> None:
        result = extract_vue_script(VUE_TYPESCRIPT)
        assert result is not None
        content, start_line = result
        assert "defineComponent" in content
        assert "ref<number>" in content
        assert start_line == 6

    def test_script_setup_extraction(self) -> None:
        result = extract_vue_script(VUE_SCRIPT_SETUP)
        assert result is not None
        content, start_line = result
        assert "const count = ref(0)" in content
        assert "function increment()" in content
        assert start_line == 6

    def test_script_setup_ts_extraction(self) -> None:
        result = extract_vue_script(VUE_SCRIPT_SETUP_TS)
        assert result is not None
        content, start_line = result
        assert "ref<string>" in content
        assert start_line == 6

    def test_no_script_returns_none(self) -> None:
        assert extract_vue_script(VUE_NO_SCRIPT) is None

    def test_script_without_template(self) -> None:
        result = extract_vue_script(VUE_NO_TEMPLATE)
        assert result is not None
        content, _ = result
        assert "render(h)" in content


# ---------------------------------------------------------------------------
# Script language detection
# ---------------------------------------------------------------------------


class TestDetectVueScriptLanguage:
    """Test detect_vue_script_language() for TS vs JS."""

    def test_default_is_javascript(self) -> None:
        assert detect_vue_script_language(VUE_BASIC) == Language.JAVASCRIPT

    def test_lang_ts_detected(self) -> None:
        assert detect_vue_script_language(VUE_TYPESCRIPT) == Language.TYPESCRIPT

    def test_script_setup_default_javascript(self) -> None:
        assert detect_vue_script_language(VUE_SCRIPT_SETUP) == Language.JAVASCRIPT

    def test_script_setup_lang_ts(self) -> None:
        assert detect_vue_script_language(VUE_SCRIPT_SETUP_TS) == Language.TYPESCRIPT

    def test_no_script_defaults_javascript(self) -> None:
        assert detect_vue_script_language(VUE_NO_SCRIPT) == Language.JAVASCRIPT

    def test_lang_typescript_full_word(self) -> None:
        source = '<script lang="typescript">\nexport default {}\n</script>'
        assert detect_vue_script_language(source) == Language.TYPESCRIPT

    def test_lang_single_quotes(self) -> None:
        source = "<script lang='ts'>\nexport default {}\n</script>"
        assert detect_vue_script_language(source) == Language.TYPESCRIPT


# ---------------------------------------------------------------------------
# Template extraction
# ---------------------------------------------------------------------------


class TestExtractVueTemplate:
    """Test extract_vue_template() for template block extraction."""

    def test_basic_template_extraction(self) -> None:
        result = extract_vue_template(VUE_BASIC)
        assert result is not None
        content, start_line = result
        assert "<h1>{{ msg }}</h1>" in content
        assert start_line == 2

    def test_no_template_returns_none(self) -> None:
        assert extract_vue_template(VUE_NO_TEMPLATE) is None

    def test_template_with_directives(self) -> None:
        source = '<template>\n  <div v-html="raw"></div>\n</template>\n<script>\nexport default {}\n</script>'
        result = extract_vue_template(source)
        assert result is not None
        content, _ = result
        assert 'v-html="raw"' in content


# ---------------------------------------------------------------------------
# Generated file detection (minified SFC)
# ---------------------------------------------------------------------------


class TestVueGeneratedFileDetection:
    """Test is_generated_file() for minified Vue SFCs."""

    def test_minified_vue_skipped(self) -> None:
        long_line = "x" * 1000
        assert is_generated_file("dist/App.vue", [long_line], Language.VUE) is True

    def test_normal_vue_not_skipped(self) -> None:
        lines = VUE_BASIC.splitlines()
        assert is_generated_file("src/App.vue", lines, Language.VUE) is False

    def test_empty_vue_not_skipped(self) -> None:
        assert is_generated_file("App.vue", [], Language.VUE) is False


# ---------------------------------------------------------------------------
# Pipeline pass-through (VUE not in symbol node configs)
# ---------------------------------------------------------------------------


class TestVuePipelineConfig:
    """Verify Vue is not in symbol node configs (uses script language instead)."""

    def test_vue_not_in_symbol_node_configs(self) -> None:
        assert Language.VUE not in _SYMBOL_NODE_CONFIGS

    def test_vue_parser_raises_unsupported(self) -> None:
        with pytest.raises(UnsupportedLanguageError, match="vue"):
            get_parser(Language.VUE)


# ---------------------------------------------------------------------------
# Pipeline integration: script block gets AST enrichment
# ---------------------------------------------------------------------------


class TestVuePipelineIntegration:
    """Verify that Vue SFC script blocks receive AST enrichment in the pipeline."""

    def test_vue_script_scopes_detected(self, tmp_path: Path) -> None:
        """Changed lines in a Vue script block produce scopes."""
        vue_source = """\
<template>
  <div>{{ msg }}</div>
</template>

<script>
export default {
  setup() {
    const msg = 'hello'
    return { msg }
  }
}
</script>"""

        vue_file = tmp_path / "App.vue"
        vue_file.write_text(vue_source)

        # Change is on line 8 of the full file (inside the setup() function)
        diff_file = DiffFile(
            old_path="App.vue",
            new_path="App.vue",
            hunks=[
                DiffHunk(
                    old_start=8,
                    old_count=1,
                    new_start=8,
                    new_count=1,
                    lines=[("+", "    const msg = 'hello'")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.VUE, config, tmp_path)

        # Scopes should be detected from the script block
        assert len(file_ctx.scopes) > 0
        # Scope line numbers should be in full-file coordinates
        for scope in file_ctx.scopes:
            assert scope.start_line >= 5  # script block starts at line 5

    def test_vue_typescript_scopes_detected(self, tmp_path: Path) -> None:
        """TypeScript script blocks also produce scopes."""
        vue_source = """\
<template>
  <div>{{ count }}</div>
</template>

<script lang="ts">
import { defineComponent, ref } from 'vue'

export default defineComponent({
  setup() {
    const count = ref<number>(0)
    return { count }
  }
})
</script>"""

        vue_file = tmp_path / "Counter.vue"
        vue_file.write_text(vue_source)

        diff_file = DiffFile(
            old_path="Counter.vue",
            new_path="Counter.vue",
            hunks=[
                DiffHunk(
                    old_start=10,
                    old_count=1,
                    new_start=10,
                    new_count=1,
                    lines=[("+", "    const count = ref<number>(0)")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.VUE, config, tmp_path)
        assert len(file_ctx.scopes) > 0

    def test_vue_no_script_no_scopes(self, tmp_path: Path) -> None:
        """Vue file without script block produces no scopes."""

        vue_file = tmp_path / "Static.vue"
        vue_file.write_text(VUE_NO_SCRIPT)

        diff_file = DiffFile(
            old_path="Static.vue",
            new_path="Static.vue",
            hunks=[
                DiffHunk(
                    old_start=2,
                    old_count=1,
                    new_start=2,
                    new_count=1,
                    lines=[("+", "  <div>Static content</div>")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.VUE, config, tmp_path)
        assert file_ctx.scopes == []
        assert file_ctx.symbols == {}

    def test_vue_changes_outside_script_no_scopes(self, tmp_path: Path) -> None:
        """Changes in template block (outside script) produce no scopes."""

        vue_file = tmp_path / "App.vue"
        vue_file.write_text(VUE_BASIC)

        # Change is on line 3 (inside <template>, outside <script>)
        diff_file = DiffFile(
            old_path="App.vue",
            new_path="App.vue",
            hunks=[
                DiffHunk(
                    old_start=3,
                    old_count=1,
                    new_start=3,
                    new_count=1,
                    lines=[("+", "    <h1>{{ msg }}</h1>")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.VUE, config, tmp_path)
        # No scopes because the change is in the template, not the script
        assert file_ctx.scopes == []

    def test_vue_full_source_preserved(self, tmp_path: Path) -> None:
        """source_lines contains the full Vue file, not just the script block."""

        vue_file = tmp_path / "App.vue"
        vue_file.write_text(VUE_BASIC)

        diff_file = DiffFile(
            old_path="App.vue",
            new_path="App.vue",
            hunks=[
                DiffHunk(
                    old_start=8,
                    old_count=1,
                    new_start=8,
                    new_count=1,
                    lines=[("+", "import { ref } from 'vue'")],
                )
            ],
            is_new_file=False,
            is_deleted=False,
            is_binary=False,
        )

        config = DiffguardConfig()
        file_ctx = _build_file_context(diff_file, Language.VUE, config, tmp_path)
        # source_lines should contain the full file including <template> and <style>
        full_text = "\n".join(file_ctx.source_lines)
        assert "<template>" in full_text
        assert "<style" in full_text
