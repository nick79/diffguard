"""Tests for JavaScript language support."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from diffguard.ast import (
    Language,
    detect_language,
    extract_imports,
    find_used_symbols,
    is_first_party,
    parse_file,
    resolve_symbol_definition,
)
from diffguard.ast.javascript import clear_package_json_cache
from diffguard.ast.python import Import
from diffguard.ast.scope import find_enclosing_scope
from diffguard.config import DiffguardConfig
from diffguard.exclusions import is_generated_file
from diffguard.git import DiffFile, DiffHunk
from diffguard.pipeline import _filter_analyzable_files

if TYPE_CHECKING:
    from tree_sitter import Tree


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_js(source: str) -> Tree:
    """Parse JavaScript source and return a tree-sitter Tree."""
    tree = parse_file(source, Language.JAVASCRIPT)
    assert tree is not None
    return tree


def _make_diff_file(path: str) -> DiffFile:
    return DiffFile(
        old_path=path,
        new_path=path,
        hunks=[DiffHunk(old_start=1, old_count=1, new_start=1, new_count=1, lines=[("+", "x")])],
        is_new_file=False,
        is_deleted=False,
        is_binary=False,
    )


# ---------------------------------------------------------------------------
# Scope Detection
# ---------------------------------------------------------------------------

JS_FUNCTION = """\
function greet(name) {
    return `Hello, ${name}!`;
}
"""

JS_ARROW_BLOCK = """\
const greet = (name) => {
    return `Hello, ${name}!`;
};
"""

JS_ARROW_EXPRESSION = """\
const double = (x) => x * 2;
"""

JS_FUNC_EXPRESSION = """\
const greet = function(name) {
    return `Hello, ${name}!`;
};
"""

JS_CLASS = """\
class Calculator {
    add(a, b) {
        return a + b;
    }
}
"""

JS_METHOD = """\
class Calculator {
    add(a, b) {
        return a + b;
    }

    subtract(a, b) {
        return a - b;
    }
}
"""

JS_ASYNC = """\
async function fetchData(url) {
    const response = await fetch(url);
    return response.json();
}
"""

JS_GENERATOR = """\
function* range(start, end) {
    for (let i = start; i < end; i++) {
        yield i;
    }
}
"""

JS_MODULE_LEVEL = """\
const x = 1;
const y = 2;
console.log(x + y);
"""


class TestJavaScriptScopeDetection:
    def test_function_declaration(self) -> None:
        tree = _parse_js(JS_FUNCTION)
        scope = find_enclosing_scope(tree, 2, Language.JAVASCRIPT)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "greet"
        assert scope.start_line == 1
        assert scope.end_line == 3

    def test_arrow_function_block_body(self) -> None:
        tree = _parse_js(JS_ARROW_BLOCK)
        scope = find_enclosing_scope(tree, 2, Language.JAVASCRIPT)
        assert scope is not None
        assert scope.type == "arrow_function"
        assert scope.name == "greet"
        assert scope.start_line == 1

    def test_arrow_function_expression_body(self) -> None:
        tree = _parse_js(JS_ARROW_EXPRESSION)
        scope = find_enclosing_scope(tree, 1, Language.JAVASCRIPT)
        assert scope is not None
        assert scope.type == "arrow_function"
        assert scope.name == "double"

    def test_function_expression(self) -> None:
        tree = _parse_js(JS_FUNC_EXPRESSION)
        scope = find_enclosing_scope(tree, 2, Language.JAVASCRIPT)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "greet"

    def test_class_declaration(self) -> None:
        tree = _parse_js(JS_CLASS)
        # Line 1 is `class Calculator {` — outside any method, inside class
        scope = find_enclosing_scope(tree, 1, Language.JAVASCRIPT)
        assert scope is not None
        assert scope.type == "class"
        assert scope.name == "Calculator"

    def test_method_definition(self) -> None:
        tree = _parse_js(JS_CLASS)
        scope = find_enclosing_scope(tree, 3, Language.JAVASCRIPT)
        assert scope is not None
        assert scope.type == "method"
        assert scope.name == "add"

    def test_async_function(self) -> None:
        tree = _parse_js(JS_ASYNC)
        scope = find_enclosing_scope(tree, 2, Language.JAVASCRIPT)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "fetchData"

    def test_generator_function(self) -> None:
        tree = _parse_js(JS_GENERATOR)
        scope = find_enclosing_scope(tree, 3, Language.JAVASCRIPT)
        assert scope is not None
        assert scope.type == "generator"
        assert scope.name == "range"

    def test_module_level_returns_none(self) -> None:
        tree = _parse_js(JS_MODULE_LEVEL)
        scope = find_enclosing_scope(tree, 1, Language.JAVASCRIPT)
        assert scope is None


# ---------------------------------------------------------------------------
# Import Extraction
# ---------------------------------------------------------------------------

JS_ES6_NAMED = """\
import { foo, bar } from './utils';
"""

JS_ES6_DEFAULT = """\
import React from 'react';
"""

JS_ES6_NAMESPACE = """\
import * as path from 'path';
"""

JS_ES6_MIXED = """\
import React, { useState, useEffect } from 'react';
"""

JS_REQUIRE = """\
const express = require('express');
"""

JS_REQUIRE_DESTRUCTURED = """\
const { readFile, writeFile } = require('fs');
"""

JS_DYNAMIC_IMPORT = """\
import('./module.js');
"""


class TestJavaScriptImportExtraction:
    def test_es6_named_imports(self) -> None:
        tree = _parse_js(JS_ES6_NAMED)
        imports = extract_imports(tree, Language.JAVASCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "./utils"
        assert imports[0].names == ["foo", "bar"]
        assert imports[0].is_relative is True

    def test_es6_default_import(self) -> None:
        tree = _parse_js(JS_ES6_DEFAULT)
        imports = extract_imports(tree, Language.JAVASCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "react"
        assert imports[0].alias == "React"
        assert imports[0].is_relative is False

    def test_es6_namespace_import(self) -> None:
        tree = _parse_js(JS_ES6_NAMESPACE)
        imports = extract_imports(tree, Language.JAVASCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "path"
        assert imports[0].is_star is True
        assert imports[0].alias == "path"

    def test_es6_mixed_default_and_named(self) -> None:
        tree = _parse_js(JS_ES6_MIXED)
        imports = extract_imports(tree, Language.JAVASCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "react"
        assert imports[0].alias == "React"
        assert imports[0].names == ["useState", "useEffect"]

    def test_require(self) -> None:
        tree = _parse_js(JS_REQUIRE)
        imports = extract_imports(tree, Language.JAVASCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "express"
        assert imports[0].alias == "express"

    def test_destructured_require(self) -> None:
        tree = _parse_js(JS_REQUIRE_DESTRUCTURED)
        imports = extract_imports(tree, Language.JAVASCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "fs"
        assert imports[0].names == ["readFile", "writeFile"]

    def test_dynamic_import(self) -> None:
        tree = _parse_js(JS_DYNAMIC_IMPORT)
        imports = extract_imports(tree, Language.JAVASCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "./module.js"
        assert imports[0].is_relative is True


# ---------------------------------------------------------------------------
# Language Detection
# ---------------------------------------------------------------------------


class TestJavaScriptLanguageDetection:
    def test_js_extension(self) -> None:
        assert detect_language("app.js") == Language.JAVASCRIPT

    def test_mjs_extension(self) -> None:
        assert detect_language("app.mjs") == Language.JAVASCRIPT

    def test_cjs_extension(self) -> None:
        assert detect_language("app.cjs") == Language.JAVASCRIPT

    def test_jsx_extension(self) -> None:
        assert detect_language("component.jsx") == Language.JAVASCRIPT

    def test_jsx_parsing(self) -> None:
        source = "const App = () => <div>Hello</div>;"
        tree = parse_file(source, Language.JAVASCRIPT)
        assert tree is not None


# ---------------------------------------------------------------------------
# First-party Detection
# ---------------------------------------------------------------------------


class TestJavaScriptFirstPartyDetection:
    def setup_method(self) -> None:
        clear_package_json_cache()

    def test_relative_import_is_first_party(self) -> None:
        assert is_first_party("./utils", Path("/project"), None, Language.JAVASCRIPT, is_relative=True) is True

    def test_bare_specifier_is_third_party(self) -> None:
        assert is_first_party("lodash", Path("/project"), None, Language.JAVASCRIPT) is False

    def test_package_json_name_is_first_party(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"name": "my-app"}')
        assert is_first_party("my-app", tmp_path, None, Language.JAVASCRIPT) is True

    def test_monorepo_workspace_is_first_party(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"name": "monorepo", "workspaces": ["packages/core"]}')
        assert is_first_party("packages/core", tmp_path, None, Language.JAVASCRIPT) is True


# ---------------------------------------------------------------------------
# Symbol Resolution
# ---------------------------------------------------------------------------


class TestJavaScriptSymbolResolution:
    def test_resolve_relative_import(self, tmp_path: Path) -> None:
        (tmp_path / "utils.js").write_text("export function helper() {}\n")
        imports = [Import(module="./utils", names=["helper"], is_relative=True)]
        current_file = tmp_path / "app.js"
        result = resolve_symbol_definition("helper", imports, tmp_path, current_file, Language.JAVASCRIPT)
        assert result is not None
        assert result.name == "utils.js"

    def test_resolve_index_convention(self, tmp_path: Path) -> None:
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "index.js").write_text("export default {}\n")
        imports = [Import(module="./lib", alias="lib", is_relative=True)]
        current_file = tmp_path / "app.js"
        result = resolve_symbol_definition("lib", imports, tmp_path, current_file, Language.JAVASCRIPT)
        assert result is not None
        assert result.name == "index.js"


# ---------------------------------------------------------------------------
# Vendor Path Filtering
# ---------------------------------------------------------------------------


class TestJavaScriptVendorPathFiltering:
    def test_skip_node_modules(self) -> None:
        diff_files = [_make_diff_file("node_modules/lodash/index.js")]
        result = _filter_analyzable_files(diff_files, DiffguardConfig())
        assert len(result) == 0

    def test_skip_bower_components(self) -> None:
        diff_files = [_make_diff_file("bower_components/jquery/jquery.js")]
        result = _filter_analyzable_files(diff_files, DiffguardConfig())
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Generated File Detection
# ---------------------------------------------------------------------------


class TestJavaScriptGeneratedFileDetection:
    def test_minified_js_detected(self) -> None:
        assert is_generated_file("dist/app.min.js", [], Language.JAVASCRIPT) is True

    def test_bundle_js_detected(self) -> None:
        assert is_generated_file("dist/main.bundle.js", [], Language.JAVASCRIPT) is True

    def test_content_heuristic_long_lines(self) -> None:
        long_line = "var a=" + "x" * 600
        assert is_generated_file("dist/app.js", [long_line], Language.JAVASCRIPT) is True

    def test_normal_js_kept(self) -> None:
        assert is_generated_file("src/app.js", ["const x = 1;"], Language.JAVASCRIPT) is False


# ---------------------------------------------------------------------------
# Symbol Usage Detection
# ---------------------------------------------------------------------------

JS_SYMBOLS = """\
function process(data) {
    const result = helper(data);
    const value = config.get('key');
    return MyClass.create(result);
}
"""

JS_BUILTINS = """\
console.log(JSON.stringify(data));
"""


class TestJavaScriptSymbolUsage:
    def test_finds_used_symbols(self) -> None:
        tree = _parse_js(JS_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 5, Language.JAVASCRIPT)
        assert "helper" in symbols
        assert "config" in symbols
        assert "MyClass" in symbols

    def test_excludes_definitions(self) -> None:
        tree = _parse_js(JS_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 5, Language.JAVASCRIPT)
        assert "result" not in symbols
        assert "value" not in symbols

    def test_excludes_params(self) -> None:
        tree = _parse_js(JS_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 5, Language.JAVASCRIPT)
        assert "data" not in symbols

    def test_attribute_root_only(self) -> None:
        tree = _parse_js(JS_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 5, Language.JAVASCRIPT)
        assert "config" in symbols
        assert "get" not in symbols

    def test_exclude_builtins(self) -> None:
        tree = _parse_js(JS_BUILTINS)
        symbols = find_used_symbols(tree, 1, 1, Language.JAVASCRIPT, exclude_builtins=True)
        assert "console" not in symbols
        assert "JSON" not in symbols

    def test_include_builtins_by_default(self) -> None:
        tree = _parse_js(JS_BUILTINS)
        symbols = find_used_symbols(tree, 1, 1, Language.JAVASCRIPT, exclude_builtins=False)
        assert "console" in symbols
