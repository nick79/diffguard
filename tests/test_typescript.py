"""Tests for TypeScript language support."""

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


def _parse_ts(source: str) -> Tree:
    """Parse TypeScript source and return a tree-sitter Tree."""
    tree = parse_file(source, Language.TYPESCRIPT)
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
# Fixtures
# ---------------------------------------------------------------------------

TS_TYPED = """\
interface User {
    name: string;
    age: number;
}

function greet(user: User): string {
    return `Hello, ${user.name}`;
}

const getAge = (user: User): number => user.age;
"""

TS_GENERICS = """\
function identity<T>(arg: T): T {
    return arg;
}

class Container<T> {
    private value: T;

    constructor(value: T) {
        this.value = value;
    }

    getValue(): T {
        return this.value;
    }
}
"""

TS_TYPE_IMPORT = """\
import type { Config, Options } from './config';
import { helper, type HelperType } from './utils';
import DefaultExport from './default';
"""

TS_TSX = """\
interface Props {
    name: string;
    count?: number;
}

function Counter({ name, count = 0 }: Props): JSX.Element {
    return (
        <div>
            <span>{name}: {count}</span>
        </div>
    );
}
"""

TS_ENUM = """\
enum Status {
    Pending = 'PENDING',
    Active = 'ACTIVE',
    Completed = 'COMPLETED',
}
"""

TS_DECORATOR = """\
@Injectable()
class UserService {
    @Autowired()
    private repository: UserRepository;

    async findAll(): Promise<User[]> {
        return this.repository.findAll();
    }
}
"""

TS_NAMESPACE = """\
namespace MyApp {
    export function init() {
        console.log('init');
    }
}
"""

TS_ASYNC = """\
async function fetchData(): Promise<Data> {
    const response = await fetch('/api');
    return response.json();
}
"""

TS_ARROW_BLOCK = """\
const greet = (name: string): string => {
    return `Hello, ${name}!`;
};
"""

TS_ARROW_EXPRESSION = """\
const double = (x: number): number => x * 2;
"""

TS_FUNC_EXPRESSION = """\
const greet = function(name: string): string {
    return `Hello, ${name}!`;
};
"""

TS_CLASS = """\
class Calculator {
    add(a: number, b: number): number {
        return a + b;
    }
}
"""

TS_METHOD = """\
class Calculator {
    add(a: number, b: number): number {
        return a + b;
    }

    subtract(a: number, b: number): number {
        return a - b;
    }
}
"""

TS_MODULE_LEVEL = """\
const x: number = 1;
const y: number = 2;
console.log(x + y);
"""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class TestTypeScriptParsing:
    def test_parse_typed_code(self) -> None:
        tree = _parse_ts(TS_TYPED)
        assert not tree.root_node.has_error

    def test_parse_interface(self) -> None:
        tree = _parse_ts(TS_TYPED)
        node_types = [c.type for c in tree.root_node.children]
        assert "interface_declaration" in node_types

    def test_parse_type_alias(self) -> None:
        source = "type MyType = string | number;"
        tree = _parse_ts(source)
        assert not tree.root_node.has_error
        node_types = [c.type for c in tree.root_node.children]
        assert "type_alias_declaration" in node_types

    def test_parse_generics(self) -> None:
        tree = _parse_ts(TS_GENERICS)
        assert not tree.root_node.has_error

    def test_parse_enum(self) -> None:
        tree = _parse_ts(TS_ENUM)
        assert not tree.root_node.has_error
        node_types = [c.type for c in tree.root_node.children]
        assert "enum_declaration" in node_types

    def test_parse_decorators(self) -> None:
        tree = _parse_ts(TS_DECORATOR)
        assert not tree.root_node.has_error

    def test_parse_tsx(self) -> None:
        tree = _parse_ts(TS_TSX)
        assert not tree.root_node.has_error

    def test_parse_tsx_with_typed_props(self) -> None:
        source = """\
function Component(props: Props): JSX.Element {
    return <div>{props.name}</div>;
}
"""
        tree = _parse_ts(source)
        assert not tree.root_node.has_error


# ---------------------------------------------------------------------------
# Scope Detection
# ---------------------------------------------------------------------------


class TestTypeScriptScopeDetection:
    def test_typed_function_scope(self) -> None:
        tree = _parse_ts(TS_TYPED)
        scope = find_enclosing_scope(tree, 7, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "greet"

    def test_async_typed_function_scope(self) -> None:
        tree = _parse_ts(TS_ASYNC)
        scope = find_enclosing_scope(tree, 2, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "fetchData"

    def test_arrow_function_with_types(self) -> None:
        tree = _parse_ts(TS_ARROW_BLOCK)
        scope = find_enclosing_scope(tree, 2, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type == "arrow_function"
        assert scope.name == "greet"

    def test_arrow_function_expression_body(self) -> None:
        tree = _parse_ts(TS_ARROW_EXPRESSION)
        scope = find_enclosing_scope(tree, 1, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type == "arrow_function"
        assert scope.name == "double"

    def test_function_expression(self) -> None:
        tree = _parse_ts(TS_FUNC_EXPRESSION)
        scope = find_enclosing_scope(tree, 2, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "greet"

    def test_class_with_type_parameters(self) -> None:
        tree = _parse_ts(TS_GENERICS)
        # Line 6 is inside class body (private value: T;)
        scope = find_enclosing_scope(tree, 6, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type == "class"
        assert scope.name == "Container"

    def test_method_in_typed_class(self) -> None:
        tree = _parse_ts(TS_CLASS)
        scope = find_enclosing_scope(tree, 3, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type == "method"
        assert scope.name == "add"

    def test_class_declaration(self) -> None:
        tree = _parse_ts(TS_CLASS)
        scope = find_enclosing_scope(tree, 1, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type == "class"
        assert scope.name == "Calculator"

    def test_method_scope_returns_method_not_class(self) -> None:
        tree = _parse_ts(TS_METHOD)
        scope = find_enclosing_scope(tree, 7, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type == "method"
        assert scope.name == "subtract"

    def test_namespace_scope(self) -> None:
        tree = _parse_ts(TS_NAMESPACE)
        scope = find_enclosing_scope(tree, 3, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type in ("namespace", "function")

    def test_module_level_returns_none(self) -> None:
        tree = _parse_ts(TS_MODULE_LEVEL)
        scope = find_enclosing_scope(tree, 1, Language.TYPESCRIPT)
        assert scope is None

    def test_decorated_class_scope(self) -> None:
        tree = _parse_ts(TS_DECORATOR)
        scope = find_enclosing_scope(tree, 4, Language.TYPESCRIPT)
        assert scope is not None
        assert scope.type == "class"
        assert scope.name == "UserService"


# ---------------------------------------------------------------------------
# Import Extraction
# ---------------------------------------------------------------------------


class TestTypeScriptImportExtraction:
    def test_type_only_import_excluded(self) -> None:
        tree = _parse_ts(TS_TYPE_IMPORT)
        imports = extract_imports(tree, Language.TYPESCRIPT)
        # type-only import should produce an Import but with no runtime names
        type_imp = [i for i in imports if i.module == "./config"]
        assert len(type_imp) == 1
        # type-only imports have no runtime names
        assert type_imp[0].names is None or len(type_imp[0].names) == 0

    def test_inline_type_import_filtered(self) -> None:
        tree = _parse_ts(TS_TYPE_IMPORT)
        imports = extract_imports(tree, Language.TYPESCRIPT)
        utils_imp = [i for i in imports if i.module == "./utils"]
        assert len(utils_imp) == 1
        # Only 'helper' should remain (HelperType is type-only)
        assert utils_imp[0].names == ["helper"]

    def test_regular_import(self) -> None:
        tree = _parse_ts(TS_TYPE_IMPORT)
        imports = extract_imports(tree, Language.TYPESCRIPT)
        default_imp = [i for i in imports if i.module == "./default"]
        assert len(default_imp) == 1
        assert default_imp[0].alias == "DefaultExport"

    def test_es6_named_imports(self) -> None:
        source = "import { foo, bar } from './utils';"
        tree = _parse_ts(source)
        imports = extract_imports(tree, Language.TYPESCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "./utils"
        assert imports[0].names == ["foo", "bar"]
        assert imports[0].is_relative is True

    def test_es6_namespace_import(self) -> None:
        source = "import * as utils from './utils';"
        tree = _parse_ts(source)
        imports = extract_imports(tree, Language.TYPESCRIPT)
        assert len(imports) == 1
        assert imports[0].is_star is True
        assert imports[0].alias == "utils"

    def test_require_call(self) -> None:
        source = "const express = require('express');"
        tree = _parse_ts(source)
        imports = extract_imports(tree, Language.TYPESCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "express"
        assert imports[0].alias == "express"

    def test_destructured_require(self) -> None:
        source = "const { readFile, writeFile } = require('fs');"
        tree = _parse_ts(source)
        imports = extract_imports(tree, Language.TYPESCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "fs"
        assert imports[0].names == ["readFile", "writeFile"]

    def test_dynamic_import(self) -> None:
        source = "import('./module.ts');"
        tree = _parse_ts(source)
        imports = extract_imports(tree, Language.TYPESCRIPT)
        assert len(imports) == 1
        assert imports[0].module == "./module.ts"
        assert imports[0].is_relative is True


# ---------------------------------------------------------------------------
# Language Detection
# ---------------------------------------------------------------------------


class TestTypeScriptLanguageDetection:
    def test_ts_extension(self) -> None:
        assert detect_language("src/main.ts") == Language.TYPESCRIPT

    def test_mts_extension(self) -> None:
        assert detect_language("src/module.mts") == Language.TYPESCRIPT

    def test_cts_extension(self) -> None:
        assert detect_language("src/config.cts") == Language.TYPESCRIPT

    def test_tsx_extension(self) -> None:
        assert detect_language("src/Component.tsx") == Language.TYPESCRIPT

    def test_dts_extension(self) -> None:
        assert detect_language("types/index.d.ts") == Language.TYPESCRIPT

    def test_ts_distinguished_from_js(self) -> None:
        assert detect_language("app.ts") == Language.TYPESCRIPT
        assert detect_language("app.js") == Language.JAVASCRIPT


# ---------------------------------------------------------------------------
# First-party Detection
# ---------------------------------------------------------------------------


class TestTypeScriptFirstPartyDetection:
    def setup_method(self) -> None:
        clear_package_json_cache()

    def test_relative_import_is_first_party(self) -> None:
        assert is_first_party("./utils", Path("/project"), None, Language.TYPESCRIPT, is_relative=True) is True

    def test_bare_specifier_is_third_party(self) -> None:
        assert is_first_party("lodash", Path("/project"), None, Language.TYPESCRIPT) is False

    def test_scoped_package_is_third_party(self) -> None:
        assert is_first_party("@types/node", Path("/project"), None, Language.TYPESCRIPT) is False

    def test_package_json_name_is_first_party(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"name": "my-app"}')
        assert is_first_party("my-app", tmp_path, None, Language.TYPESCRIPT) is True

    def test_monorepo_workspace_is_first_party(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"name": "monorepo", "workspaces": ["packages/core"]}')
        assert is_first_party("packages/core", tmp_path, None, Language.TYPESCRIPT) is True


# ---------------------------------------------------------------------------
# Symbol Resolution
# ---------------------------------------------------------------------------


class TestTypeScriptSymbolResolution:
    def test_resolve_relative_ts_import(self, tmp_path: Path) -> None:
        (tmp_path / "utils.ts").write_text("export function helper() {}\n")
        imports = [Import(module="./utils", names=["helper"], is_relative=True)]
        current_file = tmp_path / "app.ts"
        result = resolve_symbol_definition("helper", imports, tmp_path, current_file, Language.TYPESCRIPT)
        assert result is not None
        assert result.name == "utils.ts"

    def test_resolve_index_ts_convention(self, tmp_path: Path) -> None:
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "index.ts").write_text("export default {}\n")
        imports = [Import(module="./lib", alias="lib", is_relative=True)]
        current_file = tmp_path / "app.ts"
        result = resolve_symbol_definition("lib", imports, tmp_path, current_file, Language.TYPESCRIPT)
        assert result is not None
        assert result.name == "index.ts"

    def test_resolve_ts_extension_fallback(self, tmp_path: Path) -> None:
        (tmp_path / "config.ts").write_text("export const config = {};\n")
        imports = [Import(module="./config", names=["config"], is_relative=True)]
        current_file = tmp_path / "app.ts"
        result = resolve_symbol_definition("config", imports, tmp_path, current_file, Language.TYPESCRIPT)
        assert result is not None
        assert result.name == "config.ts"

    def test_resolve_tsx_extension(self, tmp_path: Path) -> None:
        (tmp_path / "Button.tsx").write_text("export function Button() {}\n")
        imports = [Import(module="./Button", names=["Button"], is_relative=True)]
        current_file = tmp_path / "App.tsx"
        result = resolve_symbol_definition("Button", imports, tmp_path, current_file, Language.TYPESCRIPT)
        assert result is not None
        assert result.name == "Button.tsx"


# ---------------------------------------------------------------------------
# Vendor Path Filtering
# ---------------------------------------------------------------------------


class TestTypeScriptVendorPathFiltering:
    def test_skip_node_modules(self) -> None:
        diff_files = [_make_diff_file("node_modules/@types/node/index.d.ts")]
        result = _filter_analyzable_files(diff_files, DiffguardConfig())
        assert len(result) == 0

    def test_skip_bower_components(self) -> None:
        diff_files = [_make_diff_file("bower_components/lib/component.ts")]
        result = _filter_analyzable_files(diff_files, DiffguardConfig())
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Generated File Detection
# ---------------------------------------------------------------------------


class TestTypeScriptGeneratedFileDetection:
    def test_generated_dts_with_header(self) -> None:
        assert is_generated_file("dist/types.d.ts", ["// Generated by tsc", "export {};"], Language.TYPESCRIPT) is True

    def test_auto_generated_dts_with_header(self) -> None:
        assert (
            is_generated_file(
                "dist/api.d.ts",
                ["// Auto-generated from OpenAPI schema", "export interface Api {}"],
                Language.TYPESCRIPT,
            )
            is True
        )

    def test_normal_dts_kept(self) -> None:
        assert (
            is_generated_file("src/types.d.ts", ["export interface User {}", "  name: string;"], Language.TYPESCRIPT)
            is False
        )

    def test_minified_ts_detected_by_content(self) -> None:
        long_line = "var a=" + "x" * 600
        assert is_generated_file("dist/app.ts", [long_line], Language.TYPESCRIPT) is True

    def test_normal_ts_kept(self) -> None:
        assert is_generated_file("src/app.ts", ["const x: number = 1;"], Language.TYPESCRIPT) is False

    def test_dts_without_generated_header_kept(self) -> None:
        lines = ["declare module 'my-module' {", "  export function foo(): void;", "}"]
        assert is_generated_file("typings/custom.d.ts", lines, Language.TYPESCRIPT) is False


# ---------------------------------------------------------------------------
# Symbol Usage Detection
# ---------------------------------------------------------------------------

TS_SYMBOLS = """\
function process(data: InputData): OutputData {
    const result = helper(data);
    const value = config.get('key');
    return MyClass.create(result);
}
"""

TS_BUILTINS = """\
console.log(JSON.stringify(data));
const x: Partial<Config> = {};
"""


class TestTypeScriptSymbolUsage:
    def test_finds_used_symbols(self) -> None:
        tree = _parse_ts(TS_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 5, Language.TYPESCRIPT)
        assert "helper" in symbols
        assert "config" in symbols
        assert "MyClass" in symbols

    def test_excludes_definitions(self) -> None:
        tree = _parse_ts(TS_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 5, Language.TYPESCRIPT)
        assert "result" not in symbols
        assert "value" not in symbols

    def test_excludes_params(self) -> None:
        tree = _parse_ts(TS_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 5, Language.TYPESCRIPT)
        assert "data" not in symbols

    def test_attribute_root_only(self) -> None:
        tree = _parse_ts(TS_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 5, Language.TYPESCRIPT)
        assert "config" in symbols
        assert "get" not in symbols

    def test_exclude_ts_builtins(self) -> None:
        tree = _parse_ts(TS_BUILTINS)
        symbols = find_used_symbols(tree, 1, 2, Language.TYPESCRIPT, exclude_builtins=True)
        assert "console" not in symbols
        assert "JSON" not in symbols
        assert "Partial" not in symbols

    def test_include_builtins_by_default(self) -> None:
        tree = _parse_ts(TS_BUILTINS)
        symbols = find_used_symbols(tree, 1, 2, Language.TYPESCRIPT, exclude_builtins=False)
        assert "console" in symbols
