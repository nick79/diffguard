"""Tests for Python symbol resolution."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from diffguard.ast import Language, parse_file
from diffguard.ast.python import (
    Import,
    extract_imports,
    find_used_symbols,
    is_first_party,
    resolve_symbol_definition,
)

if TYPE_CHECKING:
    from tree_sitter import Tree

# ---------------------------------------------------------------------------
# Fixtures — Python source strings
# ---------------------------------------------------------------------------

IMPORTS_PYTHON = """\
import os
import json
import numpy as np
from src.utils import helper, formatter
from src.utils import validator as v
from .local import LocalClass
from ..parent import ParentClass
from . import sibling
from third_party_lib import something
from module import *
"""

SIMPLE_IMPORT = """\
import os
"""

ALIASED_IMPORT = """\
import numpy as np
"""

MULTI_IMPORT = """\
import os, sys, json
"""

FROM_IMPORT_SINGLE = """\
from mymodule import helper
"""

FROM_IMPORT_MULTIPLE = """\
from mymodule import helper, formatter, validator
"""

FROM_IMPORT_ALIASED = """\
from mymodule import helper as h, formatter as fmt
"""

STAR_IMPORT = """\
from mymodule import *
"""

RELATIVE_IMPORT_SINGLE = """\
from .local import LocalClass
"""

RELATIVE_IMPORT_MULTI_DOT = """\
from ...parent.module import thing
"""

RELATIVE_IMPORT_DOTS_ONLY = """\
from . import sibling
"""

CODE_WITH_SYMBOLS = """\
def process(data):
    result = helper(data)
    validated = v.check(result)
    return MyClass(validated)
"""

CODE_WITH_ATTRIBUTE = """\
x = config.settings.value
"""

CODE_WITH_LOCAL_DEF = """\
x = 1
print(x)
"""

CODE_WITH_BUILTINS = """\
print(len(str(42)))
"""

CODE_WITH_CLASS_INSTANTIATION = """\
obj = MyClass()
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(source: str) -> Tree:
    tree = parse_file(source, Language.PYTHON)
    assert tree is not None
    return tree


@pytest.fixture
def fake_project(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "__init__.py").touch()
    (tmp_path / "src" / "utils.py").write_text("def helper(): pass\ndef formatter(): pass\n")
    (tmp_path / "src" / "api").mkdir()
    (tmp_path / "src" / "api" / "__init__.py").touch()
    (tmp_path / "src" / "api" / "handler.py").write_text("from .utils import helper\n")
    (tmp_path / "src" / "api" / "utils.py").write_text("def helper(): pass\n")
    return tmp_path


# ---------------------------------------------------------------------------
# TestExtractImports
# ---------------------------------------------------------------------------


class TestExtractImports:
    """Tests for extract_imports()."""

    def test_simple_import(self) -> None:
        tree = _parse(SIMPLE_IMPORT)
        imports = extract_imports(tree)
        assert len(imports) == 1
        assert imports[0].module == "os"
        assert imports[0].names is None
        assert imports[0].alias is None

    def test_import_with_alias(self) -> None:
        tree = _parse(ALIASED_IMPORT)
        imports = extract_imports(tree)
        assert len(imports) == 1
        assert imports[0].module == "numpy"
        assert imports[0].alias == "np"

    def test_multiple_imports_one_line(self) -> None:
        tree = _parse(MULTI_IMPORT)
        imports = extract_imports(tree)
        assert len(imports) == 3
        modules = {imp.module for imp in imports}
        assert modules == {"os", "sys", "json"}

    def test_from_import_single_name(self) -> None:
        tree = _parse(FROM_IMPORT_SINGLE)
        imports = extract_imports(tree)
        assert len(imports) == 1
        assert imports[0].module == "mymodule"
        assert imports[0].names == ["helper"]

    def test_from_import_multiple_names(self) -> None:
        tree = _parse(FROM_IMPORT_MULTIPLE)
        imports = extract_imports(tree)
        assert len(imports) == 1
        assert imports[0].module == "mymodule"
        assert imports[0].names == ["helper", "formatter", "validator"]

    def test_from_import_with_aliases(self) -> None:
        tree = _parse(FROM_IMPORT_ALIASED)
        imports = extract_imports(tree)
        assert len(imports) == 1
        assert imports[0].name_aliases == [("helper", "h"), ("formatter", "fmt")]

    def test_star_import(self) -> None:
        tree = _parse(STAR_IMPORT)
        imports = extract_imports(tree)
        assert len(imports) == 1
        assert imports[0].module == "mymodule"
        assert imports[0].names == ["*"]
        assert imports[0].is_star is True

    def test_relative_import_single_dot(self) -> None:
        tree = _parse(RELATIVE_IMPORT_SINGLE)
        imports = extract_imports(tree)
        assert len(imports) == 1
        assert imports[0].module == ".local"
        assert imports[0].is_relative is True
        assert imports[0].level == 1

    def test_relative_import_multiple_dots(self) -> None:
        tree = _parse(RELATIVE_IMPORT_MULTI_DOT)
        imports = extract_imports(tree)
        assert len(imports) == 1
        assert imports[0].module == "...parent.module"
        assert imports[0].is_relative is True
        assert imports[0].level == 3

    def test_relative_import_dots_only(self) -> None:
        tree = _parse(RELATIVE_IMPORT_DOTS_ONLY)
        imports = extract_imports(tree)
        assert len(imports) == 1
        assert imports[0].module == "."
        assert imports[0].names == ["sibling"]
        assert imports[0].level == 1

    def test_all_imports_from_fixture(self) -> None:
        tree = _parse(IMPORTS_PYTHON)
        imports = extract_imports(tree)
        assert len(imports) == 10
        modules = [imp.module for imp in imports]
        assert "os" in modules
        assert "json" in modules
        assert "numpy" in modules


# ---------------------------------------------------------------------------
# TestFindUsedSymbols
# ---------------------------------------------------------------------------


class TestFindUsedSymbols:
    """Tests for find_used_symbols()."""

    def test_function_calls(self) -> None:
        tree = _parse(CODE_WITH_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 4)
        assert "helper" in symbols
        assert "v" in symbols

    def test_attribute_access_root_only(self) -> None:
        tree = _parse(CODE_WITH_ATTRIBUTE)
        symbols = find_used_symbols(tree, 1, 1)
        assert "config" in symbols
        assert "settings" not in symbols
        assert "value" not in symbols

    def test_class_instantiation(self) -> None:
        tree = _parse(CODE_WITH_CLASS_INSTANTIATION)
        symbols = find_used_symbols(tree, 1, 1)
        assert "MyClass" in symbols

    def test_exclude_local_definitions(self) -> None:
        tree = _parse(CODE_WITH_LOCAL_DEF)
        symbols = find_used_symbols(tree, 1, 2)
        assert "print" in symbols
        assert "x" not in symbols

    def test_exclude_builtins(self) -> None:
        tree = _parse(CODE_WITH_BUILTINS)
        symbols = find_used_symbols(tree, 1, 1, exclude_builtins=True)
        assert "print" not in symbols
        assert "len" not in symbols
        assert "str" not in symbols

    def test_include_builtins_by_default(self) -> None:
        tree = _parse(CODE_WITH_BUILTINS)
        symbols = find_used_symbols(tree, 1, 1, exclude_builtins=False)
        assert "print" in symbols

    def test_function_params_excluded(self) -> None:
        tree = _parse(CODE_WITH_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 4)
        assert "data" not in symbols

    def test_myclass_in_code_with_symbols(self) -> None:
        tree = _parse(CODE_WITH_SYMBOLS)
        symbols = find_used_symbols(tree, 1, 4)
        assert "MyClass" in symbols


# ---------------------------------------------------------------------------
# TestIsFirstParty
# ---------------------------------------------------------------------------


class TestIsFirstParty:
    """Tests for is_first_party()."""

    def test_stdlib_not_first_party(self) -> None:
        assert is_first_party("os", Path("/project")) is False
        assert is_first_party("sys", Path("/project")) is False
        assert is_first_party("json", Path("/project")) is False
        assert is_first_party("pathlib", Path("/project")) is False

    def test_relative_import_always_first_party(self) -> None:
        assert is_first_party(".utils", Path("/project"), is_relative=True) is True

    def test_third_party_venv_pattern(self) -> None:
        assert is_first_party("venv/lib/something", Path("/project"), ["venv/"]) is False

    def test_third_party_site_packages(self) -> None:
        assert is_first_party("lib/site-packages/requests", Path("/project"), ["site-packages/"]) is False

    def test_first_party_in_project(self, fake_project: Path) -> None:
        assert is_first_party("src.utils", fake_project) is True

    def test_third_party_known_package(self, fake_project: Path) -> None:
        # "requests" is not a stdlib and won't resolve to a project file
        assert is_first_party("requests", fake_project) is False


# ---------------------------------------------------------------------------
# TestResolveSymbolDefinition
# ---------------------------------------------------------------------------


class TestResolveSymbolDefinition:
    """Tests for resolve_symbol_definition()."""

    def test_resolve_direct_module(self, fake_project: Path) -> None:
        imports = [Import(module="src.utils", names=["helper"])]
        result = resolve_symbol_definition("helper", imports, fake_project)
        assert result is not None
        assert result.name == "utils.py"

    def test_resolve_package_init(self, fake_project: Path) -> None:
        imports = [Import(module="src.api", names=["handler"])]
        result = resolve_symbol_definition("handler", imports, fake_project)
        assert result is not None
        assert result.name == "__init__.py"

    def test_resolve_not_found(self, fake_project: Path) -> None:
        imports = [Import(module="nonexistent", names=["missing"])]
        result = resolve_symbol_definition("missing", imports, fake_project)
        assert result is None

    def test_resolve_relative_import(self, fake_project: Path) -> None:
        imports = [Import(module=".utils", names=["helper"], is_relative=True, level=1)]
        current_file = fake_project / "src" / "api" / "handler.py"
        result = resolve_symbol_definition("helper", imports, fake_project, current_file)
        assert result is not None
        assert result.name == "utils.py"
        assert "api" in str(result)

    def test_resolve_symbol_not_in_imports(self, fake_project: Path) -> None:
        imports = [Import(module="src.utils", names=["helper"])]
        result = resolve_symbol_definition("unknown_symbol", imports, fake_project)
        assert result is None

    def test_resolve_aliased_import(self, fake_project: Path) -> None:
        imports = [Import(module="src.utils", alias="utils")]
        result = resolve_symbol_definition("utils", imports, fake_project)
        assert result is not None
        assert result.name == "utils.py"

    def test_resolve_from_import_alias(self, fake_project: Path) -> None:
        imports = [Import(module="src.utils", name_aliases=[("helper", "h")])]
        result = resolve_symbol_definition("h", imports, fake_project)
        assert result is not None
        assert result.name == "utils.py"

    def test_circular_import_no_infinite_loop(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("from b import thing\n")
        (tmp_path / "b.py").write_text("from a import other\n")
        imports = [Import(module="a", names=["thing"])]
        result = resolve_symbol_definition("thing", imports, tmp_path)
        assert result is not None
        assert result.name == "a.py"
