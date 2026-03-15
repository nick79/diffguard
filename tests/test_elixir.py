"""Tests for Elixir language support."""

from __future__ import annotations

from typing import TYPE_CHECKING

from diffguard.ast import Import, Language, detect_language, extract_imports, find_used_symbols, is_first_party
from diffguard.ast.elixir import clear_caches, resolve_elixir_symbol
from diffguard.ast.parser import parse_file
from diffguard.ast.scope import find_enclosing_scope
from diffguard.config import DiffguardConfig
from diffguard.exclusions import is_generated_file

if TYPE_CHECKING:
    from pathlib import Path

    from tree_sitter import Tree

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

ELIXIR_MODULE_WITH_FUNCTIONS = """
defmodule MyApp.Accounts do
  alias MyApp.Repo
  alias MyApp.Accounts.User

  def list_users do
    Repo.all(User)
  end

  def get_user!(id) do
    Repo.get!(User, id)
  end

  defp validate_attrs(attrs) do
    # validation logic
    attrs
  end
end
"""

ELIXIR_IMPORTS = """
defmodule MyApp.AccountsTest do
  use ExUnit.Case
  alias MyApp.Accounts
  alias MyApp.Accounts.{User, Role}
  import Ecto.Query, only: [from: 2]
  require Logger

  test "list users" do
    Logger.info("testing")
    query = from u in User, select: u
    assert Accounts.list_users() == []
  end
end
"""

ELIXIR_PROTOCOL = """
defprotocol Printable do
  @doc "Converts data to a printable string"
  def to_string(data)
end

defimpl Printable, for: User do
  def to_string(user) do
    user.name
  end
end
"""

ELIXIR_GENSERVER = """
defmodule MyApp.Cache do
  use GenServer

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    {:ok, %{}}
  end

  @impl true
  def handle_call({:get, key}, _from, state) do
    {:reply, Map.get(state, key), state}
  end
end
"""

ELIXIR_ANONYMOUS_FN = """
defmodule MyApp.Processor do
  def process(items) do
    Enum.map(items, fn item ->
      transform(item)
    end)
  end

  defp transform(item) do
    String.upcase(item.name)
  end
end
"""

ELIXIR_GUARD = """
defmodule MyApp.Validators do
  defguard is_positive(value) when is_number(value) and value > 0
  defguardp is_valid_age(age) when is_integer(age) and age >= 0 and age <= 150
end
"""

MIX_EXS_CONTENT = """
defmodule MyApp.MixProject do
  use Mix.Project

  def project do
    [
      app: :my_app,
      version: "0.1.0",
      elixir: "~> 1.14",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:ecto, "~> 3.10"},
      {:jason, "~> 1.2"}
    ]
  end
end
"""

ELIXIR_ALIAS_WITH_AS = """
defmodule MyApp.Example do
  alias MyApp.Accounts.User, as: U

  def run do
    U.new()
  end
end
"""


def _parse_elixir(source: str) -> Tree:
    """Parse Elixir source and return tree, asserting success."""
    tree = parse_file(source, Language.ELIXIR)
    assert tree is not None
    return tree


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


class TestElixirLanguageDetection:
    def test_detect_ex_extension(self) -> None:
        assert detect_language("lib/my_app/accounts.ex") == Language.ELIXIR

    def test_detect_exs_extension(self) -> None:
        assert detect_language("test/my_app_test.exs") == Language.ELIXIR

    def test_detect_mix_exs(self) -> None:
        assert detect_language("mix.exs") == Language.ELIXIR

    def test_non_elixir_file(self) -> None:
        assert detect_language("main.py") != Language.ELIXIR


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class TestElixirParsing:
    def test_parse_valid_module(self) -> None:
        tree = _parse_elixir(ELIXIR_MODULE_WITH_FUNCTIONS)
        assert tree.root_node.has_error is False

    def test_parse_protocol(self) -> None:
        tree = _parse_elixir(ELIXIR_PROTOCOL)
        assert tree.root_node.has_error is False

    def test_parse_genserver(self) -> None:
        tree = _parse_elixir(ELIXIR_GENSERVER)
        assert tree.root_node.has_error is False

    def test_parse_guard(self) -> None:
        tree = _parse_elixir(ELIXIR_GUARD)
        assert tree.root_node.has_error is False


# ---------------------------------------------------------------------------
# Scope detection
# ---------------------------------------------------------------------------


class TestElixirScopeDetection:
    def test_detect_module_scope(self) -> None:
        tree = _parse_elixir(ELIXIR_MODULE_WITH_FUNCTIONS)
        # Line 4 is "alias MyApp.Accounts.User" — inside module, outside functions
        scope = find_enclosing_scope(tree, 4, Language.ELIXIR)
        assert scope is not None
        assert scope.type == "module"
        assert scope.name == "MyApp.Accounts"

    def test_detect_public_function_scope(self) -> None:
        tree = _parse_elixir(ELIXIR_MODULE_WITH_FUNCTIONS)
        # Line 7 is "Repo.all(User)" inside list_users
        scope = find_enclosing_scope(tree, 7, Language.ELIXIR)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "list_users"

    def test_detect_private_function_scope(self) -> None:
        tree = _parse_elixir(ELIXIR_MODULE_WITH_FUNCTIONS)
        # Line 16 is "attrs" inside validate_attrs
        scope = find_enclosing_scope(tree, 16, Language.ELIXIR)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "validate_attrs"

    def test_detect_protocol_scope(self) -> None:
        tree = _parse_elixir(ELIXIR_PROTOCOL)
        # Line 3 is inside defprotocol Printable
        scope = find_enclosing_scope(tree, 3, Language.ELIXIR)
        assert scope is not None
        assert scope.type == "protocol"
        assert scope.name == "Printable"

    def test_detect_impl_scope(self) -> None:
        tree = _parse_elixir(ELIXIR_PROTOCOL)
        # Line 8 is inside defimpl
        scope = find_enclosing_scope(tree, 8, Language.ELIXIR)
        assert scope is not None
        assert scope.type in ("function", "implementation")

    def test_detect_anonymous_function_scope(self) -> None:
        tree = _parse_elixir(ELIXIR_ANONYMOUS_FN)
        # Line 5 is "transform(item)" inside the fn
        scope = find_enclosing_scope(tree, 5, Language.ELIXIR)
        assert scope is not None
        assert scope.type == "anonymous_function"

    def test_detect_guard_scope(self) -> None:
        tree = _parse_elixir(ELIXIR_GUARD)
        # Line 3 is the defguard line
        scope = find_enclosing_scope(tree, 3, Language.ELIXIR)
        assert scope is not None
        assert scope.type == "guard"
        assert scope.name == "is_positive"

    def test_detect_macro_scope(self) -> None:
        source = """
defmodule MyApp.Macros do
  defmacro my_macro(arg) do
    quote do
      unquote(arg)
    end
  end
end
"""
        tree = _parse_elixir(source)
        # Line 4 is inside the macro body
        scope = find_enclosing_scope(tree, 4, Language.ELIXIR)
        assert scope is not None
        assert scope.type == "macro"
        assert scope.name == "my_macro"

    def test_nested_scope_returns_innermost(self) -> None:
        tree = _parse_elixir(ELIXIR_MODULE_WITH_FUNCTIONS)
        # Line 7 is inside list_users which is inside MyApp.Accounts
        scope = find_enclosing_scope(tree, 7, Language.ELIXIR)
        assert scope is not None
        assert scope.type == "function"
        assert scope.name == "list_users"

    def test_no_scope_outside_module(self) -> None:
        source = "x = 1\n"
        tree = _parse_elixir(source)
        scope = find_enclosing_scope(tree, 1, Language.ELIXIR)
        assert scope is None


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------


class TestElixirImportExtraction:
    def test_extract_alias(self) -> None:
        tree = _parse_elixir(ELIXIR_MODULE_WITH_FUNCTIONS)
        imports = extract_imports(tree, Language.ELIXIR)
        modules = [imp.module for imp in imports]
        assert "MyApp.Repo" in modules
        assert "MyApp.Accounts.User" in modules

    def test_extract_multi_alias(self) -> None:
        tree = _parse_elixir(ELIXIR_IMPORTS)
        imports = extract_imports(tree, Language.ELIXIR)
        modules = [imp.module for imp in imports]
        assert "MyApp.Accounts.User" in modules
        assert "MyApp.Accounts.Role" in modules

    def test_extract_import_with_only(self) -> None:
        tree = _parse_elixir(ELIXIR_IMPORTS)
        imports = extract_imports(tree, Language.ELIXIR)
        ecto_imports = [imp for imp in imports if imp.module == "Ecto.Query"]
        assert len(ecto_imports) == 1
        assert ecto_imports[0].names is not None
        assert "from" in ecto_imports[0].names

    def test_extract_import_without_only_is_star(self) -> None:
        source = """
defmodule MyApp.Example do
  import Ecto.Query
end
"""
        tree = _parse_elixir(source)
        imports = extract_imports(tree, Language.ELIXIR)
        ecto_imports = [imp for imp in imports if imp.module == "Ecto.Query"]
        assert len(ecto_imports) == 1
        assert ecto_imports[0].is_star is True

    def test_extract_require(self) -> None:
        tree = _parse_elixir(ELIXIR_IMPORTS)
        imports = extract_imports(tree, Language.ELIXIR)
        modules = [imp.module for imp in imports]
        assert "Logger" in modules

    def test_extract_use(self) -> None:
        tree = _parse_elixir(ELIXIR_IMPORTS)
        imports = extract_imports(tree, Language.ELIXIR)
        modules = [imp.module for imp in imports]
        assert "ExUnit.Case" in modules

    def test_extract_alias_with_as(self) -> None:
        tree = _parse_elixir(ELIXIR_ALIAS_WITH_AS)
        imports = extract_imports(tree, Language.ELIXIR)
        aliased = [imp for imp in imports if imp.module == "MyApp.Accounts.User"]
        assert len(aliased) == 1
        assert aliased[0].alias == "U"


# ---------------------------------------------------------------------------
# Symbol usage detection
# ---------------------------------------------------------------------------


class TestElixirSymbolUsage:
    def test_detect_module_reference(self) -> None:
        tree = _parse_elixir(ELIXIR_MODULE_WITH_FUNCTIONS)
        # Lines 6-8 contain list_users which references Repo and User
        symbols = find_used_symbols(tree, 6, 8, Language.ELIXIR)
        assert "Repo" in symbols
        assert "User" in symbols

    def test_exclude_builtins(self) -> None:
        tree = _parse_elixir(ELIXIR_ANONYMOUS_FN)
        # Lines 4-6 contain Enum.map call
        symbols = find_used_symbols(tree, 4, 6, Language.ELIXIR, exclude_builtins=True)
        assert "Enum" not in symbols

    def test_include_builtins_by_default(self) -> None:
        tree = _parse_elixir(ELIXIR_ANONYMOUS_FN)
        symbols = find_used_symbols(tree, 4, 6, Language.ELIXIR, exclude_builtins=False)
        assert "Enum" in symbols

    def test_definition_names_excluded(self) -> None:
        tree = _parse_elixir(ELIXIR_MODULE_WITH_FUNCTIONS)
        # The whole module — function names should not be in used set
        symbols = find_used_symbols(tree, 1, 18, Language.ELIXIR)
        assert "list_users" not in symbols
        assert "validate_attrs" not in symbols

    def test_module_definition_excluded(self) -> None:
        tree = _parse_elixir(ELIXIR_MODULE_WITH_FUNCTIONS)
        # MyApp (from defmodule MyApp.Accounts) on line 2 should be a definition
        symbols = find_used_symbols(tree, 2, 2, Language.ELIXIR)
        assert "MyApp" not in symbols


# ---------------------------------------------------------------------------
# First-party detection
# ---------------------------------------------------------------------------


class TestElixirFirstParty:
    def test_project_module_is_first_party(self, tmp_path: Path) -> None:
        clear_caches()
        mix_path = tmp_path / "mix.exs"
        mix_path.write_text(MIX_EXS_CONTENT)
        assert is_first_party("MyApp.Accounts", tmp_path, None, Language.ELIXIR) is True

    def test_stdlib_module_not_first_party(self, tmp_path: Path) -> None:
        clear_caches()
        mix_path = tmp_path / "mix.exs"
        mix_path.write_text(MIX_EXS_CONTENT)
        assert is_first_party("Enum", tmp_path, None, Language.ELIXIR) is False

    def test_dep_module_not_first_party(self, tmp_path: Path) -> None:
        clear_caches()
        mix_path = tmp_path / "mix.exs"
        mix_path.write_text(MIX_EXS_CONTENT)
        assert is_first_party("Ecto.Query", tmp_path, None, Language.ELIXIR) is False

    def test_erlang_module_not_first_party(self, tmp_path: Path) -> None:
        clear_caches()
        assert is_first_party(":crypto", tmp_path, None, Language.ELIXIR) is False

    def test_phoenix_dep_not_first_party(self, tmp_path: Path) -> None:
        clear_caches()
        mix_path = tmp_path / "mix.exs"
        mix_path.write_text(MIX_EXS_CONTENT)
        assert is_first_party("Phoenix.Controller", tmp_path, None, Language.ELIXIR) is False

    def test_relative_is_first_party(self, tmp_path: Path) -> None:
        clear_caches()
        assert is_first_party("./helper", tmp_path, None, Language.ELIXIR, is_relative=True) is True


# ---------------------------------------------------------------------------
# Symbol resolution
# ---------------------------------------------------------------------------


class TestElixirSymbolResolution:
    def test_resolve_module_to_file(self, tmp_path: Path) -> None:
        clear_caches()
        lib_path = tmp_path / "lib" / "my_app" / "accounts" / "user.ex"
        lib_path.parent.mkdir(parents=True)
        lib_path.write_text("defmodule MyApp.Accounts.User do\nend\n")

        result = resolve_elixir_symbol("MyApp.Accounts.User", [], tmp_path)
        assert result == lib_path

    def test_resolve_simple_module(self, tmp_path: Path) -> None:
        clear_caches()
        lib_path = tmp_path / "lib" / "my_app" / "helper.ex"
        lib_path.parent.mkdir(parents=True)
        lib_path.write_text("defmodule MyApp.Helper do\nend\n")

        result = resolve_elixir_symbol("MyApp.Helper", [], tmp_path)
        assert result == lib_path

    def test_unresolvable_returns_none(self, tmp_path: Path) -> None:
        clear_caches()
        result = resolve_elixir_symbol("SomeUnknown.Module", [], tmp_path)
        assert result is None

    def test_resolve_via_alias(self, tmp_path: Path) -> None:
        clear_caches()
        lib_path = tmp_path / "lib" / "my_app" / "accounts" / "user.ex"
        lib_path.parent.mkdir(parents=True)
        lib_path.write_text("defmodule MyApp.Accounts.User do\nend\n")

        imports = [Import(module="MyApp.Accounts.User")]
        result = resolve_elixir_symbol("User", imports, tmp_path)
        assert result == lib_path

    def test_resolve_umbrella_project(self, tmp_path: Path) -> None:
        clear_caches()
        app_path = tmp_path / "apps" / "accounts" / "lib" / "accounts" / "user.ex"
        app_path.parent.mkdir(parents=True)
        app_path.write_text("defmodule Accounts.User do\nend\n")

        result = resolve_elixir_symbol("Accounts.User", [], tmp_path)
        assert result == app_path


# ---------------------------------------------------------------------------
# Vendor path filtering
# ---------------------------------------------------------------------------


class TestElixirVendorPaths:
    def test_deps_directory_skipped(self) -> None:
        config = DiffguardConfig()
        assert any("deps/" in p for p in config.third_party_patterns)

    def test_build_directory_skipped(self) -> None:
        config = DiffguardConfig()
        assert any("_build/" in p for p in config.third_party_patterns)


# ---------------------------------------------------------------------------
# Generated file detection
# ---------------------------------------------------------------------------


class TestElixirGeneratedFiles:
    def test_generated_header_detected(self) -> None:
        lines = ["# Generated by some tool", "defmodule Gen do", "end"]
        assert is_generated_file("gen.ex", lines, Language.ELIXIR) is True

    def test_do_not_edit_header_detected(self) -> None:
        lines = ["# DO NOT EDIT this file", "defmodule Gen do", "end"]
        assert is_generated_file("gen.ex", lines, Language.ELIXIR) is True

    def test_normal_file_not_detected(self) -> None:
        lines = ["defmodule MyApp.Accounts do", "  def list_users do", "  end", "end"]
        assert is_generated_file("accounts.ex", lines, Language.ELIXIR) is False

    def test_minified_file_detected(self) -> None:
        lines = ["x" * 600]
        assert is_generated_file("minified.ex", lines, Language.ELIXIR) is True
