"""Tests for Elixir framework support (Phoenix, LiveView)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from diffguard.ast import Language, detect_language, is_first_party
from diffguard.ast.elixir import _detect_phoenix_project, clear_caches, resolve_elixir_symbol
from diffguard.config import DiffguardConfig
from diffguard.exclusions import is_generated_file

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

PHOENIX_MIX_EXS = """
defmodule MyAppWeb.MixProject do
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
      {:phoenix_live_view, "~> 0.20"},
      {:phoenix_html, "~> 4.0"},
      {:ecto_sql, "~> 3.10"},
      {:postgrex, ">= 0.0.0"},
      {:jason, "~> 1.2"}
    ]
  end
end
"""

NON_PHOENIX_MIX_EXS = """
defmodule MyLib.MixProject do
  use Mix.Project

  def project do
    [
      app: :my_lib,
      version: "0.1.0",
      elixir: "~> 1.14",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.2"},
      {:httpoison, "~> 2.0"}
    ]
  end
end
"""


def _write_mix_exs(tmp_path: Path, content: str) -> None:
    (tmp_path / "mix.exs").write_text(content)


def _create_file(tmp_path: Path, rel_path: str) -> Path:
    full = tmp_path / rel_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text("defmodule Placeholder do\nend\n")
    return full


# ---------------------------------------------------------------------------
# Phoenix detection
# ---------------------------------------------------------------------------


class TestPhoenixDetection:
    def test_detect_phoenix_project(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, PHOENIX_MIX_EXS)
        assert _detect_phoenix_project(tmp_path) is True

    def test_non_phoenix_project(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, NON_PHOENIX_MIX_EXS)
        assert _detect_phoenix_project(tmp_path) is False

    def test_no_mix_exs(self, tmp_path: Path) -> None:
        clear_caches()
        assert _detect_phoenix_project(tmp_path) is False


# ---------------------------------------------------------------------------
# Phoenix symbol resolution
# ---------------------------------------------------------------------------


class TestPhoenixSymbolResolution:
    def test_resolve_controller(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, PHOENIX_MIX_EXS)
        target = _create_file(tmp_path, "lib/my_app_web/controllers/page_controller.ex")

        result = resolve_elixir_symbol("MyAppWeb.PageController", [], tmp_path)
        assert result == target

    def test_resolve_liveview_module(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, PHOENIX_MIX_EXS)
        target = _create_file(tmp_path, "lib/my_app_web/live/user_live/index.ex")

        result = resolve_elixir_symbol("MyAppWeb.UserLive.Index", [], tmp_path)
        assert result == target

    def test_resolve_component_module(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, PHOENIX_MIX_EXS)
        target = _create_file(tmp_path, "lib/my_app_web/components/core_components.ex")

        result = resolve_elixir_symbol("MyAppWeb.CoreComponents", [], tmp_path)
        assert result == target

    def test_resolve_router(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, PHOENIX_MIX_EXS)
        target = _create_file(tmp_path, "lib/my_app_web/router.ex")

        result = resolve_elixir_symbol("MyAppWeb.Router", [], tmp_path)
        assert result == target

    def test_resolve_endpoint(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, PHOENIX_MIX_EXS)
        target = _create_file(tmp_path, "lib/my_app_web/endpoint.ex")

        result = resolve_elixir_symbol("MyAppWeb.Endpoint", [], tmp_path)
        assert result == target

    def test_non_phoenix_does_not_use_convention(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, NON_PHOENIX_MIX_EXS)
        _create_file(tmp_path, "lib/my_lib_web/controllers/page_controller.ex")

        result = resolve_elixir_symbol("MyLibWeb.PageController", [], tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# First-party detection in Phoenix projects
# ---------------------------------------------------------------------------


class TestPhoenixFirstParty:
    def test_web_namespace_is_first_party(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, PHOENIX_MIX_EXS)
        assert is_first_party("MyAppWeb.PageController", tmp_path, None, Language.ELIXIR) is True

    def test_app_namespace_is_first_party(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, PHOENIX_MIX_EXS)
        assert is_first_party("MyApp.Accounts", tmp_path, None, Language.ELIXIR) is True

    def test_phoenix_dep_is_third_party(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, PHOENIX_MIX_EXS)
        assert is_first_party("Phoenix.Controller", tmp_path, None, Language.ELIXIR) is False

    def test_ecto_dep_is_third_party(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, PHOENIX_MIX_EXS)
        assert is_first_party("Ecto.Changeset", tmp_path, None, Language.ELIXIR) is False

    def test_non_phoenix_web_not_first_party(self, tmp_path: Path) -> None:
        clear_caches()
        _write_mix_exs(tmp_path, NON_PHOENIX_MIX_EXS)
        assert is_first_party("MyLibWeb.Something", tmp_path, None, Language.ELIXIR) is False


# ---------------------------------------------------------------------------
# HEEx template registration
# ---------------------------------------------------------------------------


class TestHeexDetection:
    def test_heex_detected_as_html(self) -> None:
        assert detect_language("page.html.heex") == Language.HTML

    def test_heex_in_nested_path(self) -> None:
        assert detect_language("lib/my_app_web/controllers/page_html/home.html.heex") == Language.HTML

    def test_heex_without_html_prefix(self) -> None:
        assert detect_language("templates/index.heex") == Language.HTML


# ---------------------------------------------------------------------------
# Vendor path filtering
# ---------------------------------------------------------------------------


class TestPhoenixVendorPaths:
    def test_priv_static_skipped(self) -> None:
        config = DiffguardConfig()
        assert any("priv/static/" in p for p in config.third_party_patterns)


# ---------------------------------------------------------------------------
# Generated file detection
# ---------------------------------------------------------------------------


class TestPhoenixGeneratedFiles:
    def test_minified_asset_detected(self) -> None:
        lines = ["x" * 600]
        assert is_generated_file("priv/static/assets/app-ABC123.js", lines, Language.JAVASCRIPT) is True

    def test_normal_elixir_not_detected(self) -> None:
        lines = ["defmodule MyAppWeb.PageController do", "  def index(conn, _params) do", "  end", "end"]
        assert is_generated_file("lib/my_app_web/controllers/page_controller.ex", lines, Language.ELIXIR) is False
