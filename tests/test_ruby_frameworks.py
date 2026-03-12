"""Tests for Ruby framework support (Rails, Sinatra, Padrino)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from diffguard.ast.languages import Language
from diffguard.ast.ruby import (
    _class_to_snake,
    _detect_rails_project,
    _resolve_rails_autoload,
    clear_gemfile_cache,
    is_first_party_ruby,
    resolve_ruby_symbol,
)
from diffguard.config import DiffguardConfig
from diffguard.exclusions import is_generated_file
from diffguard.pipeline import _is_vendor_path

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


@pytest.fixture()
def rails_project(tmp_path: Path) -> Generator[Path]:
    """Create a minimal Rails project structure."""
    # Rails marker
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "application.rb").write_text("module MyApp\nend\n")

    # Models
    (tmp_path / "app" / "models").mkdir(parents=True)
    (tmp_path / "app" / "models" / "user.rb").write_text("class User\nend\n")

    # Controllers
    (tmp_path / "app" / "controllers").mkdir(parents=True)
    (tmp_path / "app" / "controllers" / "users_controller.rb").write_text("class UsersController\nend\n")
    (tmp_path / "app" / "controllers" / "admin").mkdir()
    (tmp_path / "app" / "controllers" / "admin" / "dashboard_controller.rb").write_text(
        "class Admin::DashboardController\nend\n"
    )

    # Mailers
    (tmp_path / "app" / "mailers").mkdir(parents=True)
    (tmp_path / "app" / "mailers" / "user_mailer.rb").write_text("class UserMailer\nend\n")

    # Jobs
    (tmp_path / "app" / "jobs").mkdir(parents=True)
    (tmp_path / "app" / "jobs" / "user_job.rb").write_text("class UserJob\nend\n")

    clear_gemfile_cache()
    yield tmp_path
    clear_gemfile_cache()


@pytest.fixture()
def non_rails_project(tmp_path: Path) -> Generator[Path]:
    """Create a non-Rails Ruby project (no config/application.rb)."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "helper.rb").write_text("class Helper\nend\n")
    clear_gemfile_cache()
    yield tmp_path
    clear_gemfile_cache()


class TestRailsDetection:
    def test_detects_rails_project(self, rails_project: Path) -> None:
        assert _detect_rails_project(rails_project) is True

    def test_non_rails_project(self, non_rails_project: Path) -> None:
        assert _detect_rails_project(non_rails_project) is False


class TestRailsAutoloadResolution:
    def test_resolves_model(self, rails_project: Path) -> None:
        result = _resolve_rails_autoload("User", rails_project)
        assert result == rails_project / "app" / "models" / "user.rb"

    def test_resolves_controller(self, rails_project: Path) -> None:
        result = _resolve_rails_autoload("UsersController", rails_project)
        assert result == rails_project / "app" / "controllers" / "users_controller.rb"

    def test_resolves_namespaced_controller(self, rails_project: Path) -> None:
        result = _resolve_rails_autoload("Admin::DashboardController", rails_project)
        assert result == rails_project / "app" / "controllers" / "admin" / "dashboard_controller.rb"

    def test_resolves_mailer(self, rails_project: Path) -> None:
        result = _resolve_rails_autoload("UserMailer", rails_project)
        assert result == rails_project / "app" / "mailers" / "user_mailer.rb"

    def test_resolves_job(self, rails_project: Path) -> None:
        result = _resolve_rails_autoload("UserJob", rails_project)
        assert result == rails_project / "app" / "jobs" / "user_job.rb"

    def test_returns_none_for_unknown_symbol(self, rails_project: Path) -> None:
        result = _resolve_rails_autoload("NonExistent", rails_project)
        assert result is None


class TestRailsSymbolResolutionFallback:
    def test_rails_falls_back_to_autoload(self, rails_project: Path) -> None:
        result = resolve_ruby_symbol("User", imports=[], project_root=rails_project)
        assert result == rails_project / "app" / "models" / "user.rb"

    def test_non_rails_returns_none_without_import(self, non_rails_project: Path) -> None:
        result = resolve_ruby_symbol("User", imports=[], project_root=non_rails_project)
        assert result is None


class TestRailsFirstPartyDetection:
    def test_autoloaded_symbol_is_first_party(self, rails_project: Path) -> None:
        assert is_first_party_ruby("user", rails_project) is True


class TestRailsGeneratedFileDetection:
    def test_auto_generated_migration_detected(self) -> None:
        lines = [
            "# This migration was auto-generated",
            "class AddUsersTable < ActiveRecord::Migration[7.0]",
            "  def change",
            "  end",
            "end",
        ]
        assert is_generated_file("db/migrate/20240101_add_users.rb", lines, Language.RUBY) is True

    def test_hand_written_migration_not_detected(self) -> None:
        lines = [
            "class AddUsersTable < ActiveRecord::Migration[7.0]",
            "  def change",
            "    create_table :users do |t|",
            "    end",
            "  end",
            "end",
        ]
        assert is_generated_file("db/migrate/20240101_add_users.rb", lines, Language.RUBY) is False


class TestRailsVendorPathFiltering:
    def test_tmp_cache_filtered(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("tmp/cache/assets/app.js", config.third_party_patterns) is True

    def test_log_filtered(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("log/development.rb", config.third_party_patterns) is True


class TestClassToSnake:
    def test_simple_class(self) -> None:
        assert _class_to_snake("User") == "user"

    def test_multi_word_class(self) -> None:
        assert _class_to_snake("UsersController") == "users_controller"

    def test_namespaced_class(self) -> None:
        assert _class_to_snake("Admin::DashboardController") == "admin/dashboard_controller"

    def test_acronym_handling(self) -> None:
        assert _class_to_snake("HTMLParser") == "html_parser"
