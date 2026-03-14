"""Tests for Laravel framework support."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from diffguard.ast.languages import Language
from diffguard.ast.php import (
    _detect_laravel_project,
    _resolve_laravel_convention,
    _resolve_laravel_symbol,
    clear_composer_cache,
    is_first_party_php,
    resolve_php_symbol,
)
from diffguard.config import DiffguardConfig
from diffguard.exclusions import is_generated_file
from diffguard.pipeline import _is_vendor_path

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


@pytest.fixture()
def laravel_project(tmp_path: Path) -> Generator[Path]:
    """Create a minimal Laravel project structure."""
    # Laravel marker
    (tmp_path / "artisan").write_text("#!/usr/bin/env php\n")

    # Models
    (tmp_path / "app" / "Models").mkdir(parents=True)
    (tmp_path / "app" / "Models" / "User.php").write_text("<?php\nclass User {}\n")

    # Controllers
    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)
    (tmp_path / "app" / "Http" / "Controllers" / "UserController.php").write_text("<?php\nclass UserController {}\n")

    # Nested namespace
    (tmp_path / "app" / "Services" / "Payment").mkdir(parents=True)
    (tmp_path / "app" / "Services" / "Payment" / "StripeService.php").write_text("<?php\nclass StripeService {}\n")

    clear_composer_cache()
    yield tmp_path
    clear_composer_cache()


@pytest.fixture()
def non_laravel_project(tmp_path: Path) -> Generator[Path]:
    """Create a non-Laravel PHP project (no artisan file)."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Helper.php").write_text("<?php\nclass Helper {}\n")
    clear_composer_cache()
    yield tmp_path
    clear_composer_cache()


class TestLaravelDetection:
    def test_detects_laravel_project(self, laravel_project: Path) -> None:
        assert _detect_laravel_project(laravel_project) is True

    def test_non_laravel_project(self, non_laravel_project: Path) -> None:
        assert _detect_laravel_project(non_laravel_project) is False


class TestLaravelConventionResolution:
    def test_resolves_model_by_namespace(self, laravel_project: Path) -> None:
        result = _resolve_laravel_convention("App\\Models\\User", laravel_project)
        assert result == laravel_project / "app" / "Models" / "User.php"

    def test_resolves_controller_by_namespace(self, laravel_project: Path) -> None:
        result = _resolve_laravel_convention("App\\Http\\Controllers\\UserController", laravel_project)
        assert result == laravel_project / "app" / "Http" / "Controllers" / "UserController.php"

    def test_resolves_nested_namespace(self, laravel_project: Path) -> None:
        result = _resolve_laravel_convention("App\\Services\\Payment\\StripeService", laravel_project)
        assert result == laravel_project / "app" / "Services" / "Payment" / "StripeService.php"

    def test_returns_none_for_non_app_namespace(self, laravel_project: Path) -> None:
        result = _resolve_laravel_convention("Illuminate\\Support\\Facades\\Auth", laravel_project)
        assert result is None

    def test_returns_none_for_nonexistent_file(self, laravel_project: Path) -> None:
        result = _resolve_laravel_convention("App\\Models\\NonExistent", laravel_project)
        assert result is None

    def test_resolves_model_by_symbol(self, laravel_project: Path) -> None:
        result = _resolve_laravel_symbol("User", laravel_project)
        assert result == laravel_project / "app" / "Models" / "User.php"

    def test_resolves_controller_by_symbol(self, laravel_project: Path) -> None:
        result = _resolve_laravel_symbol("UserController", laravel_project)
        assert result == laravel_project / "app" / "Http" / "Controllers" / "UserController.php"

    def test_symbol_returns_none_for_unknown(self, laravel_project: Path) -> None:
        result = _resolve_laravel_symbol("NonExistent", laravel_project)
        assert result is None


class TestLaravelSymbolResolutionFallback:
    def test_laravel_falls_back_to_convention(self, laravel_project: Path) -> None:
        # No import for User, but Laravel convention resolves it
        result = resolve_php_symbol("User", imports=[], project_root=laravel_project)
        assert result == laravel_project / "app" / "Models" / "User.php"

    def test_non_laravel_returns_none_without_import(self, non_laravel_project: Path) -> None:
        result = resolve_php_symbol("User", imports=[], project_root=non_laravel_project)
        assert result is None


class TestLaravelFirstPartyDetection:
    def test_app_namespace_is_first_party(self, laravel_project: Path) -> None:
        assert is_first_party_php("App\\Models\\User", laravel_project) is True

    def test_vendor_namespace_is_third_party(self, laravel_project: Path) -> None:
        assert is_first_party_php("Illuminate\\Support\\Facades\\Auth", laravel_project) is False

    def test_app_namespace_not_first_party_in_non_laravel(self, non_laravel_project: Path) -> None:
        assert is_first_party_php("App\\Models\\User", non_laravel_project) is False


class TestLaravelGeneratedFileDetection:
    def test_compiled_blade_view_detected(self) -> None:
        lines = ["<?php // auto-generated", "echo 'Hello';"]
        assert is_generated_file("storage/framework/views/abc123.php", lines, Language.PHP) is True

    def test_normal_php_file_not_detected(self) -> None:
        lines = ["<?php", "class User {", "}"]
        assert is_generated_file("app/Models/User.php", lines, Language.PHP) is False

    def test_storage_framework_views_path_detected(self) -> None:
        lines = ["<?php", "echo 'compiled';"]
        assert is_generated_file("storage/framework/views/abc123.php", lines, Language.PHP) is True


class TestLaravelVendorPathFiltering:
    def test_storage_framework_filtered(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("storage/framework/cache/data/abc.php", config.third_party_patterns) is True

    def test_storage_framework_views_filtered(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("storage/framework/views/abc123.php", config.third_party_patterns) is True

    def test_app_models_not_filtered(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("app/Models/User.php", config.third_party_patterns) is False
