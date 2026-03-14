"""Tests for WordPress framework support."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from diffguard.ast.php import (
    _detect_wordpress_project,
    clear_composer_cache,
    is_first_party_php,
)
from diffguard.config import DiffguardConfig
from diffguard.pipeline import _is_vendor_path

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


@pytest.fixture()
def wp_full_project(tmp_path: Path) -> Generator[Path]:
    """Create a full WordPress installation structure."""
    (tmp_path / "wp-config.php").write_text("<?php\ndefine('DB_NAME', 'wp');\n")
    (tmp_path / "wp-includes").mkdir()
    (tmp_path / "wp-includes" / "class-wp-query.php").write_text("<?php\nclass WP_Query {}\n")
    (tmp_path / "wp-admin").mkdir()
    (tmp_path / "wp-admin" / "includes").mkdir()
    (tmp_path / "wp-admin" / "includes" / "dashboard.php").write_text("<?php\n")
    (tmp_path / "wp-content" / "plugins" / "my-plugin").mkdir(parents=True)
    (tmp_path / "wp-content" / "plugins" / "my-plugin" / "my-plugin.php").write_text(
        "<?php\n/*\nPlugin Name: My Plugin\n*/\n"
    )
    (tmp_path / "wp-content" / "plugins" / "my-plugin" / "includes").mkdir()
    (tmp_path / "wp-content" / "plugins" / "my-plugin" / "includes" / "class-handler.php").write_text(
        "<?php\nclass Handler {}\n"
    )
    (tmp_path / "wp-content" / "plugins" / "other-plugin").mkdir(parents=True)
    (tmp_path / "wp-content" / "plugins" / "other-plugin" / "other.php").write_text("<?php\n")
    (tmp_path / "wp-content" / "themes" / "my-theme").mkdir(parents=True)
    (tmp_path / "wp-content" / "themes" / "my-theme" / "functions.php").write_text("<?php\n")
    (tmp_path / "wp-content" / "cache").mkdir(parents=True)
    (tmp_path / "wp-content" / "uploads" / "2024" / "01").mkdir(parents=True)
    (tmp_path / "wp-content" / "upgrade").mkdir(parents=True)
    clear_composer_cache()
    yield tmp_path
    clear_composer_cache()


@pytest.fixture()
def wp_plugin_project(tmp_path: Path) -> Generator[Path]:
    """Create a standalone WordPress plugin project (no wp-config.php)."""
    (tmp_path / "my-plugin.php").write_text(
        "<?php\n/**\n * Plugin Name: My Plugin\n * Description: A test plugin\n */\n"
    )
    (tmp_path / "includes").mkdir()
    (tmp_path / "includes" / "class-handler.php").write_text("<?php\nclass Handler {}\n")
    clear_composer_cache()
    yield tmp_path
    clear_composer_cache()


@pytest.fixture()
def wp_theme_project(tmp_path: Path) -> Generator[Path]:
    """Create a standalone WordPress theme project."""
    (tmp_path / "style.css").write_text("/*\nTheme Name: My Theme\nVersion: 1.0\n*/\n")
    (tmp_path / "functions.php").write_text("<?php\n")
    (tmp_path / "index.php").write_text("<?php\nget_header();\n")
    clear_composer_cache()
    yield tmp_path
    clear_composer_cache()


@pytest.fixture()
def non_wp_project(tmp_path: Path) -> Generator[Path]:
    """Create a non-WordPress PHP project."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.php").write_text("<?php\nclass App {}\n")
    clear_composer_cache()
    yield tmp_path
    clear_composer_cache()


class TestWordPressDetection:
    def test_detects_full_install_via_wp_config(self, wp_full_project: Path) -> None:
        assert _detect_wordpress_project(wp_full_project) is True

    def test_detects_plugin_via_header(self, wp_plugin_project: Path) -> None:
        assert _detect_wordpress_project(wp_plugin_project) is True

    def test_detects_theme_via_style_css(self, wp_theme_project: Path) -> None:
        assert _detect_wordpress_project(wp_theme_project) is True

    def test_non_wordpress_project(self, non_wp_project: Path) -> None:
        assert _detect_wordpress_project(non_wp_project) is False


class TestWordPressFirstPartyDetection:
    def test_plugin_own_files_are_first_party(self, wp_full_project: Path) -> None:
        current_file = wp_full_project / "wp-content" / "plugins" / "my-plugin" / "includes" / "class-handler.php"
        assert (
            is_first_party_php(
                "SomeClass",
                wp_full_project,
                current_file=current_file,
            )
            is True
        )

    def test_wp_includes_is_third_party(self, wp_full_project: Path) -> None:
        current_file = wp_full_project / "wp-includes" / "class-wp-query.php"
        assert (
            is_first_party_php(
                "WP_Query",
                wp_full_project,
                current_file=current_file,
            )
            is False
        )

    def test_wp_admin_is_third_party(self, wp_full_project: Path) -> None:
        current_file = wp_full_project / "wp-admin" / "includes" / "dashboard.php"
        assert (
            is_first_party_php(
                "SomeClass",
                wp_full_project,
                current_file=current_file,
            )
            is False
        )

    def test_theme_own_files_are_first_party(self, wp_full_project: Path) -> None:
        current_file = wp_full_project / "wp-content" / "themes" / "my-theme" / "functions.php"
        assert (
            is_first_party_php(
                "ThemeHelper",
                wp_full_project,
                current_file=current_file,
            )
            is True
        )

    def test_non_wp_project_ignores_wp_logic(self, non_wp_project: Path) -> None:
        current_file = non_wp_project / "src" / "App.php"
        assert (
            is_first_party_php(
                "SomeClass",
                non_wp_project,
                current_file=current_file,
            )
            is False
        )


class TestWordPressVendorPathFiltering:
    def test_wp_includes_files_skipped(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("wp-includes/class-wp-query.php", config.third_party_patterns) is True

    def test_wp_admin_files_skipped(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("wp-admin/includes/dashboard.php", config.third_party_patterns) is True

    def test_cache_directory_files_skipped(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("wp-content/cache/supercache/index.html", config.third_party_patterns) is True

    def test_uploads_directory_files_skipped(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("wp-content/uploads/2024/01/image.php", config.third_party_patterns) is True

    def test_upgrade_directory_files_skipped(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("wp-content/upgrade/plugin-temp/file.php", config.third_party_patterns) is True

    def test_plugin_own_files_not_skipped(self) -> None:
        config = DiffguardConfig()
        assert _is_vendor_path("wp-content/plugins/my-plugin/my-plugin.php", config.third_party_patterns) is False
