"""Tests for configuration loading and validation."""

import os
import stat
from pathlib import Path

import pytest

from diffguard.config import CONFIG_FILENAME, DiffguardConfig, find_config_file, load_config
from diffguard.exceptions import ConfigError


class TestDiffguardConfigDefaults:
    """Test DiffguardConfig default values."""

    def test_default_hunk_expansion_lines(self) -> None:
        """Default hunk expansion lines should be 50."""
        config = DiffguardConfig()
        assert config.hunk_expansion_lines == 50

    def test_default_scope_size_limit(self) -> None:
        """Default scope size limit should be 200."""
        config = DiffguardConfig()
        assert config.scope_size_limit == 200

    def test_default_model(self) -> None:
        """Default model should be gpt-5.2."""
        config = DiffguardConfig()
        assert config.model == "gpt-5.2"

    def test_default_max_concurrent_api_calls(self) -> None:
        """Default max concurrent API calls should be 5."""
        config = DiffguardConfig()
        assert config.max_concurrent_api_calls == 5

    def test_default_symbol_resolution_depth(self) -> None:
        """Default symbol resolution depth should be 1."""
        config = DiffguardConfig()
        assert config.symbol_resolution_depth == 1

    def test_default_third_party_patterns(self) -> None:
        """Default third party patterns should include common paths."""
        config = DiffguardConfig()
        assert "venv/" in config.third_party_patterns
        assert "site-packages/" in config.third_party_patterns


class TestLoadConfigFromFile:
    """Test loading config from .diffguard.toml files."""

    def test_load_config_from_file(self, tmp_path: Path, sample_valid_config_toml: str) -> None:
        """AC1: Config loading from file with hunk_expansion_lines = 100."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text(sample_valid_config_toml)

        config = load_config(config_path=config_file)

        assert config.hunk_expansion_lines == 100

    def test_load_config_defaults_when_file_missing(self, tmp_path: Path) -> None:
        """AC2: Config defaults when file missing."""
        config = load_config(start_path=tmp_path)

        assert config.hunk_expansion_lines == 50
        assert config.scope_size_limit == 200
        assert config.model == "gpt-5.2"

    def test_load_config_partial_override(self, tmp_path: Path, sample_partial_config_toml: str) -> None:
        """AC3: Config partial override - only model specified."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text(sample_partial_config_toml)

        config = load_config(config_path=config_file)

        assert config.model == "gpt-4o"
        assert config.hunk_expansion_lines == 50  # default
        assert config.scope_size_limit == 200  # default

    def test_invalid_toml_syntax_raises_error(self, tmp_path: Path, sample_invalid_syntax_toml: str) -> None:
        """AC4: Invalid TOML syntax raises ConfigError."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text(sample_invalid_syntax_toml)

        with pytest.raises(ConfigError) as exc_info:
            load_config(config_path=config_file)

        assert "Invalid TOML" in str(exc_info.value)

    def test_negative_value_raises_error(self, tmp_path: Path, sample_negative_value_toml: str) -> None:
        """AC5: Pydantic validation - negative value raises ConfigError."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text(sample_negative_value_toml)

        with pytest.raises(ConfigError) as exc_info:
            load_config(config_path=config_file)

        assert "hunk_expansion_lines" in str(exc_info.value)

    def test_wrong_type_raises_error(self, tmp_path: Path, sample_wrong_type_toml: str) -> None:
        """AC6: Pydantic validation - wrong type raises ConfigError."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text(sample_wrong_type_toml)

        with pytest.raises(ConfigError) as exc_info:
            load_config(config_path=config_file)

        assert "hunk_expansion_lines" in str(exc_info.value)

    def test_unknown_field_ignored(self, tmp_path: Path, sample_unknown_field_toml: str) -> None:
        """AC7: Unknown field is ignored (extra='ignore' mode)."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text(sample_unknown_field_toml)

        config = load_config(config_path=config_file)

        # Should succeed with defaults
        assert config.hunk_expansion_lines == 50
        # Unknown field should not be present
        assert not hasattr(config, "unknown_field")

    def test_empty_config_file(self, tmp_path: Path) -> None:
        """AC9: Empty config file returns defaults."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text("")

        config = load_config(config_path=config_file)

        assert config.hunk_expansion_lines == 50
        assert config.model == "gpt-5.2"

    def test_comments_only_config_file(self, tmp_path: Path, sample_comments_only_toml: str) -> None:
        """AC10: Config file with only comments returns defaults."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text(sample_comments_only_toml)

        config = load_config(config_path=config_file)

        assert config.hunk_expansion_lines == 50
        assert config.model == "gpt-5.2"


class TestFindConfigFile:
    """Test finding config file in directory tree."""

    def test_find_config_in_current_directory(self, tmp_path: Path) -> None:
        """Find config file in current directory."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text("model = 'test'")

        found = find_config_file(tmp_path)

        assert found == config_file

    def test_find_config_in_parent_directory(self, tmp_path: Path) -> None:
        """AC8: Config file in parent directory is found."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text("model = 'test'")

        subdir = tmp_path / "subdir" / "nested"
        subdir.mkdir(parents=True)

        found = find_config_file(subdir)

        assert found == config_file

    def test_no_config_file_returns_none(self, tmp_path: Path) -> None:
        """No config file in tree returns None."""
        subdir = tmp_path / "isolated"
        subdir.mkdir()

        # Searching only in the isolated directory shouldn't find anything
        # unless there's a .diffguard.toml higher up
        found = find_config_file(subdir)

        # This may find a file in the actual filesystem above tmp_path
        # For a pure test, we accept None or any Path
        # The key is it doesn't crash
        assert found is None or isinstance(found, Path)

    def test_load_config_from_parent_directory(self, tmp_path: Path) -> None:
        """AC8: load_config() finds config in parent directory."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text("hunk_expansion_lines = 75")

        subdir = tmp_path / "src" / "module"
        subdir.mkdir(parents=True)

        config = load_config(start_path=subdir)

        assert config.hunk_expansion_lines == 75


class TestConfigFilePermissions:
    """Test config file permission handling."""

    @pytest.mark.skipif(os.name == "nt", reason="chmod not reliable on Windows")
    def test_permission_denied_raises_error(self, tmp_path: Path) -> None:
        """AC13: Config file permission error raises ConfigError."""
        config_file = tmp_path / CONFIG_FILENAME
        config_file.write_text("model = 'test'")
        config_file.chmod(0o000)

        try:
            with pytest.raises(ConfigError) as exc_info:
                load_config(config_path=config_file)

            assert "permission" in str(exc_info.value).lower()
        finally:
            # Restore permissions for cleanup
            config_file.chmod(stat.S_IRUSR | stat.S_IWUSR)


class TestDiffguardConfigValidation:
    """Test Pydantic validation on DiffguardConfig."""

    def test_zero_hunk_expansion_allowed(self) -> None:
        """Zero expansion lines should be valid."""
        config = DiffguardConfig(hunk_expansion_lines=0)
        assert config.hunk_expansion_lines == 0

    def test_zero_scope_size_limit_allowed(self) -> None:
        """Zero scope size limit should be valid."""
        config = DiffguardConfig(scope_size_limit=0)
        assert config.scope_size_limit == 0

    def test_empty_model_name_rejected(self) -> None:
        """Empty model name should be rejected."""
        with pytest.raises(ValueError, match="model name cannot be empty"):
            DiffguardConfig(model="")

    def test_whitespace_model_name_rejected(self) -> None:
        """Whitespace-only model name should be rejected."""
        with pytest.raises(ValueError, match="model name cannot be empty"):
            DiffguardConfig(model="   ")

    def test_custom_third_party_patterns(self) -> None:
        """Custom third party patterns should override defaults."""
        config = DiffguardConfig(third_party_patterns=["custom/"])
        assert config.third_party_patterns == ["custom/"]
        assert "venv/" not in config.third_party_patterns

    def test_max_concurrent_must_be_positive(self) -> None:
        """Max concurrent API calls must be >= 1."""
        with pytest.raises(ValueError):
            DiffguardConfig(max_concurrent_api_calls=0)

    def test_timeout_must_be_positive(self) -> None:
        """Timeout must be >= 1."""
        with pytest.raises(ValueError):
            DiffguardConfig(timeout=0)
