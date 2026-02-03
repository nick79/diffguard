"""Configuration management for Diffguard."""

import tomllib
from pathlib import Path
from typing import Self

from pydantic import BaseModel, Field, ValidationError, model_validator

from diffguard.exceptions import ConfigError

CONFIG_FILENAME = ".diffguard.toml"


class DiffguardConfig(BaseModel):
    """Configuration for Diffguard security analysis."""

    model_config = {"extra": "ignore"}

    # Context building settings
    hunk_expansion_lines: int = Field(default=50, ge=0, description="Number of lines to expand around each hunk")
    scope_size_limit: int = Field(default=200, ge=0, description="Maximum lines for scope extraction before truncation")

    # Symbol resolution settings
    symbol_resolution_depth: int = Field(
        default=1, ge=0, description="How deep to follow imports for symbol resolution"
    )
    third_party_patterns: list[str] = Field(
        default_factory=lambda: ["venv/", ".venv/", "site-packages/", "node_modules/"],
        description="Patterns identifying third-party code paths",
    )

    # LLM settings
    model: str = Field(default="gpt-4o-mini", description="OpenAI model to use for analysis")
    max_concurrent_api_calls: int = Field(default=5, ge=1, description="Maximum concurrent API calls")
    timeout: int = Field(default=120, ge=1, description="API timeout in seconds")

    @model_validator(mode="after")
    def validate_model_name(self) -> Self:
        """Validate model name is not empty."""
        if not self.model.strip():
            msg = "model name cannot be empty"
            raise ValueError(msg)
        return self


def find_config_file(start_path: Path | None = None) -> Path | None:
    """Find .diffguard.toml by walking up the directory tree.

    Args:
        start_path: Starting directory. Defaults to current working directory.

    Returns:
        Path to config file if found, None otherwise.
    """
    if start_path is None:
        start_path = Path.cwd()

    current = start_path.resolve()

    while True:
        config_path = current / CONFIG_FILENAME
        if config_path.exists():
            return config_path

        parent = current.parent
        if parent == current:
            # Reached filesystem root
            return None
        current = parent


def load_config(config_path: Path | None = None, start_path: Path | None = None) -> DiffguardConfig:
    """Load configuration from .diffguard.toml file.

    Args:
        config_path: Explicit path to config file. If None, searches for it.
        start_path: Starting directory for config file search. Defaults to cwd.

    Returns:
        DiffguardConfig instance with loaded or default values.

    Raises:
        ConfigError: If config file has invalid TOML syntax, invalid values,
            or cannot be read due to permissions.
    """
    if config_path is None:
        config_path = find_config_file(start_path)

    if config_path is None:
        return DiffguardConfig()

    try:
        content = config_path.read_text(encoding="utf-8")
    except PermissionError as e:
        msg = f"Cannot read config file '{config_path}': permission denied"
        raise ConfigError(msg) from e
    except OSError as e:
        msg = f"Cannot read config file '{config_path}': {e}"
        raise ConfigError(msg) from e

    if not content.strip():
        return DiffguardConfig()

    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as e:
        msg = f"Invalid TOML in '{config_path}': {e}"
        raise ConfigError(msg) from e

    if not data:
        return DiffguardConfig()

    try:
        return DiffguardConfig(**data)
    except ValidationError as e:
        errors = e.errors()
        if errors:
            first_error = errors[0]
            field = ".".join(str(loc) for loc in first_error["loc"])
            error_type = first_error["type"]
            error_msg = first_error["msg"]
            msg = f"Invalid config value for '{field}': {error_msg} (type: {error_type})"
        else:
            msg = f"Invalid config values: {e}"
        raise ConfigError(msg) from e
