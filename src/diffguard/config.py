"""Configuration management for Diffguard."""

import tomllib
from enum import Enum
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from diffguard.exceptions import ConfigError
from diffguard.llm.response import ConfidenceLevel

CONFIG_FILENAME = ".diffguard.toml"

_VALID_THRESHOLD_ACTIONS = ("block", "warn", "allow")


class ThresholdAction(Enum):
    """Action to take when a finding meets or exceeds a severity threshold."""

    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"


# Import SeverityLevel here to avoid circular imports — severity.py imports from config,
# but SeverityLevel lives in llm.response which doesn't import config.
from diffguard.llm.response import SeverityLevel  # noqa: E402

DEFAULT_THRESHOLDS: dict[SeverityLevel, ThresholdAction] = {
    SeverityLevel.CRITICAL: ThresholdAction.BLOCK,
    SeverityLevel.HIGH: ThresholdAction.BLOCK,
    SeverityLevel.MEDIUM: ThresholdAction.WARN,
    SeverityLevel.LOW: ThresholdAction.ALLOW,
    SeverityLevel.INFO: ThresholdAction.ALLOW,
}


_CONFIDENCE_MAP = {c.value.lower(): c for c in ConfidenceLevel}


def _parse_min_confidence(data: dict[str, object]) -> dict[str, object]:
    """Convert a string min_confidence value to ConfidenceLevel enum."""
    raw = data.get("min_confidence")
    if raw is None or isinstance(raw, ConfidenceLevel):
        return data

    str_value = str(raw).strip().lower()
    matched = _CONFIDENCE_MAP.get(str_value)
    if matched is None:
        valid = ", ".join(sorted(_CONFIDENCE_MAP.keys()))
        msg = f"Invalid min_confidence '{raw}'. Valid levels: {valid}"
        raise ConfigError(msg)

    data = dict(data)
    data["min_confidence"] = matched
    return data


class DiffguardConfig(BaseModel):
    """Configuration for Diffguard security analysis."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    # Context building settings
    hunk_expansion_lines: int = Field(default=50, ge=0, description="Number of lines to expand around each hunk")
    scope_size_limit: int = Field(default=200, ge=0, description="Maximum lines for scope extraction before truncation")

    # Symbol resolution settings
    symbol_resolution_depth: int = Field(
        default=1, ge=0, description="How deep to follow imports for symbol resolution"
    )
    third_party_patterns: list[str] = Field(
        default_factory=lambda: ["venv/", ".venv/", "site-packages/", "node_modules/"],
        description="Patterns identifying third-party code paths (excluded from analysis and symbol resolution)",
    )

    # Sensitive file exclusion
    sensitive_patterns: list[str] = Field(
        default_factory=list, description="Additional glob patterns for sensitive file exclusion"
    )
    use_default_sensitive_patterns: bool = Field(
        default=True, description="Whether to include built-in sensitive file patterns"
    )

    # LLM settings
    model: str = Field(default="gpt-5.2", description="OpenAI model to use for analysis")
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="LLM sampling temperature (0 = deterministic)")
    min_confidence: ConfidenceLevel = Field(
        default=ConfidenceLevel.LOW,
        description="Minimum confidence level for findings (Low, Medium, High). "
        "Set to Medium to filter out borderline findings and improve run-to-run consistency.",
    )
    max_concurrent_api_calls: int = Field(default=5, ge=1, description="Maximum concurrent API calls")
    timeout: int = Field(default=120, ge=1, description="API timeout in seconds")

    # Baseline
    baseline_path: str = Field(
        default=".diffguard-baseline.json",
        description="Path to baseline file relative to project root",
    )

    # Severity thresholds
    thresholds: dict[SeverityLevel, ThresholdAction] = Field(
        default_factory=lambda: dict(DEFAULT_THRESHOLDS),
        description="Per-severity threshold actions (block, warn, allow)",
    )

    @model_validator(mode="before")
    @classmethod
    def parse_before(cls, data: dict[str, object]) -> dict[str, object]:
        """Convert TOML string values to enum instances for thresholds and min_confidence."""
        if not isinstance(data, dict):
            return data

        data = _parse_min_confidence(data)

        raw_thresholds = data.get("thresholds")
        if raw_thresholds is None:
            return data

        if not isinstance(raw_thresholds, dict):
            return data

        severity_map = {s.value.lower(): s for s in SeverityLevel}
        parsed: dict[SeverityLevel, ThresholdAction] = dict(DEFAULT_THRESHOLDS)

        for key, value in raw_thresholds.items():
            # Accept both SeverityLevel enum instances and string keys
            if isinstance(key, SeverityLevel):
                severity = key
            else:
                str_key = str(key).strip().lower()
                matched = severity_map.get(str_key)
                if matched is None:
                    valid_keys = ", ".join(sorted(severity_map.keys()))
                    msg = f"Unknown severity level '{key}' in [thresholds]. Valid levels: {valid_keys}"
                    raise ConfigError(msg)
                severity = matched

            # Accept both ThresholdAction enum instances and string values
            if isinstance(value, ThresholdAction):
                parsed[severity] = value
            else:
                str_value = str(value).strip().lower()
                if str_value not in _VALID_THRESHOLD_ACTIONS:
                    valid_actions = ", ".join(_VALID_THRESHOLD_ACTIONS)
                    msg = f"Invalid threshold action '{value}' for {key}. Valid actions: {valid_actions}"
                    raise ConfigError(msg)
                parsed[severity] = ThresholdAction(str_value)

        data = dict(data)
        data["thresholds"] = parsed
        return data

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
