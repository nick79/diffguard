"""Sensitive file exclusion for preventing secrets from being sent to LLM."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from diffguard.config import DiffguardConfig

if TYPE_CHECKING:
    from diffguard.git import DiffFile

# Comprehensive default patterns from PRD section 3.6.1.
# Patterns without "/" match against the filename (basename) only.
# Patterns with "/" match against the full path.
DEFAULT_SENSITIVE_PATTERNS: list[str] = [
    # ── Environment & Secrets Files ──
    ".env",
    ".env.*",
    "*.env",
    ".env.*.local",
    "secrets.json",
    "secrets.yml",
    "secrets.yaml",
    "secrets.toml",
    "credentials.json",
    "credentials.yml",
    "credentials.yaml",
    ".secrets",
    "*.secrets",
    "*.secrets.*",
    # ── Private Keys & Certificates ──
    "*.pem",
    "*.key",
    "*.crt",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.jceks",
    "id_rsa",
    "id_rsa.*",
    "id_dsa",
    "id_dsa.*",
    "id_ecdsa",
    "id_ecdsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "*.gpg",
    "*.asc",
    # ── Java/JVM ──
    "application-secrets.properties",
    "application-local.properties",
    "*-local.properties",
    "*.local.properties",
    "env.properties",
    "secrets.properties",
    "bootstrap-local.yml",
    "bootstrap-local.yaml",
    # ── Ruby/Rails ──
    "master.key",
    "database.yml",
    # ── PHP/Laravel/Symfony ──
    "parameters.yml",
    "parameters.yaml",
    "*.decrypt.private.php",
    "config.local.php",
    # ── Python ──
    "local_settings.py",
    "settings_local.py",
    "secrets.py",
    ".pypirc",
    # ── JavaScript/Node.js ──
    ".npmrc",
    "config.local.js",
    "config.local.json",
    # ── Go ──
    "config.local.yaml",
    # ── Terraform/Infrastructure ──
    "*.tfvars",
    "*.tfvars.json",
    "*.tfstate",
    "*.tfstate.*",
    ".terraformrc",
    "terraform.rc",
    # ── Cloud Provider Credentials ──
    ".aws/credentials",
    "*-sa-key.json",
    "*-sa.json",
    "service-account*.json",
    "gcloud*.json",
    ".azure/credentials",
    # ── Docker/Kubernetes ──
    ".docker/config.json",
    "docker-compose.override.yml",
    "*-secret.yaml",
    "*-secret.yml",
    # ── Miscellaneous ──
    ".htpasswd",
    "*.kdbx",
    "*.kdb",
    "vault.yml",
    "vault.yaml",
    "*.cred",
    "*.credentials",
    "authinfo",
    ".authinfo",
    ".netrc",
]


@dataclass
class FilterResult:
    """Result of filtering sensitive files from a diff."""

    kept: list[DiffFile] = field(default_factory=list)
    excluded: list[tuple[str, str]] = field(default_factory=list)


def _get_effective_patterns(config: DiffguardConfig) -> list[str]:
    """Build the effective list of sensitive file patterns from config."""
    patterns: list[str] = []
    if config.use_default_sensitive_patterns:
        patterns.extend(DEFAULT_SENSITIVE_PATTERNS)
    patterns.extend(config.sensitive_patterns)
    return patterns


def _matches_pattern(file_path: str, pattern: str) -> bool:
    """Check if a file path matches a single glob pattern (case-insensitive).

    Patterns containing "/" are matched against the full path.
    Patterns without "/" are matched against the basename only.

    Note: Uses fnmatch, where ``*`` matches everything including ``/``.
    The ``**`` glob syntax is not distinctly supported — ``**`` behaves
    identically to ``*``.  This is acceptable because basename-only
    matching already handles the common deep-path cases.
    """
    path_lower = file_path.lower()
    pattern_lower = pattern.lower()

    if "/" in pattern:
        return fnmatch.fnmatch(path_lower, pattern_lower) or fnmatch.fnmatch(path_lower, "*/" + pattern_lower)

    basename = path_lower.rsplit("/", 1)[-1]
    return fnmatch.fnmatch(basename, pattern_lower)


_DEFAULT_CONFIG: DiffguardConfig | None = None


def _get_default_config() -> DiffguardConfig:
    """Return a lazily-initialised default config (avoids repeated Pydantic validation)."""
    global _DEFAULT_CONFIG  # noqa: PLW0603
    if _DEFAULT_CONFIG is None:
        _DEFAULT_CONFIG = DiffguardConfig()
    return _DEFAULT_CONFIG


def is_sensitive_file(file_path: str, config: DiffguardConfig | None = None) -> bool:
    """Check if a file path matches any sensitive file pattern.

    Args:
        file_path: The file path to check (relative or absolute).
        config: Optional config with custom patterns. Uses defaults if None.

    Returns:
        True if the file matches a sensitive pattern.
    """
    if config is None:
        config = _get_default_config()

    patterns = _get_effective_patterns(config)
    return any(_matches_pattern(file_path, pattern) for pattern in patterns)


def filter_sensitive_files(diff_files: list[DiffFile], config: DiffguardConfig) -> FilterResult:
    """Remove sensitive files from a list of diff files.

    Args:
        diff_files: List of parsed diff files to filter.
        config: Configuration with sensitive file patterns.

    Returns:
        FilterResult with kept files and excluded (path, matched_pattern) pairs.
    """
    result = FilterResult()
    patterns = _get_effective_patterns(config)

    for diff_file in diff_files:
        path = diff_file.path
        matched = _find_matching_pattern(path, patterns)
        if matched is not None:
            result.excluded.append((path, matched))
        else:
            result.kept.append(diff_file)

    return result


def _find_matching_pattern(file_path: str, patterns: list[str]) -> str | None:
    """Find the first matching sensitive pattern for a file path.

    Returns the matched pattern string, or None if no match.
    """
    for pattern in patterns:
        if _matches_pattern(file_path, pattern):
            return pattern
    return None
