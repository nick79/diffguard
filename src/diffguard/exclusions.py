"""Sensitive file exclusion and generated file detection."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from diffguard.ast.languages import Language
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


# ---------------------------------------------------------------------------
# Generated file detection
# ---------------------------------------------------------------------------


def is_generated_file(file_path: str, source_lines: list[str], language: Language) -> bool:  # noqa: PLR0911
    """Check if a file is machine-generated or auto-created.

    Args:
        file_path: The file path to check (relative or absolute).
        source_lines: Lines of the file content (may be empty if not yet read).
        language: The detected programming language.

    Returns:
        True if the file is detected as generated/auto-created.
    """
    match language:
        case Language.JAVASCRIPT:
            return _is_generated_javascript(file_path, source_lines)
        case Language.TYPESCRIPT:
            return _is_generated_typescript(file_path, source_lines)
        case Language.JAVA:
            return _is_generated_java(file_path, source_lines)
        case Language.RUBY:
            return _is_generated_ruby(file_path, source_lines)
        case Language.GO:
            return _is_generated_go(file_path, source_lines)
        case Language.PHP:
            return _is_generated_php(file_path, source_lines)
        case Language.HTML:
            return _is_generated_html(source_lines)
        case _:
            return False


_MINIFIED_JS_SUFFIXES: tuple[str, ...] = (
    ".min.js",
    ".min.mjs",
    ".min.cjs",
    ".bundle.js",
    ".chunk.js",
)


_GENERATED_DTS_MARKERS: tuple[str, ...] = (
    "// Generated by",
    "// Auto-generated",
    "// auto-generated",
    "/* Generated by",
    "/* Auto-generated",
)


def _is_generated_typescript(file_path: str, source_lines: list[str]) -> bool:
    """Check if a TypeScript file is generated."""
    path_lower = file_path.lower()

    # Declaration files with generated headers
    if path_lower.endswith(".d.ts") or path_lower.endswith(".d.mts") or path_lower.endswith(".d.cts"):
        for line in source_lines[:5]:
            stripped = line.strip()
            if any(stripped.startswith(marker) for marker in _GENERATED_DTS_MARKERS):
                return True

    # Content heuristic: avg line length > 500 chars indicates minified/bundled
    if source_lines:
        total_chars = sum(len(line) for line in source_lines)
        avg_length = total_chars / len(source_lines)
        if avg_length > 500:
            return True

    return False


_JAVA_GENERATED_PATH_SEGMENTS: tuple[str, ...] = (
    "generated-sources/",
    "generated/",
    "apt_generated/",
)


def _is_generated_java(file_path: str, source_lines: list[str]) -> bool:
    """Check if a Java file is generated."""
    # Path-based: generated-sources, apt_generated, etc.
    path_lower = file_path.lower()
    if any(segment in path_lower for segment in _JAVA_GENERATED_PATH_SEGMENTS):
        return True

    # Content-based: @Generated annotation in first 20 lines
    for line in source_lines[:20]:
        stripped = line.strip()
        if stripped.startswith("@Generated") or stripped.startswith("@javax.annotation.Generated"):
            return True

    return False


_RUBY_GENERATED_MARKERS: tuple[str, ...] = (
    "# This file is auto-generated",
    "# Auto-generated",
    "# Generated by",
    "# DO NOT EDIT",
    "# This file was generated",
    "# This migration was auto-generated",
)


def _is_generated_ruby(file_path: str, source_lines: list[str]) -> bool:
    """Check if a Ruby file is auto-generated."""
    # db/schema.rb is always auto-generated by Rails
    if file_path.endswith("db/schema.rb"):
        return True

    # Content markers: look for auto-generated comments in first 5 lines
    for line in source_lines[:5]:
        stripped = line.strip()
        if any(stripped.startswith(marker) for marker in _RUBY_GENERATED_MARKERS):
            return True

    return False


_GO_GENERATED_NAME_PATTERNS: tuple[str, ...] = (
    ".pb.go",
    "_string.go",
    "_gen.go",
)

_GO_GENERATED_HEADER = re.compile(r"^// Code generated .+ DO NOT EDIT\.$")


def _is_generated_go(file_path: str, source_lines: list[str]) -> bool:
    """Check if a Go file is generated."""
    basename = file_path.rsplit("/", 1)[-1]

    # Filename patterns
    if any(basename.endswith(suffix) for suffix in _GO_GENERATED_NAME_PATTERNS):
        return True
    if basename.startswith("mock_") and basename.endswith(".go"):
        return True
    if basename.endswith("_mock.go"):
        return True

    # Content: `// Code generated ... DO NOT EDIT.` convention
    # The header appears as the first content line (may be preceded by build tags or blank lines)
    for line in source_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//go:build") or stripped.startswith("// +build"):
            continue
        if _GO_GENERATED_HEADER.match(stripped):
            return True
        break

    return False


_PHP_CACHE_PATH_SEGMENTS: tuple[str, ...] = (
    "var/cache/",
    "bootstrap/cache/",
    "storage/framework/cache/",
)

_PHP_GENERATED_MARKERS: tuple[str, ...] = (
    "<?php // auto-generated",
    "<?php // Auto-generated",
    "// auto-generated",
    "// Auto-generated",
    "@generated",
    "/* auto-generated",
    "/* Auto-generated",
)


def _is_generated_php(file_path: str, source_lines: list[str]) -> bool:
    """Check if a PHP file is auto-generated or a framework cache file."""
    # Path-based: framework cache directories
    path_lower = file_path.lower()
    if any(segment in path_lower for segment in _PHP_CACHE_PATH_SEGMENTS):
        return True

    # Content markers in first 5 lines
    for line in source_lines[:5]:
        stripped = line.strip()
        if any(marker in stripped for marker in _PHP_GENERATED_MARKERS):
            return True

    return False


def _is_generated_html(source_lines: list[str]) -> bool:
    """Check if an HTML/template file is minified."""
    if source_lines:
        total_chars = sum(len(line) for line in source_lines)
        avg_length = total_chars / len(source_lines)
        if avg_length > 500:
            return True
    return False


def _is_generated_javascript(file_path: str, source_lines: list[str]) -> bool:
    """Check if a JavaScript file is minified or bundled."""
    path_lower = file_path.lower()
    if any(path_lower.endswith(suffix) for suffix in _MINIFIED_JS_SUFFIXES):
        return True

    # Content heuristic: avg line length > 500 chars indicates minified code
    if source_lines:
        total_chars = sum(len(line) for line in source_lines)
        avg_length = total_chars / len(source_lines)
        if avg_length > 500:
            return True

    return False
