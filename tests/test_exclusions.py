"""Tests for sensitive file exclusion."""

import pytest

from diffguard.config import DiffguardConfig
from diffguard.exclusions import (
    DEFAULT_SENSITIVE_PATTERNS,
    FilterResult,
    filter_sensitive_files,
    is_sensitive_file,
)
from diffguard.git import DiffFile

# ── Test fixtures ──

SENSITIVE_PATHS = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development.local",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "credentials.json",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "server.key",
    "private.key",
    "certificate.pem",
    "server.crt",
    "config/master.key",
    "terraform.tfvars",
    "terraform.tfvars.json",
    ".aws/credentials",
    "service-account.json",
    "gcp-sa-key.json",
    "keystore.jks",
    "app.keystore",
    "cert.p12",
]

SAFE_PATHS = [
    "src/main.py",
    "tests/test_api.py",
    "README.md",
    "package.json",
    "pyproject.toml",
    "Makefile",
    "Dockerfile",
    ".gitignore",
    "src/config.py",
    "docs/security.md",
]


def _make_diff_file(path: str) -> DiffFile:
    """Create a minimal DiffFile for testing."""
    return DiffFile(old_path=path, new_path=path)


# ── AC 1: .env file excluded ──


def test_env_file_excluded() -> None:
    assert is_sensitive_file(".env") is True


# ── AC 2: .env.* variants excluded ──


@pytest.mark.parametrize("path", [".env.local", ".env.production", ".env.development"])
def test_env_variants_excluded(path: str) -> None:
    assert is_sensitive_file(path) is True


# ── AC 3: Private key files - common names ──


@pytest.mark.parametrize("path", ["id_rsa", "id_ed25519", "id_dsa"])
def test_ssh_key_files_excluded(path: str) -> None:
    assert is_sensitive_file(path) is True


# ── AC 4: Private key files - .key extension ──


@pytest.mark.parametrize("path", ["server.key", "private.key", "ssl.key"])
def test_key_extension_excluded(path: str) -> None:
    assert is_sensitive_file(path) is True


# ── AC 5: Private key files - .pem extension ──


@pytest.mark.parametrize("path", ["certificate.pem", "private.pem"])
def test_pem_extension_excluded(path: str) -> None:
    assert is_sensitive_file(path) is True


# ── AC 6: Certificate files excluded ──


@pytest.mark.parametrize("path", ["server.crt", "ca-bundle.crt"])
def test_certificate_files_excluded(path: str) -> None:
    assert is_sensitive_file(path) is True


# ── AC 7: Secrets/credentials files excluded ──


@pytest.mark.parametrize("path", ["secrets.json", "credentials.json", "secrets.yaml"])
def test_secrets_credentials_excluded(path: str) -> None:
    assert is_sensitive_file(path) is True


# ── AC 8: AWS credentials excluded ──


def test_aws_credentials_excluded() -> None:
    assert is_sensitive_file(".aws/credentials") is True


def test_aws_credentials_in_subpath() -> None:
    assert is_sensitive_file("home/user/.aws/credentials") is True


# ── AC 9: GCP service account excluded ──


@pytest.mark.parametrize("path", ["service-account.json", "gcp-sa.json", "my-project-sa-key.json"])
def test_gcp_service_account_excluded(path: str) -> None:
    assert is_sensitive_file(path) is True


# ── AC 10: Terraform secrets excluded ──


@pytest.mark.parametrize("path", ["terraform.tfvars", "production.tfvars", "vars.tfvars.json"])
def test_terraform_vars_excluded(path: str) -> None:
    assert is_sensitive_file(path) is True


# ── AC 11: Rails master key excluded ──


def test_rails_master_key_excluded() -> None:
    assert is_sensitive_file("config/master.key") is True


# ── AC 12: Docker secrets ──


def test_docker_compose_override_excluded() -> None:
    assert is_sensitive_file("docker-compose.override.yml") is True


# ── AC 13: Keystore files excluded ──


@pytest.mark.parametrize("path", ["release.jks", "app.keystore", "cert.p12"])
def test_keystore_files_excluded(path: str) -> None:
    assert is_sensitive_file(path) is True


# ── AC 14: Normal code files not excluded ──


def test_normal_code_not_excluded() -> None:
    assert is_sensitive_file("src/main.py") is False


# ── AC 15: Test files not excluded ──


def test_test_files_not_excluded() -> None:
    assert is_sensitive_file("tests/test_api.py") is False


# ── AC 16: Documentation not excluded ──


@pytest.mark.parametrize("path", ["README.md", "docs/guide.md"])
def test_documentation_not_excluded(path: str) -> None:
    assert is_sensitive_file(path) is False


# ── AC 17: Config files (non-sensitive) not excluded ──


@pytest.mark.parametrize("path", ["package.json", "pyproject.toml"])
def test_nonsensitive_config_not_excluded(path: str) -> None:
    assert is_sensitive_file(path) is False


# ── AC 18: User can extend patterns via config ──


def test_user_custom_pattern() -> None:
    config = DiffguardConfig(sensitive_patterns=["*.secret.json"])
    assert is_sensitive_file("config.secret.json", config) is True


# ── AC 19: User patterns add to defaults ──


def test_user_patterns_add_to_defaults() -> None:
    config = DiffguardConfig(
        sensitive_patterns=["*.custom"],
        use_default_sensitive_patterns=True,
    )
    # Custom pattern matches
    assert is_sensitive_file("data.custom", config) is True
    # Default pattern still matches
    assert is_sensitive_file(".env", config) is True


# ── AC 20: User can disable default patterns ──


def test_disable_default_patterns() -> None:
    config = DiffguardConfig(
        sensitive_patterns=["*.custom"],
        use_default_sensitive_patterns=False,
    )
    # Custom pattern matches
    assert is_sensitive_file("data.custom", config) is True
    # Default pattern no longer matches
    assert is_sensitive_file(".env", config) is False


# ── AC 21: Filter removes sensitive files ──


def test_filter_removes_sensitive_files() -> None:
    diff_files = [
        _make_diff_file(".env"),
        _make_diff_file("main.py"),
        _make_diff_file("test.py"),
    ]
    config = DiffguardConfig()
    result = filter_sensitive_files(diff_files, config)

    assert len(result.kept) == 2
    kept_paths = [f.path for f in result.kept]
    assert "main.py" in kept_paths
    assert "test.py" in kept_paths


# ── AC 22: Filter reports excluded files ──


def test_filter_reports_excluded_files() -> None:
    diff_files = [
        _make_diff_file(".env"),
        _make_diff_file("main.py"),
    ]
    config = DiffguardConfig()
    result = filter_sensitive_files(diff_files, config)

    assert len(result.excluded) == 1
    path, pattern = result.excluded[0]
    assert path == ".env"
    assert pattern == ".env"


# ── AC 23: Filter handles empty list ──


def test_filter_empty_list() -> None:
    result = filter_sensitive_files([], DiffguardConfig())
    assert result.kept == []
    assert result.excluded == []


# ── AC 24: Filter handles all sensitive ──


def test_filter_all_sensitive() -> None:
    diff_files = [
        _make_diff_file(".env"),
        _make_diff_file("secrets.json"),
    ]
    result = filter_sensitive_files(diff_files, DiffguardConfig())

    assert result.kept == []
    assert len(result.excluded) == 2


# ── AC 25: Case sensitivity handling ──


@pytest.mark.parametrize("path", [".ENV", "SECRETS.JSON", "Id_Rsa"])
def test_case_insensitive_matching(path: str) -> None:
    assert is_sensitive_file(path) is True


# ── AC 26: Path pattern matching (glob) ──


def test_glob_path_pattern_matching() -> None:
    config = DiffguardConfig(sensitive_patterns=["**/secrets/**"])
    # fnmatch doesn't support **, but with our path matching it will be handled
    # as a wildcard prefix
    assert is_sensitive_file("config/secrets/api.json", config) is True


# ── AC 27: Verbose shows exclusion reason (tested via FilterResult data) ──


def test_filter_result_includes_pattern() -> None:
    diff_files = [_make_diff_file("server.pem")]
    result = filter_sensitive_files(diff_files, DiffguardConfig())

    assert len(result.excluded) == 1
    _, pattern = result.excluded[0]
    assert pattern == "*.pem"


# ── Bulk parametrized tests ──


@pytest.mark.parametrize("path", SENSITIVE_PATHS)
def test_all_sensitive_paths_detected(path: str) -> None:
    assert is_sensitive_file(path) is True, f"Expected {path!r} to be detected as sensitive"


@pytest.mark.parametrize("path", SAFE_PATHS)
def test_all_safe_paths_allowed(path: str) -> None:
    assert is_sensitive_file(path) is False, f"Expected {path!r} to be allowed (not sensitive)"


# ── Edge cases ──


def test_sensitive_file_in_subdirectory() -> None:
    assert is_sensitive_file("deploy/config/.env.production") is True


def test_key_file_in_nested_path() -> None:
    assert is_sensitive_file("ssl/certs/server.key") is True


def test_tfstate_variants() -> None:
    assert is_sensitive_file("terraform.tfstate") is True
    assert is_sensitive_file("terraform.tfstate.backup") is True


def test_kubernetes_secret_manifests() -> None:
    assert is_sensitive_file("k8s/db-secret.yaml") is True
    assert is_sensitive_file("k8s/db-secret.yml") is True


def test_docker_config_json() -> None:
    assert is_sensitive_file(".docker/config.json") is True
    assert is_sensitive_file("home/user/.docker/config.json") is True


def test_azure_credentials() -> None:
    assert is_sensitive_file(".azure/credentials") is True


def test_dot_env_with_suffix() -> None:
    assert is_sensitive_file("prod.env") is True
    assert is_sensitive_file("local.env") is True


def test_secrets_file_variants() -> None:
    assert is_sensitive_file(".secrets") is True
    assert is_sensitive_file("app.secrets") is True
    assert is_sensitive_file("app.secrets.bak") is True


def test_default_config_returns_true_for_sensitive() -> None:
    assert is_sensitive_file(".env") is True
    assert is_sensitive_file(".env", None) is True


def test_filter_result_is_dataclass() -> None:
    result = FilterResult()
    assert result.kept == []
    assert result.excluded == []


def test_default_patterns_list_not_empty() -> None:
    assert len(DEFAULT_SENSITIVE_PATTERNS) > 0


def test_no_false_positive_on_similar_names() -> None:
    """Files with 'secret' or 'env' in the name but not matching patterns."""
    assert is_sensitive_file("src/environment.py") is False
    assert is_sensitive_file("src/secret_service.py") is False
    assert is_sensitive_file("lib/envelope.js") is False
