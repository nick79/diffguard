"""Shared pytest configuration and fixtures."""

import pytest


@pytest.fixture
def sample_valid_config_toml() -> str:
    """Return valid TOML config string."""
    return """
hunk_expansion_lines = 100
scope_size_limit = 300
model = "gpt-4o"
max_concurrent_api_calls = 10
"""


@pytest.fixture
def sample_partial_config_toml() -> str:
    """Return TOML config with only some fields."""
    return """
model = "gpt-4o"
"""


@pytest.fixture
def sample_invalid_syntax_toml() -> str:
    """Return TOML with invalid syntax."""
    return """
key = "unclosed string
"""


@pytest.fixture
def sample_negative_value_toml() -> str:
    """Return TOML with negative value for positive-only field."""
    return """
hunk_expansion_lines = -5
"""


@pytest.fixture
def sample_wrong_type_toml() -> str:
    """Return TOML with wrong type for a field."""
    return """
hunk_expansion_lines = "fifty"
"""


@pytest.fixture
def sample_unknown_field_toml() -> str:
    """Return TOML with unknown field."""
    return """
unknown_field = "value"
"""


@pytest.fixture
def sample_comments_only_toml() -> str:
    """Return TOML with only comments."""
    return """
# This is a comment
# Another comment

    # Indented comment
"""
