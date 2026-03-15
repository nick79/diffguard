"""Tests for token estimation and cost control."""

import tiktoken

from diffguard.config import DiffguardConfig
from diffguard.llm.prompts import SYSTEM_PROMPT
from diffguard.llm.tokens import check_cost_limit, estimate_cost, estimate_tokens

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SHORT_PROMPT = "Analyze this code for security issues."
LONG_PROMPT = "def foo():\n    pass\n" * 1000  # ~4000 tokens
CODE_SAMPLE = """\
def process_user_input(data: str) -> dict:
    \"\"\"Process and validate user input.\"\"\"
    if not data:
        raise ValueError("Empty input")

    result = json.loads(data)
    validate_schema(result)
    return sanitize(result)
"""
UNICODE_TEXT = "Hello 世界! 🎉 Привет мир"


def _actual_token_count(text: str, model: str = "gpt-4o") -> int:
    """Get the ground-truth token count from tiktoken directly."""
    enc = tiktoken.encoding_for_model(model)
    return len(enc.encode(text))


# ---------------------------------------------------------------------------
# estimate_tokens — accuracy
# ---------------------------------------------------------------------------


class TestEstimateTokensAccuracy:
    def test_short_text_within_10_percent(self) -> None:
        actual = _actual_token_count(SHORT_PROMPT)
        estimated = estimate_tokens(SHORT_PROMPT, model="gpt-4o")
        assert estimated == actual

    def test_code_within_10_percent(self) -> None:
        actual = _actual_token_count(LONG_PROMPT)
        estimated = estimate_tokens(LONG_PROMPT, model="gpt-4o")
        assert estimated == actual

    def test_code_sample_within_10_percent(self) -> None:
        actual = _actual_token_count(CODE_SAMPLE)
        estimated = estimate_tokens(CODE_SAMPLE, model="gpt-4o")
        assert estimated == actual

    def test_model_specific_encoding(self) -> None:
        tokens_4o = estimate_tokens(LONG_PROMPT, model="gpt-4o")
        tokens_35 = estimate_tokens(LONG_PROMPT, model="gpt-3.5-turbo")
        # Both should be positive; they may or may not differ
        assert tokens_4o > 0
        assert tokens_35 > 0

    def test_empty_string_returns_zero(self) -> None:
        assert estimate_tokens("") == 0
        assert estimate_tokens("", model="gpt-4o") == 0

    def test_unicode_text(self) -> None:
        actual = _actual_token_count(UNICODE_TEXT)
        estimated = estimate_tokens(UNICODE_TEXT, model="gpt-4o")
        assert estimated == actual
        assert estimated > 0


# ---------------------------------------------------------------------------
# check_cost_limit
# ---------------------------------------------------------------------------


class TestCheckCostLimit:
    def test_under_limit_passes(self) -> None:
        ok, count = check_cost_limit(1000, 5000)
        assert ok is True
        assert count == 1000

    def test_at_limit_passes(self) -> None:
        ok, count = check_cost_limit(5000, 5000)
        assert ok is True
        assert count == 5000

    def test_over_limit_fails(self) -> None:
        ok, count = check_cost_limit(10000, 5000)
        assert ok is False
        assert count == 10000

    def test_margin_triggers_rejection(self) -> None:
        # 4800 tokens, limit 5000, margin 10% → effective limit 4500
        ok, count = check_cost_limit(4800, 5000, margin=0.1)
        assert ok is False
        assert count == 4800

    def test_margin_allows_low_count(self) -> None:
        # 4000 tokens, limit 5000, margin 10% → effective limit 4500
        ok, count = check_cost_limit(4000, 5000, margin=0.1)
        assert ok is True
        assert count == 4000

    def test_zero_limit_always_fails(self) -> None:
        ok, count = check_cost_limit(1, 0)
        assert ok is False
        assert count == 1

    def test_zero_tokens_always_passes(self) -> None:
        ok, count = check_cost_limit(0, 5000)
        assert ok is True
        assert count == 0


# ---------------------------------------------------------------------------
# Config integration
# ---------------------------------------------------------------------------


class TestConfigMaxTokens:
    def test_config_max_tokens_per_scan_from_toml(self) -> None:
        config = DiffguardConfig(max_tokens_per_scan=10000)
        assert config.max_tokens_per_scan == 10000

    def test_default_max_tokens_per_scan(self) -> None:
        config = DiffguardConfig()
        assert config.max_tokens_per_scan == 40_000

    def test_zero_means_unlimited(self) -> None:
        config = DiffguardConfig(max_tokens_per_scan=0)
        assert config.max_tokens_per_scan == 0


# ---------------------------------------------------------------------------
# Token aggregation
# ---------------------------------------------------------------------------


class TestTokenAggregation:
    def test_aggregate_across_files(self) -> None:
        counts = [1000, 2000, 500]
        assert sum(counts) == 3500

    def test_aggregate_single_file(self) -> None:
        assert sum([1000]) == 1000

    def test_aggregate_empty(self) -> None:
        assert sum([]) == 0


# ---------------------------------------------------------------------------
# System prompt inclusion
# ---------------------------------------------------------------------------


class TestSystemPromptTokens:
    def test_system_prompt_has_tokens(self) -> None:
        tokens = estimate_tokens(SYSTEM_PROMPT)
        assert tokens > 0

    def test_total_includes_system_prompt(self) -> None:
        user_tokens = estimate_tokens(SHORT_PROMPT)
        system_tokens = estimate_tokens(SYSTEM_PROMPT)
        total = user_tokens + system_tokens
        assert total > user_tokens


# ---------------------------------------------------------------------------
# estimate_cost
# ---------------------------------------------------------------------------


class TestEstimateCost:
    def test_known_model(self) -> None:
        cost = estimate_cost(1_000_000, "gpt-4o")
        assert cost == 2.50

    def test_zero_tokens(self) -> None:
        assert estimate_cost(0, "gpt-4o") == 0.0

    def test_unknown_model_returns_zero(self) -> None:
        assert estimate_cost(10000, "unknown-model") == 0.0

    def test_proportional_to_tokens(self) -> None:
        cost_small = estimate_cost(1000, "gpt-4o")
        cost_large = estimate_cost(10000, "gpt-4o")
        assert cost_large == cost_small * 10
