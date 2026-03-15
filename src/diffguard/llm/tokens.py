"""Token estimation and cost control for LLM analysis."""

import logging
from functools import lru_cache

import tiktoken

__all__ = [
    "check_cost_limit",
    "estimate_cost",
    "estimate_tokens",
]

logger = logging.getLogger(__name__)

# Per-million-token pricing (input tokens only).
# Updated as of 2026-03. Add new models as needed.
_MODEL_PRICING: dict[str, float] = {
    "gpt-4o": 2.50,
    "gpt-4o-mini": 0.15,
    "gpt-4.1": 2.00,
    "gpt-4.1-mini": 0.40,
    "gpt-4.1-nano": 0.10,
    "gpt-5.2": 2.00,
    "gpt-3.5-turbo": 0.50,
    "o3-mini": 1.10,
}


@lru_cache(maxsize=8)
def _get_encoding(model: str) -> tiktoken.Encoding | None:
    """Get tiktoken encoding for a model, returning None on failure."""
    try:
        return tiktoken.encoding_for_model(model)
    except KeyError:
        try:
            # Fall back to cl100k_base (GPT-4/4o family default)
            return tiktoken.get_encoding("cl100k_base")
        except Exception:
            logger.debug("tiktoken encoding unavailable, using heuristic")
            return None


def estimate_tokens(text: str, model: str = "gpt-4o") -> int:
    """Count tokens in text using tiktoken for the given model.

    Falls back to a ~4 characters per token heuristic if tiktoken
    cannot load the encoding.

    Args:
        text: The text to tokenize.
        model: OpenAI model name for encoding selection.

    Returns:
        Token count.
    """
    if not text:
        return 0

    encoding = _get_encoding(model)
    if encoding is None:
        return len(text) // 4

    return len(encoding.encode(text))


def check_cost_limit(
    token_count: int,
    limit: int,
    *,
    margin: float = 0.0,
) -> tuple[bool, int]:
    """Check whether a token count is within the allowed limit.

    Args:
        token_count: Number of tokens to check.
        limit: Maximum allowed tokens.
        margin: Fraction (0.0-1.0) for a warning zone below the hard limit.
            When margin > 0, tokens exceeding ``limit * (1 - margin)``
            are treated as over-limit.

    Returns:
        Tuple of (ok, token_count). ``ok`` is True when the count
        is within the effective limit.
    """
    effective_limit = int(limit * (1 - margin)) if margin > 0 else limit
    ok = token_count <= effective_limit
    return (ok, token_count)


def estimate_cost(tokens: int, model: str) -> float:
    """Estimate the dollar cost for a given token count and model.

    Uses input-token pricing. Returns 0.0 for unknown models.

    Args:
        tokens: Number of input tokens.
        model: OpenAI model name.

    Returns:
        Estimated cost in US dollars.
    """
    price_per_million = _MODEL_PRICING.get(model, 0.0)
    return tokens * price_per_million / 1_000_000
