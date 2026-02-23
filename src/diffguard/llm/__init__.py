"""LLM integration for Diffguard security analysis."""

from diffguard.llm.client import OpenAIClient
from diffguard.llm.prompts import (
    SYSTEM_PROMPT,
    CodeContext,
    DiffLine,
    ScopeContext,
    SymbolDef,
    build_user_prompt,
)
from diffguard.llm.response import (
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    parse_llm_response,
)

__all__ = [
    "SYSTEM_PROMPT",
    "CodeContext",
    "ConfidenceLevel",
    "DiffLine",
    "Finding",
    "OpenAIClient",
    "ScopeContext",
    "SeverityLevel",
    "SymbolDef",
    "build_user_prompt",
    "parse_llm_response",
]
