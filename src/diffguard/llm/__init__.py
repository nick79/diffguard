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

__all__ = [
    "SYSTEM_PROMPT",
    "CodeContext",
    "DiffLine",
    "OpenAIClient",
    "ScopeContext",
    "SymbolDef",
    "build_user_prompt",
]
