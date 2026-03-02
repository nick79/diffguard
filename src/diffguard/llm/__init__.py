"""LLM integration for Diffguard security analysis."""

from diffguard.llm.analyzer import (
    AnalysisResult,
    FileAnalysisError,
    LLMClient,
    analyze_file,
    analyze_files,
)
from diffguard.llm.client import OpenAIClient
from diffguard.llm.prompts import (
    SYSTEM_PROMPT,
    CodeContext,
    DiffLine,
    ScopeContext,
    SymbolDef,
    build_user_prompt,
    estimate_tokens,
)
from diffguard.llm.response import (
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    parse_llm_response,
)

__all__ = [
    "SYSTEM_PROMPT",
    "AnalysisResult",
    "CodeContext",
    "ConfidenceLevel",
    "DiffLine",
    "FileAnalysisError",
    "Finding",
    "LLMClient",
    "OpenAIClient",
    "ScopeContext",
    "SeverityLevel",
    "SymbolDef",
    "analyze_file",
    "analyze_files",
    "build_user_prompt",
    "estimate_tokens",
    "parse_llm_response",
]
