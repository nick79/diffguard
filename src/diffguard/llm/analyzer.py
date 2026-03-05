"""Concurrent file analysis for LLM security review."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

from diffguard.exceptions import LLMError, LLMRateLimitError, LLMServerError, LLMTimeoutError
from diffguard.llm.prompts import CodeContext, build_user_prompt
from diffguard.llm.response import Finding, parse_llm_response

logger = logging.getLogger(__name__)

__all__ = [
    "AnalysisResult",
    "FileAnalysisError",
    "LLMClient",
    "analyze_file",
    "analyze_files",
]

_TRANSIENT_ERRORS = (LLMServerError, LLMRateLimitError, LLMTimeoutError)


class LLMClient(Protocol):
    """Protocol for LLM clients used by the analyzer."""

    async def analyze(self, prompt: str) -> str: ...


@dataclass
class FileAnalysisError:
    """Error encountered while analyzing a specific file."""

    file_path: str
    error: str
    error_type: str


@dataclass
class AnalysisResult:
    """Combined result of analyzing multiple files."""

    findings: list[Finding] = field(default_factory=list)
    errors: list[FileAnalysisError] = field(default_factory=list)


async def analyze_file(
    context: CodeContext,
    client: LLMClient,
    *,
    max_retries: int = 0,
) -> list[Finding]:
    """Analyze a single file context for security vulnerabilities.

    Args:
        context: Code context for the file to analyze.
        client: LLM client for API calls.
        max_retries: Number of retries for transient errors (default 0).

    Returns:
        List of findings for this file, each with file_path set.

    Raises:
        LLMError: If the LLM call fails after all retries.
        MalformedResponseError: If the LLM response cannot be parsed.
    """
    prompt = build_user_prompt(context)
    attempts = 1 + max_retries

    for attempt in range(attempts):
        try:
            raw_response = await client.analyze(prompt)
            findings = parse_llm_response(raw_response)
            return [replace(f, file_path=context.file_path) for f in findings]
        except _TRANSIENT_ERRORS:
            if attempt < attempts - 1:
                logger.warning(
                    "Transient error analyzing '%s' (attempt %d/%d): retrying",
                    context.file_path,
                    attempt + 1,
                    attempts,
                )
                continue
            raise

    raise RuntimeError("unreachable")  # pragma: no cover


async def analyze_files(
    contexts: list[CodeContext],
    client: LLMClient,
    *,
    max_concurrent: int = 5,
    max_retries: int = 0,
    timeout_per_file: float | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> AnalysisResult:
    """Analyze multiple files concurrently for security vulnerabilities.

    Uses a semaphore to limit the number of concurrent API calls.
    Continues processing remaining files when individual files fail.

    Args:
        contexts: List of code contexts to analyze.
        client: LLM client for API calls.
        max_concurrent: Maximum number of concurrent API calls.
        max_retries: Number of retries per file for transient errors.
        timeout_per_file: Optional per-file timeout in seconds.
        on_progress: Optional callback called with (completed, total) after each file.

    Returns:
        AnalysisResult containing combined findings and any errors.
    """
    if not contexts:
        return AnalysisResult()

    semaphore = asyncio.Semaphore(max_concurrent)
    total = len(contexts)
    completed = 0

    async def _analyze_one(context: CodeContext) -> list[Finding] | FileAnalysisError:
        nonlocal completed
        async with semaphore:
            try:
                coro = analyze_file(context, client, max_retries=max_retries)
                if timeout_per_file is not None:
                    findings = await asyncio.wait_for(coro, timeout=timeout_per_file)
                else:
                    findings = await coro
            except TimeoutError:
                logger.error("Timeout analyzing '%s' after %ss", context.file_path, timeout_per_file)
                result: list[Finding] | FileAnalysisError = FileAnalysisError(
                    file_path=context.file_path,
                    error=f"Analysis timed out after {timeout_per_file}s",
                    error_type="TimeoutError",
                )
            except LLMError as e:
                logger.error("Error analyzing '%s': %s", context.file_path, e)
                result = FileAnalysisError(
                    file_path=context.file_path,
                    error=str(e),
                    error_type=type(e).__name__,
                )
            else:
                result = findings

        completed += 1
        if on_progress is not None:
            on_progress(completed, total)
        return result

    tasks = [_analyze_one(ctx) for ctx in contexts]
    results = await asyncio.gather(*tasks)

    analysis_result = AnalysisResult()
    for r in results:
        if isinstance(r, FileAnalysisError):
            analysis_result.errors.append(r)
        else:
            analysis_result.findings.extend(r)

    return analysis_result
