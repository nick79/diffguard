"""OpenAI async client for Diffguard security analysis."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import openai
from openai import AsyncOpenAI

if TYPE_CHECKING:
    from openai.types.shared_params import ResponseFormatJSONSchema

from diffguard.exceptions import (
    LLMAuthenticationError,
    LLMConnectionError,
    LLMContextLengthError,
    LLMEmptyResponseError,
    LLMModelNotFoundError,
    LLMRateLimitError,
    LLMRequestError,
    LLMServerError,
    LLMTimeoutError,
    MissingAPIKeyError,
)
from diffguard.llm.prompts import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

__all__ = ["SYSTEM_PROMPT", "OpenAIClient"]

# Structured Outputs JSON schema for constrained decoding.
# Forces the model to produce valid JSON matching this exact structure,
# significantly reducing output variance between runs.
_RESPONSE_SCHEMA: ResponseFormatJSONSchema = {
    "type": "json_schema",
    "json_schema": {
        "name": "security_findings",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "what": {"type": "string"},
                            "why": {"type": "string"},
                            "how_to_fix": {"type": "string"},
                            "severity": {
                                "type": "string",
                                "enum": ["Critical", "High", "Medium", "Low", "Info"],
                            },
                            "confidence": {
                                "type": "string",
                                "enum": ["High", "Medium", "Low"],
                            },
                            "cwe_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                            "owasp_category": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                            "line_range": {
                                "anyOf": [
                                    {
                                        "type": "object",
                                        "properties": {
                                            "start": {"type": "integer"},
                                            "end": {"type": "integer"},
                                        },
                                        "required": ["start", "end"],
                                        "additionalProperties": False,
                                    },
                                    {"type": "null"},
                                ],
                            },
                            "file_path": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                        },
                        "required": [
                            "what",
                            "why",
                            "how_to_fix",
                            "severity",
                            "confidence",
                            "cwe_id",
                            "owasp_category",
                            "line_range",
                            "file_path",
                        ],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["findings"],
            "additionalProperties": False,
        },
    },
}


def _is_context_length_error(error: openai.BadRequestError) -> bool:
    """Check if a BadRequestError is about context length limits."""
    msg = error.message.lower()
    return "context_length" in msg or "context length" in msg or ("maximum" in msg and "token" in msg)


class OpenAIClient:
    """Async OpenAI client for security analysis.

    Reads the API key from the OPENAI_API_KEY environment variable.
    """

    def __init__(self, *, model: str = "gpt-5.2", timeout: int = 120, temperature: float = 0.0) -> None:
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key.strip():
            msg = (
                "OpenAI API key not found. "
                "Set the OPENAI_API_KEY environment variable: "
                "export OPENAI_API_KEY=sk-your-key-here"
            )
            raise MissingAPIKeyError(msg)

        self._client = AsyncOpenAI(api_key=api_key, timeout=timeout, max_retries=0)
        self._model = model
        self._timeout = timeout
        self._temperature = temperature

    @property
    def model(self) -> str:
        """The OpenAI model used for analysis."""
        return self._model

    @property
    def timeout(self) -> int:
        """API request timeout in seconds."""
        return self._timeout

    async def analyze(self, prompt: str) -> str:
        """Send a prompt to the LLM for security analysis.

        Args:
            prompt: The user prompt containing code context to analyze.

        Returns:
            The response content string from the LLM.

        Raises:
            LLMTimeoutError: API request timed out.
            LLMRateLimitError: Rate limit exceeded.
            LLMAuthenticationError: Invalid API key.
            LLMConnectionError: Network connectivity issue.
            LLMServerError: Server-side error (5xx).
            LLMModelNotFoundError: Requested model not available.
            LLMContextLengthError: Input exceeds model context window.
            LLMRequestError: Invalid request parameters.
            LLMEmptyResponseError: LLM returned empty content.
        """
        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                temperature=self._temperature,
                top_p=1,
                seed=42,
                response_format=_RESPONSE_SCHEMA,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
        except openai.APITimeoutError as e:
            msg = f"OpenAI API request timed out after {self._timeout}s"
            raise LLMTimeoutError(msg) from e
        except openai.RateLimitError as e:
            retry_after = e.response.headers.get("retry-after") if e.response else None
            msg = "OpenAI API rate limit exceeded"
            if retry_after:
                msg += f" (retry after {retry_after}s)"
            raise LLMRateLimitError(msg) from e
        except openai.AuthenticationError as e:
            msg = f"OpenAI API authentication failed. Check your OPENAI_API_KEY: {e.message}"
            raise LLMAuthenticationError(msg) from e
        except openai.NotFoundError as e:
            msg = f"Model '{self._model}' not found. Check available models at https://platform.openai.com/docs/models"
            raise LLMModelNotFoundError(msg) from e
        except openai.BadRequestError as e:
            if _is_context_length_error(e):
                msg = f"Input exceeds model context window: {e.message}"
                raise LLMContextLengthError(msg) from e
            msg = f"Invalid request to OpenAI API: {e.message}"
            raise LLMRequestError(msg) from e
        except openai.InternalServerError as e:
            msg = "OpenAI API server error. Try again later."
            raise LLMServerError(msg) from e
        except openai.APIConnectionError as e:
            msg = "Failed to connect to OpenAI API. Check your network connection."
            raise LLMConnectionError(msg) from e

        fingerprint = getattr(response, "system_fingerprint", None)
        if fingerprint:
            logger.debug("system_fingerprint=%s (model=%s)", fingerprint, self._model)

        choice = response.choices[0]
        content = choice.message.content

        if choice.finish_reason == "length":
            logger.warning("LLM response was truncated (finish_reason=length) for model '%s'", self._model)

        if not content:
            msg = "OpenAI API returned an empty response"
            raise LLMEmptyResponseError(msg)

        return content
