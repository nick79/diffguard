"""Custom exception hierarchy for Diffguard."""


class DiffguardError(Exception):
    """Base exception for all Diffguard errors."""


class ConfigError(DiffguardError):
    """Configuration-related errors."""


class GitError(DiffguardError):
    """Git operation errors."""


class LLMError(DiffguardError):
    """Base exception for LLM-related errors."""


class MissingAPIKeyError(LLMError):
    """API key not provided or empty."""


class LLMTimeoutError(LLMError):
    """LLM API request timed out."""


class LLMRateLimitError(LLMError):
    """LLM API rate limit exceeded."""


class LLMAuthenticationError(LLMError):
    """LLM API authentication failed."""


class LLMConnectionError(LLMError):
    """LLM API connection failed."""


class LLMServerError(LLMError):
    """LLM API server error."""


class LLMModelNotFoundError(LLMError):
    """Requested LLM model not found."""


class LLMRequestError(LLMError):
    """Invalid LLM API request."""


class LLMContextLengthError(LLMError):
    """Context length exceeded."""


class LLMEmptyResponseError(LLMError):
    """LLM returned empty response."""


class MalformedResponseError(LLMError):
    """LLM response could not be parsed."""


class UnsupportedLanguageError(DiffguardError):
    """Programming language not supported."""
