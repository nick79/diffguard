"""Tests for OpenAI async client."""

import logging
from unittest.mock import AsyncMock, Mock, patch

import httpx
import openai
import pytest

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
from diffguard.llm.client import SYSTEM_PROMPT, OpenAIClient

# --- Helpers ---


def _make_completion(content: str = '{"findings": []}', finish_reason: str = "stop") -> Mock:
    """Create a mock ChatCompletion response."""
    choice = Mock()
    choice.message.content = content
    choice.finish_reason = finish_reason
    completion = Mock()
    completion.choices = [choice]
    return completion


def _make_request() -> httpx.Request:
    """Create a dummy httpx.Request for openai exceptions."""
    return httpx.Request("POST", "https://api.openai.com/v1/chat/completions")


def _make_response(status_code: int = 400, headers: dict[str, str] | None = None) -> httpx.Response:
    """Create a dummy httpx.Response for openai exceptions."""
    return httpx.Response(status_code=status_code, request=_make_request(), headers=headers or {})


# --- Fixtures ---


@pytest.fixture
def env_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set a valid OPENAI_API_KEY env var."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-12345")


@pytest.fixture
@pytest.mark.usefixtures("env_api_key")
def client(env_api_key: None) -> OpenAIClient:  # noqa: ARG001
    """Create an OpenAIClient with a mocked underlying async client."""
    with patch("diffguard.llm.client.AsyncOpenAI"):
        return OpenAIClient()


@pytest.fixture
def client_with_mock(client: OpenAIClient) -> tuple[OpenAIClient, AsyncMock]:
    """Return client and its mocked completions.create method."""
    mock_create = AsyncMock(return_value=_make_completion())
    client._client.chat.completions.create = mock_create  # type: ignore[method-assign]
    return client, mock_create


# --- Initialization Tests ---


@pytest.mark.usefixtures("env_api_key")
class TestClientInitialization:
    def test_init_with_valid_key(self) -> None:
        with patch("diffguard.llm.client.AsyncOpenAI"):
            client = OpenAIClient()

        assert client.model == "gpt-5.2"
        assert client.timeout == 120

    def test_init_raises_without_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        with pytest.raises(MissingAPIKeyError, match="OPENAI_API_KEY"):
            OpenAIClient()

    def test_init_raises_with_empty_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "")

        with pytest.raises(MissingAPIKeyError, match="OPENAI_API_KEY"):
            OpenAIClient()

    def test_init_raises_with_whitespace_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "   ")

        with pytest.raises(MissingAPIKeyError, match="OPENAI_API_KEY"):
            OpenAIClient()

    def test_init_custom_model(self) -> None:
        with patch("diffguard.llm.client.AsyncOpenAI"):
            client = OpenAIClient(model="gpt-4o")

        assert client.model == "gpt-4o"

    def test_init_custom_timeout(self) -> None:
        with patch("diffguard.llm.client.AsyncOpenAI") as mock_cls:
            client = OpenAIClient(timeout=60)

        assert client.timeout == 60
        mock_cls.assert_called_once_with(api_key="sk-test-key-12345", timeout=60, max_retries=0)


# --- Analyze Success Tests ---


class TestAnalyzeSuccess:
    async def test_returns_response_content(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        mock_create.return_value = _make_completion(content='{"findings": [{"what": "test"}]}')

        result = await client.analyze("analyze this code")

        assert result == '{"findings": [{"what": "test"}]}'

    @pytest.mark.usefixtures("env_api_key")
    async def test_uses_configured_model(self) -> None:
        with patch("diffguard.llm.client.AsyncOpenAI"):
            client = OpenAIClient(model="gpt-4o")

        mock_create = AsyncMock(return_value=_make_completion())
        client._client.chat.completions.create = mock_create  # type: ignore[method-assign]

        await client.analyze("test prompt")

        call_kwargs = mock_create.call_args
        assert call_kwargs.kwargs["model"] == "gpt-4o"

    async def test_uses_system_prompt(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock

        await client.analyze("user prompt here")

        call_kwargs = mock_create.call_args
        messages = call_kwargs.kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == SYSTEM_PROMPT
        assert messages[1]["role"] == "user"
        assert messages[1]["content"] == "user prompt here"

    async def test_finish_reason_length_logs_warning(
        self, client_with_mock: tuple[OpenAIClient, AsyncMock], caplog: pytest.LogCaptureFixture
    ) -> None:
        client, mock_create = client_with_mock
        mock_create.return_value = _make_completion(content="partial response", finish_reason="length")

        with caplog.at_level(logging.WARNING, logger="diffguard.llm.client"):
            result = await client.analyze("prompt")

        assert result == "partial response"
        assert "truncated" in caplog.text
        assert "finish_reason=length" in caplog.text


# --- Analyze Error Handling Tests ---


class TestAnalyzeErrors:
    async def test_timeout_error(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        mock_create.side_effect = openai.APITimeoutError(request=_make_request())

        with pytest.raises(LLMTimeoutError, match="timed out"):
            await client.analyze("prompt")

    async def test_rate_limit_error(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        response = _make_response(status_code=429, headers={"retry-after": "30"})
        mock_create.side_effect = openai.RateLimitError(message="Rate limit exceeded", response=response, body={})

        with pytest.raises(LLMRateLimitError, match="rate limit exceeded"):
            await client.analyze("prompt")

    async def test_rate_limit_includes_retry_after(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        response = _make_response(status_code=429, headers={"retry-after": "30"})
        mock_create.side_effect = openai.RateLimitError(message="Rate limit exceeded", response=response, body={})

        with pytest.raises(LLMRateLimitError, match="retry after 30s"):
            await client.analyze("prompt")

    async def test_authentication_error(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        response = _make_response(status_code=401)
        mock_create.side_effect = openai.AuthenticationError(message="Invalid API key", response=response, body={})

        with pytest.raises(LLMAuthenticationError, match="authentication failed"):
            await client.analyze("prompt")

    async def test_connection_error(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        mock_create.side_effect = openai.APIConnectionError(request=_make_request())

        with pytest.raises(LLMConnectionError, match="network connection"):
            await client.analyze("prompt")

    async def test_server_error(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        response = _make_response(status_code=500)
        mock_create.side_effect = openai.InternalServerError(
            message="Internal server error", response=response, body={}
        )

        with pytest.raises(LLMServerError, match="server error"):
            await client.analyze("prompt")

    async def test_model_not_found_error(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        response = _make_response(status_code=404)
        mock_create.side_effect = openai.NotFoundError(message="Model not found", response=response, body={})

        with pytest.raises(LLMModelNotFoundError, match="not found"):
            await client.analyze("prompt")

    async def test_bad_request_error(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        response = _make_response(status_code=400)
        mock_create.side_effect = openai.BadRequestError(message="Invalid parameter", response=response, body={})

        with pytest.raises(LLMRequestError, match="Invalid request"):
            await client.analyze("prompt")

    async def test_context_length_error(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        response = _make_response(status_code=400)
        mock_create.side_effect = openai.BadRequestError(
            message="This model's maximum context length is 8192 tokens",
            response=response,
            body={},
        )

        with pytest.raises(LLMContextLengthError, match="context window"):
            await client.analyze("very long prompt")

    async def test_empty_response_none(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        mock_create.return_value = _make_completion(content=None, finish_reason="stop")  # type: ignore[arg-type]

        with pytest.raises(LLMEmptyResponseError, match="empty response"):
            await client.analyze("prompt")

    async def test_empty_response_empty_string(self, client_with_mock: tuple[OpenAIClient, AsyncMock]) -> None:
        client, mock_create = client_with_mock
        mock_create.return_value = _make_completion(content="", finish_reason="stop")

        with pytest.raises(LLMEmptyResponseError, match="empty response"):
            await client.analyze("prompt")
