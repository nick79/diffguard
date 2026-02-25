"""Tests for concurrent file analysis."""

import asyncio
import time
from unittest.mock import AsyncMock

import pytest

from diffguard.exceptions import LLMServerError, LLMTimeoutError, MalformedResponseError
from diffguard.llm.analyzer import AnalysisResult, FileAnalysisError, analyze_file, analyze_files
from diffguard.llm.prompts import CodeContext, DiffLine
from diffguard.llm.response import SeverityLevel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context(file_path: str = "src/file.py") -> CodeContext:
    """Create a minimal CodeContext for testing."""
    return CodeContext(
        file_path=file_path,
        diff_lines=[DiffLine(line_num=1, change_type="+", content="x = 1")],
        expanded_region="x = 1",
        region_start_line=1,
    )


def _make_contexts(n: int) -> list[CodeContext]:
    """Create n CodeContexts with distinct file paths."""
    return [_make_context(f"src/file{i}.py") for i in range(n)]


def _make_response(*findings_data: tuple[str, str]) -> str:
    """Build a JSON response string with the given (what, severity) pairs."""
    if not findings_data:
        return '{"findings": []}'
    findings = [
        f'{{"what": "{what}", "why": "R", "how_to_fix": "F", "severity": "{severity}", "confidence": "Medium"}}'
        for what, severity in findings_data
    ]
    return '{"findings": [' + ", ".join(findings) + "]}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_client() -> AsyncMock:
    """Mock LLM client that returns empty findings by default."""
    client = AsyncMock()
    client.analyze.return_value = '{"findings": []}'
    return client


@pytest.fixture
def mock_client_with_findings() -> AsyncMock:
    """Mock client that returns canned responses per file."""
    client = AsyncMock()
    client.analyze.side_effect = [
        _make_response(("Issue 1", "High")),
        '{"findings": []}',
        _make_response(("Issue 2", "Medium")),
    ]
    return client


@pytest.fixture
def mock_client_with_failure() -> AsyncMock:
    """Mock client where second call fails."""
    client = AsyncMock()
    client.analyze.side_effect = [
        '{"findings": []}',
        LLMTimeoutError("Timeout"),
        '{"findings": []}',
    ]
    return client


# ---------------------------------------------------------------------------
# analyze_file — single file tests
# ---------------------------------------------------------------------------


class TestAnalyzeSingleFile:
    async def test_success_returns_findings(self) -> None:
        client = AsyncMock()
        client.analyze.return_value = _make_response(("SQL Injection", "High"))

        findings = await analyze_file(_make_context("src/api.py"), client)

        assert len(findings) == 1
        assert findings[0].what == "SQL Injection"
        assert findings[0].severity == SeverityLevel.HIGH

    async def test_no_findings_returns_empty_list(self, mock_client: AsyncMock) -> None:
        findings = await analyze_file(_make_context(), mock_client)

        assert findings == []

    async def test_findings_include_file_path(self) -> None:
        client = AsyncMock()
        client.analyze.return_value = _make_response(("Issue", "High"))

        findings = await analyze_file(_make_context("src/api.py"), client)

        assert findings[0].file_path == "src/api.py"

    async def test_multiple_findings_all_get_file_path(self) -> None:
        client = AsyncMock()
        client.analyze.return_value = _make_response(("A", "High"), ("B", "Medium"))

        findings = await analyze_file(_make_context("src/views.py"), client)

        assert len(findings) == 2
        assert all(f.file_path == "src/views.py" for f in findings)


# ---------------------------------------------------------------------------
# analyze_file — retry behavior
# ---------------------------------------------------------------------------


class TestAnalyzeFileRetry:
    async def test_retry_on_transient_server_error(self) -> None:
        client = AsyncMock()
        client.analyze.side_effect = [
            LLMServerError("Server error"),
            _make_response(("Issue", "Medium")),
        ]

        findings = await analyze_file(_make_context(), client, max_retries=1)

        assert len(findings) == 1
        assert client.analyze.call_count == 2

    async def test_retry_on_transient_timeout_error(self) -> None:
        client = AsyncMock()
        client.analyze.side_effect = [
            LLMTimeoutError("Timeout"),
            _make_response(("Issue", "Low")),
        ]

        findings = await analyze_file(_make_context(), client, max_retries=1)

        assert len(findings) == 1

    async def test_retry_exhausted_raises(self) -> None:
        client = AsyncMock()
        client.analyze.side_effect = LLMServerError("Server error")

        with pytest.raises(LLMServerError):
            await analyze_file(_make_context(), client, max_retries=1)

        assert client.analyze.call_count == 2

    async def test_non_transient_error_not_retried(self) -> None:
        client = AsyncMock()
        client.analyze.side_effect = MalformedResponseError("Bad JSON")

        with pytest.raises(MalformedResponseError):
            await analyze_file(_make_context(), client, max_retries=2)

        assert client.analyze.call_count == 1

    async def test_no_retry_by_default(self) -> None:
        client = AsyncMock()
        client.analyze.side_effect = LLMServerError("Server error")

        with pytest.raises(LLMServerError):
            await analyze_file(_make_context(), client)

        assert client.analyze.call_count == 1


# ---------------------------------------------------------------------------
# analyze_files — basic behavior
# ---------------------------------------------------------------------------


class TestAnalyzeFiles:
    async def test_multiple_files_concurrently(self, mock_client_with_findings: AsyncMock) -> None:
        contexts = _make_contexts(3)

        result = await analyze_files(contexts, mock_client_with_findings)

        assert isinstance(result, AnalysisResult)
        assert len(result.findings) == 2
        assert len(result.errors) == 0

    async def test_correct_finding_count(self, mock_client_with_findings: AsyncMock) -> None:
        contexts = _make_contexts(3)

        result = await analyze_files(contexts, mock_client_with_findings)

        whats = {f.what for f in result.findings}
        assert whats == {"Issue 1", "Issue 2"}

    async def test_empty_file_list(self, mock_client: AsyncMock) -> None:
        result = await analyze_files([], mock_client)

        assert result.findings == []
        assert result.errors == []
        mock_client.analyze.assert_not_called()

    async def test_single_file_list(self, mock_client: AsyncMock) -> None:
        mock_client.analyze.return_value = _make_response(("Issue", "Low"))

        result = await analyze_files([_make_context()], mock_client)

        assert len(result.findings) == 1

    async def test_findings_ordered_by_file(self) -> None:
        client = AsyncMock()
        client.analyze.side_effect = [
            _make_response(("A_issue", "High")),
            _make_response(("B_issue", "Medium")),
            _make_response(("C_issue", "Low")),
        ]
        contexts = [
            _make_context("src/a.py"),
            _make_context("src/b.py"),
            _make_context("src/c.py"),
        ]

        result = await analyze_files(contexts, client)

        assert [f.what for f in result.findings] == ["A_issue", "B_issue", "C_issue"]
        assert [f.file_path for f in result.findings] == ["src/a.py", "src/b.py", "src/c.py"]


# ---------------------------------------------------------------------------
# Concurrency limiting
# ---------------------------------------------------------------------------


class TestConcurrencyLimiting:
    async def test_semaphore_limits_concurrent_calls(self) -> None:
        max_concurrent_seen = 0
        current_concurrent = 0

        async def slow_analyze(_prompt: str) -> str:
            nonlocal max_concurrent_seen, current_concurrent
            current_concurrent += 1
            max_concurrent_seen = max(max_concurrent_seen, current_concurrent)
            await asyncio.sleep(0.01)
            current_concurrent -= 1
            return '{"findings": []}'

        client = AsyncMock()
        client.analyze.side_effect = slow_analyze

        await analyze_files(_make_contexts(10), client, max_concurrent=3)

        assert max_concurrent_seen <= 3

    async def test_timing_verification(self) -> None:
        async def slow_analyze(_prompt: str) -> str:
            await asyncio.sleep(0.05)
            return '{"findings": []}'

        client = AsyncMock()
        client.analyze.side_effect = slow_analyze

        start = time.monotonic()
        await analyze_files(_make_contexts(6), client, max_concurrent=2)
        elapsed = time.monotonic() - start

        # 6 files, max_concurrent=2, each 50ms -> 3 batches -> ~150ms minimum
        assert elapsed >= 0.12
        # Should be well under sequential time (6 * 50ms = 300ms)
        assert elapsed < 0.5

    async def test_max_concurrent_one_is_sequential(self) -> None:
        call_order: list[str] = []

        async def tracking_analyze(_prompt: str) -> str:
            call_order.append(_prompt)
            await asyncio.sleep(0.01)
            return '{"findings": []}'

        client = AsyncMock()
        client.analyze.side_effect = tracking_analyze

        await analyze_files(_make_contexts(3), client, max_concurrent=1)

        assert client.analyze.call_count == 3


# ---------------------------------------------------------------------------
# Partial failures
# ---------------------------------------------------------------------------


class TestPartialFailures:
    async def test_continue_on_error(self, mock_client_with_failure: AsyncMock) -> None:
        contexts = _make_contexts(3)

        result = await analyze_files(contexts, mock_client_with_failure)

        assert len(result.errors) == 1
        assert len(result.findings) == 0  # files 0 and 2 returned empty findings

    async def test_error_reporting(self, mock_client_with_failure: AsyncMock) -> None:
        contexts = _make_contexts(3)

        result = await analyze_files(contexts, mock_client_with_failure)

        err = result.errors[0]
        assert isinstance(err, FileAnalysisError)
        assert err.file_path == "src/file1.py"
        assert err.error_type == "LLMTimeoutError"
        assert "Timeout" in err.error

    async def test_all_files_failing(self) -> None:
        client = AsyncMock()
        client.analyze.side_effect = LLMTimeoutError("Timeout")

        result = await analyze_files(_make_contexts(3), client)

        assert len(result.findings) == 0
        assert len(result.errors) == 3

    async def test_malformed_response_recorded_as_error(self) -> None:
        client = AsyncMock()
        client.analyze.side_effect = [
            _make_response(("Issue", "High")),
            "not valid json at all",
            _make_response(("Issue 2", "Medium")),
        ]

        result = await analyze_files(_make_contexts(3), client)

        assert len(result.findings) == 2
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "MalformedResponseError"

    async def test_findings_from_successful_files_preserved(self) -> None:
        client = AsyncMock()
        client.analyze.side_effect = [
            _make_response(("Found it", "High")),
            LLMServerError("Boom"),
            _make_response(("Another", "Low")),
        ]

        result = await analyze_files(_make_contexts(3), client)

        assert len(result.findings) == 2
        assert {f.what for f in result.findings} == {"Found it", "Another"}
        assert len(result.errors) == 1


# ---------------------------------------------------------------------------
# Progress callback
# ---------------------------------------------------------------------------


class TestProgressCallback:
    async def test_callback_called_after_each_file(self, mock_client: AsyncMock) -> None:
        progress_calls: list[tuple[int, int]] = []

        def on_progress(completed: int, total: int) -> None:
            progress_calls.append((completed, total))

        await analyze_files(_make_contexts(3), mock_client, on_progress=on_progress)

        assert len(progress_calls) == 3
        assert all(total == 3 for _, total in progress_calls)
        completed_values = sorted(c for c, _ in progress_calls)
        assert completed_values == [1, 2, 3]

    async def test_callback_called_on_error(self) -> None:
        client = AsyncMock()
        client.analyze.side_effect = LLMTimeoutError("Timeout")
        progress_calls: list[tuple[int, int]] = []

        await analyze_files(
            _make_contexts(2),
            client,
            on_progress=lambda c, t: progress_calls.append((c, t)),
        )

        assert len(progress_calls) == 2

    async def test_no_callback_when_not_provided(self, mock_client: AsyncMock) -> None:
        # Should not raise when on_progress is None
        result = await analyze_files(_make_contexts(2), mock_client)

        assert isinstance(result, AnalysisResult)


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


class TestCancellation:
    async def test_cancellation_propagates(self) -> None:
        async def hanging_analyze(_prompt: str) -> str:
            await asyncio.sleep(10)
            return '{"findings": []}'

        client = AsyncMock()
        client.analyze.side_effect = hanging_analyze

        task = asyncio.create_task(analyze_files(_make_contexts(3), client))
        await asyncio.sleep(0.01)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task


# ---------------------------------------------------------------------------
# Timeout per file
# ---------------------------------------------------------------------------


class TestTimeoutPerFile:
    async def test_slow_file_times_out(self) -> None:
        call_count = 0

        async def mixed_analyze(_prompt: str) -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                await asyncio.sleep(10)
            return '{"findings": []}'

        client = AsyncMock()
        client.analyze.side_effect = mixed_analyze

        result = await analyze_files(_make_contexts(3), client, timeout_per_file=0.1)

        assert len(result.errors) == 1
        assert result.errors[0].error_type == "TimeoutError"
        assert "timed out" in result.errors[0].error

    async def test_timeout_does_not_affect_fast_files(self) -> None:
        client = AsyncMock()
        client.analyze.return_value = _make_response(("Issue", "Medium"))

        result = await analyze_files(_make_contexts(3), client, timeout_per_file=5.0)

        assert len(result.findings) == 3
        assert len(result.errors) == 0
