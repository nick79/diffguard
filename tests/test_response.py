"""Tests for LLM response parsing."""

import json

import pytest

from diffguard.exceptions import MalformedResponseError
from diffguard.llm.response import (
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    parse_llm_response,
)

# ---------------------------------------------------------------------------
# Sample responses
# ---------------------------------------------------------------------------

VALID_LLM_RESPONSE = """
{
  "findings": [
    {
      "what": "SQL Injection vulnerability",
      "why": "User input directly concatenated into SQL query",
      "how_to_fix": "Use parameterized queries",
      "severity": "High",
      "confidence": "High",
      "cwe_id": "CWE-89",
      "owasp_category": "A05:2025-Injection",
      "line_range": {"start": 42, "end": 45}
    }
  ]
}
"""

RESPONSE_WITH_CODE_FENCE = """
Here are the security findings:

```json
{
  "findings": [{"what": "Issue", "why": "Reason", "how_to_fix": "Fix", "severity": "Medium", "confidence": "Medium"}]
}
```

Let me know if you need more details.
"""

RESPONSE_WITH_EXTRA_TEXT = (
    "Here are the findings:\n"
    '{"findings": [{"what": "XSS", "why": "Unescaped output",'
    ' "how_to_fix": "Escape HTML", "severity": "High", "confidence": "High"}]}\n'
    "\nLet me know if you need more.\n"
)

MALFORMED_JSON = "{ this is not valid json }"

EMPTY_FINDINGS = '{"findings": []}'

MISSING_REQUIRED_FIELD = '{"findings": [{"why": "reason", "severity": "High", "confidence": "High"}]}'

UNKNOWN_SEVERITY = (
    '{"findings": [{"what": "Issue", "why": "Reason", "how_to_fix": "Fix",'
    ' "severity": "Extreme", "confidence": "High"}]}'
)

UNKNOWN_CONFIDENCE = (
    '{"findings": [{"what": "Issue", "why": "Reason", "how_to_fix": "Fix",'
    ' "severity": "High", "confidence": "Very High"}]}'
)

LINE_RANGE_ARRAY = (
    '{"findings": [{"what": "Issue", "why": "R", "how_to_fix": "F",'
    ' "severity": "Low", "confidence": "Low", "line_range": [10, 15]}]}'
)

LINE_RANGE_OBJECT = (
    '{"findings": [{"what": "Issue", "why": "R", "how_to_fix": "F",'
    ' "severity": "Low", "confidence": "Low", "line_range": {"start": 10, "end": 15}}]}'
)


def _make_response(**overrides: object) -> str:
    """Build a single-finding JSON response with overrides."""
    finding: dict[str, object] = {
        "what": "Test issue",
        "why": "Test reason",
        "how_to_fix": "Test fix",
        "severity": "Medium",
        "confidence": "Medium",
    }
    finding.update(overrides)
    return f'{{"findings": [{_to_json_value(finding)}]}}'


def _to_json_value(obj: object) -> str:
    """Convert a Python object to a JSON string value."""
    return json.dumps(obj)


# ---------------------------------------------------------------------------
# Parse valid JSON response
# ---------------------------------------------------------------------------


class TestParseValidResponse:
    def test_complete_finding(self) -> None:
        findings = parse_llm_response(VALID_LLM_RESPONSE)

        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, Finding)
        assert f.what == "SQL Injection vulnerability"
        assert f.why == "User input directly concatenated into SQL query"
        assert f.how_to_fix == "Use parameterized queries"
        assert f.severity == SeverityLevel.HIGH
        assert f.confidence == ConfidenceLevel.HIGH
        assert f.cwe_id == "CWE-89"
        assert f.owasp_category == "A05:2025-Injection"
        assert f.line_range == (42, 45)

    def test_multiple_findings(self) -> None:
        raw = """{
          "findings": [
            {"what": "Issue 1", "why": "R1", "how_to_fix": "F1", "severity": "High", "confidence": "High"},
            {"what": "Issue 2", "why": "R2", "how_to_fix": "F2", "severity": "Medium", "confidence": "Medium"},
            {"what": "Issue 3", "why": "R3", "how_to_fix": "F3", "severity": "Low", "confidence": "Low"}
          ]
        }"""
        findings = parse_llm_response(raw)

        assert len(findings) == 3
        assert findings[0].what == "Issue 1"
        assert findings[1].what == "Issue 2"
        assert findings[2].what == "Issue 3"

    def test_empty_findings(self) -> None:
        findings = parse_llm_response(EMPTY_FINDINGS)

        assert findings == []


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------


class TestJsonExtraction:
    def test_malformed_json_raises(self) -> None:
        with pytest.raises(MalformedResponseError, match="Could not extract valid JSON"):
            parse_llm_response(MALFORMED_JSON)

    def test_json_in_code_fence(self) -> None:
        findings = parse_llm_response(RESPONSE_WITH_CODE_FENCE)

        assert len(findings) == 1
        assert findings[0].what == "Issue"

    def test_json_with_extra_text(self) -> None:
        findings = parse_llm_response(RESPONSE_WITH_EXTRA_TEXT)

        assert len(findings) == 1
        assert findings[0].what == "XSS"

    def test_completely_invalid_string(self) -> None:
        with pytest.raises(MalformedResponseError):
            parse_llm_response("no json here at all")

    def test_empty_string(self) -> None:
        with pytest.raises(MalformedResponseError):
            parse_llm_response("")

    def test_json_array_not_object(self) -> None:
        with pytest.raises(MalformedResponseError):
            parse_llm_response('[{"what": "test"}]')

    def test_missing_findings_key(self) -> None:
        with pytest.raises(MalformedResponseError, match="findings"):
            parse_llm_response('{"results": []}')


# ---------------------------------------------------------------------------
# Required and optional fields
# ---------------------------------------------------------------------------


class TestFieldValidation:
    def test_missing_what_raises(self) -> None:
        with pytest.raises(MalformedResponseError, match="what"):
            parse_llm_response(MISSING_REQUIRED_FIELD)

    def test_missing_how_to_fix_raises(self) -> None:
        raw = '{"findings": [{"what": "Issue", "why": "R", "severity": "High", "confidence": "High"}]}'
        with pytest.raises(MalformedResponseError, match="how_to_fix"):
            parse_llm_response(raw)

    def test_missing_severity_raises(self) -> None:
        raw = '{"findings": [{"what": "Issue", "why": "R", "how_to_fix": "F", "confidence": "High"}]}'
        with pytest.raises(MalformedResponseError, match="severity"):
            parse_llm_response(raw)

    def test_missing_confidence_raises(self) -> None:
        raw = '{"findings": [{"what": "Issue", "why": "R", "how_to_fix": "F", "severity": "High"}]}'
        with pytest.raises(MalformedResponseError, match="confidence"):
            parse_llm_response(raw)

    def test_null_required_field_raises(self) -> None:
        raw = '{"findings": [{"what": null, "why": "R", "how_to_fix": "F", "severity": "High", "confidence": "High"}]}'
        with pytest.raises(MalformedResponseError, match="what"):
            parse_llm_response(raw)

    def test_missing_optional_cwe_id(self) -> None:
        raw = _make_response()
        findings = parse_llm_response(raw)

        assert findings[0].cwe_id is None

    def test_missing_optional_owasp(self) -> None:
        raw = _make_response()
        findings = parse_llm_response(raw)

        assert findings[0].owasp_category is None

    def test_missing_line_range(self) -> None:
        raw = _make_response()
        findings = parse_llm_response(raw)

        assert findings[0].line_range is None

    def test_null_optional_fields(self) -> None:
        raw = _make_response(cwe_id=None, owasp_category=None, line_range=None)
        findings = parse_llm_response(raw)

        assert findings[0].cwe_id is None
        assert findings[0].owasp_category is None
        assert findings[0].line_range is None


# ---------------------------------------------------------------------------
# Severity and confidence parsing
# ---------------------------------------------------------------------------


class TestSeverityParsing:
    @pytest.mark.parametrize(
        ("raw_value", "expected"),
        [
            ("Critical", SeverityLevel.CRITICAL),
            ("critical", SeverityLevel.CRITICAL),
            ("CRITICAL", SeverityLevel.CRITICAL),
            ("High", SeverityLevel.HIGH),
            ("high", SeverityLevel.HIGH),
            ("Medium", SeverityLevel.MEDIUM),
            ("medium", SeverityLevel.MEDIUM),
            ("Low", SeverityLevel.LOW),
            ("low", SeverityLevel.LOW),
            ("Info", SeverityLevel.INFO),
            ("info", SeverityLevel.INFO),
        ],
    )
    def test_severity_levels(self, raw_value: str, expected: SeverityLevel) -> None:
        raw = _make_response(severity=raw_value)
        findings = parse_llm_response(raw)

        assert findings[0].severity == expected

    def test_unknown_severity_defaults_to_medium(self) -> None:
        findings = parse_llm_response(UNKNOWN_SEVERITY)

        assert findings[0].severity == SeverityLevel.MEDIUM

    def test_very_high_severity_defaults_to_medium(self) -> None:
        raw = _make_response(severity="Very High")
        findings = parse_llm_response(raw)

        assert findings[0].severity == SeverityLevel.MEDIUM


class TestConfidenceParsing:
    @pytest.mark.parametrize(
        ("raw_value", "expected"),
        [
            ("High", ConfidenceLevel.HIGH),
            ("high", ConfidenceLevel.HIGH),
            ("HIGH", ConfidenceLevel.HIGH),
            ("Medium", ConfidenceLevel.MEDIUM),
            ("medium", ConfidenceLevel.MEDIUM),
            ("Low", ConfidenceLevel.LOW),
            ("low", ConfidenceLevel.LOW),
        ],
    )
    def test_confidence_levels(self, raw_value: str, expected: ConfidenceLevel) -> None:
        raw = _make_response(confidence=raw_value)
        findings = parse_llm_response(raw)

        assert findings[0].confidence == expected

    def test_unknown_confidence_defaults_to_medium(self) -> None:
        findings = parse_llm_response(UNKNOWN_CONFIDENCE)

        assert findings[0].confidence == ConfidenceLevel.MEDIUM


# ---------------------------------------------------------------------------
# Line range parsing
# ---------------------------------------------------------------------------


class TestLineRangeParsing:
    def test_object_format(self) -> None:
        findings = parse_llm_response(LINE_RANGE_OBJECT)

        assert findings[0].line_range == (10, 15)

    def test_array_format(self) -> None:
        findings = parse_llm_response(LINE_RANGE_ARRAY)

        assert findings[0].line_range == (10, 15)

    def test_single_line(self) -> None:
        raw = _make_response(line_range={"start": 10, "end": 10})
        findings = parse_llm_response(raw)

        assert findings[0].line_range == (10, 10)

    def test_end_before_start_swaps(self) -> None:
        raw = _make_response(line_range={"start": 20, "end": 10})
        findings = parse_llm_response(raw)

        assert findings[0].line_range == (10, 20)

    def test_negative_line_number_raises(self) -> None:
        raw = _make_response(line_range={"start": -1, "end": 10})
        with pytest.raises(MalformedResponseError, match="negative"):
            parse_llm_response(raw)

    def test_negative_end_line_raises(self) -> None:
        raw = _make_response(line_range={"start": 5, "end": -3})
        with pytest.raises(MalformedResponseError, match="negative"):
            parse_llm_response(raw)

    def test_null_line_range(self) -> None:
        raw = _make_response(line_range=None)
        findings = parse_llm_response(raw)

        assert findings[0].line_range is None

    def test_missing_start_returns_none(self) -> None:
        raw = _make_response(line_range={"end": 10})
        findings = parse_llm_response(raw)

        assert findings[0].line_range is None

    def test_missing_end_returns_none(self) -> None:
        raw = _make_response(line_range={"start": 10})
        findings = parse_llm_response(raw)

        assert findings[0].line_range is None


# ---------------------------------------------------------------------------
# CWE ID normalization
# ---------------------------------------------------------------------------


class TestCweNormalization:
    def test_cwe_with_prefix(self) -> None:
        raw = _make_response(cwe_id="CWE-89")
        findings = parse_llm_response(raw)

        assert findings[0].cwe_id == "CWE-89"

    def test_cwe_number_only(self) -> None:
        raw = _make_response(cwe_id="89")
        findings = parse_llm_response(raw)

        assert findings[0].cwe_id == "CWE-89"

    def test_cwe_lowercase_prefix(self) -> None:
        raw = _make_response(cwe_id="cwe-79")
        findings = parse_llm_response(raw)

        assert findings[0].cwe_id == "CWE-79"

    def test_null_cwe_id(self) -> None:
        raw = _make_response(cwe_id=None)
        findings = parse_llm_response(raw)

        assert findings[0].cwe_id is None


# ---------------------------------------------------------------------------
# OWASP category
# ---------------------------------------------------------------------------


class TestOwaspCategory:
    def test_owasp_preserved(self) -> None:
        raw = _make_response(owasp_category="A05:2025-Injection")
        findings = parse_llm_response(raw)

        assert findings[0].owasp_category == "A05:2025-Injection"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_extra_fields_ignored(self) -> None:
        raw = """{
          "findings": [{
            "what": "Issue",
            "why": "R",
            "how_to_fix": "F",
            "severity": "High",
            "confidence": "High",
            "extra_field": "should be ignored",
            "another": 42
          }]
        }"""
        findings = parse_llm_response(raw)

        assert len(findings) == 1
        assert findings[0].what == "Issue"

    def test_unicode_preserved(self) -> None:
        raw = _make_response(what="SQL \u6ce8\u5165\u6f0f\u6d1e", why="\u7528\u6237\u8f93\u5165\u672a\u8f6c\u4e49")
        findings = parse_llm_response(raw)

        assert findings[0].what == "SQL \u6ce8\u5165\u6f0f\u6d1e"
        assert findings[0].why == "\u7528\u6237\u8f93\u5165\u672a\u8f6c\u4e49"

    def test_long_text_fields(self) -> None:
        long_fix = "Use parameterized queries. " * 500
        raw = _make_response(how_to_fix=long_fix)
        findings = parse_llm_response(raw)

        assert findings[0].how_to_fix == long_fix

    def test_finding_not_dict_raises(self) -> None:
        raw = '{"findings": ["not a dict"]}'
        with pytest.raises(MalformedResponseError, match="JSON object"):
            parse_llm_response(raw)


class TestFilePath:
    def test_file_path_parsed(self) -> None:
        raw = _make_response(file_path="src/api/handler.py")
        findings = parse_llm_response(raw)

        assert findings[0].file_path == "src/api/handler.py"

    def test_file_path_missing(self) -> None:
        raw = _make_response()
        findings = parse_llm_response(raw)

        assert findings[0].file_path is None

    def test_file_path_null(self) -> None:
        raw = _make_response(file_path=None)
        findings = parse_llm_response(raw)

        assert findings[0].file_path is None
