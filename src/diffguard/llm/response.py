"""LLM response parsing for security findings."""

import json
import re
from dataclasses import dataclass
from enum import Enum

from diffguard.exceptions import MalformedResponseError

__all__ = [
    "ConfidenceLevel",
    "Finding",
    "SeverityLevel",
    "parse_llm_response",
]


class SeverityLevel(Enum):
    """CVSS-aligned severity levels for security findings."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ConfidenceLevel(Enum):
    """LLM confidence in a security finding."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass(frozen=True)
class Finding:
    """A single security finding from LLM analysis."""

    what: str
    why: str
    how_to_fix: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    cwe_id: str | None = None
    owasp_category: str | None = None
    line_range: tuple[int, int] | None = None
    file_path: str | None = None


_SEVERITY_MAP: dict[str, SeverityLevel] = {s.value.lower(): s for s in SeverityLevel}
_CONFIDENCE_MAP: dict[str, ConfidenceLevel] = {c.value.lower(): c for c in ConfidenceLevel}

_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n\s*```", re.DOTALL)
_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
_CWE_NORMALIZE_RE = re.compile(r"^(?:CWE-)?(\d+)$", re.IGNORECASE)

_REQUIRED_FIELDS = ("what", "why", "how_to_fix", "severity", "confidence")


def parse_llm_response(raw: str) -> list[Finding]:
    """Parse an LLM JSON response into a list of findings.

    Handles:
    - Clean JSON
    - JSON wrapped in markdown code fences
    - JSON with extra text before/after
    - Various line_range formats (object with start/end, array)
    - Case-insensitive severity and confidence levels
    - CWE ID normalization (bare number -> "CWE-XXX")
    - Unknown severity/confidence defaults to Medium

    Args:
        raw: Raw LLM response string.

    Returns:
        List of Finding objects.

    Raises:
        MalformedResponseError: If JSON cannot be parsed or required fields are missing.
    """
    data = _extract_json(raw)
    findings_data = _extract_findings_array(data)
    return [_parse_finding(f) for f in findings_data]


def _extract_json(raw: str) -> dict[str, object]:
    """Extract and parse a JSON object from the raw LLM response."""
    # Try parsing the raw string directly first
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Try extracting from a markdown code fence
    match = _CODE_FENCE_RE.search(raw)
    if match:
        try:
            parsed = json.loads(match.group(1))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    # Try finding a JSON object in the text
    match = _JSON_OBJECT_RE.search(raw)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    raise MalformedResponseError(f"Could not extract valid JSON from LLM response: {raw[:200]}")


def _extract_findings_array(data: dict[str, object]) -> list[dict[str, object]]:
    """Extract the findings array from parsed JSON."""
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise MalformedResponseError("Response JSON missing 'findings' array")
    return findings


def _parse_finding(raw_finding: dict[str, object]) -> Finding:
    """Parse a single finding dict into a Finding dataclass."""
    if not isinstance(raw_finding, dict):
        raise MalformedResponseError(f"Finding must be a JSON object, got {type(raw_finding).__name__}")

    _validate_required_fields(raw_finding)

    return Finding(
        what=str(raw_finding["what"]),
        why=str(raw_finding["why"]),
        how_to_fix=str(raw_finding["how_to_fix"]),
        severity=_parse_severity(raw_finding["severity"]),
        confidence=_parse_confidence(raw_finding["confidence"]),
        cwe_id=_normalize_cwe_id(raw_finding.get("cwe_id")),
        owasp_category=_parse_optional_str(raw_finding.get("owasp_category")),
        line_range=_parse_line_range(raw_finding.get("line_range")),
        file_path=_parse_optional_str(raw_finding.get("file_path")),
    )


def _validate_required_fields(raw_finding: dict[str, object]) -> None:
    """Raise MalformedResponseError if any required field is missing."""
    missing = [f for f in _REQUIRED_FIELDS if f not in raw_finding or raw_finding[f] is None]
    if missing:
        raise MalformedResponseError(f"Finding missing required field(s): {', '.join(missing)}")


def _parse_severity(value: object) -> SeverityLevel:
    """Parse severity string to SeverityLevel enum, defaulting to MEDIUM for unknowns."""
    if not isinstance(value, str):
        return SeverityLevel.MEDIUM
    return _SEVERITY_MAP.get(value.strip().lower(), SeverityLevel.MEDIUM)


def _parse_confidence(value: object) -> ConfidenceLevel:
    """Parse confidence string to ConfidenceLevel enum, defaulting to MEDIUM for unknowns."""
    if not isinstance(value, str):
        return ConfidenceLevel.MEDIUM
    return _CONFIDENCE_MAP.get(value.strip().lower(), ConfidenceLevel.MEDIUM)


def _normalize_cwe_id(value: object) -> str | None:
    """Normalize CWE ID to 'CWE-XXX' format. Returns None for null/missing."""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    match = _CWE_NORMALIZE_RE.match(raw)
    if match:
        return f"CWE-{match.group(1)}"
    return raw


def _parse_optional_str(value: object) -> str | None:
    """Parse an optional string field, returning None for null/empty."""
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _parse_line_range(value: object) -> tuple[int, int] | None:
    """Parse line_range from object or array format.

    Accepts:
    - {"start": 10, "end": 15}
    - [10, 15]
    - None

    Raises MalformedResponseError for negative line numbers.
    Swaps start/end if end < start.
    """
    if value is None:
        return None

    start: int
    end: int

    if isinstance(value, dict):
        raw_start = value.get("start")
        raw_end = value.get("end")
        if raw_start is None or raw_end is None:
            return None
        start, end = int(raw_start), int(raw_end)
    elif isinstance(value, list) and len(value) >= 2:
        start, end = int(value[0]), int(value[1])
    else:
        return None

    if start < 0 or end < 0:
        raise MalformedResponseError(f"Line range contains negative line number: ({start}, {end})")

    if start > end:
        start, end = end, start

    return (start, end)
