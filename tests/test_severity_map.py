"""Tests for deterministic CWE-to-severity mapping."""

from diffguard.llm.response import ConfidenceLevel, Finding, SeverityLevel
from diffguard.severity_map import CWE_SEVERITY_MAP, apply_severity_map, map_severity


def _make_finding(
    *,
    cwe_id: str | None = "CWE-89",
    severity: SeverityLevel = SeverityLevel.MEDIUM,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> Finding:
    return Finding(
        what="test",
        why="test",
        how_to_fix="test",
        severity=severity,
        confidence=confidence,
        cwe_id=cwe_id,
    )


class TestMapSeverity:
    def test_mapped_cwe_overrides_llm_severity(self) -> None:
        finding = _make_finding(cwe_id="CWE-89", severity=SeverityLevel.MEDIUM)
        assert map_severity(finding) == SeverityLevel.HIGH

    def test_critical_cwe_maps_to_critical(self) -> None:
        finding = _make_finding(cwe_id="CWE-78", severity=SeverityLevel.HIGH)
        assert map_severity(finding) == SeverityLevel.CRITICAL

    def test_medium_cwe_maps_to_medium(self) -> None:
        finding = _make_finding(cwe_id="CWE-352", severity=SeverityLevel.HIGH)
        assert map_severity(finding) == SeverityLevel.MEDIUM

    def test_low_cwe_maps_to_low(self) -> None:
        finding = _make_finding(cwe_id="CWE-209", severity=SeverityLevel.HIGH)
        assert map_severity(finding) == SeverityLevel.LOW

    def test_unmapped_cwe_uses_llm_severity(self) -> None:
        finding = _make_finding(cwe_id="CWE-999", severity=SeverityLevel.HIGH)
        assert map_severity(finding) == SeverityLevel.HIGH

    def test_no_cwe_uses_llm_severity(self) -> None:
        finding = _make_finding(cwe_id=None, severity=SeverityLevel.CRITICAL)
        assert map_severity(finding) == SeverityLevel.CRITICAL

    def test_low_confidence_caps_at_medium(self) -> None:
        finding = _make_finding(
            cwe_id="CWE-78",
            severity=SeverityLevel.CRITICAL,
            confidence=ConfidenceLevel.LOW,
        )
        assert map_severity(finding) == SeverityLevel.MEDIUM

    def test_low_confidence_does_not_upgrade(self) -> None:
        finding = _make_finding(
            cwe_id="CWE-209",
            severity=SeverityLevel.LOW,
            confidence=ConfidenceLevel.LOW,
        )
        assert map_severity(finding) == SeverityLevel.LOW

    def test_medium_confidence_no_cap(self) -> None:
        finding = _make_finding(
            cwe_id="CWE-78",
            severity=SeverityLevel.CRITICAL,
            confidence=ConfidenceLevel.MEDIUM,
        )
        assert map_severity(finding) == SeverityLevel.CRITICAL

    def test_high_confidence_no_cap(self) -> None:
        finding = _make_finding(
            cwe_id="CWE-94",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
        )
        assert map_severity(finding) == SeverityLevel.CRITICAL


class TestApplySeverityMap:
    def test_applies_to_all_findings(self) -> None:
        findings = [
            _make_finding(cwe_id="CWE-89", severity=SeverityLevel.CRITICAL),
            _make_finding(cwe_id="CWE-352", severity=SeverityLevel.HIGH),
            _make_finding(cwe_id="CWE-78", severity=SeverityLevel.LOW),
        ]
        result = apply_severity_map(findings)
        assert result[0].severity == SeverityLevel.HIGH
        assert result[1].severity == SeverityLevel.MEDIUM
        assert result[2].severity == SeverityLevel.CRITICAL

    def test_empty_list(self) -> None:
        assert apply_severity_map([]) == []

    def test_preserves_other_fields(self) -> None:
        finding = Finding(
            what="SQL injection",
            why="user input in query",
            how_to_fix="use parameterized queries",
            severity=SeverityLevel.CRITICAL,
            confidence=ConfidenceLevel.HIGH,
            cwe_id="CWE-89",
            owasp_category="A03:2025",
            line_range=(10, 15),
            file_path="src/db.py",
        )
        result = apply_severity_map([finding])[0]
        assert result.severity == SeverityLevel.HIGH
        assert result.what == "SQL injection"
        assert result.why == "user input in query"
        assert result.cwe_id == "CWE-89"
        assert result.line_range == (10, 15)
        assert result.file_path == "src/db.py"


class TestCweSeverityMap:
    def test_all_critical_cwes(self) -> None:
        critical_cwes = ["CWE-78", "CWE-94", "CWE-95", "CWE-306"]
        for cwe in critical_cwes:
            assert CWE_SEVERITY_MAP[cwe] == SeverityLevel.CRITICAL, f"{cwe} should be Critical"

    def test_sql_injection_is_high(self) -> None:
        assert CWE_SEVERITY_MAP["CWE-89"] == SeverityLevel.HIGH

    def test_xss_is_high(self) -> None:
        assert CWE_SEVERITY_MAP["CWE-79"] == SeverityLevel.HIGH

    def test_deserialization_is_high(self) -> None:
        assert CWE_SEVERITY_MAP["CWE-502"] == SeverityLevel.HIGH

    def test_csrf_is_medium(self) -> None:
        assert CWE_SEVERITY_MAP["CWE-352"] == SeverityLevel.MEDIUM

    def test_error_message_exposure_is_low(self) -> None:
        assert CWE_SEVERITY_MAP["CWE-209"] == SeverityLevel.LOW
