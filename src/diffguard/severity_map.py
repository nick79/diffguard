"""Deterministic CWE-to-severity mapping for consistent finding classification.

The LLM identifies vulnerabilities and CWE IDs; this module assigns severity
deterministically based on the CWE. This eliminates LLM non-determinism in
severity classification — the same CWE always gets the same severity.

For unmapped CWEs, the LLM's suggested severity is used as a fallback.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from diffguard.llm.response import ConfidenceLevel, SeverityLevel

if TYPE_CHECKING:
    from diffguard.llm.response import Finding

__all__ = [
    "CWE_SEVERITY_MAP",
    "apply_severity_map",
    "map_severity",
]

# Deterministic mapping of CWE IDs to severity levels.
# Covers OWASP Top 10, CWE Top 25, and common code-review findings.
# For CWEs not in this map, the LLM's suggestion is used as fallback.
CWE_SEVERITY_MAP: dict[str, SeverityLevel] = {
    # ── Critical: unauthenticated RCE / complete auth bypass ──
    "CWE-78": SeverityLevel.CRITICAL,  # OS Command Injection
    "CWE-94": SeverityLevel.CRITICAL,  # Code Injection
    "CWE-95": SeverityLevel.CRITICAL,  # Eval Injection
    "CWE-306": SeverityLevel.CRITICAL,  # Missing Authentication for Critical Function
    # ── High: exploitable with significant impact ──
    "CWE-20": SeverityLevel.HIGH,  # Improper Input Validation
    "CWE-22": SeverityLevel.HIGH,  # Path Traversal
    "CWE-77": SeverityLevel.HIGH,  # Command Injection (general)
    "CWE-79": SeverityLevel.HIGH,  # Cross-Site Scripting (XSS)
    "CWE-89": SeverityLevel.HIGH,  # SQL Injection
    "CWE-90": SeverityLevel.HIGH,  # LDAP Injection
    "CWE-259": SeverityLevel.HIGH,  # Hardcoded Password
    "CWE-287": SeverityLevel.HIGH,  # Improper Authentication
    "CWE-327": SeverityLevel.HIGH,  # Broken Cryptographic Algorithm
    "CWE-330": SeverityLevel.HIGH,  # Insufficient Randomness
    "CWE-434": SeverityLevel.HIGH,  # Unrestricted File Upload
    "CWE-502": SeverityLevel.HIGH,  # Deserialization of Untrusted Data
    "CWE-611": SeverityLevel.HIGH,  # XML External Entity (XXE)
    "CWE-776": SeverityLevel.HIGH,  # XML Entity Expansion
    "CWE-798": SeverityLevel.HIGH,  # Hardcoded Credentials
    "CWE-862": SeverityLevel.HIGH,  # Missing Authorization
    "CWE-863": SeverityLevel.HIGH,  # Incorrect Authorization
    "CWE-918": SeverityLevel.HIGH,  # Server-Side Request Forgery (SSRF)
    "CWE-943": SeverityLevel.HIGH,  # NoSQL Injection
    # ── Medium: conditional exploitation or moderate impact ──
    "CWE-200": SeverityLevel.MEDIUM,  # Information Exposure
    "CWE-285": SeverityLevel.MEDIUM,  # Improper Authorization
    "CWE-311": SeverityLevel.MEDIUM,  # Missing Encryption of Sensitive Data
    "CWE-319": SeverityLevel.MEDIUM,  # Cleartext Transmission
    "CWE-326": SeverityLevel.MEDIUM,  # Inadequate Encryption Strength
    "CWE-346": SeverityLevel.MEDIUM,  # Origin Validation Error
    "CWE-352": SeverityLevel.MEDIUM,  # Cross-Site Request Forgery (CSRF)
    "CWE-384": SeverityLevel.MEDIUM,  # Session Fixation
    "CWE-532": SeverityLevel.MEDIUM,  # Sensitive Data in Log Files
    "CWE-601": SeverityLevel.MEDIUM,  # Open Redirect
    "CWE-614": SeverityLevel.MEDIUM,  # Missing Secure Flag on Cookie
    "CWE-639": SeverityLevel.MEDIUM,  # Insecure Direct Object Reference
    "CWE-732": SeverityLevel.MEDIUM,  # Incorrect Permission Assignment
    "CWE-1004": SeverityLevel.MEDIUM,  # Missing HttpOnly Flag on Cookie
    # ── Low: minor issues with minimal impact ──
    "CWE-116": SeverityLevel.LOW,  # Improper Encoding or Escaping
    "CWE-209": SeverityLevel.LOW,  # Error Message Information Exposure
    "CWE-1236": SeverityLevel.LOW,  # Formula Injection (CSV)
}

# Severity ordering for cap comparisons (lower index = more severe)
_SEVERITY_ORDER = [
    SeverityLevel.CRITICAL,
    SeverityLevel.HIGH,
    SeverityLevel.MEDIUM,
    SeverityLevel.LOW,
    SeverityLevel.INFO,
]


def _severity_index(severity: SeverityLevel) -> int:
    """Return the index of a severity level (0=Critical, 4=Info)."""
    return _SEVERITY_ORDER.index(severity)


def _cap_severity(severity: SeverityLevel, cap: SeverityLevel) -> SeverityLevel:
    """Cap severity so it does not exceed the given limit."""
    if _severity_index(severity) < _severity_index(cap):
        return cap
    return severity


def map_severity(finding: Finding) -> SeverityLevel:
    """Determine the severity for a finding based on its CWE ID.

    Rules:
    1. Look up the CWE in the deterministic map.
    2. If not found, use the LLM's suggested severity.
    3. If confidence is Low, cap severity at Medium.

    Args:
        finding: The parsed finding from LLM response.

    Returns:
        The deterministic severity level.
    """
    cwe = finding.cwe_id
    severity = CWE_SEVERITY_MAP[cwe] if cwe and cwe in CWE_SEVERITY_MAP else finding.severity

    if finding.confidence == ConfidenceLevel.LOW:
        severity = _cap_severity(severity, SeverityLevel.MEDIUM)

    return severity


def apply_severity_map(findings: list[Finding]) -> list[Finding]:
    """Apply deterministic severity mapping to a list of findings.

    Args:
        findings: List of findings with LLM-assigned severity.

    Returns:
        New list of findings with deterministic severity.
    """
    return [replace(f, severity=map_severity(f)) for f in findings]
