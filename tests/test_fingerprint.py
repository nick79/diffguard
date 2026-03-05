"""Tests for finding fingerprinting and code normalization."""

from __future__ import annotations

from diffguard.baseline import generate_finding_id, generate_fingerprint, normalize_code
from diffguard.llm.response import ConfidenceLevel, Finding, SeverityLevel

CODE_ORIGINAL = """
def foo():
    x = 1
    return x
"""

CODE_WITH_WHITESPACE = """

def foo():
    x = 1
    return x

"""

CODE_WITH_COMMENTS = """
def foo():
    # Set x to 1
    x = 1  # inline comment
    return x
"""

CODE_WITH_DOCSTRING = '''
def foo():
    """This function returns 1."""
    x = 1
    return x
'''

CODE_DIFFERENT_LOGIC = """
def foo():
    x = 2
    return x
"""

CODE_DIFFERENT_VAR = """
def foo():
    y = 1
    return y
"""

CODE_WITH_STRING_HASH = """
def foo():
    msg = "hello # not a comment"
    return msg
"""

CODE_TWO_SPACE_INDENT = """
def foo():
  x = 1
  return x
"""

CODE_ONLY_COMMENTS = """
# This is a comment
# Another comment
"""


def _make_finding(*, cwe_id: str | None = "CWE-89") -> Finding:
    return Finding(
        what="SQL Injection",
        why="Test reason",
        how_to_fix="Test fix",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        cwe_id=cwe_id,
    )


class TestGenerateFingerprint:
    def test_deterministic(self) -> None:
        fp1 = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        fp2 = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        assert fp1 == fp2

    def test_stable_across_calls(self) -> None:
        fp = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        assert isinstance(fp, str)
        assert len(fp) > 0
        # Call again to verify no randomness
        assert generate_fingerprint(CODE_ORIGINAL, "CWE-89") == fp

    def test_format_cwe_prefix_and_hash(self) -> None:
        fp = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        assert fp.startswith("cwe89-")
        parts = fp.split("-", 1)
        assert len(parts) == 2
        assert len(parts[1]) == 16
        # Hash part should be valid hex
        int(parts[1], 16)

    def test_resilient_to_leading_trailing_whitespace(self) -> None:
        fp1 = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        fp2 = generate_fingerprint(CODE_WITH_WHITESPACE, "CWE-89")
        assert fp1 == fp2

    def test_resilient_to_indentation_differences(self) -> None:
        fp1 = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        fp2 = generate_fingerprint(CODE_TWO_SPACE_INDENT, "CWE-89")
        assert fp1 == fp2

    def test_resilient_to_blank_lines(self) -> None:
        code_with_blanks = "\ndef foo():\n\n    x = 1\n\n    return x\n\n"
        fp1 = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        fp2 = generate_fingerprint(code_with_blanks, "CWE-89")
        assert fp1 == fp2

    def test_resilient_to_single_line_comments(self) -> None:
        fp1 = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        fp2 = generate_fingerprint(CODE_WITH_COMMENTS, "CWE-89")
        assert fp1 == fp2

    def test_resilient_to_multi_line_comments(self) -> None:
        fp1 = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        fp2 = generate_fingerprint(CODE_WITH_DOCSTRING, "CWE-89")
        assert fp1 == fp2

    def test_resilient_to_inline_comments(self) -> None:
        code_inline = "x = 1  # set x"
        code_plain = "x = 1"
        fp1 = generate_fingerprint(code_plain, "CWE-89")
        fp2 = generate_fingerprint(code_inline, "CWE-89")
        assert fp1 == fp2

    def test_different_code_different_fingerprint(self) -> None:
        fp1 = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        fp2 = generate_fingerprint(CODE_DIFFERENT_LOGIC, "CWE-89")
        assert fp1 != fp2

    def test_different_cwe_different_fingerprint(self) -> None:
        fp1 = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        fp2 = generate_fingerprint(CODE_ORIGINAL, "CWE-79")
        assert fp1 != fp2

    def test_similar_code_different_fingerprint(self) -> None:
        fp1 = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        fp2 = generate_fingerprint(CODE_DIFFERENT_VAR, "CWE-89")
        assert fp1 != fp2

    def test_consistent_length(self) -> None:
        codes = [CODE_ORIGINAL, CODE_DIFFERENT_LOGIC, CODE_WITH_STRING_HASH, "x = 1", "a" * 10000]
        fingerprints = [generate_fingerprint(c, "CWE-89") for c in codes]
        lengths = {len(fp) for fp in fingerprints}
        # All should have same length: "cwe89-" (6) + 16 hex = 22
        assert len(lengths) == 1

    def test_uses_sha256_not_python_hash(self) -> None:
        fp = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        hash_part = fp.split("-", 1)[1]
        # SHA-256 hex chars, should be lowercase hex
        assert all(c in "0123456789abcdef" for c in hash_part)
        assert len(hash_part) == 16


class TestNormalizeCode:
    def test_strips_leading_trailing_whitespace(self) -> None:
        result = normalize_code("  x = 1  \n\n")
        assert result == "x = 1"

    def test_normalizes_internal_whitespace(self) -> None:
        code_4space = "    x = 1\n    return x"
        code_2space = "  x = 1\n  return x"
        assert normalize_code(code_4space) == normalize_code(code_2space)

    def test_removes_single_line_comments(self) -> None:
        result = normalize_code("# This is a comment\nx = 1")
        assert result == "x = 1"

    def test_removes_inline_comments(self) -> None:
        result = normalize_code("x = 1  # inline comment")
        assert result == "x = 1"

    def test_removes_docstrings(self) -> None:
        code = 'def foo():\n    """This is a docstring."""\n    return 1'
        result = normalize_code(code)
        assert '"""' not in result
        assert "docstring" not in result

    def test_preserves_string_literals_with_hash(self) -> None:
        result = normalize_code(CODE_WITH_STRING_HASH)
        assert '"hello # not a comment"' in result

    def test_empty_input(self) -> None:
        assert normalize_code("") == ""

    def test_only_whitespace(self) -> None:
        assert normalize_code("   \n\n   ") == ""

    def test_only_comments(self) -> None:
        assert normalize_code(CODE_ONLY_COMMENTS) == ""

    def test_fixture_pairs(self) -> None:
        cases = [
            ("  x = 1  ", "x = 1"),
            ("x = 1  # comment", "x = 1"),
            ("# only comment", ""),
            ('msg = "# in string"', 'msg = "# in string"'),
        ]
        for code_in, expected in cases:
            assert normalize_code(code_in) == expected


class TestGenerateFindingId:
    def test_returns_fingerprint(self) -> None:
        finding = _make_finding(cwe_id="CWE-89")
        fid = generate_finding_id(finding, CODE_ORIGINAL)
        fp = generate_fingerprint(CODE_ORIGINAL, "CWE-89")
        assert fid == fp

    def test_matches_fingerprint_format(self) -> None:
        finding = _make_finding(cwe_id="CWE-89")
        fid = generate_finding_id(finding, CODE_ORIGINAL)
        assert fid.startswith("cwe89-")
        assert len(fid.split("-", 1)[1]) == 16

    def test_finding_without_cwe_uses_unknown(self) -> None:
        finding = _make_finding(cwe_id=None)
        fid = generate_finding_id(finding, CODE_ORIGINAL)
        assert fid.startswith("unknown-")
