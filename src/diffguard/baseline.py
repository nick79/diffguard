"""Baseline file operations for suppressing known findings."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from diffguard.exceptions import BaselineError

if TYPE_CHECKING:
    from diffguard.llm.response import Finding

__all__ = [
    "BaselineEntry",
    "filter_suppressed",
    "generate_finding_id",
    "generate_fingerprint",
    "get_suppressed",
    "is_suppressed",
    "load_baseline",
    "normalize_code",
    "save_baseline",
]

_BASELINE_VERSION = "1.0"
_REQUIRED_ENTRY_FIELDS = ("finding_id", "cwe_id", "code_hash", "reason", "added_at")


@dataclass(frozen=True)
class BaselineEntry:
    """A single baselined finding entry."""

    finding_id: str
    cwe_id: str
    code_hash: str
    reason: str
    added_at: str
    file_path: str | None = None


def load_baseline(path: Path) -> list[BaselineEntry]:
    """Load baseline entries from a JSON file.

    Args:
        path: Path to the baseline JSON file.

    Returns:
        List of BaselineEntry objects. Empty list if file does not exist.

    Raises:
        BaselineError: If the file cannot be read, parsed, or has invalid schema.
    """
    if not path.exists():
        return []

    try:
        raw = path.read_text(encoding="utf-8")
    except PermissionError as exc:
        raise BaselineError(f"Permission denied reading baseline file: {path}") from exc
    except OSError as exc:
        raise BaselineError(f"Could not read baseline file {path}: {exc}") from exc

    if not raw.strip():
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"Invalid JSON in baseline file {path}: {exc}") from exc

    if not isinstance(data, dict) or "entries" not in data:
        raise BaselineError(f"Invalid baseline schema in {path}: expected object with 'entries' key")

    entries_data = data["entries"]
    if not isinstance(entries_data, list):
        raise BaselineError(f"Invalid baseline schema in {path}: 'entries' must be an array")

    return [_parse_entry(entry, path) for entry in entries_data]


def save_baseline(entries: list[BaselineEntry], path: Path) -> None:
    """Save baseline entries to a JSON file (atomic write).

    Args:
        entries: List of BaselineEntry objects to save.
        path: Path to the baseline JSON file.

    Raises:
        BaselineError: If the file cannot be written.
    """
    data = {
        "version": _BASELINE_VERSION,
        "entries": [_entry_to_dict(entry) for entry in entries],
    }

    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        fd, tmp_path_str = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        tmp_path = Path(tmp_path_str)
        try:
            with open(fd, "w", encoding="utf-8") as f:  # noqa: PTH123
                json.dump(data, f, indent=2)
                f.write("\n")
            tmp_path.replace(path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise BaselineError(f"Could not write baseline file {path}: {exc}") from exc


def is_suppressed(finding: Finding, baseline: list[BaselineEntry]) -> bool:
    """Check if a finding is suppressed by the baseline.

    Matches by finding_id first, then falls back to fingerprint match
    (same cwe_id + code_hash).

    Args:
        finding: The finding to check.
        baseline: List of baseline entries.

    Returns:
        True if the finding is suppressed.
    """
    if not baseline:
        return False

    fid = _finding_id(finding)
    return any(entry.finding_id == fid for entry in baseline)


def filter_suppressed(findings: list[Finding], baseline: list[BaselineEntry]) -> list[Finding]:
    """Return findings that are NOT suppressed by the baseline."""
    return [f for f in findings if not is_suppressed(f, baseline)]


def get_suppressed(findings: list[Finding], baseline: list[BaselineEntry]) -> list[Finding]:
    """Return findings that ARE suppressed by the baseline."""
    return [f for f in findings if is_suppressed(f, baseline)]


_FINGERPRINT_HASH_LENGTH = 16
_TRIPLE_DOUBLE_RE = re.compile(r'"""[\s\S]*?"""')
_TRIPLE_SINGLE_RE = re.compile(r"'''[\s\S]*?'''")


def normalize_code(code: str) -> str:
    """Normalize code for fingerprinting by stripping comments, docstrings, and whitespace.

    Removes:
    - Triple-quoted strings (docstrings)
    - Single-line comments (``# ...``)
    - Inline comments (``x = 1  # ...``)
    - Leading/trailing whitespace per line
    - Blank lines

    Preserves:
    - String literals containing ``#`` (e.g., ``"hello # world"``)
    """
    result = _TRIPLE_DOUBLE_RE.sub("", code)
    result = _TRIPLE_SINGLE_RE.sub("", result)

    lines: list[str] = []
    for line in result.splitlines():
        stripped = _remove_inline_comment(line).strip()
        if stripped:
            lines.append(stripped)

    return "\n".join(lines)


def generate_fingerprint(code: str, cwe: str) -> str:
    """Generate a deterministic fingerprint from code and CWE identifier.

    Format: ``{cwe_prefix}-{sha256_hex[:16]}`` (e.g., ``cwe89-a1b2c3d4e5f6a7b8``).

    The fingerprint is resilient to whitespace, comment, and docstring changes
    because the code is normalized before hashing.

    Args:
        code: Source code snippet.
        cwe: CWE identifier (e.g., ``CWE-89`` or ``89``).

    Returns:
        Fingerprint string.
    """
    normalized = normalize_code(code)
    cwe_prefix = _cwe_to_prefix(cwe)
    hash_input = f"{cwe_prefix}:{normalized}"
    sha = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
    return f"{cwe_prefix}-{sha[:_FINGERPRINT_HASH_LENGTH]}"


def generate_finding_id(finding: Finding, code: str) -> str:
    """Generate a finding ID from a Finding and its associated code.

    Args:
        finding: The security finding.
        code: Source code snippet associated with the finding.

    Returns:
        Finding ID string (same format as fingerprint).
    """
    cwe = finding.cwe_id or "unknown"
    return generate_fingerprint(code, cwe)


def _cwe_to_prefix(cwe: str) -> str:
    """Convert a CWE identifier to a lowercase prefix (e.g., 'CWE-89' -> 'cwe89')."""
    return cwe.lower().replace("-", "")


def _remove_inline_comment(line: str) -> str:
    """Remove ``#`` comment from a line while preserving ``#`` inside string literals."""
    result: list[str] = []
    in_single = False
    in_double = False
    escape = False

    for char in line:
        if escape:
            result.append(char)
            escape = False
            continue
        if char == "\\":
            result.append(char)
            escape = True
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            result.append(char)
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            result.append(char)
            continue
        if char == "#" and not in_single and not in_double:
            break
        result.append(char)

    return "".join(result)


def _finding_id(finding: Finding) -> str:
    """Compute a stable finding ID from CWE, file path, and line range.

    Uses stable attributes (not LLM-generated text) so the ID remains
    consistent across runs even when the LLM varies its descriptions.
    Must match cli._compute_finding_id.
    """
    prefix = _cwe_to_prefix(finding.cwe_id or "unknown")
    parts = [prefix]
    if finding.file_path:
        parts.append(finding.file_path)
    if finding.line_range:
        parts.append(str(finding.line_range[0]))
    if len(parts) == 1:
        parts.append(finding.what)
    hash_input = ":".join(parts)
    return f"{prefix}-{hashlib.sha256(hash_input.encode()).hexdigest()[:_FINGERPRINT_HASH_LENGTH]}"


def _parse_entry(raw: object, path: Path) -> BaselineEntry:
    """Parse a single baseline entry dict."""
    if not isinstance(raw, dict):
        raise BaselineError(f"Invalid baseline entry in {path}: expected object, got {type(raw).__name__}")

    missing = [f for f in _REQUIRED_ENTRY_FIELDS if f not in raw]
    if missing:
        raise BaselineError(f"Baseline entry in {path} missing required field(s): {', '.join(missing)}")

    return BaselineEntry(
        finding_id=str(raw["finding_id"]),
        cwe_id=str(raw["cwe_id"]),
        code_hash=str(raw["code_hash"]),
        reason=str(raw["reason"]),
        added_at=str(raw["added_at"]),
        file_path=str(raw["file_path"]) if raw.get("file_path") is not None else None,
    )


def _entry_to_dict(entry: BaselineEntry) -> dict[str, str | None]:
    """Convert a BaselineEntry to a JSON-serializable dict."""
    d: dict[str, str | None] = {
        "finding_id": entry.finding_id,
        "cwe_id": entry.cwe_id,
        "code_hash": entry.code_hash,
        "reason": entry.reason,
        "added_at": entry.added_at,
    }
    if entry.file_path is not None:
        d["file_path"] = entry.file_path
    return d
