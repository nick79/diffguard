"""Baseline file operations for suppressing known findings."""

from __future__ import annotations

import json
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
    "get_suppressed",
    "is_suppressed",
    "load_baseline",
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

    finding_id = _finding_id(finding)

    for entry in baseline:
        if finding_id and entry.finding_id == finding_id:
            return True
        if entry.cwe_id == (finding.cwe_id or "") and entry.file_path == (finding.file_path or ""):
            return True

    return False


def filter_suppressed(findings: list[Finding], baseline: list[BaselineEntry]) -> list[Finding]:
    """Return findings that are NOT suppressed by the baseline."""
    return [f for f in findings if not is_suppressed(f, baseline)]


def get_suppressed(findings: list[Finding], baseline: list[BaselineEntry]) -> list[Finding]:
    """Return findings that ARE suppressed by the baseline."""
    return [f for f in findings if is_suppressed(f, baseline)]


def _finding_id(finding: Finding) -> str | None:
    """Extract a finding ID from a Finding, matching baseline format."""
    if not finding.cwe_id:
        return None
    cwe_num = finding.cwe_id.lower().replace("cwe-", "cwe")
    return cwe_num


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
