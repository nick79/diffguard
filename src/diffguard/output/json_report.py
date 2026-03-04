"""JSON report generation for Diffguard analysis results."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 — used at runtime by write_report signature
from typing import Any

import typer

from diffguard import __version__
from diffguard.exceptions import ReportWriteError
from diffguard.llm.response import Finding, SeverityLevel


@dataclass
class ReportMetadata:
    """Metadata for an analysis report."""

    files_analyzed: int
    analysis_time_seconds: float | None = None
    commit_hash: str | None = None
    branch_name: str | None = None


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    """Serialize a Finding to a JSON-compatible dict."""
    d: dict[str, Any] = {
        "what": finding.what,
        "why": finding.why,
        "how_to_fix": finding.how_to_fix,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
    }
    if finding.cwe_id is not None:
        d["cwe_id"] = finding.cwe_id
    if finding.owasp_category is not None:
        d["owasp_category"] = finding.owasp_category
    if finding.line_range is not None:
        d["line_range"] = {"start": finding.line_range[0], "end": finding.line_range[1]}
    if finding.file_path is not None:
        d["file_path"] = finding.file_path
    return d


def _build_summary(findings: list[Finding]) -> dict[str, int]:
    """Build severity count summary from findings."""
    counts = {level.value: 0 for level in SeverityLevel}
    for finding in findings:
        counts[finding.severity.value] += 1
    return {"total": len(findings), **counts}


def _build_metadata_dict(metadata: ReportMetadata) -> dict[str, Any]:
    """Build metadata dict, omitting None values."""
    d: dict[str, Any] = {"files_analyzed": metadata.files_analyzed}
    if metadata.analysis_time_seconds is not None:
        d["analysis_time_seconds"] = metadata.analysis_time_seconds
    if metadata.commit_hash is not None:
        d["commit_hash"] = metadata.commit_hash
    if metadata.branch_name is not None:
        d["branch_name"] = metadata.branch_name
    return d


def generate_report(findings: list[Finding], metadata: ReportMetadata) -> dict[str, Any]:
    """Generate a full JSON report structure.

    Args:
        findings: List of security findings.
        metadata: Report metadata (files analyzed, timing, git info).

    Returns:
        Dict ready for JSON serialization.
    """
    return {
        "schema_version": "1.0",
        "version": __version__,
        "timestamp": datetime.now(UTC).isoformat(),
        "metadata": _build_metadata_dict(metadata),
        "summary": _build_summary(findings),
        "findings": [_serialize_finding(f) for f in findings],
    }


def write_report(report: dict[str, Any], path: Path) -> None:
    """Write a JSON report to a file.

    Creates parent directories if needed.

    Args:
        report: Report dict to serialize.
        path: Output file path.

    Raises:
        ReportWriteError: If the file cannot be written.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    except OSError as exc:
        msg = f"Could not write report to {path}: {exc}"
        raise ReportWriteError(msg) from exc


def print_report(report: dict[str, Any], *, compact: bool = False) -> None:
    """Print a JSON report to stdout.

    Args:
        report: Report dict to serialize.
        compact: If True, output single-line JSON; otherwise pretty-print.
    """
    indent = None if compact else 2
    typer.echo(json.dumps(report, indent=indent, ensure_ascii=False))
