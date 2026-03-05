"""Severity threshold evaluation for security findings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from diffguard.config import DEFAULT_THRESHOLDS, DiffguardConfig, ThresholdAction

if TYPE_CHECKING:
    from diffguard.llm.response import Finding, SeverityLevel

__all__ = [
    "evaluate_findings",
    "get_threshold_action",
    "group_findings_by_action",
    "has_blocking_findings",
]


def get_threshold_action(severity: SeverityLevel, config: DiffguardConfig) -> ThresholdAction:
    """Get the configured threshold action for a severity level.

    Args:
        severity: The severity level to look up.
        config: Diffguard configuration with threshold settings.

    Returns:
        The ThresholdAction for the given severity level.
    """
    return config.thresholds.get(severity, DEFAULT_THRESHOLDS[severity])


def evaluate_findings(findings: list[Finding], config: DiffguardConfig) -> dict[Finding, ThresholdAction]:
    """Determine the threshold action for each finding based on its severity.

    Args:
        findings: List of security findings to evaluate.
        config: Diffguard configuration with threshold settings.

    Returns:
        Dict mapping each finding to its threshold action, preserving insertion order.
    """
    return {finding: get_threshold_action(finding.severity, config) for finding in findings}


def group_findings_by_action(findings: list[Finding], config: DiffguardConfig) -> dict[ThresholdAction, list[Finding]]:
    """Group findings by their threshold action.

    Args:
        findings: List of security findings to group.
        config: Diffguard configuration with threshold settings.

    Returns:
        Dict mapping each ThresholdAction to its list of findings.
    """
    groups: dict[ThresholdAction, list[Finding]] = {action: [] for action in ThresholdAction}
    for finding in findings:
        action = get_threshold_action(finding.severity, config)
        groups[action].append(finding)
    return groups


def has_blocking_findings(evaluated: dict[Finding, ThresholdAction]) -> bool:
    """Check whether any evaluated findings have a BLOCK action.

    Args:
        evaluated: Dict mapping findings to their threshold actions.

    Returns:
        True if at least one finding has ThresholdAction.BLOCK.
    """
    return ThresholdAction.BLOCK in evaluated.values()
