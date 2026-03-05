"""Tests for severity threshold evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from diffguard.config import DEFAULT_THRESHOLDS, DiffguardConfig, ThresholdAction, load_config
from diffguard.exceptions import ConfigError
from diffguard.llm.response import ConfidenceLevel, Finding, SeverityLevel
from diffguard.severity import evaluate_findings, get_threshold_action, group_findings_by_action, has_blocking_findings

if TYPE_CHECKING:
    from pathlib import Path


def _make_finding(
    severity: SeverityLevel,
    *,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    what: str = "Test finding",
) -> Finding:
    return Finding(
        what=what,
        why="Test reason",
        how_to_fix="Test fix",
        severity=severity,
        confidence=confidence,
    )


@pytest.fixture
def default_config() -> DiffguardConfig:
    return DiffguardConfig()


@pytest.fixture
def strict_config() -> DiffguardConfig:
    return DiffguardConfig(
        thresholds={
            SeverityLevel.CRITICAL: ThresholdAction.BLOCK,
            SeverityLevel.HIGH: ThresholdAction.BLOCK,
            SeverityLevel.MEDIUM: ThresholdAction.BLOCK,
            SeverityLevel.LOW: ThresholdAction.BLOCK,
            SeverityLevel.INFO: ThresholdAction.WARN,
        }
    )


@pytest.fixture
def permissive_config() -> DiffguardConfig:
    return DiffguardConfig(
        thresholds={
            SeverityLevel.CRITICAL: ThresholdAction.BLOCK,
            SeverityLevel.HIGH: ThresholdAction.WARN,
            SeverityLevel.MEDIUM: ThresholdAction.ALLOW,
            SeverityLevel.LOW: ThresholdAction.ALLOW,
            SeverityLevel.INFO: ThresholdAction.ALLOW,
        }
    )


@pytest.fixture
def mixed_findings() -> list[Finding]:
    return [
        _make_finding(SeverityLevel.CRITICAL, what="Critical finding"),
        _make_finding(SeverityLevel.HIGH, what="High finding"),
        _make_finding(SeverityLevel.MEDIUM, what="Medium finding"),
        _make_finding(SeverityLevel.LOW, what="Low finding"),
        _make_finding(SeverityLevel.INFO, what="Info finding"),
    ]


class TestThresholdActionEnum:
    def test_has_block_value(self) -> None:
        assert ThresholdAction.BLOCK.value == "block"

    def test_has_warn_value(self) -> None:
        assert ThresholdAction.WARN.value == "warn"

    def test_has_allow_value(self) -> None:
        assert ThresholdAction.ALLOW.value == "allow"


class TestDefaultThresholds:
    def test_critical_blocks(self, default_config: DiffguardConfig) -> None:
        assert get_threshold_action(SeverityLevel.CRITICAL, default_config) == ThresholdAction.BLOCK

    def test_high_blocks(self, default_config: DiffguardConfig) -> None:
        assert get_threshold_action(SeverityLevel.HIGH, default_config) == ThresholdAction.BLOCK

    def test_medium_warns(self, default_config: DiffguardConfig) -> None:
        assert get_threshold_action(SeverityLevel.MEDIUM, default_config) == ThresholdAction.WARN

    def test_low_allows(self, default_config: DiffguardConfig) -> None:
        assert get_threshold_action(SeverityLevel.LOW, default_config) == ThresholdAction.ALLOW

    def test_info_allows(self, default_config: DiffguardConfig) -> None:
        assert get_threshold_action(SeverityLevel.INFO, default_config) == ThresholdAction.ALLOW


class TestCustomThresholds:
    def test_upgrade_medium_to_block(self) -> None:
        config = DiffguardConfig(thresholds={**DEFAULT_THRESHOLDS, SeverityLevel.MEDIUM: ThresholdAction.BLOCK})
        assert get_threshold_action(SeverityLevel.MEDIUM, config) == ThresholdAction.BLOCK

    def test_downgrade_high_to_warn(self) -> None:
        config = DiffguardConfig(thresholds={**DEFAULT_THRESHOLDS, SeverityLevel.HIGH: ThresholdAction.WARN})
        assert get_threshold_action(SeverityLevel.HIGH, config) == ThresholdAction.WARN

    def test_allow_critical(self) -> None:
        config = DiffguardConfig(thresholds={**DEFAULT_THRESHOLDS, SeverityLevel.CRITICAL: ThresholdAction.ALLOW})
        assert get_threshold_action(SeverityLevel.CRITICAL, config) == ThresholdAction.ALLOW

    def test_partial_custom_preserves_defaults(self) -> None:
        config = DiffguardConfig(thresholds={**DEFAULT_THRESHOLDS, SeverityLevel.MEDIUM: ThresholdAction.BLOCK})
        assert get_threshold_action(SeverityLevel.MEDIUM, config) == ThresholdAction.BLOCK
        assert get_threshold_action(SeverityLevel.CRITICAL, config) == ThresholdAction.BLOCK
        assert get_threshold_action(SeverityLevel.HIGH, config) == ThresholdAction.BLOCK
        assert get_threshold_action(SeverityLevel.LOW, config) == ThresholdAction.ALLOW
        assert get_threshold_action(SeverityLevel.INFO, config) == ThresholdAction.ALLOW


class TestThresholdConfigFromToml:
    def test_thresholds_parsed_from_toml(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".diffguard.toml"
        config_file.write_text('[thresholds]\nmedium = "block"\nlow = "warn"\n')
        config = load_config(config_path=config_file)
        assert get_threshold_action(SeverityLevel.MEDIUM, config) == ThresholdAction.BLOCK
        assert get_threshold_action(SeverityLevel.LOW, config) == ThresholdAction.WARN
        assert get_threshold_action(SeverityLevel.CRITICAL, config) == ThresholdAction.BLOCK
        assert get_threshold_action(SeverityLevel.HIGH, config) == ThresholdAction.BLOCK

    def test_invalid_action_raises_config_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".diffguard.toml"
        config_file.write_text('[thresholds]\nhigh = "ignore"\n')
        with pytest.raises(ConfigError, match=r"Invalid threshold action 'ignore'.*Valid actions: block, warn, allow"):
            load_config(config_path=config_file)

    def test_invalid_severity_raises_config_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".diffguard.toml"
        config_file.write_text('[thresholds]\nsupercritical = "block"\n')
        with pytest.raises(ConfigError, match="Unknown severity level 'supercritical'"):
            load_config(config_path=config_file)


class TestEvaluateFindings:
    def test_single_critical_finding(self, default_config: DiffguardConfig) -> None:
        finding = _make_finding(SeverityLevel.CRITICAL)
        result = evaluate_findings([finding], default_config)
        assert result == {finding: ThresholdAction.BLOCK}

    def test_multiple_findings(self, default_config: DiffguardConfig, mixed_findings: list[Finding]) -> None:
        result = evaluate_findings(mixed_findings, default_config)
        assert result[mixed_findings[0]] == ThresholdAction.BLOCK  # Critical
        assert result[mixed_findings[1]] == ThresholdAction.BLOCK  # High
        assert result[mixed_findings[2]] == ThresholdAction.WARN  # Medium
        assert result[mixed_findings[3]] == ThresholdAction.ALLOW  # Low
        assert result[mixed_findings[4]] == ThresholdAction.ALLOW  # Info

    def test_empty_findings(self, default_config: DiffguardConfig) -> None:
        result = evaluate_findings([], default_config)
        assert result == {}

    def test_preserves_insertion_order(self, default_config: DiffguardConfig, mixed_findings: list[Finding]) -> None:
        result = evaluate_findings(mixed_findings, default_config)
        assert list(result.keys()) == mixed_findings


class TestGroupFindingsByAction:
    def test_groups_mixed_findings(self, default_config: DiffguardConfig, mixed_findings: list[Finding]) -> None:
        groups = group_findings_by_action(mixed_findings, default_config)
        assert len(groups[ThresholdAction.BLOCK]) == 2  # Critical + High
        assert len(groups[ThresholdAction.WARN]) == 1  # Medium
        assert len(groups[ThresholdAction.ALLOW]) == 2  # Low + Info

    def test_empty_findings(self, default_config: DiffguardConfig) -> None:
        groups = group_findings_by_action([], default_config)
        assert groups[ThresholdAction.BLOCK] == []
        assert groups[ThresholdAction.WARN] == []
        assert groups[ThresholdAction.ALLOW] == []

    def test_counts_by_action(self, default_config: DiffguardConfig) -> None:
        findings = [
            _make_finding(SeverityLevel.CRITICAL),
            _make_finding(SeverityLevel.CRITICAL),
            _make_finding(SeverityLevel.MEDIUM),
            _make_finding(SeverityLevel.LOW),
            _make_finding(SeverityLevel.LOW),
            _make_finding(SeverityLevel.LOW),
        ]
        groups = group_findings_by_action(findings, default_config)
        assert len(groups[ThresholdAction.BLOCK]) == 2
        assert len(groups[ThresholdAction.WARN]) == 1
        assert len(groups[ThresholdAction.ALLOW]) == 3


class TestHasBlockingFindings:
    def test_with_blocking_findings(self, default_config: DiffguardConfig) -> None:
        findings = [_make_finding(SeverityLevel.CRITICAL), _make_finding(SeverityLevel.LOW)]
        evaluated = evaluate_findings(findings, default_config)
        assert has_blocking_findings(evaluated) is True

    def test_without_blocking_findings(self, default_config: DiffguardConfig) -> None:
        findings = [_make_finding(SeverityLevel.MEDIUM), _make_finding(SeverityLevel.LOW)]
        evaluated = evaluate_findings(findings, default_config)
        assert has_blocking_findings(evaluated) is False

    def test_empty_findings(self) -> None:
        assert has_blocking_findings({}) is False
