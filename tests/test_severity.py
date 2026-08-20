"""Tests for severity normalization and ordering (M5-02)."""

from forensix.detection.executor import get_rule_metadata, load_rule_files
from forensix.risk.severity import (
    compare_severity,
    is_at_least,
    normalize_severity,
    severity_rank,
)


def test_normalize_severity_lowercases_and_trims():
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("  Medium  ") == "medium"


def test_normalize_severity_falls_back_to_informational_for_unknown_values():
    assert normalize_severity("unknown_garbage") == "informational"
    assert normalize_severity("") == "informational"
    assert normalize_severity(None) == "informational"


def test_severity_rank_is_strictly_ordered():
    assert (
        severity_rank("critical")
        > severity_rank("high")
        > severity_rank("medium")
        > severity_rank("low")
        > severity_rank("informational")
    )


def test_is_at_least_compares_correctly():
    assert is_at_least("high", "medium") is True
    assert is_at_least("medium", "medium") is True
    assert is_at_least("low", "medium") is False


def test_compare_severity_returns_expected_sign():
    assert compare_severity("high", "high") == 0
    assert compare_severity("critical", "low") == 1
    assert compare_severity("low", "critical") == -1


def test_all_seven_curated_rules_have_a_valid_severity():
    """Every curated rule (M2-02) must produce a normalized, ranked severity."""
    for rule_file in load_rule_files():
        _, severity = get_rule_metadata(rule_file.read_text(encoding="utf-8"))
        assert normalize_severity(severity) == severity
        assert 0 <= severity_rank(severity) <= 4
