"""Tests for risk assessment (M5-04), per docs/risk_assessment.md."""

from forensix.risk.assessment import compute_risk


def test_incident_a_high_severity_confidence_low_criticality():
    result = compute_risk("high", 0.80, "low")
    assert abs(result.risk_score - 0.59) < 0.001
    assert result.category == "high"
    assert result.priority == "P2"


def test_incident_b_same_severity_confidence_critical_criticality():
    """B must be prioritized over A due solely to host criticality - the
    constraint validated in review: not a plain severity x confidence product."""
    result = compute_risk("high", 0.80, "critical")
    assert abs(result.risk_score - 0.8525) < 0.001
    assert result.category == "critical"
    assert result.priority == "P1"


def test_criticality_alone_can_shift_risk_category():
    result_a = compute_risk("high", 0.80, "low")
    result_b = compute_risk("high", 0.80, "critical")
    assert result_b.risk_score > result_a.risk_score
    assert result_a.category != result_b.category


def test_unknown_criticality_uses_neutral_score():
    result = compute_risk("high", 0.80, "unknown")
    expected = 0.35 * 0.75 + 0.30 * 0.80 + 0.35 * 0.5
    assert abs(result.risk_score - expected) < 0.001


def test_confidence_moves_risk_score_but_may_not_change_category():
    """Documented limitation (docs/risk_assessment.md): the numeric risk_score
    reflects confidence differences, but the discrete category can stay the
    same - callers must expose risk_score, not just category, to preserve
    the uncertainty signal."""
    low_confidence = compute_risk("critical", 0.20, "critical")
    high_confidence = compute_risk("critical", 0.90, "critical")

    assert low_confidence.category == "critical"
    assert high_confidence.category == "critical"
    assert high_confidence.risk_score - low_confidence.risk_score > 0.15


def test_risk_categories_are_ordered_correctly():
    low = compute_risk("informational", 0.10, "low")
    high = compute_risk("critical", 0.95, "critical")
    assert low.risk_score < high.risk_score
    assert low.category == "low"
    assert low.priority == "P4"
