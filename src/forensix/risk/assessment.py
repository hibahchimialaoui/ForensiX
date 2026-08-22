"""Risk assessment (M5-04), per the formula in docs/risk_assessment.md.

Combines severity, confidence, and host criticality with equal weight on
severity and criticality (0.35 each) so that host criticality alone can
shift the risk category - not a simple severity x confidence product.
"""

from dataclasses import dataclass

from forensix.risk.criticality import UNKNOWN_CRITICALITY, criticality_rank
from forensix.risk.severity import severity_rank

WEIGHT_SEVERITY = 0.35
WEIGHT_CONFIDENCE = 0.30
WEIGHT_CRITICALITY = 0.35

_SEVERITY_MAX_RANK = 4
_CRITICALITY_MAX_RANK = 3
_UNKNOWN_CRITICALITY_SCORE = 0.5  # neutral: neither downplays nor inflates risk

RISK_CATEGORIES = [
    (0.75, "critical", "P1"),
    (0.55, "high", "P2"),
    (0.35, "medium", "P3"),
    (0.0, "low", "P4"),
]


@dataclass
class RiskResult:
    """Deterministic risk assessment result, with its category and priority."""

    risk_score: float
    category: str
    priority: str


def _criticality_score(criticality: str) -> float:
    if criticality == UNKNOWN_CRITICALITY:
        return _UNKNOWN_CRITICALITY_SCORE
    rank = criticality_rank(criticality)
    return (rank + 1) / (_CRITICALITY_MAX_RANK + 1)


def compute_risk(severity: str, confidence: float, criticality: str) -> RiskResult:
    """Combine severity, confidence, and host criticality into a risk assessment."""
    severity_score = severity_rank(severity) / _SEVERITY_MAX_RANK
    criticality_score = _criticality_score(criticality)

    risk_score = (
        WEIGHT_SEVERITY * severity_score
        + WEIGHT_CONFIDENCE * confidence
        + WEIGHT_CRITICALITY * criticality_score
    )

    for threshold, category, priority in RISK_CATEGORIES:
        if risk_score >= threshold:
            return RiskResult(risk_score=risk_score, category=category, priority=priority)

    return RiskResult(risk_score=risk_score, category="low", priority="P4")
