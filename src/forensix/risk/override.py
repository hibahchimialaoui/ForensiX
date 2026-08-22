"""Analyst override capability (M6-01).

Only writes to the override_* columns (reserved since M5-05). The fields
computed by M5 (confidence, severity, risk_score, risk_category, priority)
are never modified - the analyst adds a separate decision alongside the
original assessment, preserving the full history:
ForensiX conclusion -> Analyst decision.
"""

from sqlalchemy.orm import Session

from forensix.models.db import RiskAssessmentRecord

VALID_RISK_CATEGORIES = {"low", "medium", "high", "critical"}
VALID_PRIORITIES = {"P1", "P2", "P3", "P4"}


def apply_analyst_override(
    session: Session,
    risk_assessment: RiskAssessmentRecord,
    override_risk_category: str,
    override_priority: str,
    override_reason: str,
) -> RiskAssessmentRecord:
    """Record an analyst's operational decision on a risk assessment.

    Raises ValueError if override_reason is empty/blank, or if the category
    or priority values are not among the recognized set - an override must
    always be justified and use a valid value, never a free-form guess.
    The original M5 fields on risk_assessment are never touched.
    """
    if not override_reason or not override_reason.strip():
        raise ValueError("override_reason is mandatory and cannot be empty")
    if override_risk_category not in VALID_RISK_CATEGORIES:
        raise ValueError(f"Invalid override_risk_category: {override_risk_category!r}")
    if override_priority not in VALID_PRIORITIES:
        raise ValueError(f"Invalid override_priority: {override_priority!r}")

    risk_assessment.override_risk_category = override_risk_category
    risk_assessment.override_priority = override_priority
    risk_assessment.override_reason = override_reason.strip()
    session.commit()
    return risk_assessment
