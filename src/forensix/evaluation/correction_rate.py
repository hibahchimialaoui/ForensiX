"""Analyst correction rate (M7-05), computed from real M6 review data.

Queries actual RiskAssessmentRecord rows with an override applied
(override_risk_category is not None) and measures the proportion where the
analyst's decision differs from ForensiX's original conclusion. No
fabricated numbers - this reflects whatever real review data currently
exists in the database (e.g. produced by M6-01/M6-05 test runs).
"""

from dataclasses import dataclass

from sqlalchemy.orm import Session

from forensix.models.db import RiskAssessmentRecord


@dataclass
class CorrectionRateReport:
    """Proportion of analyst-reviewed detections that were corrected vs approved."""

    total_reviewed: int
    approved_as_is: int
    corrected: int
    correction_rate: float


def compute_correction_rate(session: Session) -> CorrectionRateReport:
    """Compute the analyst correction rate from real reviewed RiskAssessmentRecord rows."""
    reviewed = (
        session.query(RiskAssessmentRecord)
        .filter(RiskAssessmentRecord.override_risk_category.isnot(None))
        .all()
    )

    total = len(reviewed)
    corrected = sum(1 for r in reviewed if r.override_risk_category != r.risk_category)
    approved = total - corrected

    return CorrectionRateReport(
        total_reviewed=total,
        approved_as_is=approved,
        corrected=corrected,
        correction_rate=(corrected / total) if total > 0 else 0.0,
    )
