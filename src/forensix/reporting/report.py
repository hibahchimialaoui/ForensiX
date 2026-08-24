"""Investigation report generator (M6-03).

Assembles timeline (M4-01), ATT&CK justification chain (M4-03), risk
assessment (M5-04), and the analyst's decision (M6-01) into a single
structured report per incident cluster. The report never asserts an
independent conclusion - it presents evidence and the documented
decision, consistent with ForensiX's evidence-driven philosophy.
"""

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from forensix.attack.justification import JustificationEntry, build_justification_chain
from forensix.models.db import EventRecord, RiskAssessmentRecord
from forensix.timeline.builder import TimelineEntry, build_timeline


@dataclass
class InvestigationReport:
    """Structured investigation report for a single incident cluster."""

    cluster_event_ids: list[str]
    timeline: list[TimelineEntry]
    justification_chain: list[JustificationEntry]
    risk_assessments: list[RiskAssessmentRecord] = field(default_factory=list)


def generate_investigation_report(
    session: Session, cluster: list[EventRecord]
) -> InvestigationReport:
    """Assemble a full investigation report for the given cluster of events."""
    event_ids = [e.id for e in cluster]

    timeline = build_timeline(session, cluster)
    justification_chain = build_justification_chain(session, event_ids)

    detection_ids = [entry.detection_id for entry in justification_chain]
    risk_assessments = (
        session.query(RiskAssessmentRecord)
        .filter(RiskAssessmentRecord.detection_id.in_(detection_ids))
        .all()
        if detection_ids
        else []
    )

    return InvestigationReport(
        cluster_event_ids=event_ids,
        timeline=timeline,
        justification_chain=justification_chain,
        risk_assessments=risk_assessments,
    )
