"""Data access layer for the Streamlit analyst interface (M6-02).

Kept separate from the Streamlit UI code (app.py) so it remains testable
with pytest, without requiring a browser or a running Streamlit server.
"""

from dataclasses import dataclass

from sqlalchemy.orm import Session

from forensix.attack.justification import build_justification_chain
from forensix.models.db import DetectionRecord, EventRecord, RiskAssessmentRecord


@dataclass
class DetectionReviewItem:
    """Everything an analyst needs to review a single detection in one place."""

    detection: DetectionRecord
    event: EventRecord
    risk: RiskAssessmentRecord | None
    techniques: list[str]


def list_pending_detections(session: Session, limit: int = 50) -> list[DetectionReviewItem]:
    """List detections that have a risk assessment but no analyst override yet.

    Ordered by risk_score descending, so the analyst sees the most urgent
    items first.
    """
    query = (
        session.query(DetectionRecord, RiskAssessmentRecord)
        .join(RiskAssessmentRecord, RiskAssessmentRecord.detection_id == DetectionRecord.id)
        .filter(RiskAssessmentRecord.override_risk_category.is_(None))
        .order_by(RiskAssessmentRecord.risk_score.desc())
        .limit(limit)
    )

    items = []
    for detection, risk in query.all():
        event = session.query(EventRecord).filter(EventRecord.id == detection.event_id).first()
        if event is None:
            continue
        chain = build_justification_chain(session, [event.id])
        techniques = sorted({t for entry in chain for t in entry.techniques})
        items.append(
            DetectionReviewItem(detection=detection, event=event, risk=risk, techniques=techniques)
        )
    return items


def get_detection_review_item(
    session: Session, detection_id: str
) -> DetectionReviewItem | None:
    """Fetch a single detection with its risk assessment and ATT&CK techniques."""
    detection = session.query(DetectionRecord).filter(DetectionRecord.id == detection_id).first()
    if detection is None:
        return None

    event = session.query(EventRecord).filter(EventRecord.id == detection.event_id).first()
    if event is None:
        return None

    risk = (
        session.query(RiskAssessmentRecord)
        .filter(RiskAssessmentRecord.detection_id == detection_id)
        .first()
    )

    chain = build_justification_chain(session, [event.id])
    techniques = sorted({t for entry in chain for t in entry.techniques})

    return DetectionReviewItem(detection=detection, event=event, risk=risk, techniques=techniques)
