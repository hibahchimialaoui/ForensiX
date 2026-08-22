"""Full risk pipeline (M5-05): assembles confidence, severity, criticality, and risk
for a detection, and persists the result.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from forensix.correlation.clustering import cluster_events
from forensix.models.db import DetectionRecord, EventRecord, RiskAssessmentRecord
from forensix.risk.assessment import compute_risk
from forensix.risk.confidence import compute_confidence
from forensix.risk.criticality import get_host_criticality


def assess_detection_risk(
    session: Session, detection: DetectionRecord, where_clause: str
) -> RiskAssessmentRecord:
    """Compute and persist the full risk assessment for a single detection.

    Rebuilds the detection's cluster (M3) from its event's host to compute
    confidence (M5-01), looks up host criticality (M5-03), combines
    everything into a risk (M5-04), and persists the result.
    """
    event = session.query(EventRecord).filter(EventRecord.id == detection.event_id).first()
    if event is None:
        raise ValueError(f"No EventRecord found for detection {detection.id}")

    host_events = session.query(EventRecord).filter(EventRecord.host == event.host).all()
    clusters = cluster_events(host_events)
    cluster = next((c for c in clusters if any(e.id == event.id for e in c)), [event])

    confidence = compute_confidence(where_clause, cluster)
    criticality = get_host_criticality(session, event.host)
    risk = compute_risk(detection.severity, confidence, criticality)

    record = RiskAssessmentRecord(
        id=str(uuid.uuid4()),
        detection_id=detection.id,
        confidence=confidence,
        severity=detection.severity,
        host_criticality=criticality,
        risk_score=risk.risk_score,
        risk_category=risk.category,
        priority=risk.priority,
        created_at=datetime.now(UTC),
    )
    session.add(record)
    session.commit()
    return record
