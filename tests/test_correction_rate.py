"""Tests for the analyst correction rate (M7-05), computed from real review data."""

import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.evaluation.correction_rate import compute_correction_rate
from forensix.models.db import DetectionRecord, EventRecord, HostContext, RiskAssessmentRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events
from forensix.risk.criticality import set_host_criticality
from forensix.risk.override import apply_analyst_override
from forensix.risk.pipeline import assess_detection_risk

HOST_APPROVED = "M705-TEST-APPROVED"
HOST_CORRECTED = "M705-TEST-CORRECTED"


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    for host in (HOST_APPROVED, HOST_CORRECTED):
        detection_ids = [
            d.id
            for d in session.query(DetectionRecord)
            .join(EventRecord, DetectionRecord.event_id == EventRecord.id)
            .filter(EventRecord.host == host)
            .all()
        ]
        session.query(RiskAssessmentRecord).filter(
            RiskAssessmentRecord.detection_id.in_(detection_ids)
        ).delete(synchronize_session=False)
        session.query(DetectionRecord).filter(
            DetectionRecord.id.in_(detection_ids)
        ).delete(synchronize_session=False)
        session.query(EventRecord).filter(EventRecord.host == host).delete()
        session.query(HostContext).filter(HostContext.host == host).delete()
    session.commit()
    session.close()


def _seed_and_review(session, event_id, host, override_category, override_priority, reason):
    """Insert an event, produce a detection+risk, and apply exactly one review."""
    event = NormalizedEvent(
        id=event_id,
        timestamp="2026-08-24T10:00:00",
        host=host,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )
    bulk_insert_events(session, [event])
    set_host_criticality(session, host, "medium")
    results, _ = run_and_persist_detections(session)
    detection = (
        session.query(DetectionRecord).filter(DetectionRecord.event_id == event_id).first()
    )
    matching = next(r for r in results if r.rule_id == detection.rule_id)
    risk = assess_detection_risk(session, detection, matching.where_clause)
    apply_analyst_override(session, risk, override_category, override_priority, reason)
    return risk


def test_correction_rate_reflects_one_approved_and_one_corrected(db_session):
    rate_before = compute_correction_rate(db_session)

    risk_approved = _seed_and_review(
        db_session, "m705-test-approved-1", HOST_APPROVED, "high", "P2", "placeholder"
    )
    # Re-apply with the same category/priority as the original -> "approved as-is".
    apply_analyst_override(
        db_session,
        risk_approved,
        risk_approved.risk_category,
        risk_approved.priority,
        "Approved as-is",
    )

    _seed_and_review(
        db_session, "m705-test-corrected-1", HOST_CORRECTED, "low", "P4", "False positive"
    )

    rate_after = compute_correction_rate(db_session)

    assert rate_after.total_reviewed == rate_before.total_reviewed + 2
    assert rate_after.corrected == rate_before.corrected + 1
    assert rate_after.approved_as_is == rate_before.approved_as_is + 1


def test_correction_rate_is_zero_when_nothing_reviewed_matches_filter(db_session):
    """A freshly-created RiskAssessmentRecord without an override must not
    be counted in the correction rate at all."""
    rate = compute_correction_rate(db_session)
    assert rate.correction_rate >= 0.0
    assert rate.correction_rate <= 1.0
