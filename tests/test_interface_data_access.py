"""Tests for the analyst interface data access layer (M6-02).

Only tests data_access.py, not app.py (Streamlit UI itself has no
automated test - verified visually, task 6 of this issue).
"""

import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.interface.data_access import get_detection_review_item, list_pending_detections
from forensix.models.db import DetectionRecord, EventRecord, HostContext, RiskAssessmentRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events
from forensix.risk.criticality import set_host_criticality
from forensix.risk.override import apply_analyst_override
from forensix.risk.pipeline import assess_detection_risk

TEST_HOST = "M602-TEST"


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    detection_ids = [
        d.id
        for d in session.query(DetectionRecord)
        .join(EventRecord, DetectionRecord.event_id == EventRecord.id)
        .filter(EventRecord.host == TEST_HOST)
        .all()
    ]
    session.query(RiskAssessmentRecord).filter(
        RiskAssessmentRecord.detection_id.in_(detection_ids)
    ).delete(synchronize_session=False)
    session.query(DetectionRecord).filter(
        DetectionRecord.id.in_(detection_ids)
    ).delete(synchronize_session=False)
    session.query(EventRecord).filter(EventRecord.host == TEST_HOST).delete()
    session.query(HostContext).filter(HostContext.host == TEST_HOST).delete()
    session.commit()
    session.close()


def _seed_detection(session, event_id="m602-test-1"):
    event = NormalizedEvent(
        id=event_id,
        timestamp="2026-08-19T10:00:00",
        host=TEST_HOST,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )
    bulk_insert_events(session, [event])
    set_host_criticality(session, TEST_HOST, "high")
    results, _ = run_and_persist_detections(session)
    detection = (
        session.query(DetectionRecord).filter(DetectionRecord.event_id == event_id).first()
    )
    matching = next(r for r in results if r.rule_id == detection.rule_id)
    assess_detection_risk(session, detection, matching.where_clause)
    return detection


def test_list_pending_detections_includes_a_new_detection(db_session):
    detection = _seed_detection(db_session)
    pending = list_pending_detections(db_session)
    matching_ids = [item.detection.id for item in pending]
    assert detection.id in matching_ids


def test_pending_item_includes_event_risk_and_techniques(db_session):
    detection = _seed_detection(db_session)
    pending = list_pending_detections(db_session)
    item = next(i for i in pending if i.detection.id == detection.id)

    assert item.event.host == TEST_HOST
    assert item.risk is not None
    assert item.techniques == ["T1036"]


def test_overridden_detection_is_excluded_from_pending_list(db_session):
    """Once an analyst has reviewed a detection (M6-01), it must no longer
    appear in the pending queue."""
    detection = _seed_detection(db_session)
    risk = (
        db_session.query(RiskAssessmentRecord)
        .filter(RiskAssessmentRecord.detection_id == detection.id)
        .first()
    )
    apply_analyst_override(db_session, risk, risk.risk_category, risk.priority, "Reviewed")

    pending = list_pending_detections(db_session)
    matching_ids = [item.detection.id for item in pending]
    assert detection.id not in matching_ids


def test_get_detection_review_item_returns_none_for_unknown_id(db_session):
    assert get_detection_review_item(db_session, "does-not-exist") is None


def test_get_detection_review_item_returns_full_data(db_session):
    detection = _seed_detection(db_session)
    item = get_detection_review_item(db_session, detection.id)

    assert item is not None
    assert item.detection.id == detection.id
    assert item.risk.risk_category is not None
    assert item.techniques == ["T1036"]
