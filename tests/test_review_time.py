"""Tests for the illustrative review cycle timing (M7-06, bonus)."""

import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.evaluation.review_time import measure_review_cycle
from forensix.models.db import DetectionRecord, EventRecord, HostContext, RiskAssessmentRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events
from forensix.risk.criticality import set_host_criticality
from forensix.risk.pipeline import assess_detection_risk

TEST_HOST = "M706-TEST"


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


def test_measure_review_cycle_returns_positive_timings(db_session):
    event = NormalizedEvent(
        id="m706-test-1",
        timestamp="2026-08-24T10:00:00",
        host=TEST_HOST,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )
    bulk_insert_events(db_session, [event])
    set_host_criticality(db_session, TEST_HOST, "medium")
    results, _ = run_and_persist_detections(db_session)
    detection = (
        db_session.query(DetectionRecord).filter(DetectionRecord.event_id == "m706-test-1").first()
    )
    matching = next(r for r in results if r.rule_id == detection.rule_id)
    assess_detection_risk(db_session, detection, matching.where_clause)

    timing = measure_review_cycle(db_session, detection.id)

    assert timing.load_seconds > 0
    assert timing.decision_seconds >= 0
    assert timing.total_seconds > 0


def test_measure_review_cycle_carries_the_non_scientific_disclaimer(db_session):
    """Every result must carry the disclaimer - this is never presented as
    a scientific human review time measurement."""
    event = NormalizedEvent(
        id="m706-test-2",
        timestamp="2026-08-24T10:00:00",
        host=TEST_HOST,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )
    bulk_insert_events(db_session, [event])
    set_host_criticality(db_session, TEST_HOST, "medium")
    results, _ = run_and_persist_detections(db_session)
    detection = (
        db_session.query(DetectionRecord).filter(DetectionRecord.event_id == "m706-test-2").first()
    )
    matching = next(r for r in results if r.rule_id == detection.rule_id)
    assess_detection_risk(db_session, detection, matching.where_clause)

    timing = measure_review_cycle(db_session, detection.id)
    assert "not a measurement of real human review time" in timing.note


def test_measure_review_cycle_raises_for_unknown_detection(db_session):
    with pytest.raises(ValueError, match="No reviewable detection"):
        measure_review_cycle(db_session, "does-not-exist")
