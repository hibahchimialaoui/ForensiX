"""Integration tests for detection persistence and the Detection -> Event link."""

import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import run_all_rules
from forensix.models.db import DetectionRecord, EventRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events, persist_detections


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(DetectionRecord).filter(
        DetectionRecord.event_id.like("m204-%")
    ).delete(synchronize_session=False)
    session.query(EventRecord).filter(EventRecord.host == "M2-04-TEST").delete()
    session.commit()
    session.close()


def test_persist_detections_creates_a_row_linked_to_the_source_event(db_session):
    event = NormalizedEvent(
        id="m204-detect-1",
        timestamp="2026-08-16T10:00:00",
        host="M2-04-TEST",
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )
    bulk_insert_events(db_session, [event])

    results = run_all_rules(db_session)
    inserted_count = persist_detections(db_session, results)
    assert inserted_count >= 1

    detections = (
        db_session.query(DetectionRecord)
        .filter(DetectionRecord.event_id == "m204-detect-1")
        .all()
    )
    assert len(detections) == 1

    detection = detections[0]
    assert detection.rule_id == "3dfd06d2-eaf4-4532-9555-68aca59f57c4"
    assert detection.severity == "high"
    assert detection.detection_status == "new"
    assert detection.detection_metadata is not None
    assert "rule_file" in detection.detection_metadata


def test_persist_detections_skips_errored_rule_matches(db_session):
    """Rules that failed to execute (M2-03, unmapped fields) must never
    produce a DetectionRecord - only clean matches are persisted."""
    event = NormalizedEvent(
        id="m204-noise-1",
        timestamp="2026-08-16T10:00:00",
        host="M2-04-TEST",
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Program Files\\legit_app.exe"),
    )
    bulk_insert_events(db_session, [event])

    results = run_all_rules(db_session)
    errored_rule_ids = {r.rule_id for r in results if r.error is not None}
    assert len(errored_rule_ids) == 3

    persist_detections(db_session, results)

    detections_from_errored_rules = (
        db_session.query(DetectionRecord)
        .filter(DetectionRecord.rule_id.in_(errored_rule_ids))
        .all()
    )
    assert len(detections_from_errored_rules) == 0


def test_persist_detections_returns_zero_for_empty_matches(db_session):
    assert persist_detections(db_session, []) == 0
