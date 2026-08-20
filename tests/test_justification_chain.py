"""Tests for the justification chain: technique -> rule -> detection -> event -> evidence."""

import pytest

from forensix.attack.justification import build_justification_chain
from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.models.db import DetectionRecord, EventRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events

TEST_HOST = "M403-TEST"


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(DetectionRecord).filter(
        DetectionRecord.event_id.like("m403-%")
    ).delete(synchronize_session=False)
    session.query(EventRecord).filter(EventRecord.host == TEST_HOST).delete()
    session.commit()
    session.close()


def test_detected_event_produces_a_complete_justification_chain(db_session):
    event = NormalizedEvent(
        id="m403-detected",
        timestamp="2026-08-17T10:00:00",
        host=TEST_HOST,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
        raw_event={"xml": "<Event>...</Event>"},
    )
    bulk_insert_events(db_session, [event])
    run_and_persist_detections(db_session)

    chain = build_justification_chain(db_session, ["m403-detected"])
    assert len(chain) == 1

    entry = chain[0]
    assert entry.techniques == ["T1036"]
    assert entry.event.id == "m403-detected"
    assert entry.raw_evidence is not None
    assert entry.rule_id
    assert entry.detection_id


def test_clean_event_produces_no_justification_entry(db_session):
    """An event with no matching detection must not appear in the chain -
    no fabricated technique or conclusion for evidence that has none."""
    event = NormalizedEvent(
        id="m403-clean",
        timestamp="2026-08-17T10:01:00",
        host=TEST_HOST,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Program Files\\legit.exe"),
        raw_event={"xml": "<Event>...</Event>"},
    )
    bulk_insert_events(db_session, [event])
    run_and_persist_detections(db_session)

    chain = build_justification_chain(db_session, ["m403-clean"])
    assert chain == []


def test_empty_event_id_list_returns_empty_chain(db_session):
    assert build_justification_chain(db_session, []) == []
