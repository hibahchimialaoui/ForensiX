"""Tests for timeline construction (M4-01): chronological order and determinism."""

import random

import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.models.db import DetectionRecord, EventRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events
from forensix.timeline.builder import build_timeline

TEST_HOST = "M401-TEST"


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(DetectionRecord).filter(
        DetectionRecord.event_id.like("m401-%")
    ).delete(synchronize_session=False)
    session.query(EventRecord).filter(EventRecord.host == TEST_HOST).delete()
    session.commit()
    session.close()


def _make_events() -> list[NormalizedEvent]:
    return [
        NormalizedEvent(
            id="m401-c", timestamp="2026-08-17T10:00:00", host=TEST_HOST,
            source="sysmon", event_id="1", event_type="sysmon_event",
            process=ProcessInfo(name="c.exe", pid=300),
        ),
        NormalizedEvent(
            id="m401-a", timestamp="2026-08-17T10:00:00", host=TEST_HOST,
            source="sysmon", event_id="1", event_type="sysmon_event",
            process=ProcessInfo(name="a.exe", pid=100),
        ),
        NormalizedEvent(
            id="m401-b", timestamp="2026-08-17T09:59:00", host=TEST_HOST,
            source="sysmon", event_id="1", event_type="sysmon_event",
            process=ProcessInfo(name="b.exe", pid=200),
        ),
    ]


def test_timeline_is_sorted_chronologically(db_session):
    bulk_insert_events(db_session, _make_events())
    records = db_session.query(EventRecord).filter(EventRecord.host == TEST_HOST).all()
    timeline = build_timeline(db_session, records)
    assert [e.event.id for e in timeline] == ["m401-b", "m401-a", "m401-c"]


def test_timeline_breaks_ties_by_event_id_deterministically(db_session):
    bulk_insert_events(db_session, _make_events())
    records = db_session.query(EventRecord).filter(EventRecord.host == TEST_HOST).all()

    reference = [e.event.id for e in build_timeline(db_session, records)]

    for _ in range(3):
        shuffled = records.copy()
        random.shuffle(shuffled)
        result = [e.event.id for e in build_timeline(db_session, shuffled)]
        assert result == reference


def test_empty_event_list_returns_empty_timeline(db_session):
    assert build_timeline(db_session, []) == []


def test_timeline_entry_links_detections_when_present(db_session):
    """An event matching a curated Sigma rule must carry its DetectionRecord
    in the corresponding TimelineEntry."""
    event = NormalizedEvent(
        id="m401-detect",
        timestamp="2026-08-17T10:05:00",
        host=TEST_HOST,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )
    bulk_insert_events(db_session, [event])
    run_and_persist_detections(db_session)

    records = (
        db_session.query(EventRecord).filter(EventRecord.id == "m401-detect").all()
    )
    timeline = build_timeline(db_session, records)

    assert len(timeline) == 1
    assert len(timeline[0].detections) >= 1
