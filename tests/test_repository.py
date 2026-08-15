"""Integration tests for the Event Store repository (requires a running PostgreSQL)."""

import pytest

from forensix.db import SessionLocal
from forensix.models.db import EventRecord
from forensix.models.event import NetworkInfo, NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(EventRecord).delete()
    session.commit()
    session.close()


def test_bulk_insert_and_read_back(db_session):
    events = [
        NormalizedEvent(
            id="test-1",
            timestamp="2026-08-15T10:00:00",
            host="WIN-TEST",
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="powershell.exe", pid=1234, ppid=1000),
        ),
        NormalizedEvent(
            id="test-2",
            timestamp="2026-08-15T10:01:00",
            host="WIN-TEST",
            source="sysmon",
            event_id="3",
            event_type="sysmon_event",
            network=NetworkInfo(destination_ip="8.8.8.8", destination_port=443),
        ),
    ]

    inserted_count = bulk_insert_events(db_session, events)
    assert inserted_count == 2

    rows = db_session.query(EventRecord).filter(EventRecord.host == "WIN-TEST").all()
    assert len(rows) == 2

    process_row = next(r for r in rows if r.id == "test-1")
    assert process_row.process_name == "powershell.exe"
    assert process_row.process_pid == 1234

    network_row = next(r for r in rows if r.id == "test-2")
    assert network_row.network_destination_port == 443
