"""End-to-end ingestion test: real EVTX fixture -> Sysmon parser -> Event Store.

This test closes Milestone 1's official acceptance criterion: a real dataset
ingested through the full pipeline, with events verifiable in PostgreSQL and
key fields validated automatically.
"""

import time
from pathlib import Path

import pytest

from forensix.db import SessionLocal
from forensix.models.db import EventRecord
from forensix.parsers.evtx import read_evtx_records
from forensix.parsers.sysmon import parse_sysmon_record
from forensix.repository import bulk_insert_events

FIXTURE_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "evtx" / "UACME_59_Sysmon.evtx"
)


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.close()


@pytest.mark.skipif(
    not FIXTURE_PATH.exists(),
    reason="Dataset fixture not downloaded; run scripts/download_test_dataset.py first",
)
def test_full_pipeline_ingests_real_evtx_dataset(db_session):
    """Read the real fixture, parse it, insert into PostgreSQL, and verify the result."""
    start = time.perf_counter()

    raw_records = list(read_evtx_records(str(FIXTURE_PATH)))
    events = [
        event
        for xml in raw_records
        if (event := parse_sysmon_record(xml, host="fallback")) is not None
    ]

    elapsed = time.perf_counter() - start

    # Volume check: the fixture has 7 raw records, 2 of which match our
    # relevant Sysmon event IDs (1, 3, 11) - confirmed manually in task 7 of M1-07.
    assert len(raw_records) == 7
    assert len(events) == 2

    event_ids = [event.id for event in events]

    try:
        inserted_count = bulk_insert_events(db_session, events)
        assert inserted_count == 2

        # Identify inserted rows by their unique id (not by host: the real
        # EVTX file has its own Computer field, which parse_sysmon_record
        # correctly prefers over our "fallback" argument).
        rows = db_session.query(EventRecord).filter(EventRecord.id.in_(event_ids)).all()
        assert len(rows) == 2

        # Field integrity: every inserted row must have the mandatory fields populated.
        for row in rows:
            assert row.id
            assert row.timestamp is not None
            assert row.host  # real hostname from the EVTX file, non-empty
            assert row.source == "sysmon"
            assert row.event_id in {"1", "3", "11"}

        print(f"Ingested {inserted_count} events from {len(raw_records)} raw records "
              f"in {elapsed:.3f}s")
    finally:
        db_session.query(EventRecord).filter(EventRecord.id.in_(event_ids)).delete(
            synchronize_session=False
        )
        db_session.commit()
