"""Pipeline performance metrics (M7-04).

Measures processing time and throughput of the existing pipeline
(ingestion -> Sigma detection -> correlation) on a given event volume.
A reference figure, not a production performance guarantee.
"""

import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from forensix.correlation.clustering import cluster_events
from forensix.detection.executor import run_all_rules
from forensix.models.db import EventRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events

PERF_TEST_HOST = "M704-PERF-TEST"


@dataclass
class PerformanceMetrics:
    """Timing and throughput for one pipeline run over a given event volume."""

    event_count: int
    ingestion_seconds: float
    detection_seconds: float
    correlation_seconds: float
    total_seconds: float
    events_per_second: float


def _build_synthetic_events(count: int) -> list[NormalizedEvent]:
    """Build a batch of synthetic Sysmon process-creation events for load testing."""
    base_time = datetime(2026, 8, 24, 10, 0, 0)
    return [
        NormalizedEvent(
            id=f"m704-perf-{i}",
            timestamp=base_time + timedelta(seconds=i),
            host=PERF_TEST_HOST,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name=f"process_{i}.exe", pid=1000 + i),
        )
        for i in range(count)
    ]


def measure_pipeline_performance(session: Session, event_count: int) -> PerformanceMetrics:
    """Run the full pipeline on `event_count` synthetic events and time each stage.

    Cleans up the inserted events before returning, so this can be called
    repeatedly (e.g. in CI) without accumulating data.
    """
    events = _build_synthetic_events(event_count)

    try:
        start_total = time.perf_counter()

        start = time.perf_counter()
        bulk_insert_events(session, events)
        ingestion_seconds = time.perf_counter() - start

        start = time.perf_counter()
        run_all_rules(session)
        detection_seconds = time.perf_counter() - start

        start = time.perf_counter()
        records = (
            session.query(EventRecord).filter(EventRecord.host == PERF_TEST_HOST).all()
        )
        cluster_events(records)
        correlation_seconds = time.perf_counter() - start

        total_seconds = time.perf_counter() - start_total

        return PerformanceMetrics(
            event_count=event_count,
            ingestion_seconds=ingestion_seconds,
            detection_seconds=detection_seconds,
            correlation_seconds=correlation_seconds,
            total_seconds=total_seconds,
            events_per_second=event_count / total_seconds if total_seconds > 0 else 0.0,
        )
    finally:
        session.query(EventRecord).filter(EventRecord.host == PERF_TEST_HOST).delete()
        session.commit()
