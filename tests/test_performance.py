"""Tests for pipeline performance measurement (M7-04)."""

import pytest

from forensix.db import SessionLocal
from forensix.evaluation.performance import PERF_TEST_HOST, measure_pipeline_performance
from forensix.models.db import EventRecord


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(EventRecord).filter(EventRecord.host == PERF_TEST_HOST).delete()
    session.commit()
    session.close()


def test_measure_pipeline_performance_returns_positive_metrics(db_session):
    metrics = measure_pipeline_performance(db_session, event_count=20)

    assert metrics.event_count == 20
    assert metrics.ingestion_seconds > 0
    assert metrics.detection_seconds > 0
    assert metrics.correlation_seconds >= 0
    assert metrics.total_seconds > 0
    assert metrics.events_per_second > 0


def test_measure_pipeline_performance_cleans_up_synthetic_events(db_session):
    measure_pipeline_performance(db_session, event_count=10)
    remaining = (
        db_session.query(EventRecord).filter(EventRecord.host == PERF_TEST_HOST).count()
    )
    assert remaining == 0


def test_events_per_second_is_consistent_with_total_time(db_session):
    metrics = measure_pipeline_performance(db_session, event_count=15)
    expected_rate = metrics.event_count / metrics.total_seconds
    assert abs(metrics.events_per_second - expected_rate) < 0.01
