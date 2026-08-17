"""Integration tests for the 3-scenario correlation validation (M3-05).

These tests run against real PostgreSQL data to validate that the clustering
algorithm (M3-02) produces the correct partition for each scenario defined
in src/forensix/correlation/validation.py and docs/correlation_validation.md.
"""

import pytest

from forensix.correlation.clustering import cluster_events
from forensix.correlation.validation import (
    VALIDATION_HOST_A,
    VALIDATION_HOST_B,
    VALIDATION_HOST_C,
    build_scenario_a,
    build_scenario_b,
    build_scenario_c,
)
from forensix.db import SessionLocal
from forensix.models.db import EventRecord
from forensix.repository import bulk_insert_events


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    for host in (VALIDATION_HOST_A, VALIDATION_HOST_B, VALIDATION_HOST_C):
        session.query(EventRecord).filter(EventRecord.host == host).delete()
    session.commit()
    session.close()


def _insert_and_cluster(session, events):
    bulk_insert_events(session, events)
    event_ids = [e.id for e in events]
    records = (
        session.query(EventRecord)
        .filter(EventRecord.id.in_(event_ids))
        .all()
    )
    return cluster_events(records)


def test_scenario_a_single_chain_produces_one_cluster(db_session):
    """4 events linked by PID/PPID chain must form exactly 1 cluster."""
    clusters = _insert_and_cluster(db_session, build_scenario_a())
    assert len(clusters) == 1
    assert len(clusters[0]) == 4


def test_scenario_b_two_independent_incidents_produce_two_clusters(db_session):
    """Two incidents on different hosts must produce 2 distinct clusters."""
    clusters = _insert_and_cluster(db_session, build_scenario_b())
    assert len(clusters) == 2
    sizes = sorted(len(c) for c in clusters)
    assert sizes == [2, 2]


def test_scenario_c_isolated_event_stays_in_its_own_cluster(db_session):
    """An event with no correlation to others must remain in a size-1 cluster."""
    clusters = _insert_and_cluster(db_session, build_scenario_c())
    assert len(clusters) == 2
    sizes = sorted(len(c) for c in clusters)
    assert sizes == [1, 2]
    isolated = next(c for c in clusters if len(c) == 1)
    assert isolated[0].id == "m305-c-e3"
