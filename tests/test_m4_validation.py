"""End-to-end validation test (M4-04): clustering + timeline + ATT&CK mapping
+ justification chain, on a multi-cluster, multi-technique dataset."""

import pytest

from forensix.attack.justification import build_justification_chain
from forensix.correlation.clustering import cluster_events
from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.models.db import DetectionRecord, EventRecord
from forensix.repository import bulk_insert_events
from forensix.timeline.builder import build_timeline
from forensix.timeline.validation import (
    VALIDATION_HOST_A,
    VALIDATION_HOST_B,
    build_cluster_a,
    build_cluster_b,
    build_unrelated_event,
)


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(DetectionRecord).filter(
        DetectionRecord.event_id.like("m404-%")
    ).delete(synchronize_session=False)
    session.query(EventRecord).filter(
        EventRecord.host.in_([VALIDATION_HOST_A, VALIDATION_HOST_B])
    ).delete(synchronize_session=False)
    session.commit()
    session.close()


@pytest.fixture
def full_dataset(db_session):
    all_events = build_cluster_a() + build_cluster_b() + [build_unrelated_event()]
    bulk_insert_events(db_session, all_events)
    run_and_persist_detections(db_session)
    return db_session.query(EventRecord).filter(
        EventRecord.id.in_([e.id for e in all_events])
    ).all()


def test_three_distinct_clusters_are_formed(full_dataset):
    clusters = cluster_events(full_dataset)
    assert len(clusters) == 3
    sizes = sorted(len(c) for c in clusters)
    assert sizes == [1, 1, 2]


def test_cluster_a_maps_to_expected_technique(db_session, full_dataset):
    clusters = cluster_events(full_dataset)
    cluster_a = next(c for c in clusters if any(e.id == "m404-a-e1" for e in c))
    chain = build_justification_chain(db_session, [e.id for e in cluster_a])
    techniques = {t for entry in chain for t in entry.techniques}
    assert techniques == {"T1036"}


def test_cluster_b_groups_linked_events_and_maps_both_techniques(db_session, full_dataset):
    clusters = cluster_events(full_dataset)
    cluster_b = next(c for c in clusters if any(e.id == "m404-b-e1" for e in c))
    assert len(cluster_b) == 2

    timeline = build_timeline(db_session, cluster_b)
    assert len(timeline) == 2

    chain = build_justification_chain(db_session, [e.id for e in cluster_b])
    techniques = {t for entry in chain for t in entry.techniques}
    assert techniques == {"T1204.002", "T1547.001"}


def test_negative_scenario_isolated_event_has_no_justification(db_session, full_dataset):
    """The event with no detection must produce zero justification entries -
    no fabricated technique for evidence that has none."""
    clusters = cluster_events(full_dataset)
    isolated = next(c for c in clusters if any(e.id == "m404-unrelated" for e in c))
    assert len(isolated) == 1

    chain = build_justification_chain(db_session, [e.id for e in isolated])
    assert chain == []
