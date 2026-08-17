"""Tests for event clustering (M3-02): transitivity and determinism, per the
3-scenario requirement from the technical review (docs/clustering_approach.md)."""

import random
from datetime import datetime

from forensix.correlation.clustering import cluster_events
from forensix.models.db import EventRecord


def make_event(**kwargs) -> EventRecord:
    defaults = dict(
        id="x",
        timestamp=datetime(2026, 8, 17, 10, 0, 0),
        host="H1",
        user=None,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process_pid=None,
        process_ppid=None,
        file_path=None,
        network_destination_ip=None,
    )
    defaults.update(kwargs)
    return EventRecord(**defaults)


def _chain_events() -> list[EventRecord]:
    """A -> B -> C -> D, linked by PID/PPID, same host, close in time."""
    return [
        make_event(id="a", host="H1", timestamp=datetime(2026, 8, 17, 10, 0, 0), process_pid=100),
        make_event(
            id="b",
            host="H1",
            timestamp=datetime(2026, 8, 17, 10, 0, 5),
            process_ppid=100,
            process_pid=200,
        ),
        make_event(
            id="c",
            host="H1",
            timestamp=datetime(2026, 8, 17, 10, 0, 10),
            process_ppid=200,
            process_pid=300,
        ),
        make_event(
            id="d", host="H1", timestamp=datetime(2026, 8, 17, 10, 0, 15), process_ppid=300
        ),
    ]


def test_scenario_a_single_incident_chain_produces_one_cluster():
    events = _chain_events()
    clusters = cluster_events(events)
    assert len(clusters) == 1
    assert len(clusters[0]) == 4


def test_scenario_b_two_independent_incidents_produce_two_clusters():
    chain = _chain_events()[:2]  # a -> b
    x = make_event(id="x", host="H2", timestamp=datetime(2026, 8, 17, 11, 0, 0), process_pid=500)
    y = make_event(
        id="y", host="H2", timestamp=datetime(2026, 8, 17, 11, 0, 5), process_ppid=500
    )

    clusters = cluster_events([*chain, x, y])
    assert len(clusters) == 2
    sizes = sorted(len(c) for c in clusters)
    assert sizes == [2, 2]


def test_scenario_c_unrelated_event_stays_isolated():
    chain = _chain_events()[:3]  # a -> b -> c
    unrelated = make_event(id="unrelated", host="H3", timestamp=datetime(2026, 8, 17, 15, 0, 0))

    clusters = cluster_events([*chain, unrelated])
    assert len(clusters) == 2

    isolated_cluster = next(c for c in clusters if len(c) == 1)
    assert isolated_cluster[0].id == "unrelated"


def test_clustering_is_deterministic_regardless_of_input_order():
    chain = _chain_events()[:3]
    x = make_event(id="x", host="H2", timestamp=datetime(2026, 8, 17, 11, 0, 0), process_pid=500)
    y = make_event(
        id="y", host="H2", timestamp=datetime(2026, 8, 17, 11, 0, 5), process_ppid=500
    )
    events = [*chain, x, y]

    def signature(clusters):
        return sorted(tuple(sorted(e.id for e in cl)) for cl in clusters)

    reference = signature(cluster_events(events))

    for _ in range(5):
        shuffled = events.copy()
        random.shuffle(shuffled)
        assert signature(cluster_events(shuffled)) == reference


def test_empty_event_list_returns_no_clusters():
    assert cluster_events([]) == []


def test_single_event_forms_its_own_cluster():
    event = make_event(id="solo", host="H4")
    clusters = cluster_events([event])
    assert len(clusters) == 1
    assert len(clusters[0]) == 1
