"""Integration tests for the cluster query API (M3-04)."""

import pytest

from forensix.correlation.api import (
    get_cluster_events,
    get_file_artifacts,
    get_network_connections,
    get_process_tree,
    rebuild_graph,
    save_cluster,
)
from forensix.db import SessionLocal
from forensix.models.db import EventRecord, IncidentCluster
from forensix.models.event import FileInfo, NetworkInfo, NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(IncidentCluster).filter(
        IncidentCluster.id.like("%-test-%")
    ).delete(synchronize_session=False)
    session.query(EventRecord).filter(EventRecord.host == "M304-TEST").delete()
    session.commit()
    session.close()


def _make_test_events() -> list[NormalizedEvent]:
    return [
        NormalizedEvent(
            id="m304-test-e1",
            timestamp="2026-08-17T10:00:00",
            host="M304-TEST",
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(
                name="powershell.exe", pid=100, ppid=None, command_line="powershell -enc ..."
            ),
        ),
        NormalizedEvent(
            id="m304-test-e2",
            timestamp="2026-08-17T10:00:05",
            host="M304-TEST",
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="cmd.exe", pid=200, ppid=100),
            file=FileInfo(path="C:\\Temp\\payload.exe"),
        ),
        NormalizedEvent(
            id="m304-test-e3",
            timestamp="2026-08-17T10:00:10",
            host="M304-TEST",
            source="sysmon",
            event_id="3",
            event_type="sysmon_event",
            process=ProcessInfo(name="cmd.exe", pid=200, ppid=100),
            network=NetworkInfo(destination_ip="8.8.8.8", destination_port=443),
        ),
    ]


def test_save_cluster_creates_a_persistent_row(db_session):
    events = _make_test_events()
    bulk_insert_events(db_session, events)
    cluster = save_cluster(db_session, [e.id for e in events])
    assert cluster.id is not None
    assert len(cluster.event_ids) == 3
    retrieved = db_session.query(IncidentCluster).filter(
        IncidentCluster.id == cluster.id
    ).first()
    assert retrieved is not None


def test_get_cluster_events_returns_events_ordered_by_timestamp(db_session):
    events = _make_test_events()
    bulk_insert_events(db_session, events)
    cluster = save_cluster(db_session, [e.id for e in events])
    retrieved = get_cluster_events(db_session, cluster)
    assert len(retrieved) == 3
    assert retrieved[0].id == "m304-test-e1"
    assert retrieved[2].id == "m304-test-e3"


def test_rebuild_graph_reconstructs_from_postgresql(db_session):
    events = _make_test_events()
    bulk_insert_events(db_session, events)
    cluster = save_cluster(db_session, [e.id for e in events])
    graph = rebuild_graph(db_session, cluster)
    assert graph.number_of_nodes() == 4
    assert graph.number_of_edges() == 3


def test_get_process_tree_returns_all_processes(db_session):
    events = _make_test_events()
    bulk_insert_events(db_session, events)
    cluster = save_cluster(db_session, [e.id for e in events])
    graph = rebuild_graph(db_session, cluster)
    processes = get_process_tree(graph)
    assert len(processes) == 2
    names = {p["name"] for p in processes}
    assert names == {"powershell.exe", "cmd.exe"}


def test_get_file_artifacts_returns_created_files(db_session):
    events = _make_test_events()
    bulk_insert_events(db_session, events)
    cluster = save_cluster(db_session, [e.id for e in events])
    graph = rebuild_graph(db_session, cluster)
    files = get_file_artifacts(graph)
    assert len(files) == 1
    assert files[0]["path"] == "C:\\Temp\\payload.exe"


def test_get_network_connections_returns_destinations(db_session):
    events = _make_test_events()
    bulk_insert_events(db_session, events)
    cluster = save_cluster(db_session, [e.id for e in events])
    graph = rebuild_graph(db_session, cluster)
    nets = get_network_connections(graph)
    assert len(nets) == 1
    assert nets[0]["destination_ip"] == "8.8.8.8"
    assert nets[0]["destination_port"] == 443
