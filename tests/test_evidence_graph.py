"""Tests for the evidence graph construction (M3-03)."""

from datetime import datetime

from forensix.correlation.graph import (
    NODE_FILE,
    NODE_NETWORK,
    NODE_PROCESS,
    NODE_USER,
    build_evidence_graph,
)
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
        process_name=None,
        process_command_line=None,
        file_path=None,
        network_destination_ip=None,
        network_destination_port=None,
    )
    defaults.update(kwargs)
    return EventRecord(**defaults)


def test_empty_cluster_produces_empty_graph():
    graph = build_evidence_graph([])
    assert graph.number_of_nodes() == 0
    assert graph.number_of_edges() == 0


def test_process_node_is_created_from_process_event():
    event = make_event(id="e1", process_pid=100, process_name="powershell.exe")
    graph = build_evidence_graph([event])
    process_nodes = [n for n, d in graph.nodes(data=True) if d["type"] == NODE_PROCESS]
    assert len(process_nodes) == 1
    assert graph.nodes[process_nodes[0]]["pid"] == 100


def test_user_to_process_edge_is_created():
    event = make_event(id="e1", user="alice", process_pid=100, process_name="powershell.exe")
    graph = build_evidence_graph([event])
    user_nodes = [n for n, d in graph.nodes(data=True) if d["type"] == NODE_USER]
    assert len(user_nodes) == 1
    edges = list(graph.out_edges(user_nodes[0], data=True))
    assert len(edges) == 1
    assert edges[0][2]["relation"] == "runs"


def test_process_to_file_edge_is_created():
    event = make_event(
        id="e1", process_pid=100, process_name="cmd.exe", file_path="C:\\Temp\\payload.exe"
    )
    graph = build_evidence_graph([event])
    file_nodes = [n for n, d in graph.nodes(data=True) if d["type"] == NODE_FILE]
    assert len(file_nodes) == 1
    edges = list(graph.in_edges(file_nodes[0], data=True))
    assert edges[0][2]["relation"] == "creates"


def test_process_to_network_edge_is_created():
    event = make_event(
        id="e1",
        process_pid=100,
        process_name="cmd.exe",
        network_destination_ip="8.8.8.8",
        network_destination_port=443,
    )
    graph = build_evidence_graph([event])
    net_nodes = [n for n, d in graph.nodes(data=True) if d["type"] == NODE_NETWORK]
    assert len(net_nodes) == 1
    edges = list(graph.in_edges(net_nodes[0], data=True))
    assert edges[0][2]["relation"] == "connects_to"


def test_parent_child_process_spawns_edge_is_created():
    parent = make_event(id="e1", process_pid=100, process_name="powershell.exe")
    child = make_event(id="e2", process_pid=200, process_ppid=100, process_name="cmd.exe")
    graph = build_evidence_graph([parent, child])
    spawns_edges = [
        (s, t) for s, t, d in graph.edges(data=True) if d["relation"] == "spawns"
    ]
    assert len(spawns_edges) == 1


def test_full_cluster_produces_correct_node_and_edge_counts():
    cluster = [
        make_event(
            id="e1", user="alice", process_pid=100, process_name="powershell.exe",
            process_command_line="powershell -enc ...",
        ),
        make_event(
            id="e2", process_pid=200, process_ppid=100, process_name="cmd.exe",
            file_path="C:\\Temp\\payload.exe",
        ),
        make_event(
            id="e3", process_pid=200, process_ppid=100, process_name="cmd.exe",
            network_destination_ip="8.8.8.8", network_destination_port=443,
        ),
    ]
    graph = build_evidence_graph(cluster)
    assert graph.number_of_nodes() == 5
    assert graph.number_of_edges() == 4
