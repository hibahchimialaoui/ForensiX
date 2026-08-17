"""Cluster query API (M3-04): reconstruct the evidence graph from PostgreSQL on demand.

PostgreSQL is the source of truth; NetworkX is a derived analytical view.
If an event is corrected in PostgreSQL, rebuilding the graph via these
functions reflects the correction automatically - no stale serialized copy.
"""

import uuid
from datetime import UTC, datetime

import networkx as nx
from sqlalchemy.orm import Session

from forensix.correlation.graph import NODE_FILE, NODE_NETWORK, NODE_PROCESS, build_evidence_graph
from forensix.models.db import EventRecord, IncidentCluster


def save_cluster(
    session: Session,
    event_ids: list[str],
    detection_ids: list[str] | None = None,
    metadata: dict | None = None,
) -> IncidentCluster:
    """Persist a stable IncidentCluster row and return it."""
    cluster = IncidentCluster(
        id=str(uuid.uuid4()),
        event_ids=event_ids,
        detection_ids=detection_ids or [],
        created_at=datetime.now(UTC),
        correlation_metadata=metadata,
    )
    session.add(cluster)
    session.commit()
    return cluster


def get_cluster_events(session: Session, cluster: IncidentCluster) -> list[EventRecord]:
    """Return the EventRecord rows belonging to a cluster, ordered by timestamp."""
    return (
        session.query(EventRecord)
        .filter(EventRecord.id.in_(cluster.event_ids))
        .order_by(EventRecord.timestamp)
        .all()
    )


def rebuild_graph(session: Session, cluster: IncidentCluster) -> nx.DiGraph:
    """Reconstruct the evidence graph for a cluster from current PostgreSQL data."""
    events = get_cluster_events(session, cluster)
    return build_evidence_graph(events)


def get_process_tree(graph: nx.DiGraph) -> list[dict]:
    """Return the process nodes and their parent-child (spawns) relationships."""
    processes = [
        {
            "node": node,
            "pid": data.get("pid"),
            "name": data.get("name"),
            "command_line": data.get("command_line"),
            "children": [
                t for s, t, d in graph.out_edges(node, data=True) if d["relation"] == "spawns"
            ],
        }
        for node, data in graph.nodes(data=True)
        if data.get("type") == NODE_PROCESS
    ]
    return processes


def get_file_artifacts(graph: nx.DiGraph) -> list[dict]:
    """Return the file nodes (created by processes) in the cluster."""
    return [
        {"node": node, "path": data.get("path"), "events": data.get("events", [])}
        for node, data in graph.nodes(data=True)
        if data.get("type") == NODE_FILE
    ]


def get_network_connections(graph: nx.DiGraph) -> list[dict]:
    """Return the network destination nodes in the cluster."""
    return [
        {
            "node": node,
            "destination_ip": data.get("destination_ip"),
            "destination_port": data.get("destination_port"),
            "events": data.get("events", []),
        }
        for node, data in graph.nodes(data=True)
        if data.get("type") == NODE_NETWORK
    ]
