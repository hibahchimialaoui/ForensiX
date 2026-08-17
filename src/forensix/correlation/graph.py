"""Evidence graph construction from a correlation cluster (M3-03).

Builds a NetworkX DiGraph where nodes are entities (processes, files, IPs,
users) and edges represent observed relationships (user -> process,
process -> child_process, process -> file, process -> network destination).
"""

import networkx as nx

from forensix.models.db import EventRecord

NODE_PROCESS = "process"
NODE_FILE = "file"
NODE_NETWORK = "network"
NODE_USER = "user"


def build_evidence_graph(cluster: list[EventRecord]) -> nx.DiGraph:
    """Build a directed evidence graph from a list of correlated events.

    Nodes carry a 'type' attribute (process/file/network/user) and an
    'events' attribute listing the EventRecord ids that produced this node.
    Edges carry a 'relation' attribute describing the observed relationship.
    """
    graph = nx.DiGraph()

    for event in cluster:
        process_node = None

        if event.process_name or event.process_pid is not None:
            process_node = f"proc:{event.process_pid}:{event.process_name}"
            if not graph.has_node(process_node):
                graph.add_node(
                    process_node,
                    type=NODE_PROCESS,
                    pid=event.process_pid,
                    ppid=event.process_ppid,
                    name=event.process_name,
                    command_line=event.process_command_line,
                    events=[],
                )
            graph.nodes[process_node]["events"].append(event.id)

        if event.user and process_node:
            user_node = f"user:{event.user}"
            if not graph.has_node(user_node):
                graph.add_node(user_node, type=NODE_USER, name=event.user, events=[])
            graph.nodes[user_node]["events"].append(event.id)
            if not graph.has_edge(user_node, process_node):
                graph.add_edge(user_node, process_node, relation="runs")

        if event.file_path and process_node:
            file_node = f"file:{event.file_path}"
            if not graph.has_node(file_node):
                graph.add_node(file_node, type=NODE_FILE, path=event.file_path, events=[])
            graph.nodes[file_node]["events"].append(event.id)
            if not graph.has_edge(process_node, file_node):
                graph.add_edge(process_node, file_node, relation="creates")

        if event.network_destination_ip and process_node:
            net_node = f"net:{event.network_destination_ip}:{event.network_destination_port}"
            if not graph.has_node(net_node):
                graph.add_node(
                    net_node,
                    type=NODE_NETWORK,
                    destination_ip=event.network_destination_ip,
                    destination_port=event.network_destination_port,
                    events=[],
                )
            graph.nodes[net_node]["events"].append(event.id)
            if not graph.has_edge(process_node, net_node):
                graph.add_edge(process_node, net_node, relation="connects_to")

    _add_parent_child_edges(graph, cluster)
    return graph


def _add_parent_child_edges(graph: nx.DiGraph, cluster: list[EventRecord]) -> None:
    """Add parent -> child process edges based on PID/PPID relationships."""
    pid_to_node: dict[int, str] = {
        event.process_pid: f"proc:{event.process_pid}:{event.process_name}"
        for event in cluster
        if event.process_pid is not None and event.process_name is not None
    }
    for event in cluster:
        if event.process_ppid and event.process_ppid in pid_to_node:
            parent_node = pid_to_node[event.process_ppid]
            child_node = f"proc:{event.process_pid}:{event.process_name}"
            if (
                graph.has_node(parent_node)
                and graph.has_node(child_node)
                and not graph.has_edge(parent_node, child_node)
            ):
                graph.add_edge(parent_node, child_node, relation="spawns")
