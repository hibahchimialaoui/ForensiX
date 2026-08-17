"""Event clustering via Union-Find, per docs/clustering_approach.md.

Guarantees transitive, deterministic grouping: if A~B and B~C, then A, B, C
end up in the same cluster regardless of pair processing order.
"""

from itertools import combinations

from forensix.correlation.score import are_correlated
from forensix.models.db import EventRecord


class _UnionFind:
    """Minimal disjoint-set structure with path compression and union by rank."""

    def __init__(self, ids: list[str]) -> None:
        self._parent = {i: i for i in ids}
        self._rank = dict.fromkeys(ids, 0)

    def find(self, i: str) -> str:
        if self._parent[i] != i:
            self._parent[i] = self.find(self._parent[i])
        return self._parent[i]

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a == root_b:
            return
        if self._rank[root_a] < self._rank[root_b]:
            root_a, root_b = root_b, root_a
        self._parent[root_b] = root_a
        if self._rank[root_a] == self._rank[root_b]:
            self._rank[root_a] += 1


def cluster_events(events: list[EventRecord]) -> list[list[EventRecord]]:
    """Group events into incident clusters using the M3-01 correlation score.

    Only pairs sharing the same host are compared (the score already assigns
    0.0 to the host factor otherwise, so comparing cross-host pairs would be
    wasted work). Returns a list of clusters, each a list of EventRecord,
    sorted by cluster size (largest first) for readability; the number and
    membership of clusters is deterministic for a given input.
    """
    if not events:
        return []

    uf = _UnionFind([e.id for e in events])
    by_host: dict[str, list[EventRecord]] = {}
    for event in events:
        by_host.setdefault(event.host, []).append(event)

    for host_events in by_host.values():
        for a, b in combinations(host_events, 2):
            if are_correlated(a, b):
                uf.union(a.id, b.id)

    groups: dict[str, list[EventRecord]] = {}
    for event in events:
        root = uf.find(event.id)
        groups.setdefault(root, []).append(event)

    clusters = list(groups.values())
    clusters.sort(key=len, reverse=True)
    return clusters
