"""Confidence scoring, per the formula documented in docs/confidence_model.md.

Confidence is an evidence-based analytical score, not a calibrated
probability of correctness (see docs/confidence_model.md for the full
caveat). Weights are fixed by that specification, written before this
implementation.
"""

from itertools import combinations

from forensix.correlation.score import correlation_score
from forensix.models.db import EventRecord

WEIGHT_RULE_SPECIFICITY = 0.40
WEIGHT_CLUSTER_SIZE = 0.35
WEIGHT_CORRELATION_STRENGTH = 0.25

_SPECIFICITY_CAP = 5
_CLUSTER_SIZE_CAP = 5


def rule_specificity(where_clause: str) -> float:
    """Approximate a Sigma rule's specificity from its compiled SQL clause.

    A rule combining more AND conditions is less likely to match by
    coincidence. Capped at 5 conditions (1 AND = 2 conditions).
    """
    condition_count = where_clause.count(" AND ") + 1
    return min(condition_count / _SPECIFICITY_CAP, 1.0)


def cluster_size_factor(cluster_size: int) -> float:
    """Normalize cluster size, capped at 5 events."""
    return min(cluster_size / _CLUSTER_SIZE_CAP, 1.0)


def correlation_strength(cluster: list[EventRecord]) -> float:
    """Average pairwise correlation score (M3-01) within a cluster.

    A cluster of size 1 has no pair to measure, so this factor is 0.0 by
    convention (documented in docs/confidence_model.md).
    """
    if len(cluster) < 2:
        return 0.0
    scores = [correlation_score(a, b) for a, b in combinations(cluster, 2)]
    return sum(scores) / len(scores)


def compute_confidence(where_clause: str, cluster: list[EventRecord]) -> float:
    """Compute the confidence score (0.0 to 1.0) for a detection's cluster."""
    return (
        WEIGHT_RULE_SPECIFICITY * rule_specificity(where_clause)
        + WEIGHT_CLUSTER_SIZE * cluster_size_factor(len(cluster))
        + WEIGHT_CORRELATION_STRENGTH * correlation_strength(cluster)
    )
