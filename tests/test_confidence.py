"""Tests for confidence scoring (M5-01), per docs/confidence_model.md."""

from datetime import datetime

from forensix.models.db import EventRecord
from forensix.risk.confidence import (
    cluster_size_factor,
    compute_confidence,
    correlation_strength,
    rule_specificity,
)


def make_event(**kwargs) -> EventRecord:
    defaults = dict(
        id="x",
        timestamp=datetime(2026, 8, 18, 10, 0, 0),
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


def test_rule_specificity_counts_and_conditions_capped_at_five():
    single_condition = '"process_name" LIKE \'%evil.exe\''
    assert abs(rule_specificity(single_condition) - 0.2) < 0.001

    two_conditions = '"process_name" LIKE \'%evil.exe\' AND "event_id" = \'1\''
    assert abs(rule_specificity(two_conditions) - 0.4) < 0.001

    many_conditions = " AND ".join([f'"c{i}" = \'{i}\'' for i in range(10)])
    assert abs(rule_specificity(many_conditions) - 1.0) < 0.001


def test_cluster_size_factor_capped_at_five():
    assert abs(cluster_size_factor(1) - 0.2) < 0.001
    assert abs(cluster_size_factor(5) - 1.0) < 0.001
    assert abs(cluster_size_factor(10) - 1.0) < 0.001


def test_correlation_strength_is_zero_for_single_event_cluster():
    assert correlation_strength([make_event(id="a")]) == 0.0


def test_correlation_strength_matches_m301_score_for_a_pair():
    a = make_event(id="a", host="H1", process_pid=100)
    b = make_event(id="b", host="H1", process_ppid=100)
    assert abs(correlation_strength([a, b]) - 0.75) < 0.001


def test_compute_confidence_combines_all_three_factors():
    where_clause = '"process_name" LIKE \'%evil.exe\' AND "event_id" = \'1\''
    a = make_event(id="a", host="H1", process_pid=100)
    b = make_event(id="b", host="H1", process_ppid=100)

    confidence = compute_confidence(where_clause, [a, b])
    expected = 0.40 * 0.4 + 0.35 * 0.4 + 0.25 * 0.75
    assert abs(confidence - expected) < 0.001
    assert 0.0 <= confidence <= 1.0
