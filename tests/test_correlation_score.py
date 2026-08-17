"""Tests for the correlation score (M3-01), per docs/correlation_score.md."""

from datetime import datetime

from forensix.correlation.score import are_correlated, correlation_score
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


def test_same_host_and_instant_scores_055_and_is_correlated():
    a = make_event(id="a", host="H1")
    b = make_event(id="b", host="H1")
    assert abs(correlation_score(a, b) - 0.55) < 0.001
    assert are_correlated(a, b) is True


def test_different_hosts_scores_025_and_is_not_correlated():
    a = make_event(id="a", host="H1")
    b = make_event(id="b", host="H2")
    assert abs(correlation_score(a, b) - 0.25) < 0.001
    assert are_correlated(a, b) is False


def test_events_outside_temporal_window_score_030_and_are_not_correlated():
    a = make_event(id="a", timestamp=datetime(2026, 8, 17, 10, 0, 0), host="H1")
    b = make_event(id="b", timestamp=datetime(2026, 8, 17, 10, 20, 0), host="H1")
    assert abs(correlation_score(a, b) - 0.30) < 0.001
    assert are_correlated(a, b) is False


def test_pid_ppid_relation_adds_020_to_the_score():
    a = make_event(id="a", host="H1", process_pid=100)
    b = make_event(id="b", host="H1", process_ppid=100)
    assert abs(correlation_score(a, b) - 0.75) < 0.001
    assert are_correlated(a, b) is True


def test_same_user_adds_015_to_the_score():
    a = make_event(id="a", host="H2", user="alice")
    b = make_event(id="b", host="H3", user="alice")
    # different hosts (0.0) + same instant (0.25) + same user (0.15) = 0.40
    assert abs(correlation_score(a, b) - 0.40) < 0.001


def test_shared_file_path_adds_010_to_the_score():
    a = make_event(id="a", host="H2", file_path="C:\\Temp\\payload.exe")
    b = make_event(id="b", host="H3", file_path="C:\\Temp\\payload.exe")
    # different hosts (0.0) + same instant (0.25) + shared file (0.10) = 0.35
    assert abs(correlation_score(a, b) - 0.35) < 0.001


def test_empty_user_on_both_sides_does_not_count_as_a_match():
    a = make_event(id="a", host="H2", user=None)
    b = make_event(id="b", host="H3", user=None)
    # different hosts (0.0) + same instant (0.25), no user credit
    assert abs(correlation_score(a, b) - 0.25) < 0.001
