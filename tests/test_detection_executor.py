"""Integration tests for the Sigma rule execution pipeline (requires PostgreSQL)."""

import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import execute_rule, load_rule_files, run_all_rules
from forensix.models.db import EventRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(EventRecord).filter(EventRecord.host == "M2-03-TEST").delete()
    session.commit()
    session.close()


def test_load_rule_files_returns_the_seven_curated_rules():
    rule_files = load_rule_files()
    assert len(rule_files) == 7


def test_execute_rule_detects_a_matching_event(db_session):
    """A process creation event in a suspicious folder must be detected by
    the corresponding curated rule (proc_creation_win_susp_execution_path)."""
    event = NormalizedEvent(
        id="m203-detect-1",
        timestamp="2026-08-16T10:00:00",
        host="M2-03-TEST",
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )
    bulk_insert_events(db_session, [event])

    rule_path = next(f for f in load_rule_files() if "susp_execution_path" in f.name)
    rule_yaml = rule_path.read_text(encoding="utf-8")

    _, matched_ids = execute_rule(db_session, rule_yaml)
    assert "m203-detect-1" in matched_ids


def test_execute_rule_does_not_match_benign_event(db_session):
    """A normal process creation event must not trigger the suspicious path rule."""
    event = NormalizedEvent(
        id="m203-benign-1",
        timestamp="2026-08-16T10:00:00",
        host="M2-03-TEST",
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Program Files\\legit_app.exe"),
    )
    bulk_insert_events(db_session, [event])

    rule_path = next(f for f in load_rule_files() if "susp_execution_path" in f.name)
    rule_yaml = rule_path.read_text(encoding="utf-8")

    _, matched_ids = execute_rule(db_session, rule_yaml)
    assert "m203-benign-1" not in matched_ids


def test_run_all_rules_isolates_failing_rules_from_the_batch(db_session):
    """A rule referencing an unmapped field (e.g. OriginalFileName) must fail
    in isolation, without preventing the other rules in the same batch from
    running - this is the rollback() behavior added in task 4."""
    event = NormalizedEvent(
        id="m203-batch-1",
        timestamp="2026-08-16T10:00:00",
        host="M2-03-TEST",
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )
    bulk_insert_events(db_session, [event])

    results = run_all_rules(db_session)
    assert len(results) == 7

    errored = [r for r in results if r.error is not None]
    succeeded = [r for r in results if r.error is None]
    assert len(errored) == 3, (
        "3 curated rules are expected to fail (documented in docs/sigma_rules.md)"
    )
    assert len(succeeded) == 4

    matched_rule = next(r for r in succeeded if "susp_execution_path" in r.rule_file)
    assert "m203-batch-1" in matched_rule.matched_event_ids

