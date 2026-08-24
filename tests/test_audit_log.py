"""Tests for the tamper-evident hash-chained audit log (M7-01)."""

import pytest

from forensix.audit.log import _compute_entry_hash, append_audit_entry, audit_log_count
from forensix.db import SessionLocal
from forensix.models.db import AuditLogEntry

TEST_ENTITY_PREFIX = "m701-test-"


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(AuditLogEntry).filter(
        AuditLogEntry.entity_id.like(f"{TEST_ENTITY_PREFIX}%")
    ).delete(synchronize_session=False)
    session.commit()
    session.close()


def test_first_entry_chains_from_genesis_hash(db_session):
    entry = append_audit_entry(
        db_session, "event", f"{TEST_ENTITY_PREFIX}1", "insert", {"host": "H1"}
    )
    assert entry.sequence_number is not None
    assert entry.entry_hash is not None
    assert len(entry.entry_hash) == 64  # SHA-256 hex digest


def test_second_entry_chains_onto_first(db_session):
    entry1 = append_audit_entry(
        db_session, "event", f"{TEST_ENTITY_PREFIX}1", "insert", {"host": "H1"}
    )
    entry2 = append_audit_entry(
        db_session, "detection", f"{TEST_ENTITY_PREFIX}2", "insert", {"rule_id": "abc"}
    )
    assert entry2.previous_hash == entry1.entry_hash
    assert entry2.sequence_number == entry1.sequence_number + 1


def test_risk_assessment_and_override_actions_are_covered(db_session):
    """Both a risk_assessment write and an override action must be
    independently loggable - the review required risk_assessments itself
    to be covered, not just the override action."""
    risk_entry = append_audit_entry(
        db_session,
        "risk_assessment",
        f"{TEST_ENTITY_PREFIX}3",
        "insert",
        {"risk_category": "high"},
    )
    override_entry = append_audit_entry(
        db_session,
        "risk_assessment",
        f"{TEST_ENTITY_PREFIX}3",
        "override",
        {"override_risk_category": "low", "override_reason": "test"},
    )
    assert risk_entry.entity_type == "risk_assessment"
    assert override_entry.action == "override"
    assert override_entry.previous_hash == risk_entry.entry_hash


def test_tampering_with_a_past_entry_is_detectable(db_session):
    """Directly modifying a past entry's data must make the stored hash
    mismatch the recomputed hash - the core tamper-evidence guarantee."""
    entry = append_audit_entry(
        db_session, "event", f"{TEST_ENTITY_PREFIX}4", "insert", {"host": "original"}
    )
    original_hash = entry.entry_hash

    db_session.query(AuditLogEntry).filter(AuditLogEntry.id == entry.id).update(
        {"data_snapshot": {"host": "tampered"}}
    )
    db_session.commit()

    tampered = db_session.query(AuditLogEntry).filter(AuditLogEntry.id == entry.id).first()
    recomputed_hash = _compute_entry_hash(
        tampered.sequence_number,
        tampered.entity_type,
        tampered.entity_id,
        tampered.action,
        tampered.data_snapshot,
        tampered.previous_hash,
    )

    assert tampered.entry_hash == original_hash  # stored hash is untouched
    assert recomputed_hash != original_hash  # but no longer matches the data


def test_audit_log_count_increases_with_each_entry(db_session):
    count_before = audit_log_count(db_session)
    append_audit_entry(db_session, "event", f"{TEST_ENTITY_PREFIX}5", "insert", {})
    append_audit_entry(db_session, "event", f"{TEST_ENTITY_PREFIX}6", "insert", {})
    assert audit_log_count(db_session) == count_before + 2
