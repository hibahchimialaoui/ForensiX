"""Tests for audit log consultation and integrity verification (M7-02)."""

import pytest

from forensix.audit.log import (
    append_audit_entry,
    get_audit_entries_for_entity,
    verify_chain_integrity,
)
from forensix.db import SessionLocal
from forensix.models.db import AuditLogEntry

TEST_ENTITY_PREFIX = "m702-test-"


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(AuditLogEntry).filter(
        AuditLogEntry.entity_id.like(f"{TEST_ENTITY_PREFIX}%")
    ).delete(synchronize_session=False)
    session.commit()
    session.close()


def test_get_audit_entries_for_entity_returns_only_matching_entries(db_session):
    append_audit_entry(db_session, "event", f"{TEST_ENTITY_PREFIX}1", "insert", {"a": 1})
    append_audit_entry(db_session, "detection", f"{TEST_ENTITY_PREFIX}1", "insert", {"b": 2})
    append_audit_entry(db_session, "event", f"{TEST_ENTITY_PREFIX}2", "insert", {"c": 3})

    entries = get_audit_entries_for_entity(db_session, f"{TEST_ENTITY_PREFIX}1")
    assert len(entries) == 2
    assert all(e.entity_id == f"{TEST_ENTITY_PREFIX}1" for e in entries)


def test_get_audit_entries_returns_entries_in_chronological_order(db_session):
    e1 = append_audit_entry(db_session, "event", f"{TEST_ENTITY_PREFIX}3", "insert", {})
    e2 = append_audit_entry(db_session, "event", f"{TEST_ENTITY_PREFIX}3", "update", {})

    entries = get_audit_entries_for_entity(db_session, f"{TEST_ENTITY_PREFIX}3")
    assert entries[0].sequence_number == e1.sequence_number
    assert entries[1].sequence_number == e2.sequence_number


def test_verify_chain_integrity_returns_true_for_intact_chain(db_session):
    append_audit_entry(db_session, "event", f"{TEST_ENTITY_PREFIX}4", "insert", {})
    append_audit_entry(db_session, "event", f"{TEST_ENTITY_PREFIX}5", "insert", {})

    is_valid, broken_at = verify_chain_integrity(db_session)
    assert is_valid is True
    assert broken_at is None


def test_verify_chain_integrity_detects_tampering_at_the_exact_entry(db_session):
    entry = append_audit_entry(db_session, "event", f"{TEST_ENTITY_PREFIX}6", "insert", {"x": 1})
    append_audit_entry(db_session, "event", f"{TEST_ENTITY_PREFIX}7", "insert", {"y": 2})

    db_session.query(AuditLogEntry).filter(AuditLogEntry.id == entry.id).update(
        {"data_snapshot": {"x": "tampered"}}
    )
    db_session.commit()

    is_valid, broken_at = verify_chain_integrity(db_session)
    assert is_valid is False
    assert broken_at == entry.sequence_number
