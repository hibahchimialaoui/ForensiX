"""Tamper-evident, hash-chained audit log (M7-01).

Covers event insertion, detection insertion, risk_assessments (including
override_* columns filled by M6-01), and override actions themselves - a
direct modification to risk_assessments in the database (bypassing
apply_analyst_override) must be just as detectable as an override action.

Tamper-evident, not tamper-proof: altering a past entry breaks the hash
chain for every entry after it, detectable at verification (M7-02) - but
this does not physically prevent an attacker who controls the database
from rewriting the whole chain, since the chain head lives in the same
database it protects.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from forensix.models.db import AuditLogEntry

GENESIS_HASH = "0" * 64


def _compute_entry_hash(
    sequence_number: int, entity_type: str, entity_id: str, action: str,
    data_snapshot: dict, previous_hash: str,
) -> str:
    """Compute SHA-256 over the entry's data plus the previous entry's hash."""
    payload = json.dumps(
        {
            "sequence_number": sequence_number,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "action": action,
            "data_snapshot": data_snapshot,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit_entry(
    session: Session, entity_type: str, entity_id: str, action: str, data_snapshot: dict
) -> AuditLogEntry:
    """Append a new hash-chained entry to the audit log."""
    last_entry = (
        session.query(AuditLogEntry)
        .order_by(AuditLogEntry.sequence_number.desc())
        .first()
    )
    sequence_number = (last_entry.sequence_number + 1) if last_entry else 0
    previous_hash = last_entry.entry_hash if last_entry else GENESIS_HASH

    entry_hash = _compute_entry_hash(
        sequence_number, entity_type, entity_id, action, data_snapshot, previous_hash
    )

    entry = AuditLogEntry(
        id=str(uuid.uuid4()),
        sequence_number=sequence_number,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        data_snapshot=data_snapshot,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        created_at=datetime.now(UTC),
    )
    session.add(entry)
    session.commit()
    return entry


def audit_log_count(session: Session) -> int:
    """Return the total number of entries in the audit log."""
    return session.query(func.count(AuditLogEntry.id)).scalar() or 0

def get_audit_entries_for_entity(session: Session, entity_id: str) -> list[AuditLogEntry]:
    """Return all audit entries related to a given entity, ordered chronologically."""
    return (
        session.query(AuditLogEntry)
        .filter(AuditLogEntry.entity_id == entity_id)
        .order_by(AuditLogEntry.sequence_number)
        .all()
    )


def verify_chain_integrity(session: Session) -> tuple[bool, int | None]:
    """Walk the entire audit log and recompute each entry's hash.

    Returns (True, None) if the chain is intact, or (False, sequence_number)
    identifying the first entry where the stored hash no longer matches the
    recomputed hash - detectable evidence of tampering, per M7-01's
    tamper-evident (not tamper-proof) guarantee.
    """
    entries = session.query(AuditLogEntry).order_by(AuditLogEntry.sequence_number).all()

    expected_previous_hash = GENESIS_HASH
    for entry in entries:
        if entry.previous_hash != expected_previous_hash:
            return False, entry.sequence_number

        recomputed = _compute_entry_hash(
            entry.sequence_number,
            entry.entity_type,
            entry.entity_id,
            entry.action,
            entry.data_snapshot,
            entry.previous_hash,
        )
        if recomputed != entry.entry_hash:
            return False, entry.sequence_number

        expected_previous_hash = entry.entry_hash

    return True, None
