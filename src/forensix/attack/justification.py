"""Justification chain: ATT&CK technique -> Sigma rule -> detection -> event -> raw evidence.

Core of ForensiX's evidence-driven philosophy: no conclusion (e.g. "this is
an attack") is ever asserted here. Only the chain of facts is exposed; the
analyst decides. This module reads-only from PostgreSQL (source of truth),
consistent with the pattern established in M3-04.
"""

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from forensix.attack.mapping import extract_attack_techniques
from forensix.detection.executor import RULES_DIR
from forensix.models.db import DetectionRecord, EventRecord


@dataclass
class JustificationEntry:
    """One traceable chain: technique(s) -> rule -> detection -> event -> raw evidence."""

    techniques: list[str]
    rule_id: str
    detection_id: str
    event: EventRecord
    raw_evidence: dict | None


def _rule_file_for_rule_id(rule_id: str) -> Path | None:
    """Find the curated rule file matching a given Sigma rule id."""
    from forensix.detection.executor import get_rule_metadata

    for rule_file in sorted(RULES_DIR.glob("*.yml")):
        candidate_id, _ = get_rule_metadata(rule_file.read_text(encoding="utf-8"))
        if candidate_id == rule_id:
            return rule_file
    return None


def build_justification_chain(
    session: Session, event_ids: list[str]
) -> list[JustificationEntry]:
    """Build the full justification chain for every detection tied to the given events.

    Events with no associated detection produce no entry - this function
    never fabricates a technique or a conclusion for evidence that has none.
    """
    detections = (
        session.query(DetectionRecord)
        .filter(DetectionRecord.event_id.in_(event_ids))
        .all()
    )

    entries = []
    for detection in detections:
        event = (
            session.query(EventRecord)
            .filter(EventRecord.id == detection.event_id)
            .first()
        )
        if event is None:
            continue

        rule_file = _rule_file_for_rule_id(detection.rule_id)
        techniques = (
            extract_attack_techniques(rule_file.read_text(encoding="utf-8"))
            if rule_file is not None
            else []
        )

        entries.append(
            JustificationEntry(
                techniques=techniques,
                rule_id=detection.rule_id,
                detection_id=detection.id,
                event=event,
                raw_evidence=event.raw_event,
            )
        )
    return entries
