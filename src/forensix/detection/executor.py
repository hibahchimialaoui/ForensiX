"""Batch execution of curated Sigma rules (M2-02) against the ForensiX Event Store.

Deterministic only: no ML/AI detection at this stage (per M2-03 scope, validated
in the milestone description). Chain: Event Store -> Load rules -> Sigma
transformation -> Detection execution -> Matching events -> Detection objects.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

from sigma.collection import SigmaCollection
from sqlalchemy import text
from sqlalchemy.orm import Session

from forensix.detection.backend import compile_rule_to_where_clause
from forensix.models.db import EventRecord

RULES_DIR = Path(__file__).resolve().parents[3] / "rules" / "sigma"

# EventRecord.event_id is a String column (M1-06), but Sigma rules express
# EventID as a number, producing an unquoted numeric literal that PostgreSQL
# rejects against a text column (limitation documented in
# docs/detection_backend.md, section 1). This regex finds bare numeric
# comparisons against event_id specifically and quotes them as strings
# before execution, without touching other numeric columns.
_EVENT_ID_NUMERIC = re.compile(r'("event_id"\s*=\s*)(\d+)(?!\d*\')')


@dataclass
class RuleMatch:
    """Result of running one curated rule against the current Event Store content."""

    rule_file: str
    rule_id: str = ""
    severity: str = "unknown"
    where_clause: str = ""
    matched_event_ids: list[str] = field(default_factory=list)
    error: str | None = None


def load_rule_files() -> list[Path]:
    """Return the curated Sigma rule files selected in M2-02."""
    return sorted(RULES_DIR.glob("*.yml"))


def get_rule_metadata(rule_yaml: str) -> tuple[str, str]:
    """Extract the Sigma rule id and severity level (e.g. 'high') from rule YAML.

    Parsed separately from compile_rule_to_where_clause because pySigma's
    conversion step consumes the rule without exposing id/level on the result.
    """
    rule_collection = SigmaCollection.from_yaml(rule_yaml)
    rule = rule_collection.rules[0]
    rule_id = str(rule.id) if rule.id else "unknown"
    severity = rule.level.name.lower() if rule.level else "unknown"
    return rule_id, severity


def quote_event_id_literals(where_clause: str) -> str:
    """Work around the event_id String/Integer type mismatch (M2-01 limitation)."""
    return _EVENT_ID_NUMERIC.sub(lambda m: f"{m.group(1)}'{m.group(2)}'", where_clause)


def execute_rule(session: Session, rule_yaml: str) -> tuple[str, list[str]]:
    """Compile and execute a single Sigma rule against the Event Store.

    Returns the executed WHERE-clause fragment and the list of matched event ids.
    On failure (e.g. unmapped field -> undefined column), rolls back the
    session so a broken rule does not poison subsequent queries in the same
    batch, and re-raises for the caller to handle.
    """
    where_clause = compile_rule_to_where_clause(rule_yaml)
    where_clause = quote_event_id_literals(where_clause)
    try:
        rows = session.query(EventRecord).filter(text(where_clause)).all()
    except Exception:
        session.rollback()
        raise
    return where_clause, [row.id for row in rows]


def run_all_rules(session: Session) -> list[RuleMatch]:
    """Execute every curated rule (M2-02) against the current Event Store content.

    A rule that fails (e.g. references an unmapped field) does not abort the
    batch: its error is captured in RuleMatch.error, and execution continues
    with the next rule.
    """
    results = []
    for rule_file in load_rule_files():
        rule_yaml = rule_file.read_text(encoding="utf-8")
        rule_id, severity = get_rule_metadata(rule_yaml)
        try:
            where_clause, matched_ids = execute_rule(session, rule_yaml)
            results.append(
                RuleMatch(rule_file.name, rule_id, severity, where_clause, matched_ids)
            )
        except Exception as e:
            results.append(
                RuleMatch(rule_file.name, rule_id, severity, error=f"{type(e).__name__}: {e}")
            )
    return results
