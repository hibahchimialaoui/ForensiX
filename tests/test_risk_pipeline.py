"""End-to-end tests for the risk pipeline (M5-05): scenarios A, B, C."""

import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.models.db import DetectionRecord, EventRecord, HostContext, RiskAssessmentRecord
from forensix.repository import bulk_insert_events
from forensix.risk.criticality import set_host_criticality
from forensix.risk.pipeline import assess_detection_risk
from forensix.risk.validation import (
    HOST_A,
    HOST_B,
    HOST_C,
    build_scenario_a_event,
    build_scenario_b_event,
    build_scenario_c_event,
)


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    for host in (HOST_A, HOST_B, HOST_C):
        detection_ids = [
            d.id
            for d in session.query(DetectionRecord)
            .join(EventRecord, DetectionRecord.event_id == EventRecord.id)
            .filter(EventRecord.host == host)
            .all()
        ]
        session.query(RiskAssessmentRecord).filter(
            RiskAssessmentRecord.detection_id.in_(detection_ids)
        ).delete(synchronize_session=False)
        session.query(DetectionRecord).filter(
            DetectionRecord.id.in_(detection_ids)
        ).delete(synchronize_session=False)
        session.query(EventRecord).filter(EventRecord.host == host).delete()
        session.query(HostContext).filter(HostContext.host == host).delete()
    session.commit()
    session.close()


def _run_scenario(session, event, host, criticality):
    bulk_insert_events(session, [event])
    set_host_criticality(session, host, criticality)
    results, _ = run_and_persist_detections(session)
    detection = (
        session.query(DetectionRecord).filter(DetectionRecord.event_id == event.id).first()
    )
    matching = next(r for r in results if r.rule_id == detection.rule_id)
    return assess_detection_risk(session, detection, matching.where_clause)


def test_scenario_b_outranks_scenario_a_due_to_criticality_alone(db_session):
    """Same rule/severity/confidence for A and B - only host criticality differs.
    B must have a higher risk_score and outrank A in priority."""
    risk_a = _run_scenario(db_session, build_scenario_a_event(), HOST_A, "low")
    risk_b = _run_scenario(db_session, build_scenario_b_event(), HOST_B, "critical")

    assert risk_a.severity == risk_b.severity
    assert abs(risk_a.confidence - risk_b.confidence) < 0.001
    assert risk_b.risk_score > risk_a.risk_score
    assert risk_b.priority < risk_a.priority or risk_b.risk_category != risk_a.risk_category


def test_scenario_c_reflects_lower_confidence_than_a_and_b(db_session):
    """Scenario C (isolated event, no cluster) must have lower confidence than
    A and B, reflecting genuine analytical uncertainty."""
    risk_a = _run_scenario(db_session, build_scenario_a_event(), HOST_A, "low")
    risk_c = _run_scenario(db_session, build_scenario_c_event(), HOST_C, "critical")

    assert risk_c.confidence < risk_a.confidence


def test_override_fields_remain_unset_in_m5(db_session):
    """M5 never writes to the M6-reserved override columns."""
    risk = _run_scenario(db_session, build_scenario_a_event(), HOST_A, "low")
    assert risk.override_risk_category is None
    assert risk.override_priority is None
    assert risk.override_reason is None
