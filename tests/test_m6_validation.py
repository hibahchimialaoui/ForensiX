"""End-to-end tests for the analyst review workflow (M6-05): the 2 required scenarios."""

import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.models.db import DetectionRecord, EventRecord, HostContext, RiskAssessmentRecord
from forensix.reporting.export import export_report_to_markdown
from forensix.reporting.report import generate_investigation_report
from forensix.reporting.validation import (
    HOST_SCENARIO_1,
    HOST_SCENARIO_2,
    build_scenario_1_event,
    build_scenario_2_event,
)
from forensix.repository import bulk_insert_events
from forensix.risk.criticality import set_host_criticality
from forensix.risk.override import apply_analyst_override
from forensix.risk.pipeline import assess_detection_risk


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    for host in (HOST_SCENARIO_1, HOST_SCENARIO_2):
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


def _run_full_workflow(session, event, host):
    bulk_insert_events(session, [event])
    set_host_criticality(session, host, "medium")
    results, _ = run_and_persist_detections(session)
    detection = (
        session.query(DetectionRecord).filter(DetectionRecord.event_id == event.id).first()
    )
    matching = next(r for r in results if r.rule_id == detection.rule_id)
    risk = assess_detection_risk(session, detection, matching.where_clause)
    records = session.query(EventRecord).filter(EventRecord.id == event.id).all()
    return detection, risk, records


def test_scenario_1_approval_final_decision_equals_original(db_session):
    event = build_scenario_1_event()
    _, risk, records = _run_full_workflow(db_session, event, HOST_SCENARIO_1)

    apply_analyst_override(
        db_session, risk, risk.risk_category, risk.priority, "Approved as-is by analyst"
    )
    report = generate_investigation_report(db_session, records)
    markdown = export_report_to_markdown(report)

    assert risk.override_risk_category == risk.risk_category
    assert risk.override_priority == risk.priority
    assert "Approved as-is by analyst" in markdown


def test_scenario_2_correction_preserves_original_and_shows_both(db_session):
    event = build_scenario_2_event()
    _, risk, records = _run_full_workflow(db_session, event, HOST_SCENARIO_2)

    original_category = risk.risk_category
    original_priority = risk.priority

    apply_analyst_override(
        db_session, risk, "low", "P4", "Confirmed authorized administrative activity"
    )
    report = generate_investigation_report(db_session, records)
    markdown = export_report_to_markdown(report)

    assert risk.risk_category == original_category
    assert risk.priority == original_priority
    assert risk.override_risk_category == "low"
    assert risk.override_priority == "P4"
    assert original_category in markdown
    assert "low" in markdown
    assert "Confirmed authorized administrative activity" in markdown
