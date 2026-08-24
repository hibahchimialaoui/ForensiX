"""Tests for the investigation report generator (M6-03)."""

import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.models.db import DetectionRecord, EventRecord, HostContext, RiskAssessmentRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.reporting.report import generate_investigation_report
from forensix.repository import bulk_insert_events
from forensix.risk.criticality import set_host_criticality
from forensix.risk.override import apply_analyst_override
from forensix.risk.pipeline import assess_detection_risk

TEST_HOST = "M603-TEST"


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    detection_ids = [
        d.id
        for d in session.query(DetectionRecord)
        .join(EventRecord, DetectionRecord.event_id == EventRecord.id)
        .filter(EventRecord.host == TEST_HOST)
        .all()
    ]
    session.query(RiskAssessmentRecord).filter(
        RiskAssessmentRecord.detection_id.in_(detection_ids)
    ).delete(synchronize_session=False)
    session.query(DetectionRecord).filter(
        DetectionRecord.id.in_(detection_ids)
    ).delete(synchronize_session=False)
    session.query(EventRecord).filter(EventRecord.host == TEST_HOST).delete()
    session.query(HostContext).filter(HostContext.host == TEST_HOST).delete()
    session.commit()
    session.close()


def _seed_detection(session, event_id="m603-test-1"):
    event = NormalizedEvent(
        id=event_id,
        timestamp="2026-08-20T10:00:00",
        host=TEST_HOST,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )
    bulk_insert_events(session, [event])
    set_host_criticality(session, TEST_HOST, "medium")
    results, _ = run_and_persist_detections(session)
    detection = (
        session.query(DetectionRecord).filter(DetectionRecord.event_id == event_id).first()
    )
    matching = next(r for r in results if r.rule_id == detection.rule_id)
    assess_detection_risk(session, detection, matching.where_clause)
    return detection


def test_report_contains_timeline_justification_and_risk(db_session):
    detection = _seed_detection(db_session)
    records = (
        db_session.query(EventRecord).filter(EventRecord.id == detection.event_id).all()
    )

    report = generate_investigation_report(db_session, records)

    assert len(report.timeline) == 1
    assert len(report.justification_chain) == 1
    assert report.justification_chain[0].techniques == ["T1036"]
    assert len(report.risk_assessments) == 1


def test_report_reflects_approved_detection_with_no_override(db_session):
    detection = _seed_detection(db_session)
    records = (
        db_session.query(EventRecord).filter(EventRecord.id == detection.event_id).all()
    )

    report = generate_investigation_report(db_session, records)
    risk = report.risk_assessments[0]

    assert risk.override_risk_category is None
    assert risk.override_reason is None


def test_report_reflects_corrected_detection_while_preserving_original(db_session):
    detection = _seed_detection(db_session)
    records = (
        db_session.query(EventRecord).filter(EventRecord.id == detection.event_id).all()
    )

    original_report = generate_investigation_report(db_session, records)
    original_risk = original_report.risk_assessments[0]
    original_category = original_risk.risk_category
    original_priority = original_risk.priority

    apply_analyst_override(
        db_session, original_risk, "low", "P4", "Known benign test scenario"
    )

    updated_report = generate_investigation_report(db_session, records)
    updated_risk = updated_report.risk_assessments[0]

    assert updated_risk.risk_category == original_category
    assert updated_risk.priority == original_priority
    assert updated_risk.override_risk_category == "low"
    assert updated_risk.override_priority == "P4"
    assert updated_risk.override_reason == "Known benign test scenario"


def test_report_for_empty_cluster_returns_empty_report(db_session):
    report = generate_investigation_report(db_session, [])
    assert report.timeline == []
    assert report.justification_chain == []
    assert report.risk_assessments == []
