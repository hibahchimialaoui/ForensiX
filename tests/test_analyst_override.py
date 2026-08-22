"""Tests for analyst override capability (M6-01)."""

import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.models.db import DetectionRecord, EventRecord, HostContext, RiskAssessmentRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events
from forensix.risk.criticality import set_host_criticality
from forensix.risk.override import apply_analyst_override
from forensix.risk.pipeline import assess_detection_risk

TEST_HOST = "M601-TEST"


@pytest.fixture
def risk_assessment(db_session=None):
    session = SessionLocal()
    event = NormalizedEvent(
        id="m601-test-1",
        timestamp="2026-08-19T10:00:00",
        host=TEST_HOST,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )
    bulk_insert_events(session, [event])
    set_host_criticality(session, TEST_HOST, "low")
    results, _ = run_and_persist_detections(session)
    detection = (
        session.query(DetectionRecord).filter(DetectionRecord.event_id == "m601-test-1").first()
    )
    matching = next(r for r in results if r.rule_id == detection.rule_id)
    risk = assess_detection_risk(session, detection, matching.where_clause)

    yield session, risk

    session.query(RiskAssessmentRecord).filter(
        RiskAssessmentRecord.detection_id == detection.id
    ).delete(synchronize_session=False)
    session.query(DetectionRecord).filter(DetectionRecord.event_id == "m601-test-1").delete(
        synchronize_session=False
    )
    session.query(EventRecord).filter(EventRecord.host == TEST_HOST).delete()
    session.query(HostContext).filter(HostContext.host == TEST_HOST).delete()
    session.commit()
    session.close()


def test_override_without_reason_is_rejected(risk_assessment):
    session, risk = risk_assessment
    with pytest.raises(ValueError, match="mandatory"):
        apply_analyst_override(session, risk, "medium", "P3", "")


def test_override_with_invalid_category_is_rejected(risk_assessment):
    session, risk = risk_assessment
    with pytest.raises(ValueError, match="Invalid override_risk_category"):
        apply_analyst_override(session, risk, "super-dangereux", "P1", "test")


def test_override_with_invalid_priority_is_rejected(risk_assessment):
    session, risk = risk_assessment
    with pytest.raises(ValueError, match="Invalid override_priority"):
        apply_analyst_override(session, risk, "medium", "P0", "test")


def test_valid_override_updates_override_fields(risk_assessment):
    session, risk = risk_assessment
    apply_analyst_override(session, risk, "medium", "P3", "Known false positive on this host")

    assert risk.override_risk_category == "medium"
    assert risk.override_priority == "P3"
    assert risk.override_reason == "Known false positive on this host"


def test_valid_override_never_modifies_original_m5_fields(risk_assessment):
    session, risk = risk_assessment
    original_score = risk.risk_score
    original_category = risk.risk_category
    original_priority = risk.priority

    apply_analyst_override(session, risk, "critical", "P1", "Escalating for review")

    assert risk.risk_score == original_score
    assert risk.risk_category == original_category
    assert risk.priority == original_priority


def test_override_persists_across_session_reload(risk_assessment):
    session, risk = risk_assessment
    apply_analyst_override(session, risk, "high", "P2", "Reviewed and confirmed")

    session.expire_all()
    reloaded = (
        session.query(RiskAssessmentRecord).filter(RiskAssessmentRecord.id == risk.id).first()
    )
    assert reloaded.override_risk_category == "high"
    assert reloaded.override_priority == "P2"
