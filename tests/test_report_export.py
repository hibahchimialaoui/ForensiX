"""Tests for report export (M6-04): Markdown (mandatory) and PDF (bonus)."""


import pytest

from forensix.db import SessionLocal
from forensix.detection.executor import run_and_persist_detections
from forensix.models.db import DetectionRecord, EventRecord, HostContext, RiskAssessmentRecord
from forensix.models.event import NormalizedEvent, ProcessInfo
from forensix.reporting.export import export_report_to_markdown, export_report_to_pdf
from forensix.reporting.report import generate_investigation_report
from forensix.repository import bulk_insert_events
from forensix.risk.criticality import set_host_criticality
from forensix.risk.override import apply_analyst_override
from forensix.risk.pipeline import assess_detection_risk

TEST_HOST = "M604-TEST"


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


def _seed_report(session, event_id="m604-test-1"):
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
    set_host_criticality(session, TEST_HOST, "low")
    results, _ = run_and_persist_detections(session)
    detection = (
        session.query(DetectionRecord).filter(DetectionRecord.event_id == event_id).first()
    )
    matching = next(r for r in results if r.rule_id == detection.rule_id)
    risk = assess_detection_risk(session, detection, matching.where_clause)
    records = session.query(EventRecord).filter(EventRecord.id == event_id).all()
    return generate_investigation_report(session, records), risk


def test_markdown_export_contains_all_sections(db_session):
    report, _ = _seed_report(db_session)
    markdown = export_report_to_markdown(report)

    assert "# ForensiX Investigation Report" in markdown
    assert "## Timeline" in markdown
    assert "## ATT&CK Mapping and Justification Chain" in markdown
    assert "## Risk Assessments" in markdown
    assert "T1036" in markdown


def test_markdown_export_shows_pending_review_before_override(db_session):
    report, _ = _seed_report(db_session)
    markdown = export_report_to_markdown(report)
    assert "pending review" in markdown


def test_markdown_export_shows_both_original_and_override_after_decision(db_session):
    report, risk = _seed_report(db_session)
    apply_analyst_override(db_session, risk, "medium", "P3", "Confirmed benign")

    updated_report = generate_investigation_report(
        db_session, db_session.query(EventRecord).filter(EventRecord.host == TEST_HOST).all()
    )
    markdown = export_report_to_markdown(updated_report)

    assert "ForensiX initial assessment" in markdown
    assert risk.risk_category in markdown
    assert "Confirmed benign" in markdown
    assert "medium" in markdown


def test_pdf_export_creates_a_non_empty_file(db_session, tmp_path):
    report, _ = _seed_report(db_session)
    output_path = tmp_path / "report.pdf"

    export_report_to_pdf(report, str(output_path))

    assert output_path.exists()
    assert output_path.stat().st_size > 0
