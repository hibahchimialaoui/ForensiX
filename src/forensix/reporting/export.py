"""Report export to Markdown (M6-04, mandatory format).

PDF export, if implemented, is a secondary/bonus addition on top of this
module and must not block M6-04's closure.
"""

from forensix.reporting.report import InvestigationReport


def _format_risk_section(risk) -> str:
    lines = [
        "**ForensiX initial assessment (immutable):**",
        f"- Confidence: {risk.confidence:.3f}",
        f"- Severity: {risk.severity}",
        f"- Host criticality: {risk.host_criticality}",
        f"- Risk score: {risk.risk_score:.3f}",
        f"- Risk category: {risk.risk_category}",
        f"- Priority: {risk.priority}",
    ]
    if risk.override_risk_category is not None:
        lines += [
            "",
            "**Analyst decision:**",
            f"- Risk category: {risk.override_risk_category}",
            f"- Priority: {risk.override_priority}",
            f"- Reason: {risk.override_reason}",
        ]
    else:
        lines += ["", "**Analyst decision:** pending review"]
    return "\n".join(lines)


def export_report_to_markdown(report: InvestigationReport) -> str:
    """Render an InvestigationReport as a Markdown document."""
    sections = ["# ForensiX Investigation Report", ""]

    sections.append("## Timeline")
    sections.append("")
    if not report.timeline:
        sections.append("_No events in this cluster._")
    else:
        for entry in report.timeline:
            sections.append(
                f"- `{entry.event.timestamp}` **{entry.event.host}** "
                f"{entry.event.process_name or ''} "
                f"({len(entry.detections)} detection(s))"
            )
    sections.append("")

    sections.append("## ATT&CK Mapping and Justification Chain")
    sections.append("")
    if not report.justification_chain:
        sections.append("_No detections with mapped evidence in this cluster._")
    else:
        for entry in report.justification_chain:
            techniques = ", ".join(entry.techniques) if entry.techniques else "none mapped"
            sections.append(f"### Detection {entry.detection_id}")
            sections.append(f"- ATT&CK techniques: {techniques}")
            sections.append(f"- Rule ID: {entry.rule_id}")
            sections.append(f"- Event ID: {entry.event.id}")
            sections.append(f"- Raw evidence available: {entry.raw_evidence is not None}")
            sections.append("")

    sections.append("## Risk Assessments")
    sections.append("")
    if not report.risk_assessments:
        sections.append("_No risk assessments in this cluster._")
    else:
        for risk in report.risk_assessments:
            sections.append(f"### Assessment {risk.id}")
            sections.append(_format_risk_section(risk))
            sections.append("")

    return "\n".join(sections)

def export_report_to_pdf(report: InvestigationReport, output_path: str) -> None:
    """Render an InvestigationReport as a PDF file, at the given path.

    Bonus format on top of the mandatory Markdown export (M6-04), reusing
    export_report_to_markdown() as the single source of content.
    """
    from markdown_pdf import MarkdownPdf, Section

    markdown_content = export_report_to_markdown(report)
    pdf = MarkdownPdf()
    pdf.add_section(Section(markdown_content))
    pdf.save(output_path)
