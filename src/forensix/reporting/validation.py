"""End-to-end review workflow validation (M6-05): the 2 scenarios from the review.

- Scenario 1: ForensiX assessment -> analyst APPROVES as-is -> report final
  decision = original assessment.
- Scenario 2: ForensiX assessment -> analyst MODIFIES with a mandatory reason
  -> report shows both the original (untouched) and the analyst's decision.
"""

from forensix.models.event import NormalizedEvent, ProcessInfo

HOST_SCENARIO_1 = "M605-SCENARIO-1"
HOST_SCENARIO_2 = "M605-SCENARIO-2"


def build_scenario_1_event() -> NormalizedEvent:
    """Detection that the analyst will approve as-is."""
    return NormalizedEvent(
        id="m605-s1-1",
        timestamp="2026-08-20T10:00:00",
        host=HOST_SCENARIO_1,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
        raw_event={"xml": "<Event>scenario 1</Event>"},
    )


def build_scenario_2_event() -> NormalizedEvent:
    """Detection that the analyst will correct with a documented reason."""
    return NormalizedEvent(
        id="m605-s2-1",
        timestamp="2026-08-20T10:00:00",
        host=HOST_SCENARIO_2,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
        raw_event={"xml": "<Event>scenario 2</Event>"},
    )
