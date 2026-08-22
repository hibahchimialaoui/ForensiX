"""Multi-scenario risk validation (M5-05): scenarios A, B, C from the technical review.

- Scenario A: high severity + high confidence + low host criticality
- Scenario B: same severity/confidence, critical host criticality (must outrank A)
- Scenario C: documented substitute for "critical severity + low confidence +
  critical host criticality" - none of our 4 operational rules has Sigma level
  "critical" (verified in M5-02). Uses the mobsync rule (medium severity,
  verified after running this scenario - not "high" as first assumed) with
  low confidence, same honesty principle as the M4-04 negative scenario: no
  fabricated critical-severity rule is used.
"""

from forensix.models.event import NetworkInfo, NormalizedEvent, ProcessInfo

HOST_A = "M505-SCENARIO-A"
HOST_B = "M505-SCENARIO-B"
HOST_C = "M505-SCENARIO-C"


def build_scenario_a_event() -> NormalizedEvent:
    """High-confidence detection (suspicious execution path, T1036) on a low-criticality host."""
    return NormalizedEvent(
        id="m505-a-1",
        timestamp="2026-08-18T10:00:00",
        host=HOST_A,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )


def build_scenario_b_event() -> NormalizedEvent:
    """Same rule/pattern as A, but on a host that will be marked critical."""
    return NormalizedEvent(
        id="m505-b-1",
        timestamp="2026-08-18T10:00:00",
        host=HOST_B,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Perflogs\\evil.exe"),
    )


def build_scenario_c_event() -> NormalizedEvent:
    """Isolated detection (low confidence: no correlated cluster) on a host
    marked critical, using the mobsync rule (medium severity)."""
    return NormalizedEvent(
        id="m505-c-1",
        timestamp="2026-08-18T10:00:00",
        host=HOST_C,
        source="sysmon",
        event_id="3",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Windows\\System32\\mobsync.exe"),
        network=NetworkInfo(destination_ip="8.8.8.8", destination_port=443),
    )
