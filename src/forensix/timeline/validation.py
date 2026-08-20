"""Multi-cluster, multi-technique validation dataset (M4-04).

Exercises the full M3 (clustering) + M4 (timeline, ATT&CK mapping,
justification) chain in one dataset. Negative scenario note: none of the
4 fully operational rules (M2-02) has zero ATT&CK techniques, so this
dataset validates the negative case differently - an event with no
detection at all, already covered structurally in M4-03 and M4-02's own
unit tests (a rule with no technique tag returns an empty list). This
avoids fabricating an artificial zero-technique positive match that does
not exist in the real curated rule set.
"""

from forensix.models.event import FileInfo, NetworkInfo, NormalizedEvent, ProcessInfo

VALIDATION_HOST_A = "M404-HOST-A"
VALIDATION_HOST_B = "M404-HOST-B"


def build_cluster_a() -> list[NormalizedEvent]:
    """Cluster A: suspicious execution path (T1036), single event, host A."""
    return [
        NormalizedEvent(
            id="m404-a-e1",
            timestamp="2026-08-17T10:00:00",
            host=VALIDATION_HOST_A,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="C:\\Perflogs\\evil.exe", pid=100),
            raw_event={"xml": "<Event>cluster A</Event>"},
        ),
    ]


def build_cluster_b() -> list[NormalizedEvent]:
    """Cluster B: startup folder persistence (T1204.002 / T1547.001), host B.

    Two linked events (process creates the file) to also exercise clustering
    transitivity in the same validation pass.
    """
    return [
        NormalizedEvent(
            id="m404-b-e1",
            timestamp="2026-08-17T11:00:00",
            host=VALIDATION_HOST_B,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="powershell.exe", pid=200, ppid=None),
            raw_event={"xml": "<Event>cluster B e1</Event>"},
        ),
        NormalizedEvent(
            id="m404-b-e2",
            timestamp="2026-08-17T11:00:05",
            host=VALIDATION_HOST_B,
            source="sysmon",
            event_id="11",
            event_type="sysmon_event",
            process=ProcessInfo(pid=200),
            file=FileInfo(
                path=(
                    "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\"
                    "Start Menu\\Programs\\Startup\\malicious.ps1"
                )
            ),
            raw_event={"xml": "<Event>cluster B e2</Event>"},
        ),
    ]


def build_unrelated_event() -> NormalizedEvent:
    """A benign event with no correlation to either cluster and no detection.

    Serves as the negative scenario: must produce no justification entry.
    """
    return NormalizedEvent(
        id="m404-unrelated",
        timestamp="2026-08-17T12:00:00",
        host=VALIDATION_HOST_A,
        source="sysmon",
        event_id="3",
        event_type="sysmon_event",
        process=ProcessInfo(name="C:\\Program Files\\legit_app.exe", pid=999),
        network=NetworkInfo(destination_ip="192.168.50.1", destination_port=443),
        raw_event={"xml": "<Event>unrelated</Event>"},
    )
