"""Multi-scenario correlation validation dataset (M3-05).

The M1-07 dataset (UACME_59_Sysmon.evtx, T1548.002 UAC bypass) is a
single-technique capture and does not contain multi-event chains suitable
for testing correlation clustering - same methodological limit as M2-05.
This module provides a purpose-built evaluation set with the 3 scenarios
required by the M3-05 technical review.
"""


from forensix.models.event import NetworkInfo, NormalizedEvent, ProcessInfo

VALIDATION_HOST_A = "M305-HOST-A"
VALIDATION_HOST_B = "M305-HOST-B"
VALIDATION_HOST_C = "M305-HOST-C"


def build_scenario_a() -> list[NormalizedEvent]:
    """Scenario A: a single incident chain A->B->C->D linked by PID/PPID.

    Expected result: all 4 events form exactly 1 cluster.
    """
    return [
        NormalizedEvent(
            id="m305-a-e1",
            timestamp="2026-08-17T10:00:00",
            host=VALIDATION_HOST_A,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="powershell.exe", pid=100, ppid=None),
        ),
        NormalizedEvent(
            id="m305-a-e2",
            timestamp="2026-08-17T10:00:05",
            host=VALIDATION_HOST_A,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="cmd.exe", pid=200, ppid=100),
        ),
        NormalizedEvent(
            id="m305-a-e3",
            timestamp="2026-08-17T10:00:10",
            host=VALIDATION_HOST_A,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="certutil.exe", pid=300, ppid=200),
        ),
        NormalizedEvent(
            id="m305-a-e4",
            timestamp="2026-08-17T10:00:15",
            host=VALIDATION_HOST_A,
            source="sysmon",
            event_id="3",
            event_type="sysmon_event",
            process=ProcessInfo(name="certutil.exe", pid=300, ppid=200),
            network=NetworkInfo(destination_ip="8.8.8.8", destination_port=443),
        ),
    ]


def build_scenario_b() -> list[NormalizedEvent]:
    """Scenario B: two independent incidents on separate hosts.

    Expected result: 2 distinct clusters (one per host).
    """
    incident_1 = [
        NormalizedEvent(
            id="m305-b-e1",
            timestamp="2026-08-17T11:00:00",
            host=VALIDATION_HOST_A,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="wscript.exe", pid=500, ppid=None),
        ),
        NormalizedEvent(
            id="m305-b-e2",
            timestamp="2026-08-17T11:00:10",
            host=VALIDATION_HOST_A,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="powershell.exe", pid=600, ppid=500),
        ),
    ]
    incident_2 = [
        NormalizedEvent(
            id="m305-b-e3",
            timestamp="2026-08-17T11:00:00",
            host=VALIDATION_HOST_B,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="explorer.exe", pid=700, ppid=None),
        ),
        NormalizedEvent(
            id="m305-b-e4",
            timestamp="2026-08-17T11:00:05",
            host=VALIDATION_HOST_B,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="mshta.exe", pid=800, ppid=700),
        ),
    ]
    return incident_1 + incident_2


def build_scenario_c() -> list[NormalizedEvent]:
    """Scenario C: one chain plus one completely unrelated event.

    Expected result: 2 clusters (the chain + the isolated event).
    """
    chain = [
        NormalizedEvent(
            id="m305-c-e1",
            timestamp="2026-08-17T12:00:00",
            host=VALIDATION_HOST_A,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="powershell.exe", pid=900, ppid=None),
        ),
        NormalizedEvent(
            id="m305-c-e2",
            timestamp="2026-08-17T12:00:08",
            host=VALIDATION_HOST_A,
            source="sysmon",
            event_id="1",
            event_type="sysmon_event",
            process=ProcessInfo(name="notepad.exe", pid=1000, ppid=900),
        ),
    ]
    unrelated = NormalizedEvent(
        id="m305-c-e3",
        timestamp="2026-08-17T12:00:00",
        host=VALIDATION_HOST_C,
        source="sysmon",
        event_id="1",
        event_type="sysmon_event",
        process=ProcessInfo(name="svchost.exe", pid=4, ppid=None),
    )
    return chain + [unrelated]
