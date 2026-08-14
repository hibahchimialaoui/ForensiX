"""Tests for the Common Event Model."""

from forensix.models.event import FileInfo, NetworkInfo, NormalizedEvent, ProcessInfo


def test_minimal_event_is_valid():
    """An event with only the mandatory fields must be valid, with all sub-objects None."""
    event = NormalizedEvent(
        id="1",
        timestamp="2026-08-14T10:00:00",
        host="WIN-01",
        source="sysmon",
        event_id="4624",
        event_type="logon",
    )
    assert event.process is None
    assert event.file is None
    assert event.network is None
    assert event.raw_event is None


def test_full_event_with_all_subobjects_is_valid():
    """An event with all sub-objects populated must be valid."""
    event = NormalizedEvent(
        id="2",
        timestamp="2026-08-14T10:05:00",
        host="WIN-01",
        user="alice",
        source="sysmon",
        event_id="1",
        event_type="process_creation",
        process=ProcessInfo(
            name="powershell.exe", pid=1234, ppid=1000, command_line="powershell -enc ..."
        ),
        file=FileInfo(path="C:\\Temp\\payload.exe", hash_sha256="abc123"),
        network=NetworkInfo(
            source_ip="10.0.0.5", destination_ip="8.8.8.8", destination_port=443, protocol="tcp"
        ),
        raw_event={"raw": "data"},
    )
    assert event.process.name == "powershell.exe"
    assert event.file.hash_sha256 == "abc123"
    assert event.network.destination_port == 443
    assert event.raw_event == {"raw": "data"}
