"""Tests for the Sysmon parser and Common Event Model mapping."""

from forensix.parsers.sysmon import parse_sysmon_record

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _sysmon_xml(event_id: str, data_fields: dict[str, str]) -> str:
    data_xml = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data_fields.items())
    return f"""<Event xmlns="{_NS}">
  <System>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="2026-08-14T10:00:00.000000Z"/>
    <Computer>WIN-01</Computer>
  </System>
  <EventData>{data_xml}</EventData>
</Event>"""


PROCESS_CREATION_XML = _sysmon_xml(
    "1",
    {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "ProcessId": "1234",
        "ParentProcessId": "1000",
        "CommandLine": "powershell -enc ...",
    },
)

FILE_CREATE_XML = _sysmon_xml(
    "11",
    {"TargetFilename": "C:\\Temp\\payload.exe", "Hashes": "SHA256=abc123"},
)

NETWORK_CONNECTION_XML = _sysmon_xml(
    "3",
    {
        "SourceIp": "10.0.0.5",
        "DestinationIp": "8.8.8.8",
        "DestinationPort": "443",
        "Protocol": "tcp",
    },
)

IRRELEVANT_XML = _sysmon_xml("7", {"ImageLoaded": "some.dll"})


def test_process_creation_event_maps_to_process_info():
    event = parse_sysmon_record(PROCESS_CREATION_XML, host="fallback")
    assert event is not None
    assert event.event_id == "1"
    assert event.process is not None
    assert event.process.pid == 1234
    assert event.process.ppid == 1000
    assert event.file is None
    assert event.network is None


def test_file_create_event_maps_to_file_info():
    event = parse_sysmon_record(FILE_CREATE_XML, host="fallback")
    assert event is not None
    assert event.file is not None
    assert event.file.path == "C:\\Temp\\payload.exe"
    assert event.process is None


def test_network_connection_event_maps_to_network_info():
    event = parse_sysmon_record(NETWORK_CONNECTION_XML, host="fallback")
    assert event is not None
    assert event.network is not None
    assert event.network.destination_port == 443
    assert event.file is None


def test_irrelevant_event_id_returns_none():
    assert parse_sysmon_record(IRRELEVANT_XML, host="fallback") is None
