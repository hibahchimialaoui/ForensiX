"""Parser and Common Event Model mapper for Sysmon events.

Sysmon events share the .evtx binary format with native Windows Event Logs, but carry
their specific data in an <EventData> section of named <Data> fields rather than in
<System>. This module only extracts individual events; it does not draw conclusions.
Any interpretation (e.g. flagging a network connection as exfiltration or C2) belongs
to the Correlation Engine (M3), which combines multiple pieces of evidence rather than
a single event, in line with ForensiX's evidence -> correlation -> conclusion philosophy.
"""

import uuid
from xml.etree import ElementTree

from forensix.models.event import FileInfo, NetworkInfo, NormalizedEvent, ProcessInfo

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Event ID 1: Process Creation - reconstructs the parent -> child process chain and
#             command line, the backbone of process-based investigation.
# Event ID 3: Network Connection - provides elements to identify and later correlate
#             network activity potentially associated with exfiltration or C2; it does
#             not by itself prove either.
# Event ID 11: File Create - provides elements to correlate a process with a dropped
#             file, a potential payload or dropper indicator.
RELEVANT_SYSMON_EVENT_IDS = {"1", "3", "11"}


def _event_data_dict(root: ElementTree.Element) -> dict[str, str]:
    """Extract Sysmon's <EventData><Data Name="...">value</Data></EventData> into a dict."""
    data = {}
    event_data = root.find(f"{_NS}EventData")
    if event_data is None:
        return data
    for item in event_data.findall(f"{_NS}Data"):
        name = item.get("Name")
        if name is not None:
            data[name] = item.text
    return data

def parse_sysmon_record(xml_text: str, host: str) -> NormalizedEvent | None:
    """Map a single raw Sysmon EVTX XML record to a NormalizedEvent.

    Returns None if the record is malformed, missing required fields, or not
    one of the relevant event types (RELEVANT_SYSMON_EVENT_IDS).
    """
    try:
        root = ElementTree.fromstring(xml_text)
        system = root.find(f"{_NS}System")
        if system is None:
            return None

        event_id_el = system.find(f"{_NS}EventID")
        time_el = system.find(f"{_NS}TimeCreated")
        computer_el = system.find(f"{_NS}Computer")

        if event_id_el is None or time_el is None:
            return None

        event_id = event_id_el.text
        if event_id not in RELEVANT_SYSMON_EVENT_IDS:
            return None

        timestamp = time_el.get("SystemTime")
        computer = computer_el.text if computer_el is not None else host
        data = _event_data_dict(root)

        process = None
        file = None
        network = None

        if event_id == "1":
            process = ProcessInfo(
                name=data.get("Image"),
                pid=int(data["ProcessId"]) if data.get("ProcessId") else None,
                ppid=int(data["ParentProcessId"]) if data.get("ParentProcessId") else None,
                command_line=data.get("CommandLine"),
            )
        elif event_id == "11":
            file = FileInfo(
                path=data.get("TargetFilename"),
                hash_sha256=data.get("Hashes"),
            )
        elif event_id == "3":
            network = NetworkInfo(
                source_ip=data.get("SourceIp"),
                destination_ip=data.get("DestinationIp"),
                destination_port=(
                    int(data["DestinationPort"]) if data.get("DestinationPort") else None
                ),
                protocol=data.get("Protocol"),
            )

        return NormalizedEvent(
            id=str(uuid.uuid4()),
            timestamp=timestamp,
            host=computer,
            source="sysmon",
            event_id=event_id,
            event_type="sysmon_event",
            process=process,
            file=file,
            network=network,
            raw_event={"xml": xml_text},
        )
    except ElementTree.ParseError:
        return None


