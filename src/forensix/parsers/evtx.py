"""Reader and Common Event Model mapper for Windows Event Log (.evtx) files."""

import uuid
from collections.abc import Iterator
from xml.etree import ElementTree

from Evtx.Evtx import Evtx

from forensix.models.event import NormalizedEvent

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def read_evtx_records(file_path: str) -> Iterator[str]:
    """Yield each record of an .evtx file as raw XML text."""
    with Evtx(file_path) as log:
        for record in log.records():
            yield record.xml()


def parse_evtx_record(xml_text: str, host: str) -> NormalizedEvent | None:
    """Map a single raw EVTX XML record to a NormalizedEvent.

    Returns None instead of raising if the record is malformed or missing
    required fields, so the caller can skip it and keep processing the rest
    of the log without the whole pipeline failing on a single bad record.
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
        timestamp = time_el.get("SystemTime")
        computer = computer_el.text if computer_el is not None else host

        user = None
        security_el = system.find(f"{_NS}Security")
        if security_el is not None:
            user = security_el.get("UserID")

        return NormalizedEvent(
            id=str(uuid.uuid4()),
            timestamp=timestamp,
            host=computer,
            user=user,
            source="windows_event_log",
            event_id=event_id,
            event_type="windows_event",
            raw_event={"xml": xml_text},
        )
    except ElementTree.ParseError:
        return None


RELEVANT_EVENT_IDS = {"4624", "4625", "4688"}


def is_relevant_event(xml_text: str) -> bool:
    """Return True if the raw EVTX record's EventID is one we care about for investigation."""
    try:
        root = ElementTree.fromstring(xml_text)
        system = root.find(f"{_NS}System")
        if system is None:
            return False
        event_id_el = system.find(f"{_NS}EventID")
        if event_id_el is None:
            return False
        return event_id_el.text in RELEVANT_EVENT_IDS
    except ElementTree.ParseError:
        return False
