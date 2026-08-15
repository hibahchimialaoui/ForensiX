"""Tests for the EVTX parser and Common Event Model mapping."""

from forensix.parsers.evtx import is_relevant_event, parse_evtx_record

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

VALID_LOGON_XML = f"""<Event xmlns="{_NS}">
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-08-14T10:00:00.000000Z"/>
    <Computer>WIN-01</Computer>
    <Security UserID="S-1-5-21-domain-1001"/>
  </System>
</Event>"""

IRRELEVANT_XML = f"""<Event xmlns="{_NS}">
  <System>
    <EventID>1234</EventID>
    <TimeCreated SystemTime="2026-08-14T10:00:00.000000Z"/>
    <Computer>WIN-01</Computer>
  </System>
</Event>"""

MALFORMED_XML = "<Event><System><EventID>4624</EventID>"


def test_parse_valid_logon_event():
    event = parse_evtx_record(VALID_LOGON_XML, host="fallback-host")
    assert event is not None
    assert event.event_id == "4624"
    assert event.host == "WIN-01"
    assert event.user == "S-1-5-21-domain-1001"
    assert event.source == "windows_event_log"


def test_parse_malformed_record_returns_none():
    event = parse_evtx_record(MALFORMED_XML, host="fallback-host")
    assert event is None


def test_relevant_event_id_is_detected():
    assert is_relevant_event(VALID_LOGON_XML) is True


def test_irrelevant_event_id_is_filtered_out():
    assert is_relevant_event(IRRELEVANT_XML) is False


def test_malformed_xml_is_not_relevant():
    assert is_relevant_event(MALFORMED_XML) is False
