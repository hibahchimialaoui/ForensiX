"""Repository functions for persisting NormalizedEvent instances to the Event Store."""

from sqlalchemy.orm import Session

from forensix.models.db import EventRecord
from forensix.models.event import NormalizedEvent


def _to_record(event: NormalizedEvent) -> EventRecord:
    """Convert a NormalizedEvent (Pydantic) into an EventRecord (SQLAlchemy) row."""
    return EventRecord(
        id=event.id,
        timestamp=event.timestamp,
        host=event.host,
        user=event.user,
        source=event.source,
        event_id=event.event_id,
        event_type=event.event_type,
        process_name=event.process.name if event.process else None,
        process_pid=event.process.pid if event.process else None,
        process_ppid=event.process.ppid if event.process else None,
        process_command_line=event.process.command_line if event.process else None,
        file_path=event.file.path if event.file else None,
        file_hash_sha256=event.file.hash_sha256 if event.file else None,
        network_source_ip=event.network.source_ip if event.network else None,
        network_destination_ip=event.network.destination_ip if event.network else None,
        network_destination_port=event.network.destination_port if event.network else None,
        network_protocol=event.network.protocol if event.network else None,
        raw_event=event.raw_event,
    )


def bulk_insert_events(session: Session, events: list[NormalizedEvent]) -> int:
    """Insert a list of NormalizedEvent into the Event Store in a single operation.

    Returns the number of events inserted.
    """
    records = [_to_record(event) for event in events]
    session.bulk_save_objects(records)
    session.commit()
    return len(records)
