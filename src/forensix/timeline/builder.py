"""Timeline construction from a correlation cluster (M4-01).

The timeline is a reconstructed view over PostgreSQL data (EventRecord and
DetectionRecord), not a new source of truth - consistent with the M3-04
principle: PostgreSQL is the source of truth, derived views are rebuilt
on demand.
"""

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from forensix.models.db import DetectionRecord, EventRecord


@dataclass
class TimelineEntry:
    """A single chronological entry, linking an event to its detections (if any)."""

    event: EventRecord
    detections: list[DetectionRecord] = field(default_factory=list)


def build_timeline(session: Session, events: list[EventRecord]) -> list[TimelineEntry]:
    """Build a deterministic, chronologically ordered timeline for a cluster.

    Events are sorted by timestamp; ties are broken by event_id (a stable
    identifier) to guarantee the exact same order across runs, as required
    by the technical review.
    """
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: (e.timestamp, e.id))

    event_ids = [e.id for e in sorted_events]
    detections = (
        session.query(DetectionRecord)
        .filter(DetectionRecord.event_id.in_(event_ids))
        .all()
    )
    detections_by_event: dict[str, list[DetectionRecord]] = {}
    for detection in detections:
        detections_by_event.setdefault(detection.event_id, []).append(detection)

    return [
        TimelineEntry(event=event, detections=detections_by_event.get(event.id, []))
        for event in sorted_events
    ]
