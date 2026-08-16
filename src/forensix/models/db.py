"""SQLAlchemy ORM model for persisting NormalizedEvent to PostgreSQL.

Process/file/network sub-fields are flattened into prefixed columns rather than
stored as nested JSON, so they can be queried directly with SQL (e.g. filtering
by process_pid) - needed by the Correlation Engine in Milestone 3.
"""

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    """Database row for a single normalized event."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    host: Mapped[str] = mapped_column(String, index=True)
    user: Mapped[str | None] = mapped_column(String, nullable=True)
    source: Mapped[str] = mapped_column(String)
    event_id: Mapped[str] = mapped_column(String)
    event_type: Mapped[str] = mapped_column(String, index=True)

    process_name: Mapped[str | None] = mapped_column(String, nullable=True)
    process_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_ppid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_command_line: Mapped[str | None] = mapped_column(String, nullable=True)

    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    file_hash_sha256: Mapped[str | None] = mapped_column(String, nullable=True)

    network_source_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    network_destination_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    network_destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    network_protocol: Mapped[str | None] = mapped_column(String, nullable=True)

    raw_event: Mapped[dict | None] = mapped_column(JSON, nullable=True)

class DetectionRecord(Base):
    """Database row for a single Sigma rule detection, linked to its source event."""

    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String, index=True)
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("events.id"), index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    severity: Mapped[str] = mapped_column(String, index=True)
    detection_status: Mapped[str] = mapped_column(String, default="new")
    detection_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

