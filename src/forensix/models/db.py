"""SQLAlchemy ORM model for persisting NormalizedEvent to PostgreSQL.

Process/file/network sub-fields are flattened into prefixed columns rather than
stored as nested JSON, so they can be queried directly with SQL (e.g. filtering
by process_pid) - needed by the Correlation Engine in Milestone 3.
"""

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String
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


class IncidentCluster(Base):
    """Stable identifier for a group of correlated events (M3-02 clustering output).

    PostgreSQL is the source of truth; the NetworkX graph is a derived
    analytical view, reconstructed on demand from event_ids. This table
    provides a stable cluster_id that M4 (Timeline + ATT&CK) and later
    milestones can reference without re-running the clustering algorithm.
    """

    __tablename__ = "incident_clusters"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    event_ids: Mapped[list] = mapped_column(JSON)
    detection_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    correlation_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

class HostContext(Base):
    """Independent host criticality/context, orthogonal to detection severity (M5-03).

    Never derived automatically from severity: a given severity can coexist
    with any host criticality. A host with no row here defaults to
    'unknown' criticality (see forensix.risk.criticality).
    """

    __tablename__ = "host_context"

    host: Mapped[str] = mapped_column(String, primary_key=True)
    criticality: Mapped[str] = mapped_column(String, index=True)
    context_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

class RiskAssessmentRecord(Base):
    """Persisted risk assessment (M5-04) for a detection, linked to its source.

    override_* columns are reserved for M6 (analyst review) and remain
    unused in M5 - prepared now so M6 does not require a schema migration
    just to add analyst correction capability.
    """

    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    detection_id: Mapped[str] = mapped_column(
        String, ForeignKey("detections.id"), index=True
    )
    confidence: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String)
    host_criticality: Mapped[str] = mapped_column(String)
    risk_score: Mapped[float] = mapped_column(Float, index=True)
    risk_category: Mapped[str] = mapped_column(String, index=True)
    priority: Mapped[str] = mapped_column(String, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    # Reserved for M6 - not used in M5.
    override_risk_category: Mapped[str | None] = mapped_column(String, nullable=True)
    override_priority: Mapped[str | None] = mapped_column(String, nullable=True)
    override_reason: Mapped[str | None] = mapped_column(String, nullable=True)


class AuditLogEntry(Base):
    """Append-only, hash-chained audit log entry (M7-01).

    Each entry's hash covers its own data plus the previous entry's hash,
    so altering any past entry breaks the chain for every entry after it -
    detectable at verification, not physically prevented (tamper-evident,
    never described as tamper-proof/infalsifiable).
    """

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    sequence_number: Mapped[int] = mapped_column(Integer, index=True, unique=True)
    entity_type: Mapped[str] = mapped_column(String, index=True)
    entity_id: Mapped[str] = mapped_column(String, index=True)
    action: Mapped[str] = mapped_column(String)
    data_snapshot: Mapped[dict] = mapped_column(JSON)
    previous_hash: Mapped[str] = mapped_column(String)
    entry_hash: Mapped[str] = mapped_column(String, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
