"""Common Event Model - the shared representation for all ingested security events."""

from datetime import datetime

from pydantic import BaseModel


class ProcessInfo(BaseModel):
    """Process-related fields, present on process creation / execution events."""

    name: str | None = None
    pid: int | None = None
    ppid: int | None = None
    command_line: str | None = None


class FileInfo(BaseModel):
    """File-related fields, present on file creation / access events."""

    path: str | None = None
    hash_sha256: str | None = None


class NetworkInfo(BaseModel):
    """Network-related fields, present on connection events."""

    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None


class NormalizedEvent(BaseModel):
    """Common fields present on every normalized event, regardless of source."""

    id: str
    timestamp: datetime
    host: str
    user: str | None = None
    source: str
    event_id: str
    event_type: str

    process: ProcessInfo | None = None
    file: FileInfo | None = None
    network: NetworkInfo | None = None

    raw_event: dict | None = None
