"""Host criticality (M5-03), independent of and never derived from detection severity.

A host with no explicit HostContext row has 'unknown' criticality by
default - never assumed to be 'low' (which would silently downplay an
unregistered critical server) nor 'critical' (which would flood every
unregistered host with false urgency).
"""

from sqlalchemy.orm import Session

from forensix.models.db import HostContext

CRITICALITY_LEVELS = ["low", "medium", "high", "critical"]
_RANK = {level: index for index, level in enumerate(CRITICALITY_LEVELS)}

UNKNOWN_CRITICALITY = "unknown"


def normalize_criticality(raw: str) -> str:
    """Return a validated, lowercase criticality level, or 'unknown' if unrecognized."""
    candidate = raw.strip().lower() if raw else ""
    return candidate if candidate in _RANK else UNKNOWN_CRITICALITY


def criticality_rank(criticality: str) -> int:
    """Return the numeric rank (0=low, 3=critical), or -1 for 'unknown'."""
    normalized = normalize_criticality(criticality)
    return _RANK.get(normalized, -1)


def get_host_criticality(session: Session, host: str) -> str:
    """Look up a host's criticality from PostgreSQL. Defaults to 'unknown'."""
    context = session.query(HostContext).filter(HostContext.host == host).first()
    if context is None:
        return UNKNOWN_CRITICALITY
    return normalize_criticality(context.criticality)


def set_host_criticality(
    session: Session, host: str, criticality: str, context_metadata: dict | None = None
) -> HostContext:
    """Create or update a host's criticality."""
    normalized = normalize_criticality(criticality)
    existing = session.query(HostContext).filter(HostContext.host == host).first()
    if existing is not None:
        existing.criticality = normalized
        existing.context_metadata = context_metadata
        session.commit()
        return existing

    context = HostContext(host=host, criticality=normalized, context_metadata=context_metadata)
    session.add(context)
    session.commit()
    return context
