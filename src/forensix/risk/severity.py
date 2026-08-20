"""Severity normalization (M5-02), formalizing DetectionRecord.severity.

Severity is an intrinsic property of the detection/technique (inherited
from the Sigma rule's level, M2-04), independent of the host it occurs on.
This module does not recreate a second severity system - it formalizes and
orders the 5-level scale already produced by get_rule_metadata (M2-03),
reusing pySigma's own SigmaLevel ordering (verified before implementation).
"""

SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]
_RANK = {level: index for index, level in enumerate(SEVERITY_LEVELS)}


def normalize_severity(raw: str) -> str:
    """Return a validated, lowercase severity level.

    Falls back to 'informational' (the lowest level) for any unrecognized
    value, rather than raising - a missing/unknown severity should never
    silently escalate to a higher level than warranted.
    """
    candidate = raw.strip().lower() if raw else ""
    return candidate if candidate in _RANK else "informational"


def severity_rank(severity: str) -> int:
    """Return the numeric rank of a severity level (0=informational, 4=critical)."""
    return _RANK[normalize_severity(severity)]


def is_at_least(severity: str, threshold: str) -> bool:
    """Return True if severity is at or above the given threshold level."""
    return severity_rank(severity) >= severity_rank(threshold)


def compare_severity(a: str, b: str) -> int:
    """Return -1, 0, or 1 comparing severity a to severity b (like Python cmp)."""
    rank_a, rank_b = severity_rank(a), severity_rank(b)
    return (rank_a > rank_b) - (rank_a < rank_b)
