"""Correlation score between two events, per the specification in docs/correlation_score.md.

Weights and threshold are fixed by that specification, written before this
implementation to avoid tuning parameters until a desired result appears.
Any future change to weights or threshold must be justified by M3-05 test
results, not by iterative adjustment.
"""


from forensix.models.db import EventRecord

WEIGHT_HOST = 0.30
WEIGHT_TEMPORAL = 0.25
WEIGHT_PID_PPID = 0.20
WEIGHT_USER = 0.15
WEIGHT_FILE_NETWORK = 0.10

TEMPORAL_WINDOW_SECONDS = 900  # 15 minutes

CORRELATION_THRESHOLD = 0.5


def _same_host(a: EventRecord, b: EventRecord) -> float:
    return 1.0 if a.host == b.host else 0.0


def _temporal_proximity(a: EventRecord, b: EventRecord) -> float:
    delta_seconds = abs((a.timestamp - b.timestamp).total_seconds())
    if delta_seconds >= TEMPORAL_WINDOW_SECONDS:
        return 0.0
    return 1.0 - (delta_seconds / TEMPORAL_WINDOW_SECONDS)


def _pid_ppid_relation(a: EventRecord, b: EventRecord) -> float:
    if a.process_pid is not None and a.process_pid == b.process_ppid:
        return 1.0
    if b.process_pid is not None and b.process_pid == a.process_ppid:
        return 1.0
    return 0.0


def _same_user(a: EventRecord, b: EventRecord) -> float:
    if a.user and b.user and a.user == b.user:
        return 1.0
    return 0.0


def _shared_file_or_network(a: EventRecord, b: EventRecord) -> float:
    if a.file_path and b.file_path and a.file_path == b.file_path:
        return 1.0
    if (
        a.network_destination_ip
        and b.network_destination_ip
        and a.network_destination_ip == b.network_destination_ip
    ):
        return 1.0
    return 0.0


def correlation_score(a: EventRecord, b: EventRecord) -> float:
    """Compute the correlation score between two events (0.0 to 1.0)."""
    return (
        WEIGHT_HOST * _same_host(a, b)
        + WEIGHT_TEMPORAL * _temporal_proximity(a, b)
        + WEIGHT_PID_PPID * _pid_ppid_relation(a, b)
        + WEIGHT_USER * _same_user(a, b)
        + WEIGHT_FILE_NETWORK * _shared_file_or_network(a, b)
    )


def are_correlated(a: EventRecord, b: EventRecord) -> bool:
    """Return True if the correlation score meets the decision threshold."""
    return correlation_score(a, b) >= CORRELATION_THRESHOLD
