"""Illustrative review cycle timing (M7-06, bonus, non-scientific).

Measures backend processing time for one review cycle (load detection
data -> apply an analyst decision). This is NOT a measurement of real
human review time - no controlled protocol, single tester, backend only.
Presented explicitly as illustrative in all outputs, per the same
discipline as the M6-04 PDF bonus: light effort, dropped without
hesitation if it complicates anything.
"""

import time
from dataclasses import dataclass

from sqlalchemy.orm import Session

from forensix.interface.data_access import get_detection_review_item
from forensix.risk.override import apply_analyst_override


@dataclass
class ReviewCycleTiming:
    """Backend timing for one review cycle - illustrative only, not a human metric."""

    load_seconds: float
    decision_seconds: float
    total_seconds: float
    note: str = (
        "Illustrative backend timing only, not a measurement of real human "
        "review time. No controlled protocol, single tester, backend "
        "processing only - not to be presented as a scientific measurement."
    )


def measure_review_cycle(session: Session, detection_id: str) -> ReviewCycleTiming:
    """Time loading a detection's review data, then applying an approval decision."""
    start = time.perf_counter()
    item = get_detection_review_item(session, detection_id)
    load_seconds = time.perf_counter() - start

    if item is None or item.risk is None:
        raise ValueError(f"No reviewable detection found for id {detection_id}")

    start = time.perf_counter()
    apply_analyst_override(
        session, item.risk, item.risk.risk_category, item.risk.priority, "Approved as-is"
    )
    decision_seconds = time.perf_counter() - start

    return ReviewCycleTiming(
        load_seconds=load_seconds,
        decision_seconds=decision_seconds,
        total_seconds=load_seconds + decision_seconds,
    )
