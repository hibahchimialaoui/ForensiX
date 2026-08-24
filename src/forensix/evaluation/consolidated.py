"""Consolidated TP/FP/FN evaluation report (M7-03).

Consolidates existing M2-05 (Sigma detection baseline) and M3-05
(correlation validation) results into a single report. This is not a new
measurement - both baselines were built on purpose-constructed test sets,
not a representative production dataset (documented limitation carried
forward from M2-05/M3-05, not re-litigated here).
"""

from dataclasses import dataclass

from sqlalchemy.orm import Session

from forensix.correlation.clustering import cluster_events
from forensix.correlation.validation import build_scenario_a, build_scenario_b, build_scenario_c
from forensix.detection.evaluation import compute_tp_fp_fn
from forensix.models.db import EventRecord
from forensix.repository import bulk_insert_events


@dataclass
class ConsolidatedEvaluation:
    """Combined detection (M2-05) and correlation (M3-05) evaluation results."""

    detection_scores: dict
    correlation_scenario_a_clusters: int
    correlation_scenario_b_clusters: int
    correlation_scenario_c_clusters: int
    methodology_limitation: str = (
        "Both baselines run on purpose-constructed test sets (M2-05, M3-05), "
        "not a representative production dataset. Results confirm logical "
        "correctness of the detection and correlation engines, not their "
        "real-world false positive/negative rates at scale."
    )


def run_consolidated_evaluation(session: Session) -> ConsolidatedEvaluation:
    """Re-run the M2-05 and M3-05 baselines and consolidate their results."""
    detection_scores = compute_tp_fp_fn(session)

    scenario_a = build_scenario_a()
    scenario_b = build_scenario_b()
    scenario_c = build_scenario_c()

    try:
        bulk_insert_events(session, scenario_a + scenario_b + scenario_c)
        all_records = (
            session.query(EventRecord)
            .filter(
                EventRecord.id.in_(
                    [e.id for e in scenario_a + scenario_b + scenario_c]
                )
            )
            .all()
        )
        clusters = cluster_events(all_records)

        scenario_a_ids = {e.id for e in scenario_a}
        scenario_b_ids = {e.id for e in scenario_b}
        scenario_c_ids = {e.id for e in scenario_c}

        n_clusters_a = len(
            [c for c in clusters if any(e.id in scenario_a_ids for e in c)]
        )
        n_clusters_b = len(
            [c for c in clusters if any(e.id in scenario_b_ids for e in c)]
        )
        n_clusters_c = len(
            [c for c in clusters if any(e.id in scenario_c_ids for e in c)]
        )
    finally:
        event_ids = [e.id for e in scenario_a + scenario_b + scenario_c]
        session.query(EventRecord).filter(EventRecord.id.in_(event_ids)).delete(
            synchronize_session=False
        )
        session.commit()

    return ConsolidatedEvaluation(
        detection_scores=detection_scores,
        correlation_scenario_a_clusters=n_clusters_a,
        correlation_scenario_b_clusters=n_clusters_b,
        correlation_scenario_c_clusters=n_clusters_c,
    )
