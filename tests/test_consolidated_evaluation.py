"""Tests for the consolidated TP/FP/FN evaluation (M7-03).

These tests exist as a regression guard: they must keep passing with the
same expected values as M2-05 and M3-05 for as long as those baselines'
rule set and scenarios remain unchanged.
"""

from forensix.db import SessionLocal
from forensix.evaluation.consolidated import run_consolidated_evaluation


def test_consolidated_detection_scores_match_m205_baseline():
    session = SessionLocal()
    try:
        result = run_consolidated_evaluation(session)
        assert len(result.detection_scores) == 4
        for score in result.detection_scores.values():
            assert score.true_positives == 1
            assert score.false_positives == 0
            assert score.false_negatives == 0
    finally:
        session.close()


def test_consolidated_correlation_results_match_m305_baseline():
    session = SessionLocal()
    try:
        result = run_consolidated_evaluation(session)
        assert result.correlation_scenario_a_clusters == 1
        assert result.correlation_scenario_b_clusters == 2
        assert result.correlation_scenario_c_clusters == 2
    finally:
        session.close()


def test_consolidated_evaluation_carries_the_methodology_limitation():
    session = SessionLocal()
    try:
        result = run_consolidated_evaluation(session)
        assert "not a representative production dataset" in result.methodology_limitation
    finally:
        session.close()
