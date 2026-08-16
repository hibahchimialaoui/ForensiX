"""Tests for the TP/FP/FN baseline evaluation (M2-05)."""

import pytest

from forensix.db import SessionLocal
from forensix.detection.evaluation import OPERATIONAL_RULE_IDS, compute_tp_fp_fn
from forensix.models.db import EventRecord


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.close()


def test_baseline_covers_exactly_the_four_operational_rules(db_session):
    scores = compute_tp_fp_fn(db_session)
    assert set(scores.keys()) == OPERATIONAL_RULE_IDS
    assert len(scores) == 4


def test_baseline_achieves_perfect_score_on_the_evaluation_set(db_session):
    """Each operational rule must detect exactly its own positive case (TP=1),
    with no false positive or false negative on the shared benign cases."""
    scores = compute_tp_fp_fn(db_session)
    for rule_id, score in scores.items():
        assert score.true_positives == 1, f"{rule_id}: expected TP=1, got {score.true_positives}"
        assert score.false_positives == 0, f"{rule_id}: expected FP=0, got {score.false_positives}"
        assert score.false_negatives == 0, f"{rule_id}: expected FN=0, got {score.false_negatives}"


def test_baseline_cleans_up_evaluation_events_after_running(db_session):
    """The evaluation dataset must not leak into the Event Store after scoring."""
    compute_tp_fp_fn(db_session)
    remaining = (
        db_session.query(EventRecord)
        .filter(EventRecord.host == "M2-05-EVAL")
        .count()
    )
    assert remaining == 0
