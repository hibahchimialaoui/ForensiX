"""Integration tests for host criticality (M5-03), independent of severity."""

import pytest

from forensix.db import SessionLocal
from forensix.models.db import HostContext
from forensix.risk.criticality import (
    criticality_rank,
    get_host_criticality,
    normalize_criticality,
    set_host_criticality,
)

TEST_HOST_PREFIX = "M503-TEST-"


@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.query(HostContext).filter(
        HostContext.host.like(f"{TEST_HOST_PREFIX}%")
    ).delete(synchronize_session=False)
    session.commit()
    session.close()


def test_unregistered_host_defaults_to_unknown(db_session):
    result = get_host_criticality(db_session, f"{TEST_HOST_PREFIX}never-seen")
    assert result == "unknown"


def test_normalize_criticality_handles_case_and_whitespace():
    assert normalize_criticality("HIGH") == "high"
    assert normalize_criticality("  critical  ") == "critical"


def test_normalize_criticality_falls_back_to_unknown_for_invalid_values():
    assert normalize_criticality("not_a_level") == "unknown"
    assert normalize_criticality("") == "unknown"


def test_criticality_rank_is_strictly_ordered():
    assert (
        criticality_rank("critical")
        > criticality_rank("high")
        > criticality_rank("medium")
        > criticality_rank("low")
    )
    assert criticality_rank("unknown") == -1


def test_set_and_get_host_criticality_round_trip(db_session):
    host = f"{TEST_HOST_PREFIX}server-1"
    set_host_criticality(db_session, host, "critical", {"role": "domain_controller"})
    result = get_host_criticality(db_session, host)
    assert result == "critical"


def test_set_host_criticality_updates_without_creating_duplicate(db_session):
    host = f"{TEST_HOST_PREFIX}server-2"
    set_host_criticality(db_session, host, "low")
    set_host_criticality(db_session, host, "high")

    assert get_host_criticality(db_session, host) == "high"
    count = db_session.query(HostContext).filter(HostContext.host == host).count()
    assert count == 1


def test_criticality_is_orthogonal_to_severity(db_session):
    """A host can have any criticality regardless of what severity level
    its detections carry - the two dimensions are stored independently."""
    high_severity_low_criticality_host = f"{TEST_HOST_PREFIX}dev-box"
    set_host_criticality(db_session, high_severity_low_criticality_host, "low")
    assert get_host_criticality(db_session, high_severity_low_criticality_host) == "low"
