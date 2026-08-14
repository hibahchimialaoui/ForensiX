"""Placeholder test to validate the CI pipeline before M1 features land."""

from forensix import __version__


def test_version_is_defined():
    assert __version__ == "0.1.0"
