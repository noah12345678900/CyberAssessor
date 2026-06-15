"""Shared pytest fixtures for the cybersecurity-assessor test suite.

The backend lives next to this directory; we add it to ``sys.path`` so the
test files can ``import cybersecurity_assessor`` without an editable install (so
``pytest tests/`` works from a fresh clone).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# tests/  ->  repo root  ->  backend/
_REPO_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = _REPO_ROOT / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402

# Hypothesis profile registration. The kernel-hardening property tests
# (tests/engine/test_properties.py) live alongside the legacy unit suite,
# so we register the profile at conftest load time — every test session
# gets the same example budget and the same health-check posture without
# the property tests having to know about it. ``suppress_health_check =
# [too_slow]`` exists because regex-heavy validator paths can run a
# generated example in ~5-10ms and Hypothesis's default 200ms-per-example
# health check would flag perfectly normal runs as "too slow".
try:
    from hypothesis import HealthCheck, settings  # noqa: E402

    settings.register_profile(
        "default",
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
    )
    settings.load_profile("default")
except ImportError:
    # Hypothesis is in the dev extras; if a user runs tests without
    # installing them the property tests will skip themselves via their
    # own ``pytest.importorskip("hypothesis")`` guard. Don't fail
    # collection here.
    pass


def _make_row(**overrides) -> CcisRow:
    defaults = dict(
        excel_row=42,
        required=True,
        control_id="AC-2(1)",
        ap_acronym="AC-2.1",
        cci_id="CCI-000015",
        implementation_status="Implemented",
        designation="Hybrid",
        narrative=None,
        definition="The organization employs automated mechanisms to support the management of information system accounts.",
        guidance="Automated mechanisms include enterprise IdAM tooling.",
        procedures="Examine account management documentation; verify automation.",
        inherited="Local",
        remote_inheritance=None,
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )
    defaults.update(overrides)
    return CcisRow(**defaults)


@pytest.fixture
def make_row():
    """Factory for ``CcisRow`` test instances with overrides."""
    return _make_row
