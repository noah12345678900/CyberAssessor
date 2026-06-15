"""Unit tests for ``catalogs.csf_loader.load_csf_catalog``.

The loader ingests the official NIST Cybersecurity Framework (CSF) 2.0 OSCAL
catalog as a *root* Framework (no parent) and writes one Control per
subcategory (the assessable unit). Concerns pinned here:

1.  The Framework carries the canonical identifier/version and the 185
    subcategory Controls land with the FUNCTION id as ``family`` and a
    non-empty statement. No Objective rows are created (CSF has no CCIs).
2.  Re-running the loader converges -- one Framework, same Control count,
    no duplicates.
3.  The distinct ``family`` set is exactly the six CSF function ids.

Tests use the wheel-bundled real catalog via ``offline=True`` so they never
touch the network.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.catalogs.csf_loader import (  # noqa: E402
    load_csf_catalog,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Framework,
    Objective,
)

# CSF 2.0 has 185 assessable subcategories and 6 functions.
_EXPECTED_SUBCATEGORIES = 185
_FUNCTION_IDS = {"GV", "ID", "PR", "DE", "RS", "RC"}


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_loads_csf_framework_and_subcategories(session):
    """Happy path: root Framework + 185 subcategory Controls, no Objectives."""
    framework = load_csf_catalog(session, offline=True)

    assert framework.framework_id == "NIST-CSF-2.0"
    assert framework.version == "2.0"
    assert framework.name == "NIST Cybersecurity Framework"
    # Root catalog -- no parent; enabled uses the model default (True).
    assert framework.parent_framework_id is None
    assert framework.enabled is True

    controls = session.exec(
        select(Control).where(Control.framework_id == framework.id)
    ).all()
    assert len(controls) == _EXPECTED_SUBCATEGORIES

    # A known subcategory is present, families to its function, has prose.
    by_id = {c.control_id: c for c in controls}
    assert "GV.OC-01" in by_id
    gv_oc_01 = by_id["GV.OC-01"]
    assert gv_oc_01.family == "GV"
    assert gv_oc_01.statement
    assert gv_oc_01.statement.strip()

    # CSF has no CCIs/objectives -- none should be written.
    objectives = session.exec(select(Objective)).all()
    assert objectives == []


def test_idempotent_reload_converges(session):
    """Loading twice yields one Framework and an unchanged Control set."""
    first = load_csf_catalog(session, offline=True)
    second = load_csf_catalog(session, offline=True)

    assert first.id == second.id

    frameworks = session.exec(select(Framework)).all()
    assert len(frameworks) == 1

    controls = session.exec(
        select(Control).where(Control.framework_id == first.id)
    ).all()
    assert len(controls) == _EXPECTED_SUBCATEGORIES


def test_families_are_function_ids(session):
    """Every Control families to one of the six CSF function ids."""
    framework = load_csf_catalog(session, offline=True)
    controls = session.exec(
        select(Control).where(Control.framework_id == framework.id)
    ).all()
    families = {c.family for c in controls}
    assert families == _FUNCTION_IDS
