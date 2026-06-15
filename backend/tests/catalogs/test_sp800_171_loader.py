"""Unit tests for ``catalogs.sp800_171_loader.load_sp800_171_catalog``.

The loader writes a root Framework + one Control per security requirement
from the bundled NIST SP 800-171 Rev 3 OSCAL catalog. Loaded with
``offline=True`` so the test never touches the network -- it reads the
wheel-bundled copy under ``catalogs/_bundled/``.

Three concerns pinned here:

1.  The framework metadata + requirement count (130) are correct, and a
    known requirement (03.01.01) carries a non-empty statement and family.
2.  Re-running the loader converges -- one Framework row, 130 Controls, no
    duplicates.
3.  No Objective rows are minted (800-171 OSCAL publishes no CCIs).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, func, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.catalogs.sp800_171_loader import (  # noqa: E402
    load_sp800_171_catalog,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Framework,
    Objective,
)

# NIST SP 800-171 Rev 3 publishes 130 OSCAL control entries, but 33 of those
# are withdrawn shells (status=withdrawn, e.g. 03.01.13 -> incorporated into
# 03.13.08) that the loader intentionally skips. The loader keeps only the 97
# active class="requirement" entries -- that is the canonical Rev 3 requirement
# count and what the loader is documented to insert.
_EXPECTED_REQUIREMENT_COUNT = 97


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


def test_loads_171_framework_and_requirements(session):
    """Happy path: framework metadata, 130 requirements, a known one populated."""
    fw = load_sp800_171_catalog(session, offline=True)

    assert fw.framework_id == "NIST-800-171r3"
    assert fw.name == "NIST SP 800-171"
    assert fw.version == "Rev 3"
    assert fw.parent_framework_id is None
    # enabled defaults True -- the loader must NOT set it; verify the default.
    assert fw.enabled is True

    count = session.exec(
        select(func.count()).select_from(Control).where(
            Control.framework_id == fw.id
        )
    ).one()
    assert count == _EXPECTED_REQUIREMENT_COUNT

    # A known requirement exists with the canonical dotted id, non-empty
    # statement, and a non-empty family.
    ac1 = session.exec(
        select(Control).where(
            Control.framework_id == fw.id,
            Control.control_id == "03.01.01",
        )
    ).first()
    assert ac1 is not None
    assert ac1.title  # non-empty title
    assert ac1.statement is not None and ac1.statement.strip()
    assert ac1.family and ac1.family.strip()


def test_idempotent_reload_converges(session):
    """Loading the bundled catalog twice -> one Framework, 130 Controls."""
    first = load_sp800_171_catalog(session, offline=True)
    second = load_sp800_171_catalog(session, offline=True)

    assert first.id == second.id

    fw_count = session.exec(select(func.count()).select_from(Framework)).one()
    assert fw_count == 1

    ctrl_count = session.exec(
        select(func.count()).select_from(Control).where(
            Control.framework_id == second.id
        )
    ).one()
    assert ctrl_count == _EXPECTED_REQUIREMENT_COUNT


def test_no_objectives_created(session):
    """800-171 OSCAL publishes no CCIs -- zero Objective rows after load."""
    load_sp800_171_catalog(session, offline=True)

    obj_count = session.exec(select(func.count()).select_from(Objective)).one()
    assert obj_count == 0
