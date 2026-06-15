"""Pins for the cross-framework resolver helpers.

Covers the three public functions in
:mod:`cybersecurity_assessor.catalogs.crosswalk_resolver`:

- :func:`resolve_equivalent_controls`
- :func:`resolve_equivalent_objectives`
- :func:`objectives_visible_in_framework`

All three are pure SQL helpers — no HTTP, no app factory, just a
SQLModel session. The fixtures seed two Frameworks (call them A and B)
with one Control each, two Objectives per Control, then exercise the
resolver under three scenarios: no crosswalk rows, objective-level
crosswalk, control-level crosswalk.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.catalogs.crosswalk_resolver import (  # noqa: E402
    objectives_visible_in_framework,
    resolve_equivalent_controls,
    resolve_equivalent_objectives,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    ControlCrosswalk,
    Crosswalk,
    Framework,
    Objective,
)


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def seeded(session: Session) -> dict[str, int]:
    """Two frameworks (A, B), one Control each, two Objectives per Control.

    Returns the integer ids by short name so tests don't have to re-look
    them up. No Crosswalk/ControlCrosswalk rows seeded — each test that
    wants a crosswalk inserts its own.
    """
    fw_a = Framework(name="Framework A", version="r1")
    fw_b = Framework(name="Framework B", version="r1")
    session.add_all([fw_a, fw_b])
    session.commit()
    session.refresh(fw_a)
    session.refresh(fw_b)

    ctrl_a = Control(framework_id=fw_a.id, control_id="A-1", title="A control", family="A")
    ctrl_b = Control(framework_id=fw_b.id, control_id="B-1", title="B control", family="B")
    session.add_all([ctrl_a, ctrl_b])
    session.commit()
    session.refresh(ctrl_a)
    session.refresh(ctrl_b)

    obj_a1 = Objective(control_id_fk=ctrl_a.id, objective_id="A-1.1", text="A obj 1")
    obj_a2 = Objective(control_id_fk=ctrl_a.id, objective_id="A-1.2", text="A obj 2")
    obj_b1 = Objective(control_id_fk=ctrl_b.id, objective_id="B-1.1", text="B obj 1")
    obj_b2 = Objective(control_id_fk=ctrl_b.id, objective_id="B-1.2", text="B obj 2")
    session.add_all([obj_a1, obj_a2, obj_b1, obj_b2])
    session.commit()
    for o in (obj_a1, obj_a2, obj_b1, obj_b2):
        session.refresh(o)

    return {
        "fw_a": fw_a.id,
        "fw_b": fw_b.id,
        "ctrl_a": ctrl_a.id,
        "ctrl_b": ctrl_b.id,
        "obj_a1": obj_a1.id,
        "obj_a2": obj_a2.id,
        "obj_b1": obj_b1.id,
        "obj_b2": obj_b2.id,
    }


# ---------------------------------------------------------------------------
# resolve_equivalent_controls
# ---------------------------------------------------------------------------


def test_resolve_equivalent_controls_empty_when_no_crosswalks(
    session: Session, seeded: dict[str, int]
) -> None:
    assert resolve_equivalent_controls(session, seeded["ctrl_a"], seeded["fw_b"]) == []


def test_resolve_equivalent_controls_forward_direction(
    session: Session, seeded: dict[str, int]
) -> None:
    session.add(
        ControlCrosswalk(from_control_id=seeded["ctrl_a"], to_control_id=seeded["ctrl_b"])
    )
    session.commit()

    eq = resolve_equivalent_controls(session, seeded["ctrl_a"], seeded["fw_b"])
    assert [c.id for c in eq] == [seeded["ctrl_b"]]


def test_resolve_equivalent_controls_reverse_direction(
    session: Session, seeded: dict[str, int]
) -> None:
    """Symmetric — a row from B→A still resolves A→B and vice versa."""
    session.add(
        ControlCrosswalk(from_control_id=seeded["ctrl_b"], to_control_id=seeded["ctrl_a"])
    )
    session.commit()

    eq = resolve_equivalent_controls(session, seeded["ctrl_a"], seeded["fw_b"])
    assert [c.id for c in eq] == [seeded["ctrl_b"]]


def test_resolve_equivalent_controls_filters_to_target_framework(
    session: Session, seeded: dict[str, int]
) -> None:
    """A→B crosswalk exists, but ask for "equivalents in framework A" — empty."""
    session.add(
        ControlCrosswalk(from_control_id=seeded["ctrl_a"], to_control_id=seeded["ctrl_b"])
    )
    session.commit()

    eq = resolve_equivalent_controls(session, seeded["ctrl_a"], seeded["fw_a"])
    assert eq == []  # B isn't in fw_a; source A is excluded by design


# ---------------------------------------------------------------------------
# resolve_equivalent_objectives
# ---------------------------------------------------------------------------


def test_resolve_equivalent_objectives_empty_when_no_crosswalks(
    session: Session, seeded: dict[str, int]
) -> None:
    assert (
        resolve_equivalent_objectives(session, seeded["obj_a1"], seeded["fw_b"]) == []
    )


def test_resolve_equivalent_objectives_walks_both_directions(
    session: Session, seeded: dict[str, int]
) -> None:
    session.add(
        Crosswalk(from_objective_id=seeded["obj_a1"], to_objective_id=seeded["obj_b1"])
    )
    # Reverse direction, separate pair.
    session.add(
        Crosswalk(from_objective_id=seeded["obj_b2"], to_objective_id=seeded["obj_a2"])
    )
    session.commit()

    eq_forward = resolve_equivalent_objectives(session, seeded["obj_a1"], seeded["fw_b"])
    assert [o.id for o in eq_forward] == [seeded["obj_b1"]]

    eq_reverse = resolve_equivalent_objectives(session, seeded["obj_a2"], seeded["fw_b"])
    assert [o.id for o in eq_reverse] == [seeded["obj_b2"]]


def test_resolve_equivalent_objectives_filters_by_target_framework(
    session: Session, seeded: dict[str, int]
) -> None:
    session.add(
        Crosswalk(from_objective_id=seeded["obj_a1"], to_objective_id=seeded["obj_b1"])
    )
    session.commit()
    assert (
        resolve_equivalent_objectives(session, seeded["obj_a1"], seeded["fw_a"]) == []
    )


# ---------------------------------------------------------------------------
# objectives_visible_in_framework
# ---------------------------------------------------------------------------


def test_objectives_visible_returns_direct_only_when_no_crosswalks(
    session: Session, seeded: dict[str, int]
) -> None:
    visible = objectives_visible_in_framework(session, seeded["fw_a"])
    assert visible == {seeded["obj_a1"], seeded["obj_a2"]}


def test_objectives_visible_empty_when_framework_has_no_controls(
    session: Session, seeded: dict[str, int]
) -> None:
    """A framework with zero controls / zero objectives short-circuits to set()."""
    fw_empty = Framework(name="Empty", version="r1")
    session.add(fw_empty)
    session.commit()
    session.refresh(fw_empty)
    assert objectives_visible_in_framework(session, fw_empty.id) == set()


def test_objectives_visible_includes_objective_crosswalk_partners(
    session: Session, seeded: dict[str, int]
) -> None:
    """When viewing framework B, an objective in A that crosswalks to a B
    objective should be in the visible set."""
    session.add(
        Crosswalk(from_objective_id=seeded["obj_a1"], to_objective_id=seeded["obj_b1"])
    )
    session.commit()

    visible_b = objectives_visible_in_framework(session, seeded["fw_b"])
    # Direct: b1, b2. Crosswalked-from-A: a1.
    assert seeded["obj_b1"] in visible_b
    assert seeded["obj_b2"] in visible_b
    assert seeded["obj_a1"] in visible_b


def test_objectives_visible_includes_control_crosswalk_partners(
    session: Session, seeded: dict[str, int]
) -> None:
    """Control-level crosswalk → every objective under the equivalent
    control becomes visible too, even without per-objective Crosswalk rows."""
    session.add(
        ControlCrosswalk(from_control_id=seeded["ctrl_a"], to_control_id=seeded["ctrl_b"])
    )
    session.commit()

    visible_a = objectives_visible_in_framework(session, seeded["fw_a"])
    # Direct: a1, a2. Via control crosswalk: b1, b2 (under ctrl_b).
    assert visible_a == {
        seeded["obj_a1"],
        seeded["obj_a2"],
        seeded["obj_b1"],
        seeded["obj_b2"],
    }
