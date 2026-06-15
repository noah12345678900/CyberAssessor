"""Golden tests for the per-workbook CRM lookup snapshot.

``engine.crm_context.build_crm_context`` is the read-side query that
turns ``WorkbookOverlay`` rows whose ``Baseline.source_type == CRM`` and
whose ``BaselineControl.responsibility`` is set into a frozen ``CrmContext``
the assessor consumes once per batch.

This is the fourth patent-supporting kernel guard's lookup layer: a
``provider`` entry short-circuits the LLM with NOT_APPLICABLE, ``hybrid``
injects a ``## responsibility_split`` block into the prompt, and
``inherited`` short-circuits with COMPLIANT. Get the source-type filter,
responsibility-NULL filter, or latest-wins ordering wrong and either (a)
a stale CRM overlay overrides a corrected one, (b) a non-CRM baseline
(CCIS_WORKBOOK overlay) bleeds in as if it were a CRM, or (c) controls
the CRM intentionally left to the customer (responsibility=NULL) get
mis-classified as covered.

DB-shaped tests: in-memory SQLite + StaticPool (matches the pattern in
``test_workbook_sync.py``) with hand-built Framework → Control + Workbook
+ Baseline (CRM and non-CRM) → BaselineControl → WorkbookOverlay rows.
``attached_at`` is pinned explicitly so latest-wins ordering is
deterministic; we never rely on default-factory wall-clock timing.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Ensure the backend package is importable when pytest is launched from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
    build_crm_context,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Baseline,
    BaselineControl,
    BaselineSourceType,
    Control,
    Framework,
    Workbook,
    WorkbookOverlay,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite, single shared connection per test."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def framework(session) -> Framework:
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)
    return fw


@pytest.fixture
def controls(session, framework) -> dict[str, Control]:
    """Three OSCAL-canonical control rows so we can pin lookup() behavior."""
    out: dict[str, Control] = {}
    for cid, title, family in (
        ("ac-2", "Account Management", "AC"),
        ("ac-2.1", "Automated Account Management", "AC"),
        ("ac-3", "Access Enforcement", "AC"),
    ):
        c = Control(framework_id=framework.id, control_id=cid, title=title, family=family)
        session.add(c)
        session.commit()
        session.refresh(c)
        out[cid] = c
    return out


@pytest.fixture
def workbook(session) -> Workbook:
    wb = Workbook(path="C:/wb/primary.xlsx", filename="primary.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


def _add_baseline(
    session: Session,
    *,
    framework_id: int,
    name: str,
    source_type: BaselineSourceType = BaselineSourceType.CRM,
) -> Baseline:
    b = Baseline(framework_id=framework_id, name=name, source_type=source_type)
    session.add(b)
    session.commit()
    session.refresh(b)
    return b


def _add_baseline_control(
    session: Session,
    *,
    baseline_id: int,
    control_id_int: int,
    responsibility: str | None,
    narrative: str | None = None,
) -> BaselineControl:
    bc = BaselineControl(
        baseline_id=baseline_id,
        control_id=control_id_int,
        responsibility=responsibility,
        responsibility_narrative=narrative,
    )
    session.add(bc)
    session.commit()
    session.refresh(bc)
    return bc


def _attach_overlay(
    session: Session,
    *,
    workbook_id: int,
    baseline_id: int,
    attached_at: datetime,
) -> WorkbookOverlay:
    ov = WorkbookOverlay(
        workbook_id=workbook_id,
        baseline_id=baseline_id,
        attached_at=attached_at,
    )
    session.add(ov)
    session.commit()
    session.refresh(ov)
    return ov


# Reference epoch — pin explicit timestamps so latest-wins is deterministic.
_T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Empty / no-overlay paths
# ---------------------------------------------------------------------------


def test_empty_classmethod_constructs_empty_context():
    """CrmContext.empty() returns a context whose lookup never hits.

    Pin the empty-case shape — the route handler relies on always passing
    *some* context past the kernel boundary so the kernel can stay
    null-check free.
    """
    ctx = CrmContext.empty()
    assert ctx.by_control == {}
    assert ctx.lookup("ac-2") is None


def test_workbook_with_no_overlays_returns_empty_context(session, workbook):
    """No WorkbookOverlay rows at all → empty CrmContext (not None)."""
    ctx = build_crm_context(workbook.id, session)
    assert isinstance(ctx, CrmContext)
    assert ctx.by_control == {}
    assert ctx.lookup("ac-2") is None


def test_non_crm_overlay_does_not_contribute(session, workbook, framework, controls):
    """Overlay attached but baseline.source_type != CRM → still empty.

    The WHERE filter on ``Baseline.source_type == CRM`` is load-bearing —
    a CCIS_WORKBOOK reference overlay (sibling system) must NOT leak
    responsibility data into the assessor's CRM lookup.
    """
    sibling = _add_baseline(
        session,
        framework_id=framework.id,
        name="sibling system CCIS",
        source_type=BaselineSourceType.CCIS_WORKBOOK,
    )
    _add_baseline_control(
        session,
        baseline_id=sibling.id,
        control_id_int=controls["ac-2"].id,
        responsibility="provider",  # would short-circuit if it leaked
    )
    _attach_overlay(
        session, workbook_id=workbook.id, baseline_id=sibling.id, attached_at=_T0
    )

    ctx = build_crm_context(workbook.id, session)
    assert ctx.by_control == {}


def test_baseline_control_with_null_responsibility_excluded(
    session, workbook, framework, controls
):
    """CRM overlay attached but responsibility=NULL → not in the map.

    Per the overlay-default-local rule: a row with no responsibility
    assignment means the CSP didn't ship a decision — fall back to full
    LLM assessment, not a silent "customer" classification.
    """
    crm = _add_baseline(session, framework_id=framework.id, name="vendor CRM")
    _add_baseline_control(
        session,
        baseline_id=crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility=None,
    )
    _attach_overlay(
        session, workbook_id=workbook.id, baseline_id=crm.id, attached_at=_T0
    )

    ctx = build_crm_context(workbook.id, session)
    assert ctx.lookup("ac-2") is None
    assert ctx.by_control == {}


# ---------------------------------------------------------------------------
# Happy path — every responsibility value flows through
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "responsibility",
    ["customer", "provider", "hybrid", "inherited", "not_applicable"],
)
def test_each_responsibility_value_flows_through(
    session, workbook, framework, controls, responsibility
):
    """Pin all five responsibility strings the assessor branches on.

    crm_context is loader-agnostic — it doesn't validate the string, it
    just carries it. The branching lives in the assessor; this test
    guarantees the assessor can rely on the value reaching it intact.
    """
    crm = _add_baseline(session, framework_id=framework.id, name=f"crm {responsibility}")
    _add_baseline_control(
        session,
        baseline_id=crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility=responsibility,
        narrative=f"narrative for {responsibility}",
    )
    _attach_overlay(
        session, workbook_id=workbook.id, baseline_id=crm.id, attached_at=_T0
    )

    ctx = build_crm_context(workbook.id, session)
    entry = ctx.lookup("ac-2")
    assert isinstance(entry, CrmEntry)
    assert entry.control_id == "ac-2"
    assert entry.responsibility == responsibility
    assert entry.narrative == f"narrative for {responsibility}"
    assert entry.source_baseline_id == crm.id


def test_responsibility_narrative_optional_passes_through_none(
    session, workbook, framework, controls
):
    """``responsibility_narrative=None`` → CrmEntry.narrative is None (not "")."""
    crm = _add_baseline(session, framework_id=framework.id, name="silent CRM")
    _add_baseline_control(
        session,
        baseline_id=crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility="provider",
        narrative=None,
    )
    _attach_overlay(
        session, workbook_id=workbook.id, baseline_id=crm.id, attached_at=_T0
    )

    entry = build_crm_context(workbook.id, session).lookup("ac-2")
    assert entry is not None
    assert entry.narrative is None


def test_multiple_controls_in_one_baseline(session, workbook, framework, controls):
    """One CRM baseline can carry several control rows; all should map."""
    crm = _add_baseline(session, framework_id=framework.id, name="multi-control CRM")
    _add_baseline_control(
        session,
        baseline_id=crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility="provider",
    )
    _add_baseline_control(
        session,
        baseline_id=crm.id,
        control_id_int=controls["ac-2.1"].id,
        responsibility="hybrid",
        narrative="customer configures roles",
    )
    _add_baseline_control(
        session,
        baseline_id=crm.id,
        control_id_int=controls["ac-3"].id,
        responsibility="inherited",
    )
    _attach_overlay(
        session, workbook_id=workbook.id, baseline_id=crm.id, attached_at=_T0
    )

    ctx = build_crm_context(workbook.id, session)
    assert ctx.lookup("ac-2").responsibility == "provider"  # type: ignore[union-attr]
    assert ctx.lookup("ac-2.1").responsibility == "hybrid"  # type: ignore[union-attr]
    assert ctx.lookup("ac-2.1").narrative == "customer configures roles"  # type: ignore[union-attr]
    assert ctx.lookup("ac-3").responsibility == "inherited"  # type: ignore[union-attr]


def test_lookup_returns_none_for_unmapped_control(
    session, workbook, framework, controls
):
    """A control the CRM doesn't mention → lookup() is None.

    Per the overlay-default-local rule: absence = 100% customer
    responsibility, so the assessor takes the full LLM path. The kernel
    relies on None (not a sentinel object) to signal "no CRM entry".
    """
    crm = _add_baseline(session, framework_id=framework.id, name="only ac-2 CRM")
    _add_baseline_control(
        session,
        baseline_id=crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility="provider",
    )
    _attach_overlay(
        session, workbook_id=workbook.id, baseline_id=crm.id, attached_at=_T0
    )

    ctx = build_crm_context(workbook.id, session)
    assert ctx.lookup("ac-3") is None
    # And the requested-but-absent control is genuinely absent from the dict.
    assert "ac-3" not in ctx.by_control


# ---------------------------------------------------------------------------
# Latest-wins on duplicate control_id (re-uploaded CRM)
# ---------------------------------------------------------------------------


def test_latest_overlay_wins_on_duplicate_control_id(
    session, workbook, framework, controls
):
    """Two CRM baselines, both with an entry for ac-2 — newer attached_at wins.

    This is the re-upload-corrected-CRM path called out in the module
    docstring. The query orders by ``attached_at desc`` and the loop
    skips already-seen control_ids; pin that with a value-distinguishable
    pair so a future ORDER BY drop surfaces here.
    """
    old_crm = _add_baseline(session, framework_id=framework.id, name="old CRM")
    _add_baseline_control(
        session,
        baseline_id=old_crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility="customer",
        narrative="old (wrong)",
    )

    new_crm = _add_baseline(session, framework_id=framework.id, name="new CRM (corrected)")
    _add_baseline_control(
        session,
        baseline_id=new_crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility="provider",
        narrative="new (correct)",
    )

    # Attach old first, new second. The loader inserts attached_at on
    # commit, but we pin explicit timestamps so timing jitter can't flip
    # the ordering on a fast machine.
    _attach_overlay(
        session, workbook_id=workbook.id, baseline_id=old_crm.id, attached_at=_T0
    )
    _attach_overlay(
        session,
        workbook_id=workbook.id,
        baseline_id=new_crm.id,
        attached_at=_T0 + timedelta(days=30),
    )

    ctx = build_crm_context(workbook.id, session)
    entry = ctx.lookup("ac-2")
    assert entry is not None
    assert entry.responsibility == "provider"  # newer overlay's value
    assert entry.narrative == "new (correct)"
    assert entry.source_baseline_id == new_crm.id


def test_latest_wins_is_per_control(session, workbook, framework, controls):
    """Two overlays where each covers an overlapping AND a disjoint control.

    Pin that the dedupe is keyed on control_id, not "winning overlay
    blanks the older one entirely" — the old CRM's ac-3 entry must still
    surface when the new CRM doesn't mention ac-3.
    """
    old_crm = _add_baseline(session, framework_id=framework.id, name="old CRM")
    _add_baseline_control(
        session,
        baseline_id=old_crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility="customer",
    )
    _add_baseline_control(
        session,
        baseline_id=old_crm.id,
        control_id_int=controls["ac-3"].id,
        responsibility="inherited",  # only in old CRM
    )

    new_crm = _add_baseline(session, framework_id=framework.id, name="new CRM")
    _add_baseline_control(
        session,
        baseline_id=new_crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility="provider",  # overrides old
    )

    _attach_overlay(
        session, workbook_id=workbook.id, baseline_id=old_crm.id, attached_at=_T0
    )
    _attach_overlay(
        session,
        workbook_id=workbook.id,
        baseline_id=new_crm.id,
        attached_at=_T0 + timedelta(days=30),
    )

    ctx = build_crm_context(workbook.id, session)
    # New CRM wins on the overlap.
    assert ctx.lookup("ac-2").responsibility == "provider"  # type: ignore[union-attr]
    # Old CRM still contributes the disjoint entry.
    assert ctx.lookup("ac-3").responsibility == "inherited"  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Cross-workbook isolation
# ---------------------------------------------------------------------------


def test_only_returns_overlays_for_requested_workbook(
    session, workbook, framework, controls
):
    """A CRM overlay attached to a different workbook MUST NOT leak in.

    Pin the WHERE clause on ``workbook_id`` with a second workbook in
    the same session whose CRM would otherwise surface against the
    requested workbook.
    """
    # Other workbook with its own CRM.
    other_wb = Workbook(path="C:/wb/other.xlsx", filename="other.xlsx")
    session.add(other_wb)
    session.commit()
    session.refresh(other_wb)

    other_crm = _add_baseline(session, framework_id=framework.id, name="other CRM")
    _add_baseline_control(
        session,
        baseline_id=other_crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility="provider",
        narrative="belongs to other workbook only",
    )
    _attach_overlay(
        session, workbook_id=other_wb.id, baseline_id=other_crm.id, attached_at=_T0
    )

    # Requested workbook has no overlays at all.
    ctx = build_crm_context(workbook.id, session)
    assert ctx.by_control == {}
    assert ctx.lookup("ac-2") is None

    # Sanity check: the other workbook DOES see its own overlay (otherwise
    # the test wouldn't actually be proving isolation).
    other_ctx = build_crm_context(other_wb.id, session)
    assert other_ctx.lookup("ac-2") is not None


def test_mixed_crm_and_non_crm_overlays_filters_to_crm(
    session, workbook, framework, controls
):
    """Workbook with one CRM and one CCIS_WORKBOOK overlay → only the CRM contributes.

    Combines the source_type filter test with the multi-overlay case so
    a future loader that ``UNION``s baseline types together would red
    this test (and the assessor would stop trusting the responsibility
    field to mean what it says).
    """
    crm = _add_baseline(
        session,
        framework_id=framework.id,
        name="real CRM",
        source_type=BaselineSourceType.CRM,
    )
    _add_baseline_control(
        session,
        baseline_id=crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility="provider",
        narrative="from CRM",
    )

    sibling_ccis = _add_baseline(
        session,
        framework_id=framework.id,
        name="sibling system CCIS reference",
        source_type=BaselineSourceType.CCIS_WORKBOOK,
    )
    # Same control, different responsibility — must NOT win, must NOT even
    # appear, regardless of attached_at ordering.
    _add_baseline_control(
        session,
        baseline_id=sibling_ccis.id,
        control_id_int=controls["ac-2"].id,
        responsibility="customer",
        narrative="from sibling CCIS",
    )

    # Attach the non-CRM more recently so a missing source-type filter
    # would let it overwrite the real CRM via latest-wins.
    _attach_overlay(
        session, workbook_id=workbook.id, baseline_id=crm.id, attached_at=_T0
    )
    _attach_overlay(
        session,
        workbook_id=workbook.id,
        baseline_id=sibling_ccis.id,
        attached_at=_T0 + timedelta(days=30),
    )

    ctx = build_crm_context(workbook.id, session)
    entry = ctx.lookup("ac-2")
    assert entry is not None
    assert entry.responsibility == "provider"  # CRM survived
    assert entry.narrative == "from CRM"
    assert entry.source_baseline_id == crm.id


# ---------------------------------------------------------------------------
# Returned object shape
# ---------------------------------------------------------------------------


def test_returns_crm_context_dataclass_with_frozen_entries(
    session, workbook, framework, controls
):
    """Top-level type is CrmContext; entries are frozen CrmEntry dataclasses.

    Frozenness matters: the assessor reads CrmEntry under the assumption
    it cannot be mutated mid-batch (the snapshot is built once per assess
    request). A future refactor that drops ``frozen=True`` on either
    dataclass should fail this assertion.
    """
    crm = _add_baseline(session, framework_id=framework.id, name="frozen check CRM")
    _add_baseline_control(
        session,
        baseline_id=crm.id,
        control_id_int=controls["ac-2"].id,
        responsibility="provider",
    )
    _attach_overlay(
        session, workbook_id=workbook.id, baseline_id=crm.id, attached_at=_T0
    )

    ctx = build_crm_context(workbook.id, session)
    assert isinstance(ctx, CrmContext)
    entry = ctx.lookup("ac-2")
    assert isinstance(entry, CrmEntry)

    # Frozen dataclasses raise FrozenInstanceError (a dataclasses.FrozenInstanceError,
    # which is an AttributeError subclass) on attribute assignment.
    with pytest.raises(Exception):
        entry.responsibility = "customer"  # type: ignore[misc]
