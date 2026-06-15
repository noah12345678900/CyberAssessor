"""Property-based tests for the per-workbook CRM lookup snapshot.

The example suite at ``backend/tests/engine/test_crm_context.py`` pins
specific branches: each empty/no-overlay path, each documented
responsibility value, the latest-wins case for one duplicated control,
cross-workbook isolation with two workbooks. This file fuzzes the
(workbook count × CRM-vs-non-CRM source mix × responsibility-NULL mix ×
attach-order timestamps × duplicated-control_id mix) input space so a
refactor that broke an invariant in a corner of the input set gets
caught.

In-scope invariants:

  1. **Source-type filter totality.** No matter how many
     non-CRM baselines (CCIS_WORKBOOK, PROGRAM_CONTROLS, OTHER, ...) are
     attached to a workbook, ``build_crm_context`` MUST NOT surface any
     of their BaselineControl rows. A regression that loosened the
     ``WHERE Baseline.source_type == CRM`` filter would let a sibling
     workbook reference (CCIS_WORKBOOK overlay) bleed in as if it had
     real responsibility verdicts — silently mis-classifying controls
     and tainting the assessor's short-circuit decisions.

  2. **Latest-wins on duplicate control_id.** Across N overlays all
     touching the same control, the entry retained MUST be the one
     attached at the maximum ``attached_at`` timestamp. The re-upload-
     corrected-CRM flow depends on this; if a stale overlay shadowed a
     fresh one the assessor would lock in last quarter's mistakes.

  3. **NULL-responsibility filter.** A BaselineControl with BOTH
     ``responsibility`` AND ``responsibility_onprem`` NULL MUST NOT
     surface in the map. A BaselineControl with EITHER set MUST surface
     (per the on-prem-only contributing-signal carve-out in
     ``build_crm_context``). A regression that dropped the
     ``or_(...is_not(None), ...is_not(None))`` filter would either (a)
     silently classify "CSP didn't ship a decision" as "customer"
     (over-claiming compliance), or (b) drop legitimate on-prem-only
     CRMs (under-claiming).

  4. **Cross-workbook isolation.** Given M workbooks each with their
     own CRM overlays, ``build_crm_context(workbook_id=k)`` MUST return
     entries derived ONLY from overlays attached to workbook k. Pin the
     ``WHERE workbook_id == k`` filter — without it, a multi-workbook
     session would cross-contaminate every CRM lookup.

  5. **Per-workbook determinism.** Running ``build_crm_context`` twice
     against the same DB state MUST produce the same map. The kernel
     reads-only — there's no caching layer — but a future ORDER BY
     change that introduced nondeterminism (e.g. dropping the
     ``attached_at`` tiebreaker) would let SQLite's unstable iteration
     order surface as latest-wins flapping.

  6. **Returns frozen CrmContext + frozen CrmEntry.** Top-level type is
     ``CrmContext`` and every value is a ``CrmEntry`` whose attributes
     refuse assignment. The assessor reads CrmEntry under the assumption
     it cannot be mutated mid-batch; a future refactor that dropped
     ``frozen=True`` on either dataclass would silently let a downstream
     consumer rewrite an entry between two lookups in the same assess
     run.

DB-shaped tests: per-Hypothesis-example we wipe & rebuild a tiny
Framework + Controls + Workbooks + Baselines + WorkbookOverlay schema
in an in-memory SQLite (StaticPool, matches the per-example reset
pattern in ``test_crm_backfill_properties.py``). ``attached_at`` is
strategy-driven so the latest-wins property explores arbitrary
orderings instead of just the +30-day spread the example suite pins.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

# Ensure backend is importable regardless of pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
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
# Strategies
# ---------------------------------------------------------------------------


# Reference epoch — any ``attached_at`` is this + a random offset (days).
# Pinning the base lets us reason about ordering in terms of small ints.
_T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


# Every responsibility value the assessor branches on, plus None so the
# NULL-responsibility filter test exercises rows that should be dropped.
_RESPONSIBILITY = st.one_of(
    st.sampled_from(
        ["customer", "provider", "hybrid", "inherited", "not_applicable"]
    ),
    st.none(),
)


# Source type mix — CRM is the only one that should contribute. The
# others stand in for the realistic overlay zoo: CCIS_WORKBOOK (sibling-
# system reference), PROGRAM_CONTROLS (PSC overlays), OTHER (inert
# unclassified overlays), MANUAL (UI-picked baselines).
_SOURCE_TYPE = st.sampled_from(
    [
        BaselineSourceType.CRM,
        BaselineSourceType.CCIS_WORKBOOK,
        BaselineSourceType.PROGRAM_CONTROLS,
        BaselineSourceType.OTHER,
        BaselineSourceType.MANUAL,
    ]
)


# A small control corpus (1-5 distinct control_ids). Keeps the
# Hypothesis budget tight enough to explore overlay-count and
# duplicate-control_id permutations without DB churn dominating.
_CONTROL_IDS = ["ac-2", "ac-2.1", "ac-3", "au-12", "cm-6"]


# Day offset for ``attached_at``. Small range (0-30) so collisions are
# plausible — exercises the latest-wins tiebreak when two overlays land
# on the same day.
_ATTACHED_DAY_OFFSET = st.integers(min_value=0, max_value=30)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite, single shared connection per Hypothesis example.

    Each example wipes & rebuilds inside the body (``_wipe`` below),
    so this fixture is per-test not per-example — matches the pattern
    in ``test_crm_backfill_properties.py``.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _wipe(session: Session) -> None:
    """Drop every row a prior example might have inserted.

    Order respects FK relationships (children before parents). Without
    this, a multi-example test sees prior examples' overlays and
    counter assertions tank immediately.
    """
    for table in (
        WorkbookOverlay,
        BaselineControl,
        Control,
        Workbook,
        Baseline,
        Framework,
    ):
        for row in session.exec(select(table)).all():
            session.delete(row)
    session.commit()


def _make_framework_and_controls(
    session: Session, control_ids: list[str]
) -> tuple[Framework, dict[str, Control]]:
    """Create one framework + one Control per id; return (fw, id->ctrl)."""
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    ctrls: dict[str, Control] = {}
    for cid in control_ids:
        c = Control(
            framework_id=fw.id,
            control_id=cid,
            title=f"Control {cid}",
            family=cid.split("-")[0].upper(),
        )
        session.add(c)
        session.commit()
        session.refresh(c)
        ctrls[cid] = c
    return fw, ctrls


def _make_workbook(session: Session, name: str) -> Workbook:
    wb = Workbook(path=f"C:/wb/{name}.xlsx", filename=f"{name}.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


def _make_baseline_with_control(
    session: Session,
    *,
    framework_id: int,
    source_type: BaselineSourceType,
    control_db_id: int,
    responsibility: str | None,
    responsibility_onprem: str | None = None,
    narrative: str | None = None,
    name: str = "baseline",
) -> Baseline:
    """One Baseline + one BaselineControl, returns the Baseline."""
    b = Baseline(framework_id=framework_id, name=name, source_type=source_type)
    session.add(b)
    session.commit()
    session.refresh(b)
    bc = BaselineControl(
        baseline_id=b.id,
        control_id=control_db_id,
        responsibility=responsibility,
        responsibility_onprem=responsibility_onprem,
        responsibility_narrative=narrative,
    )
    session.add(bc)
    session.commit()
    return b


def _attach(
    session: Session,
    *,
    workbook_id: int,
    baseline_id: int,
    attached_at: datetime,
) -> None:
    ov = WorkbookOverlay(
        workbook_id=workbook_id,
        baseline_id=baseline_id,
        attached_at=attached_at,
    )
    session.add(ov)
    session.commit()


# ---------------------------------------------------------------------------
# Invariant 1 — source-type filter totality
# ---------------------------------------------------------------------------


@given(
    overlays=st.lists(
        st.tuples(
            _SOURCE_TYPE,
            st.sampled_from(_CONTROL_IDS),
            st.sampled_from(
                ["provider", "customer", "hybrid", "inherited", "not_applicable"]
            ),
            _ATTACHED_DAY_OFFSET,
        ),
        min_size=1,
        max_size=8,
        # Per (control_id, day_offset) pair must be unique — so for any
        # given control, no two overlays share an attached_at. The
        # "latest wins" contract is well-defined only without ties; the
        # SQL only orders by attached_at desc and SQLite's secondary
        # order on equal sort keys is implementation-defined. Pinning a
        # tie-break here would test the database, not the kernel.
        unique_by=lambda x: (x[1], x[3]),
    )
)
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_only_crm_source_type_contributes(overlays, session):
    """No matter what mix of source types is attached, only CRM rows surface.

    Pin invariant #1: the ``WHERE Baseline.source_type == CRM`` filter
    is load-bearing. A regression that loosened it would let
    CCIS_WORKBOOK / PROGRAM_CONTROLS / OTHER / MANUAL overlays leak
    their (non-existent or arbitrary) responsibility verdicts into the
    assessor's CRM lookup.
    """
    _wipe(session)
    fw, ctrls = _make_framework_and_controls(session, _CONTROL_IDS)
    wb = _make_workbook(session, "primary")

    # Track which control_ids should end up in the result: latest-wins
    # restricted to CRM-typed overlays. Day is unique per control (see
    # strategy), so the per-control winner is the CRM overlay with the
    # largest day_offset — no tie-break needed.
    crm_winners: dict[str, tuple[int, str]] = {}
    for idx, (src, cid_text, resp, day) in enumerate(overlays):
        b = _make_baseline_with_control(
            session,
            framework_id=fw.id,
            source_type=src,
            control_db_id=ctrls[cid_text].id,
            responsibility=resp,
            name=f"b{idx}",
        )
        _attach(
            session,
            workbook_id=wb.id,
            baseline_id=b.id,
            attached_at=_T0 + timedelta(days=day),
        )
        if src == BaselineSourceType.CRM:
            prior = crm_winners.get(cid_text)
            if prior is None or day > prior[0]:
                crm_winners[cid_text] = (day, resp)

    ctx = build_crm_context(wb.id, session)
    assert isinstance(ctx, CrmContext)

    # Every key in the result must come from a CRM overlay.
    expected_keys = set(crm_winners)
    assert set(ctx.by_control) == expected_keys, (
        f"non-CRM leak: got {set(ctx.by_control) - expected_keys}, "
        f"missing {expected_keys - set(ctx.by_control)}"
    )

    # And the value retained must be the winning CRM overlay's verdict.
    for cid_text, (_day, expected_resp) in crm_winners.items():
        entry = ctx.lookup(cid_text)
        assert entry is not None
        assert entry.responsibility == expected_resp


# ---------------------------------------------------------------------------
# Invariant 2 — latest-wins on duplicate control_id
# ---------------------------------------------------------------------------


@given(
    # 2-6 CRM overlays all targeting the SAME control. Day offsets are
    # forced UNIQUE so the test pins the documented "latest wins"
    # invariant without making any claim about the kernel's tie-break
    # behavior — the SQL only orders by ``attached_at desc`` and SQLite's
    # secondary order on equal sort keys is implementation-defined.
    # Pinning a tie-break here would test the database, not the kernel.
    entries=st.lists(
        st.tuples(
            _ATTACHED_DAY_OFFSET,
            st.sampled_from(
                ["provider", "inherited", "customer", "hybrid", "not_applicable"]
            ),
        ),
        min_size=2,
        max_size=6,
        unique_by=lambda e: e[0],
    )
)
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_latest_attached_at_wins_on_duplicate_control(entries, session):
    """Among N CRM overlays for one control, max(attached_at) wins.

    Pin invariant #2: the ``ORDER BY attached_at DESC`` + first-wins
    loop semantics. A regression that dropped the ORDER BY (or flipped
    it ASC) would silently re-elect a stale CRM after a corrected re-
    upload, locking in last quarter's mistakes.
    """
    _wipe(session)
    fw, ctrls = _make_framework_and_controls(session, ["ac-2"])
    wb = _make_workbook(session, "primary")
    target = ctrls["ac-2"]

    # Tag each overlay so we can recover the winner from the result.
    # Build narrative as f"#{idx}:{resp}" — the narrative carries through
    # unmodified so we can read it back to identify the winning overlay.
    # Day offsets are unique-by-construction, so the winner is the single
    # entry with the maximum day_offset — no tie-break needed.
    winning_day = max(e[0] for e in entries)
    winner_idx = next(i for i, e in enumerate(entries) if e[0] == winning_day)
    _, winning_resp = entries[winner_idx]

    for idx, (day, resp) in enumerate(entries):
        b = _make_baseline_with_control(
            session,
            framework_id=fw.id,
            source_type=BaselineSourceType.CRM,
            control_db_id=target.id,
            responsibility=resp,
            narrative=f"#{idx}:{resp}",
            name=f"crm-{idx}",
        )
        _attach(
            session,
            workbook_id=wb.id,
            baseline_id=b.id,
            attached_at=_T0 + timedelta(days=day),
        )

    ctx = build_crm_context(wb.id, session)
    entry = ctx.lookup("ac-2")
    assert entry is not None
    # The retained narrative must be the winning overlay's tag — using
    # the narrative as the witness is more diagnostic than just
    # comparing responsibility (which could collide across entries).
    assert entry.narrative == f"#{winner_idx}:{winning_resp}", (
        f"latest-wins violation: entries={entries}, "
        f"expected idx={winner_idx} ({winning_resp}), got {entry.narrative}"
    )
    assert entry.responsibility == winning_resp


# ---------------------------------------------------------------------------
# Invariant 3 — NULL-responsibility filter (with on-prem carve-out)
# ---------------------------------------------------------------------------


@given(
    rows=st.lists(
        st.tuples(
            st.sampled_from(_CONTROL_IDS),
            # cloud responsibility (may be None)
            _RESPONSIBILITY,
            # on-prem responsibility (may be None)
            _RESPONSIBILITY,
        ),
        min_size=1,
        max_size=6,
    )
)
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_null_responsibility_filter_with_onprem_carveout(rows, session):
    """A row with EITHER cloud OR on-prem responsibility set must surface.
    A row with BOTH NULL must be excluded.

    Pin invariant #3. ``build_crm_context``'s WHERE clause is
    ``or_(responsibility.is_not(None), responsibility_onprem.is_not(None))``
    so an all-NULL row contributes no signal and silently dropping it
    would mask CRM data-quality issues. Conversely, an on-prem-only
    CRM (rare but valid) must still surface for the on-prem footprint.
    """
    _wipe(session)
    fw, ctrls = _make_framework_and_controls(session, _CONTROL_IDS)
    wb = _make_workbook(session, "primary")

    # Per-control: latest-wins among rows where the WHERE clause holds.
    # Since this strategy uses one overlay per row but they may share
    # control_ids, we still need to dedupe by control_id. Each row gets
    # a strictly-monotonic attached_at so iteration index == recency
    # order, removing tie ambiguity.
    expected_winners: dict[str, tuple[str | None, str | None]] = {}
    for idx, (cid_text, cloud_resp, onprem_resp) in enumerate(rows):
        b = _make_baseline_with_control(
            session,
            framework_id=fw.id,
            source_type=BaselineSourceType.CRM,
            control_db_id=ctrls[cid_text].id,
            responsibility=cloud_resp,
            responsibility_onprem=onprem_resp,
            name=f"crm-{idx}",
        )
        _attach(
            session,
            workbook_id=wb.id,
            baseline_id=b.id,
            attached_at=_T0 + timedelta(days=idx),
        )
        # Only contributes if at least one of the two is set.
        if cloud_resp is not None or onprem_resp is not None:
            # Newer attached_at always wins because we monotonically
            # increment day offset by idx.
            expected_winners[cid_text] = (cloud_resp, onprem_resp)

    ctx = build_crm_context(wb.id, session)

    # Keys: exactly the controls that had at least one row with at
    # least one responsibility set, AND whose winning overlay (by
    # attached_at) was such a row. But because we monotonically bumped
    # attached_at by idx, the LAST row per control_id wins. If the
    # winning row was all-NULL, that control is excluded entirely (the
    # WHERE filter strips it before ORDER BY).
    #
    # Re-derive expected by walking newest-to-oldest and taking the
    # first non-NULL-pair entry per control.
    derived: dict[str, tuple[str | None, str | None]] = {}
    for idx in range(len(rows) - 1, -1, -1):
        cid_text, cloud_resp, onprem_resp = rows[idx]
        if cid_text in derived:
            continue
        if cloud_resp is None and onprem_resp is None:
            continue
        derived[cid_text] = (cloud_resp, onprem_resp)

    assert set(ctx.by_control) == set(derived), (
        f"null-filter / latest-wins mismatch: got {set(ctx.by_control)}, "
        f"expected {set(derived)}, rows={rows}"
    )

    for cid_text, (cloud_resp, onprem_resp) in derived.items():
        entry = ctx.lookup(cid_text)
        assert entry is not None
        assert entry.responsibility == cloud_resp
        assert entry.responsibility_onprem == onprem_resp


# ---------------------------------------------------------------------------
# Invariant 4 — cross-workbook isolation
# ---------------------------------------------------------------------------


@given(
    # 2-4 workbooks, each with 1-3 CRM overlays (workbook_idx, control_id,
    # responsibility, day_offset). Per (workbook, control) pair the day
    # must be unique so the per-workbook "latest wins" computation has
    # no ties — see invariant #2 strategy for why we don't pin tie
    # behavior. Two different (wb, control) pairs CAN share a day.
    plan=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=3),  # workbook index
            st.sampled_from(_CONTROL_IDS),
            st.sampled_from(["provider", "inherited", "customer"]),
            _ATTACHED_DAY_OFFSET,
        ),
        min_size=2,
        max_size=10,
        unique_by=lambda x: (x[0], x[1], x[3]),
    )
)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_workbook_isolation_no_cross_contamination(plan, session):
    """A CRM attached to workbook A never appears in build_crm_context(B).

    Pin invariant #4: the ``WHERE workbook_id == k`` filter. Without
    it, a multi-workbook session would cross-contaminate every CRM
    lookup the moment the user opened a second workbook.
    """
    _wipe(session)
    fw, ctrls = _make_framework_and_controls(session, _CONTROL_IDS)

    # Materialize the unique workbook indices that appear in the plan,
    # so an unused index doesn't create a stray workbook row.
    workbook_indices = sorted({wb_idx for wb_idx, *_ in plan})
    workbooks: dict[int, Workbook] = {
        i: _make_workbook(session, f"wb-{i}") for i in workbook_indices
    }

    # Per-workbook winning expectations (same latest-wins rule as in
    # invariant 1, but partitioned by workbook).
    per_wb_winners: dict[int, dict[str, tuple[int, int, str]]] = {
        i: {} for i in workbook_indices
    }
    for idx, (wb_idx, cid_text, resp, day) in enumerate(plan):
        b = _make_baseline_with_control(
            session,
            framework_id=fw.id,
            source_type=BaselineSourceType.CRM,
            control_db_id=ctrls[cid_text].id,
            responsibility=resp,
            name=f"crm-{idx}",
        )
        _attach(
            session,
            workbook_id=workbooks[wb_idx].id,
            baseline_id=b.id,
            attached_at=_T0 + timedelta(days=day),
        )
        prior = per_wb_winners[wb_idx].get(cid_text)
        # Days are unique per (workbook, control) by construction (see
        # strategy unique_by), so no tie-break is needed — the winner
        # is unambiguously the row with the maximum day_offset.
        if prior is None or day > prior[0]:
            per_wb_winners[wb_idx][cid_text] = (day, idx, resp)

    # Now assert each workbook's CrmContext matches ONLY its own winners.
    for wb_idx, wb in workbooks.items():
        ctx = build_crm_context(wb.id, session)
        expected_keys = set(per_wb_winners[wb_idx])
        assert set(ctx.by_control) == expected_keys, (
            f"workbook {wb_idx} leakage: got {set(ctx.by_control)}, "
            f"expected {expected_keys}, plan={plan}"
        )
        for cid_text, (_day, _idx, expected_resp) in per_wb_winners[wb_idx].items():
            entry = ctx.lookup(cid_text)
            assert entry is not None
            assert entry.responsibility == expected_resp


# ---------------------------------------------------------------------------
# Invariant 5 — per-workbook determinism (idempotent reads)
# ---------------------------------------------------------------------------


@given(
    overlays=st.lists(
        st.tuples(
            st.sampled_from(_CONTROL_IDS),
            st.sampled_from(["provider", "inherited", "customer", "hybrid"]),
            _ATTACHED_DAY_OFFSET,
        ),
        min_size=1,
        max_size=8,
    )
)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_repeated_calls_produce_identical_maps(overlays, session):
    """Two consecutive ``build_crm_context`` calls return the same map.

    Pin invariant #5: the kernel is a pure read with deterministic
    ordering. A future change that dropped the ``attached_at`` tiebreak
    (or sorted on something non-deterministic like ``Baseline.id`` in
    the wrong direction) would let SQLite's unstable iteration order
    surface as latest-wins flapping between consecutive calls. Catches
    this without needing to set up a deliberate tie.
    """
    _wipe(session)
    fw, ctrls = _make_framework_and_controls(session, _CONTROL_IDS)
    wb = _make_workbook(session, "primary")

    for idx, (cid_text, resp, day) in enumerate(overlays):
        b = _make_baseline_with_control(
            session,
            framework_id=fw.id,
            source_type=BaselineSourceType.CRM,
            control_db_id=ctrls[cid_text].id,
            responsibility=resp,
            name=f"crm-{idx}",
        )
        _attach(
            session,
            workbook_id=wb.id,
            baseline_id=b.id,
            attached_at=_T0 + timedelta(days=day),
        )

    first = build_crm_context(wb.id, session)
    second = build_crm_context(wb.id, session)

    assert set(first.by_control) == set(second.by_control)
    for cid_text, entry in first.by_control.items():
        other = second.by_control[cid_text]
        assert entry == other, (
            f"non-deterministic CrmEntry for {cid_text}: "
            f"first={entry}, second={other}"
        )


# ---------------------------------------------------------------------------
# Invariant 6 — frozen dataclass shape
# ---------------------------------------------------------------------------


@given(
    overlays=st.lists(
        st.tuples(
            st.sampled_from(_CONTROL_IDS),
            st.sampled_from(["provider", "inherited", "customer"]),
        ),
        min_size=1,
        max_size=4,
    )
)
@settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_returns_frozen_crm_context_with_frozen_entries(overlays, session):
    """Result is a CrmContext whose CrmEntry values reject mutation.

    Pin invariant #6: ``frozen=True`` on both dataclasses. The assessor
    reads a snapshot once per assess request and relies on it not
    changing mid-batch — if a refactor unfroze CrmEntry, a downstream
    consumer could rewrite responsibility between two lookups in the
    same run and the assessor's reasoning would silently diverge from
    the persisted overlay state.
    """
    _wipe(session)
    fw, ctrls = _make_framework_and_controls(session, _CONTROL_IDS)
    wb = _make_workbook(session, "primary")

    for idx, (cid_text, resp) in enumerate(overlays):
        b = _make_baseline_with_control(
            session,
            framework_id=fw.id,
            source_type=BaselineSourceType.CRM,
            control_db_id=ctrls[cid_text].id,
            responsibility=resp,
            name=f"crm-{idx}",
        )
        _attach(
            session,
            workbook_id=wb.id,
            baseline_id=b.id,
            attached_at=_T0 + timedelta(days=idx),
        )

    ctx = build_crm_context(wb.id, session)
    assert isinstance(ctx, CrmContext)
    assert ctx.by_control, "test set up at least one overlay; result must be non-empty"

    for entry in ctx.by_control.values():
        assert isinstance(entry, CrmEntry)
        # Frozen dataclass raises FrozenInstanceError (an
        # AttributeError subclass) on any attribute assignment.
        with pytest.raises(Exception):
            entry.responsibility = "customer"  # type: ignore[misc]
        with pytest.raises(Exception):
            entry.narrative = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Cross-cutting — empty workbook always returns empty CrmContext
# ---------------------------------------------------------------------------


@given(
    # Vary "noise" baselines that aren't attached to the workbook under
    # test — pinning that they don't leak via some accidental cross-join.
    noise=st.lists(_SOURCE_TYPE, min_size=0, max_size=5)
)
@settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_unattached_baselines_never_surface(noise, session):
    """Baselines that exist but aren't attached to the workbook → empty result.

    Cross-checks the WorkbookOverlay join: a CRM baseline floating
    around in the DB without an overlay link must NOT contribute to
    any workbook's CrmContext. A regression that joined Baseline
    directly (skipping WorkbookOverlay) would let detached vendor
    CRMs bleed into every workbook.
    """
    _wipe(session)
    fw, ctrls = _make_framework_and_controls(session, ["ac-2"])
    wb = _make_workbook(session, "primary")

    for idx, src in enumerate(noise):
        # Create the baseline + a row, but DO NOT attach via
        # WorkbookOverlay. The result must remain empty.
        _make_baseline_with_control(
            session,
            framework_id=fw.id,
            source_type=src,
            control_db_id=ctrls["ac-2"].id,
            responsibility="provider",
            name=f"detached-{idx}",
        )

    ctx = build_crm_context(wb.id, session)
    assert ctx.by_control == {}
    assert ctx.lookup("ac-2") is None
