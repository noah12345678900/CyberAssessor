"""Tests for :func:`update_weights_online` — the SGD partial-fit pass that
runs after a sweep-triage Ingest commits ``SweepDecision`` rows.

What we pin down:

1. **Below-threshold short-circuit.** Fewer than
   ``MIN_DECISIONS_FOR_ONLINE_FIT`` (25) unconsumed rows → no fit, no new
   ``SweepWeights`` row written, rows stay unconsumed (the next batch
   will pick them up again). The SGD partial_fit on a tiny mini-batch
   would swing wildly and corrupt the active row.

2. **Single-class refusal.** All-included or all-excluded batches can't
   train a decision boundary. The updater marks those rows consumed
   (so they don't keep blocking the queue forever) and bails without
   writing a row. Either label alone teaches nothing.

3. **Happy path persistence.** A balanced 30-row batch → exactly one
   new ``SweepWeights`` row with ``source="sgd_online"``,
   ``is_active=False``, ``parent_weights_id`` pointing at the active
   row, and ``n_decisions_seen`` incremented by the batch size. We
   intentionally do NOT auto-activate — the operator promotes via the
   recalibration UI.

4. **Directional drift.** When the labels say "priority signal is always
   kept, doc-prefix signal is always rejected," the new row's
   ``weight_priority_link`` should be **at least as large** as the
   warm-start, and ``weight_doc_prefix`` should be **smaller** (or
   clipped to zero by the sign constraint). We don't pin exact values —
   SGD's learning_rate="optimal" makes those non-trivial to predict —
   but the *direction* is the load-bearing contract.

5. **Consumed flag flip.** Every row that fed the fit gets
   ``consumed_for_training=True``. The next call returns None (queue
   empty) and writes nothing — proves we're not re-fitting on already-
   trained rows on every triage click.

6. **Cold-start fallback.** No active SweepWeights row in the DB →
   updater warm-starts from the hand-tuned ``_W_*`` defaults and
   writes a new row with ``parent_weights_id=None``. Documents the
   "fresh DB with seed missing" path, even though ``init_db`` always
   seeds v1 in production.

We import sklearn lazily inside the updater; if it's missing in the test
environment we ``importorskip`` rather than xfail — the SGD path is
genuinely untestable without it.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

# sklearn is required for the SGD path; skip the whole module if missing.
pytest.importorskip("sklearn", reason="online SGD updater requires scikit-learn")

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine.sweep_online import (  # noqa: E402
    MIN_DECISIONS_FOR_ONLINE_FIT,
    update_weights_online,
)
from cybersecurity_assessor.evidence.sources.sweep import (  # noqa: E402
    _W_DOC_PREFIX,
    _W_HOST,
    _W_PRIORITY_LINK,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Framework,
    SweepDecision,
    SweepWeights,
    Workbook,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path: Path):
    """In-memory SQLite + a seeded Workbook (for the FK).

    Yields ``(session_factory, workbook_id)``. Tests open their own
    sessions so they can verify post-commit DB state cleanly.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    wb_path = tmp_path / "demo.xlsx"
    wb_path.write_bytes(b"x")

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)
        wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
        s.add(wb)
        s.commit()
        s.refresh(wb)
        wb_id = wb.id

    yield engine, wb_id


def _seed_active_weights(engine) -> int:
    """Seed an active SweepWeights row matching the hand-tuned defaults.

    Returns the row id so tests can assert ``parent_weights_id`` linkage.
    """
    with Session(engine) as s:
        row = SweepWeights(
            source="manual",
            weight_host=_W_HOST,
            weight_control_id=0.30,
            weight_family=0.20,
            weight_crm_keyword=0.15,
            weight_doc_prefix=_W_DOC_PREFIX,
            weight_priority_link=_W_PRIORITY_LINK,
            intercept=0.0,
            surface_threshold=0.30,
            precheck_threshold=0.60,
            n_decisions_seen=0,
            is_active=True,
        )
        s.add(row)
        s.commit()
        s.refresh(row)
        return row.id


def _add_decisions(
    engine,
    wb_id: int,
    weights_id: int | None,
    *,
    signals_label_pairs: list[tuple[list[str], bool]],
) -> list[int]:
    """Bulk-insert SweepDecision rows for one workbook. Returns ids.

    Each entry is ``(signals_list, included_label)``. The other columns
    get neutral fillers — the updater only reads ``signals_json`` and
    ``included``.
    """
    ids: list[int] = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=1)
    with Session(engine) as s:
        # If weights_id is None we can't satisfy the FK; pull any row to use as anchor.
        if weights_id is None:
            any_w = s.exec(select(SweepWeights)).first()
            if any_w is None:
                # Insert a throwaway anchor; tests that exercise "no active row"
                # mark it is_active=False so the loader returns None.
                anchor = SweepWeights(
                    source="manual",
                    weight_host=0.0,
                    weight_control_id=0.0,
                    weight_family=0.0,
                    weight_crm_keyword=0.0,
                    weight_doc_prefix=0.0,
                    weight_priority_link=0.0,
                    intercept=0.0,
                    surface_threshold=0.30,
                    precheck_threshold=0.60,
                    n_decisions_seen=0,
                    is_active=False,
                )
                s.add(anchor)
                s.commit()
                s.refresh(anchor)
                weights_id = anchor.id
            else:
                weights_id = any_w.id

        for i, (signals, included) in enumerate(signals_label_pairs):
            d = SweepDecision(
                workbook_id=wb_id,
                candidate_path=f"/x/file-{i}.pdf",
                candidate_name=f"file-{i}.pdf",
                score_at_decision=0.5,
                signals_json=json.dumps(signals),
                proposed_ccis_json=json.dumps([]),
                fingerprint_snapshot_json=json.dumps({}),
                weights_version_id=weights_id,
                included=included,
                auto_prechecked=False,
                consumed_for_training=False,
                created_at=base_time + timedelta(seconds=i),
            )
            s.add(d)
        s.commit()
        ids = [
            r.id
            for r in s.exec(
                select(SweepDecision).order_by(SweepDecision.created_at)  # type: ignore[arg-type]
            ).all()
        ]
    return ids


def _balanced_batch(n: int) -> list[tuple[list[str], bool]]:
    """n/2 included rows with host+priority signals, n/2 excluded with doc-prefix.

    Picks a separable label structure so the SGD fit is well-defined:
    "priority" perfectly predicts kept, "doc-prefix" perfectly predicts
    dropped. Used by the directional-drift test.
    """
    out: list[tuple[list[str], bool]] = []
    half = n // 2
    for _ in range(half):
        out.append((["host:server01", "priority:link"], True))
    for _ in range(n - half):
        out.append((["doc-prefix:DR-"], False))
    return out


# ---------------------------------------------------------------------------
# Below-threshold short-circuit
# ---------------------------------------------------------------------------


def test_update_below_threshold_returns_none_and_writes_nothing(env):
    """Fewer than 25 unconsumed rows → no fit, rows untouched."""
    engine, wb_id = env
    active_id = _seed_active_weights(engine)
    _add_decisions(
        engine,
        wb_id,
        active_id,
        signals_label_pairs=_balanced_batch(MIN_DECISIONS_FOR_ONLINE_FIT - 1),
    )

    with Session(engine) as s:
        result = update_weights_online(s)
    assert result is None

    with Session(engine) as s:
        weights_rows = s.exec(select(SweepWeights)).all()
        decision_rows = s.exec(select(SweepDecision)).all()
    # Only the seeded row exists — no sgd_online row written.
    assert [w.source for w in weights_rows] == ["manual"]
    # No rows consumed — they need to be re-tried next time.
    assert all(d.consumed_for_training is False for d in decision_rows)


# ---------------------------------------------------------------------------
# Single-class refusal
# ---------------------------------------------------------------------------


def test_update_single_class_marks_consumed_and_skips(env):
    """All-included batch → no fit, but rows flipped consumed so they
    don't keep blocking the queue forever.

    The next batch with mixed labels will be the one that trains. We
    intentionally accept the cost of "throwing away" these rows for
    online training — they're still in the corpus for the batch refit
    script, which doesn't care about consumed_for_training.
    """
    engine, wb_id = env
    active_id = _seed_active_weights(engine)
    n = MIN_DECISIONS_FOR_ONLINE_FIT + 5
    pairs = [(["host:server01"], True) for _ in range(n)]
    _add_decisions(engine, wb_id, active_id, signals_label_pairs=pairs)

    with Session(engine) as s:
        result = update_weights_online(s)
    assert result is None

    with Session(engine) as s:
        weights_rows = s.exec(select(SweepWeights)).all()
        decision_rows = s.exec(select(SweepDecision)).all()
    assert [w.source for w in weights_rows] == ["manual"]
    # All rows flipped consumed so the next pass doesn't re-fail on them.
    assert all(d.consumed_for_training is True for d in decision_rows)


# ---------------------------------------------------------------------------
# Happy path — persistence shape
# ---------------------------------------------------------------------------


def test_update_writes_inactive_sgd_row_with_parent_link(env):
    """Balanced batch → exactly one new sgd_online row, not active,
    pointing at the prior active row, with n_decisions_seen bumped."""
    engine, wb_id = env
    active_id = _seed_active_weights(engine)
    n = MIN_DECISIONS_FOR_ONLINE_FIT + 5
    _add_decisions(
        engine, wb_id, active_id, signals_label_pairs=_balanced_batch(n)
    )

    with Session(engine) as s:
        result = update_weights_online(s)
    assert result is not None
    assert result.source == "sgd_online"
    assert result.is_active is False
    assert result.parent_weights_id == active_id
    assert result.n_decisions_seen == n  # warm-start was 0, this is the first batch

    with Session(engine) as s:
        all_w = s.exec(select(SweepWeights).order_by(SweepWeights.id)).all()
    # Original manual row plus the new sgd_online row, in that order.
    assert [w.source for w in all_w] == ["manual", "sgd_online"]
    # Active flag did NOT auto-flip; operator promotes by hand.
    assert [w.is_active for w in all_w] == [True, False]


# ---------------------------------------------------------------------------
# Directional drift
# ---------------------------------------------------------------------------


def test_update_drifts_toward_observed_label_structure(env):
    """If 'priority' always-kept and 'doc-prefix' always-dropped, the new
    weight for 'priority' must not shrink and 'doc-prefix' must shrink
    (or get clipped to zero by the sign constraint).

    We compare to the warm-start values, not zero — the SGD path blends
    the partial_fit toward the warm vector, so the priority weight
    should land somewhere in [warm, warm + drift]. Exact magnitude is
    learning-rate-dependent and not contracted.
    """
    engine, wb_id = env
    active_id = _seed_active_weights(engine)
    n = 60  # bigger batch → more decisive drift
    _add_decisions(
        engine, wb_id, active_id, signals_label_pairs=_balanced_batch(n)
    )

    with Session(engine) as s:
        result = update_weights_online(s)
    assert result is not None

    # priority_link is the perfectly-positive signal — must not move backward.
    assert result.weight_priority_link >= _W_PRIORITY_LINK - 1e-9, (
        f"weight_priority_link={result.weight_priority_link} should be >= "
        f"warm-start {_W_PRIORITY_LINK}"
    )
    # doc-prefix is the perfectly-negative signal — must move down (or be
    # clipped to zero by the sign-constraint guard).
    assert result.weight_doc_prefix < _W_DOC_PREFIX or result.weight_doc_prefix == 0.0, (
        f"weight_doc_prefix={result.weight_doc_prefix} should be < warm-start "
        f"{_W_DOC_PREFIX} or clipped to 0"
    )


# ---------------------------------------------------------------------------
# Consumed flag flip + idempotency
# ---------------------------------------------------------------------------


def test_update_marks_consumed_and_second_call_is_noop(env):
    """After a successful fit, all fed rows have consumed_for_training=True.
    Calling update_weights_online again with no new rows returns None.

    Guarantees the background-task path isn't accidentally re-fitting on
    every triage click — each row contributes to exactly one online
    update across its lifetime.
    """
    engine, wb_id = env
    active_id = _seed_active_weights(engine)
    n = MIN_DECISIONS_FOR_ONLINE_FIT + 5
    _add_decisions(
        engine, wb_id, active_id, signals_label_pairs=_balanced_batch(n)
    )

    with Session(engine) as s:
        first = update_weights_online(s)
    assert first is not None

    with Session(engine) as s:
        decisions = s.exec(select(SweepDecision)).all()
    assert all(d.consumed_for_training is True for d in decisions)

    # Second call with no new unconsumed rows → below threshold → None.
    with Session(engine) as s:
        second = update_weights_online(s)
    assert second is None

    with Session(engine) as s:
        all_w = s.exec(select(SweepWeights)).all()
    # Only the one sgd_online row from the first call — no second write.
    assert sum(1 for w in all_w if w.source == "sgd_online") == 1


# ---------------------------------------------------------------------------
# Cold-start fallback
# ---------------------------------------------------------------------------


def test_update_with_no_active_row_uses_hand_tuned_warm_start(env):
    """No active SweepWeights row → warm-start from _W_* defaults,
    write new row with parent_weights_id=None."""
    engine, wb_id = env
    # Don't seed any active row. _add_decisions will create a non-active
    # anchor row to satisfy the FK; the updater must ignore it because
    # is_active=False.
    n = MIN_DECISIONS_FOR_ONLINE_FIT + 5
    _add_decisions(
        engine, wb_id, weights_id=None, signals_label_pairs=_balanced_batch(n)
    )

    with Session(engine) as s:
        result = update_weights_online(s)
    assert result is not None
    assert result.source == "sgd_online"
    assert result.parent_weights_id is None
    # n_decisions_seen has no prior to bump from, so it equals the batch size.
    assert result.n_decisions_seen == n
