"""Tests for ``scripts/recalibrate_sweep_weights.py`` — the operator
"reset to canonical" batch refit. Counterpart to the live SGD updater.

What we pin down:

1. **Argument-parsing mutex.** ``--activate`` and ``--dry-run`` together
   exit 1 without touching the DB. Operator typo'd "do both" — bail
   loudly before any fit work.

2. **Below-threshold refusal (exit 2).** Fewer than
   ``MIN_DECISIONS_FOR_BATCH_FIT`` (50) rows in the table → no fit, no
   new ``SweepWeights`` row, exit 2. A batch L2 LR on 30 rows is too
   noisy to overwrite the active row with.

3. **Single-class refusal (exit 3).** All-included or all-excluded
   corpora → no fit, no row, exit 3. The fit is mathematically
   degenerate. Distinct from the n<50 case because the operator may
   have a lot of data but it's all one-sided — different diagnostic.

4. **AUC-gate refusal (exit 5).** A corpus where the labels don't track
   the features (random labels) drops CV AUC below 0.70 → no row, exit
   5. The override path is ``--min-auc 0.0``; we exercise both branches.

5. **Happy path (exit 0).** A balanced 60-row separable corpus →
   exactly one new ``SweepWeights`` row with ``source="batch_lr"``,
   ``is_active=False`` by default, ``parent_weights_id`` pointing at
   the prior active row, ``auc`` populated, and the weights actually
   reflect the feature/label correlation (priority_link non-zero,
   doc_prefix clipped or near zero).

6. **--dry-run skips the write.** Even with a perfectly fittable
   corpus, ``--dry-run`` exits 0 without writing a row. Used for
   "show me what the refit would do" before committing.

7. **--activate flips the swap atomically.** With ``--activate``, the
   new row lands ``is_active=True`` AND the previously-active row gets
   flipped to ``is_active=False`` in the same commit — operator gets
   one row active at all times.

We monkeypatch the script's module-level ``engine`` to point at an
in-memory SQLite so the real on-disk DB is never touched. ``init_db``
is also stubbed because the script calls it eagerly and it would
otherwise try to create tables on the real engine.

sklearn is required for the batch fit; module-level ``importorskip``.
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

pytest.importorskip("sklearn", reason="batch recalibration requires scikit-learn")

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
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
from scripts import recalibrate_sweep_weights as script  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def patched_env(tmp_path: Path, monkeypatch):
    """In-memory SQLite + monkeypatched script.engine + monkeypatched init_db.

    The script's ``init_db`` is replaced with a no-op because the in-memory
    engine already has the schema (we call ``SQLModel.metadata.create_all``
    here). Letting the real ``init_db`` run would also re-seed v1
    SweepWeights, which is fine but invisible — we seed our own active row
    explicitly in tests that need one so the assertions are unambiguous.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    monkeypatch.setattr(script, "engine", engine)
    monkeypatch.setattr(script, "init_db", lambda: None)

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
    """Insert one is_active=True SweepWeights row, return id."""
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
    weights_id: int,
    *,
    signals_label_pairs: list[tuple[list[str], bool]],
) -> None:
    """Bulk-insert SweepDecision rows."""
    base = datetime.now(timezone.utc) - timedelta(hours=1)
    with Session(engine) as s:
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
                created_at=base + timedelta(seconds=i),
            )
            s.add(d)
        s.commit()


def _separable_batch(n: int) -> list[tuple[list[str], bool]]:
    """Perfectly-separable corpus: half kept (priority+host), half dropped
    (doc-prefix only). 5-fold CV AUC should land near 1.0 on this.
    """
    out: list[tuple[list[str], bool]] = []
    half = n // 2
    for _ in range(half):
        out.append((["host:server01", "priority:link"], True))
    for _ in range(n - half):
        out.append((["doc-prefix:DR-"], False))
    return out


def _random_labeled_batch(n: int, seed: int = 0) -> list[tuple[list[str], bool]]:
    """Signals + labels with no correlation → CV AUC near 0.5.

    Uses Python's stdlib random with a fixed seed so the test is
    deterministic. Each row gets a random signal set drawn from the
    full alphabet, paired with a random label.
    """
    import random

    rng = random.Random(seed)
    palette = [
        "host:server01",
        "control:ac-2",
        "family:AC",
        "crm-kw:audit",
        "doc-prefix:DR-",
        "priority:link",
    ]
    out: list[tuple[list[str], bool]] = []
    for _ in range(n):
        # pick 1-3 random signals
        k = rng.randint(1, 3)
        sigs = rng.sample(palette, k)
        out.append((sigs, bool(rng.randint(0, 1))))
    return out


# ---------------------------------------------------------------------------
# Argument-parsing mutex
# ---------------------------------------------------------------------------


def test_activate_and_dry_run_are_mutually_exclusive(patched_env):
    """``--activate --dry-run`` → exit 1 before any DB work."""
    engine, _ = patched_env
    # Don't seed anything — the mutex check must precede DB access.
    code = script.main(["--activate", "--dry-run"])
    assert code == 1

    with Session(engine) as s:
        assert s.exec(select(SweepWeights)).all() == []


# ---------------------------------------------------------------------------
# Below-threshold refusal
# ---------------------------------------------------------------------------


def test_refuses_when_fewer_than_min_decisions(patched_env):
    """n < MIN_DECISIONS_FOR_BATCH_FIT → exit 2, no SweepWeights row written."""
    engine, wb_id = patched_env
    active_id = _seed_active_weights(engine)
    # 30 rows — separable but undersized.
    _add_decisions(
        engine, wb_id, active_id, signals_label_pairs=_separable_batch(30)
    )

    code = script.main([])
    assert code == 2

    with Session(engine) as s:
        rows = s.exec(select(SweepWeights)).all()
    # Only the seeded manual row — no batch_lr row appended.
    assert [w.source for w in rows] == ["manual"]


# ---------------------------------------------------------------------------
# Single-class refusal
# ---------------------------------------------------------------------------


def test_refuses_when_corpus_is_single_class(patched_env):
    """All-included corpus → exit 3 (degenerate fit), no row written."""
    engine, wb_id = patched_env
    active_id = _seed_active_weights(engine)
    # 60 rows but all included=True.
    pairs = [(["host:server01"], True) for _ in range(60)]
    _add_decisions(engine, wb_id, active_id, signals_label_pairs=pairs)

    code = script.main([])
    assert code == 3

    with Session(engine) as s:
        rows = s.exec(select(SweepWeights)).all()
    assert [w.source for w in rows] == ["manual"]


# ---------------------------------------------------------------------------
# AUC gate
# ---------------------------------------------------------------------------


def test_refuses_when_cv_auc_below_threshold(patched_env):
    """Random labels → CV AUC near 0.5 → exit 5 with default --min-auc 0.70."""
    engine, wb_id = patched_env
    active_id = _seed_active_weights(engine)
    # 200 rows of garbage labels — well above n threshold, but unfittable.
    _add_decisions(
        engine, wb_id, active_id, signals_label_pairs=_random_labeled_batch(200)
    )

    code = script.main([])
    assert code == 5

    with Session(engine) as s:
        rows = s.exec(select(SweepWeights)).all()
    # No batch_lr row written — only the seeded manual row.
    assert [w.source for w in rows] == ["manual"]


def test_min_auc_zero_override_writes_row_even_when_features_dont_separate(
    patched_env,
):
    """``--min-auc 0`` disables the gate — operator opt-in for diagnostic
    comparison even when the labels are noisy. Row is still written with
    ``is_active=False`` so nothing surprising goes live.
    """
    engine, wb_id = patched_env
    active_id = _seed_active_weights(engine)
    _add_decisions(
        engine, wb_id, active_id, signals_label_pairs=_random_labeled_batch(200)
    )

    code = script.main(["--min-auc", "0"])
    assert code == 0

    with Session(engine) as s:
        rows = s.exec(select(SweepWeights).order_by(SweepWeights.id)).all()
    assert [w.source for w in rows] == ["manual", "batch_lr"]
    new = rows[1]
    assert new.is_active is False  # default — no --activate
    assert new.parent_weights_id == active_id


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_separable_corpus_writes_inactive_batch_lr_row_with_auc(patched_env):
    """60 separable rows → exit 0, new batch_lr row, is_active=False,
    parent_weights_id linked, auc field populated, weights reflect labels.
    """
    engine, wb_id = patched_env
    active_id = _seed_active_weights(engine)
    _add_decisions(
        engine, wb_id, active_id, signals_label_pairs=_separable_batch(60)
    )

    code = script.main([])
    assert code == 0

    with Session(engine) as s:
        rows = s.exec(select(SweepWeights).order_by(SweepWeights.id)).all()
    assert [w.source for w in rows] == ["manual", "batch_lr"]
    new = rows[1]
    assert new.is_active is False
    assert new.parent_weights_id == active_id
    assert new.n_decisions_seen == 60
    assert new.auc is not None
    # Separable corpus → AUC should be very high.
    assert new.auc >= 0.95, f"expected AUC near 1.0 on separable corpus, got {new.auc}"
    # priority_link was positively correlated with kept → must end positive.
    assert new.weight_priority_link > 0.0
    # doc_prefix was perfectly negatively correlated → clipped to zero
    # (the script's _clip_coefficients forbids negative weights).
    assert new.weight_doc_prefix == 0.0


# ---------------------------------------------------------------------------
# --dry-run
# ---------------------------------------------------------------------------


def test_dry_run_does_not_write_a_row(patched_env):
    """--dry-run on a perfectly fittable corpus → exit 0, no SweepWeights
    row appended.
    """
    engine, wb_id = patched_env
    active_id = _seed_active_weights(engine)
    _add_decisions(
        engine, wb_id, active_id, signals_label_pairs=_separable_batch(60)
    )

    code = script.main(["--dry-run"])
    assert code == 0

    with Session(engine) as s:
        rows = s.exec(select(SweepWeights)).all()
    # Only the seeded row — no batch_lr write.
    assert [w.source for w in rows] == ["manual"]


# ---------------------------------------------------------------------------
# --activate atomic swap
# ---------------------------------------------------------------------------


def test_activate_flips_old_off_and_new_on_atomically(patched_env):
    """--activate → new row is_active=True, previous active row flipped off,
    exactly one active row at end-of-commit.
    """
    engine, wb_id = patched_env
    active_id = _seed_active_weights(engine)
    _add_decisions(
        engine, wb_id, active_id, signals_label_pairs=_separable_batch(60)
    )

    code = script.main(["--activate"])
    assert code == 0

    with Session(engine) as s:
        rows = s.exec(select(SweepWeights).order_by(SweepWeights.id)).all()
    assert len(rows) == 2
    old, new = rows
    assert old.id == active_id
    assert old.is_active is False  # flipped off by the swap
    assert new.source == "batch_lr"
    assert new.is_active is True
    # Exactly one active row in the DB at end-of-commit.
    active_rows = [w for w in rows if w.is_active]
    assert len(active_rows) == 1
    assert active_rows[0].id == new.id
