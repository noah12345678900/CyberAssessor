"""Tests for ``scripts/refit_crm_anomaly_model.py`` — the operator-invoked
batch refit of the CRM IsolationForest. Counterpart to live scoring in
:func:`engine.crm_ml.score_anomaly` and the live-recompute path in
``routes/baselines.py::compute_crm_suspicion``.

What we pin down:

1. **Argument-parsing mutex.** ``--activate --dry-run`` together exit 1
   without touching the DB. Operator typo of "do both" must bail loudly
   before any fit work.

2. **Below-MIN_CORPUS_SIZE refusal (exit 2).** Fewer than 10 in-version
   rows → no fit, no ``CrmAnomalyModel`` row written, exit 2. The fit
   would learn essentially nothing at smaller sizes (every point is its
   own outlier under IsolationForest's path-length math).

3. **Schema-version filtering.** Rows whose
   ``feature_schema_version != CURRENT_FEATURE_SCHEMA_VERSION`` are
   silently ignored. If filtering pushes the in-version count below the
   threshold the script refuses (exit 2) — proving the script counts
   only what it'll fit on, not raw row totals.

4. **Happy path (exit 0).** A 12-row in-version corpus → exactly one
   new ``CrmAnomalyModel`` row, ``is_active=False`` by default,
   ``n_samples=12``, ``feature_schema_version`` matching CURRENT, a
   non-empty ``model_blob``, and ``notes`` containing the fit metadata
   plus ``parent_active_model_id`` linking to the prior active row.

5. **--dry-run skips the write.** Even with a fittable corpus,
   ``--dry-run`` exits 0 without writing a row. Operators use this to
   eyeball the training-score distribution before committing.

6. **--activate flips the swap atomically.** With ``--activate``, the
   new row lands ``is_active=True`` AND the previously-active row is
   flipped to ``is_active=False`` in the same commit. Exactly one row
   is_active at any time.

7. **The model_blob round-trips through score_anomaly.** Pin the
   train→serve contract: the joblib bytes the script writes must be
   loadable by the inference path. Cheapest catch for a swap that
   accidentally pickles a non-IsolationForest object.

We monkeypatch the script's module-level ``engine`` to point at an
in-memory SQLite so the on-disk DB is never touched. ``init_db`` is
stubbed because the script calls it eagerly and would otherwise try to
create tables on the real engine.

sklearn + joblib are required for the fit; module-level ``importorskip``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

pytest.importorskip("sklearn", reason="IsolationForest refit requires scikit-learn")
pytest.importorskip("joblib", reason="model blob persistence requires joblib")

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine.crm_ml import (  # noqa: E402
    CURRENT_FEATURE_SCHEMA_VERSION,
    CrmFeatureVector,
    score_anomaly,
)
from cybersecurity_assessor.models import CrmAnomalyModel, CrmCorpusFeatures  # noqa: E402
from scripts import refit_crm_anomaly_model as script  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def patched_env(monkeypatch):
    """In-memory SQLite + monkeypatched script.engine + monkeypatched init_db.

    The script's ``init_db`` is stubbed to a no-op because the in-memory
    engine already has the schema (we call ``SQLModel.metadata.create_all``
    here). Letting the real ``init_db`` run would re-target the on-disk
    sidecar DB.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(script, "engine", engine)
    monkeypatch.setattr(script, "init_db", lambda: None)
    yield engine


def _make_vector(
    i: int, *, schema_version: int = CURRENT_FEATURE_SCHEMA_VERSION
) -> CrmFeatureVector:
    """Build a synthetic in-corpus vector. Values vary across i so the
    IsolationForest fit isn't degenerate (identical rows → ConstantInputWarning).
    """
    return CrmFeatureVector(
        schema_version=schema_version,
        inherited_pct=0.40 + (i % 5) * 0.05,
        provider_pct=0.10 + (i % 3) * 0.05,
        not_applicable_pct=0.05 + (i % 4) * 0.02,
        narrative_present_pct=0.70 + (i % 5) * 0.03,
        narrative_len_mean=120.0 + i * 7.0,
        narrative_len_stdev=30.0 + (i % 6) * 4.0,
        intra_crm_tfidf_max_similarity=0.5 + (i % 5) * 0.05,
        intra_crm_tfidf_mean_similarity=0.2 + (i % 4) * 0.03,
        family_evidence_contradictions=i % 3,
        in_scope_control_count=200 + i * 4,
    )


def _seed_corpus_rows(
    engine,
    n: int,
    *,
    schema_version: int = CURRENT_FEATURE_SCHEMA_VERSION,
    crm_baseline_id: int = 99,
    workbook_id: int = 1,
) -> None:
    """Insert n ``CrmCorpusFeatures`` rows at the given schema version."""
    with Session(engine) as s:
        for i in range(n):
            vec = _make_vector(i, schema_version=schema_version)
            s.add(
                CrmCorpusFeatures(
                    crm_baseline_id=crm_baseline_id,
                    workbook_id=workbook_id,
                    feature_schema_version=schema_version,
                    features_json=vec.to_json(),
                )
            )
        s.commit()


def _seed_active_model(engine) -> int:
    """Insert one ``is_active=True`` CrmAnomalyModel row, return its id.

    The blob can be a placeholder — the active row is only consulted for
    the swap behavior in ``--activate`` and the ``parent_active_model_id``
    pointer in the notes; nothing here re-loads it as a joblib pickle.
    """
    with Session(engine) as s:
        row = CrmAnomalyModel(
            n_samples=10,
            feature_schema_version=CURRENT_FEATURE_SCHEMA_VERSION,
            model_blob=b"\x00placeholder\x00",
            notes="placeholder active model",
            is_active=True,
        )
        s.add(row)
        s.commit()
        s.refresh(row)
        return row.id


# ---------------------------------------------------------------------------
# Argument-parsing mutex
# ---------------------------------------------------------------------------


def test_activate_and_dry_run_are_mutually_exclusive(patched_env):
    """``--activate --dry-run`` → exit 1 before any DB work."""
    code = script.main(["--activate", "--dry-run"])
    assert code == 1

    with Session(patched_env) as s:
        assert s.exec(select(CrmAnomalyModel)).all() == []


# ---------------------------------------------------------------------------
# Below-MIN_CORPUS_SIZE refusal
# ---------------------------------------------------------------------------


def test_refuses_when_corpus_below_min_size(patched_env):
    """5 rows < MIN_CORPUS_SIZE (10) → exit 2, no model row written."""
    _seed_corpus_rows(patched_env, n=5)
    code = script.main([])
    assert code == 2

    with Session(patched_env) as s:
        assert s.exec(select(CrmAnomalyModel)).all() == []


def test_refuses_when_in_version_corpus_below_min_even_if_total_above(patched_env):
    """20 total rows, only 5 at current schema → exit 2. Pins that the
    threshold is checked against IN-VERSION count, not raw row total.
    """
    _seed_corpus_rows(patched_env, n=5, schema_version=CURRENT_FEATURE_SCHEMA_VERSION)
    # 15 stale rows at an older version — should be ignored.
    _seed_corpus_rows(
        patched_env,
        n=15,
        schema_version=CURRENT_FEATURE_SCHEMA_VERSION - 1,
    )

    code = script.main([])
    assert code == 2

    with Session(patched_env) as s:
        assert s.exec(select(CrmAnomalyModel)).all() == []


# ---------------------------------------------------------------------------
# Happy path — write CrmAnomalyModel row with is_active=False by default
# ---------------------------------------------------------------------------


def test_happy_path_writes_one_inactive_row_with_parent_pointer(patched_env):
    """12 in-version rows + a prior active model → one new row with
    ``is_active=False`` (operator review required), ``n_samples=12``,
    ``feature_schema_version`` matching CURRENT, non-empty
    ``model_blob``, and notes JSON containing the parent pointer.
    """
    prior_active_id = _seed_active_model(patched_env)
    _seed_corpus_rows(patched_env, n=12)

    code = script.main([])
    assert code == 0

    with Session(patched_env) as s:
        rows = s.exec(select(CrmAnomalyModel).order_by(CrmAnomalyModel.id)).all()

    assert len(rows) == 2
    new_row = rows[-1]
    assert new_row.id != prior_active_id
    assert new_row.is_active is False
    assert new_row.n_samples == 12
    assert new_row.feature_schema_version == CURRENT_FEATURE_SCHEMA_VERSION
    assert isinstance(new_row.model_blob, (bytes, bytearray))
    assert len(new_row.model_blob) > 0

    notes_payload = json.loads(new_row.notes)
    assert notes_payload["parent_active_model_id"] == prior_active_id
    assert notes_payload["total_corpus_rows_at_fit_time"] == 12
    assert notes_payload["wrong_version_rows_ignored"] == 0
    assert notes_payload["fit_metadata"]["n_samples"] == 12

    # Prior active row stays active (no --activate flag).
    prior = next(r for r in rows if r.id == prior_active_id)
    assert prior.is_active is True


def test_happy_path_ignores_wrong_version_rows_in_fit(patched_env):
    """Mixed corpus: 12 at current + 5 at old version → fit on 12 only,
    notes reports ``wrong_version_rows_ignored=5``.
    """
    _seed_corpus_rows(patched_env, n=12)
    _seed_corpus_rows(patched_env, n=5, schema_version=CURRENT_FEATURE_SCHEMA_VERSION - 1)

    code = script.main([])
    assert code == 0

    with Session(patched_env) as s:
        rows = s.exec(select(CrmAnomalyModel)).all()
    assert len(rows) == 1
    notes = json.loads(rows[0].notes)
    assert rows[0].n_samples == 12
    assert notes["wrong_version_rows_ignored"] == 5
    assert notes["total_corpus_rows_at_fit_time"] == 17


# ---------------------------------------------------------------------------
# --dry-run
# ---------------------------------------------------------------------------


def test_dry_run_with_fittable_corpus_writes_nothing(patched_env):
    """``--dry-run`` exits 0 but does NOT persist a CrmAnomalyModel row."""
    _seed_corpus_rows(patched_env, n=12)
    code = script.main(["--dry-run"])
    assert code == 0

    with Session(patched_env) as s:
        assert s.exec(select(CrmAnomalyModel)).all() == []


# ---------------------------------------------------------------------------
# --activate (atomic swap)
# ---------------------------------------------------------------------------


def test_activate_flips_swap_atomically(patched_env):
    """``--activate`` writes the new row with ``is_active=True`` AND flips
    the prior active row to ``is_active=False`` — exactly one active row
    after the script returns.
    """
    prior_active_id = _seed_active_model(patched_env)
    _seed_corpus_rows(patched_env, n=12)

    code = script.main(["--activate"])
    assert code == 0

    with Session(patched_env) as s:
        rows = s.exec(select(CrmAnomalyModel)).all()
    actives = [r for r in rows if r.is_active]
    assert len(actives) == 1
    assert actives[0].id != prior_active_id
    assert actives[0].n_samples == 12

    prior = next(r for r in rows if r.id == prior_active_id)
    assert prior.is_active is False


def test_activate_without_prior_active_just_activates_new_row(patched_env):
    """No prior active model → ``--activate`` still works; new row lands
    active and is the only model row in the DB.
    """
    _seed_corpus_rows(patched_env, n=12)
    code = script.main(["--activate"])
    assert code == 0

    with Session(patched_env) as s:
        rows = s.exec(select(CrmAnomalyModel)).all()
    assert len(rows) == 1
    assert rows[0].is_active is True


# ---------------------------------------------------------------------------
# Train → serve contract — the blob must score new vectors
# ---------------------------------------------------------------------------


def test_written_model_blob_round_trips_through_score_anomaly(patched_env):
    """The script's ``model_blob`` must be loadable by the inference path.
    Cheapest catch for a pickling regression that would silently break
    live scoring in ``routes/baselines.py``.
    """
    _seed_corpus_rows(patched_env, n=12)
    code = script.main([])
    assert code == 0

    with Session(patched_env) as s:
        row = s.exec(select(CrmAnomalyModel)).first()
    assert row is not None

    # Score a synthetic vector — anything in [0, 1] proves the blob is
    # a real fitted IsolationForest, not a corrupted pickle.
    s_score = score_anomaly(row.model_blob, _make_vector(0))
    assert 0.0 <= s_score <= 1.0
