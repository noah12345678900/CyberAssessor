"""Batch IsolationForest refit for CRM anomaly detection.

Operator-invoked counterpart to the live scoring path in
``engine.crm_ml.score_anomaly``. Pulls every ``CrmCorpusFeatures`` row
at the current feature schema version, fits a fresh IsolationForest,
and writes a new ``CrmAnomalyModel`` row.

Run from ``backend/`` with the project venv:

    cd backend
    uv run python scripts/refit_crm_anomaly_model.py [--activate] [--dry-run]

Why this is operator-triggered (not auto-fitted on every CRM upload):

  * IsolationForest fits are cheap (sub-second at corpus sizes in the
    hundreds), but **changing the active model changes scoring behavior
    for every future CRM**. That's an operator-visible decision, not a
    silent background side-effect.
  * The fit script prints the training-set anomaly score distribution
    (min/max/mean/stdev) so the operator can eyeball whether the new
    model spreads the corpus the way they expect before promoting.
  * It also keeps the train/serve split clean: the sidecar never imports
    sklearn at request time for scoring (joblib unpickle only — the
    pickled IsolationForest brings sklearn in lazily on first score).

Schema versioning:

  ``CrmCorpusFeatures`` rows persist with the
  ``CURRENT_FEATURE_SCHEMA_VERSION`` they were extracted under. When the
  version bumps, this script silently ignores old rows (they're kept for
  diagnostics, never deleted). This is the right default — fitting on
  mixed-schema rows would produce a model that misinterprets feature
  columns at score time.

Refusal conditions:

  * Fewer than ``MIN_CORPUS_SIZE`` (10) in-version rows: IsolationForest
    on a tiny corpus learns nothing useful. Exits 2 with a diagnostic
    showing total rows vs in-version rows so the operator can tell
    whether they're cold-start short or schema-version mismatched.
  * sklearn/joblib unavailable in the environment. Exits 4.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from sqlmodel import Session, select

# Make this script runnable both as ``python scripts/refit_crm_anomaly_model.py``
# from backend/ and as ``python -m scripts.refit_crm_anomaly_model``.
_THIS_DIR = Path(__file__).resolve().parent
_BACKEND_ROOT = _THIS_DIR.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from cybersecurity_assessor.db import engine, init_db  # noqa: E402
from cybersecurity_assessor.engine.crm_ml import (  # noqa: E402
    CURRENT_FEATURE_SCHEMA_VERSION,
    MIN_CORPUS_SIZE,
    CrmFeatureVector,
)
from cybersecurity_assessor.models import CrmAnomalyModel, CrmCorpusFeatures  # noqa: E402

log = logging.getLogger("refit_crm_anomaly_model")


def _collect_corpus(
    session: Session,
) -> tuple[list[CrmFeatureVector], int, int]:
    """Pull all CrmCorpusFeatures rows, filter to the current schema version.

    Returns ``(in_version_vectors, total_rows, skipped_wrong_version)``.
    Rows whose ``features_json`` is unparseable are skipped silently —
    they're a serialization bug, not an operator-actionable diagnostic.
    """
    rows = session.exec(select(CrmCorpusFeatures)).all()
    total = len(rows)
    in_version: list[CrmFeatureVector] = []
    wrong_version = 0
    for r in rows:
        if r.feature_schema_version != CURRENT_FEATURE_SCHEMA_VERSION:
            wrong_version += 1
            continue
        try:
            vec = CrmFeatureVector.from_json(r.features_json)
        except (ValueError, KeyError, TypeError) as e:
            log.warning(
                "skipping CrmCorpusFeatures id=%s (unparseable features_json: %s)",
                r.id,
                e,
            )
            continue
        # Belt-and-suspenders: the JSON could embed a different schema version
        # than the DB column says. Trust the deserialized value, not the row.
        if vec.schema_version != CURRENT_FEATURE_SCHEMA_VERSION:
            wrong_version += 1
            continue
        in_version.append(vec)
    return in_version, total, wrong_version


def refit(*, activate: bool, dry_run: bool) -> int:
    """Run one IsolationForest refit. Returns a shell exit code (0 = success)."""
    init_db()

    try:
        from cybersecurity_assessor.engine.crm_ml import fit_anomaly_model
    except ImportError as e:
        log.error("crm_ml import failed: %s", e)
        return 4

    with Session(engine) as session:
        corpus, total_rows, wrong_version = _collect_corpus(session)
        log.info(
            "corpus: %d rows total, %d at current schema v%d, %d at other versions",
            total_rows,
            len(corpus),
            CURRENT_FEATURE_SCHEMA_VERSION,
            wrong_version,
        )

        if len(corpus) < MIN_CORPUS_SIZE:
            log.error(
                "refusing to fit: %d in-version rows < MIN_CORPUS_SIZE (%d). "
                "%s",
                len(corpus),
                MIN_CORPUS_SIZE,
                (
                    "Upload more CRMs to grow the corpus."
                    if wrong_version == 0
                    else f"Note: {wrong_version} rows are at an older feature "
                    f"schema and were ignored — re-extracting them would help."
                ),
            )
            return 2

        try:
            fit_result = fit_anomaly_model(corpus)
        except ValueError as e:
            # crm_ml.fit_anomaly_model raises ValueError on undersized corpus
            # or wrong schema — we pre-checked both, so this is defensive only.
            log.error("fit_anomaly_model rejected the corpus: %s", e)
            return 2
        except ImportError as e:
            log.error(
                "sklearn / joblib / numpy not installed — install backend dev extras: %s",
                e,
            )
            return 4

        meta = fit_result.metadata
        print()
        print("IsolationForest refit summary:")
        print(f"  Samples:          {meta['n_samples']}")
        print(f"  Feature schema:   v{meta['feature_schema_version']}")
        print(f"  Features/row:     {meta['n_features']}")
        print(f"  Training score:   min={meta['training_score_min']:+.4f}  "
              f"max={meta['training_score_max']:+.4f}  "
              f"mean={meta['training_score_mean']:+.4f}  "
              f"stdev={meta['training_score_stdev']:.4f}")
        print()
        print(
            "  Reminder: IsolationForest score_samples returns negative-of-path-length; "
            "more-negative = more-anomalous. A tight stdev means the corpus is "
            "homogeneous (most new CRMs will score near the mean); a wide stdev "
            "means meaningful spread between typical and outlier CRMs."
        )
        print()

        if dry_run:
            log.info("--dry-run set; not writing CrmAnomalyModel row")
            return 0

        active = session.exec(
            select(CrmAnomalyModel).where(CrmAnomalyModel.is_active.is_(True)).limit(1)  # type: ignore[union-attr]
        ).first()

        notes_payload = {
            "fit_metadata": meta,
            "wrong_version_rows_ignored": wrong_version,
            "total_corpus_rows_at_fit_time": total_rows,
            "parent_active_model_id": active.id if active else None,
        }

        new_row = CrmAnomalyModel(
            n_samples=meta["n_samples"],
            feature_schema_version=meta["feature_schema_version"],
            model_blob=fit_result.model_blob,
            notes=json.dumps(notes_payload, indent=2),
            is_active=False,
        )
        session.add(new_row)

        if activate and active is not None:
            # Atomic swap: deactivate old, activate new in the same commit.
            active.is_active = False
            session.add(active)
        if activate:
            new_row.is_active = True

        session.commit()
        session.refresh(new_row)

        log.info(
            "wrote CrmAnomalyModel id=%s (n_samples=%d, is_active=%s)",
            new_row.id,
            new_row.n_samples,
            new_row.is_active,
        )
        if not activate:
            print(
                f"New CrmAnomalyModel id={new_row.id} written with is_active=False. "
                "Review the training score distribution above, spot-check a "
                "few CRMs against the new model if you can, then promote with "
                "--activate (or flip is_active in the DB)."
            )
        return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Batch-refit the CRM IsolationForest anomaly model from "
            "CrmCorpusFeatures history. By default writes a new "
            "CrmAnomalyModel row with is_active=False so the operator can "
            "review the training-score spread before promoting."
        )
    )
    p.add_argument(
        "--activate",
        action="store_true",
        help="Flip is_active on the new row and deactivate the prior active row.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Fit and print the training-score distribution, then exit without writing.",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="DEBUG-level logging.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.activate and args.dry_run:
        log.error("--activate and --dry-run are mutually exclusive")
        return 1
    return refit(activate=args.activate, dry_run=args.dry_run)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
