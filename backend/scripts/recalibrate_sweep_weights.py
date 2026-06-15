"""Batch logistic-regression recalibration of sweep weights.

Operator's "reset to canonical" path. Where ``engine.sweep_online`` drifts
the active ``SweepWeights`` row toward operator behavior one mini-batch at
a time (SGD ``partial_fit``), this script fits a full L2 logistic regression
over **all** historical ``SweepDecision`` rows in one shot.

Run from ``backend/`` with the project venv:

    cd backend
    uv run python scripts/recalibrate_sweep_weights.py [--activate] [--dry-run]

Why this exists alongside the online updater:

  * Online SGD is great for tracking gradual preference drift but can wander
    off-canonical if the operator goes through a streak of unusual triage
    sessions (e.g. one project where everything is custom-named and no
    candidates match the ``host:`` indicator). The batch refit pulls weights
    back to the global optimum across the entire decision history.
  * A batch fit gives us a real held-out AUC (5-fold CV) we can stamp onto
    the new ``SweepWeights`` row. The online path can't compute one — its
    mini-batches are too small.
  * Manual invocation by an operator is the right interaction model: a
    batch refit changes scoring behavior for every future sweep, so the
    operator should be the one initiating it (and reviewing AUC before
    flipping ``is_active``).

Train/serve split (per the ML architecture rule):

  * **Inference** (``score_candidate``) loads ``SweepWeights`` from DB,
    does pure vector math. No sklearn at the hot path.
  * **Training** (this script) imports ``sklearn.linear_model`` and
    ``sklearn.model_selection`` lazily, only when fitting.

Refusal conditions:

  * Fewer than ``MIN_DECISIONS_FOR_BATCH_FIT`` (50) rows in the table:
    L2 LR on a tiny corpus is too noisy to overwrite the active row with.
    Exits 2.
  * Only one class present (everything kept or everything dropped): the
    fit is degenerate. Exits 3.
  * Cross-validated AUC below ``--min-auc`` (default 0.70): the features
    aren't separating the labels well enough to trust the new weights.
    The operator can override with ``--min-auc 0.0`` if they explicitly
    want the row written for diagnostic comparison.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from sqlmodel import Session, select

# Make this script runnable both as ``python scripts/recalibrate_sweep_weights.py``
# from backend/ and as ``python -m scripts.recalibrate_sweep_weights``.
_THIS_DIR = Path(__file__).resolve().parent
_BACKEND_ROOT = _THIS_DIR.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from cybersecurity_assessor.db import engine, init_db  # noqa: E402
from cybersecurity_assessor.engine.sweep_online import (  # noqa: E402
    FEATURE_NAMES,
    MIN_DECISIONS_FOR_BATCH_FIT,
    _active_weights_to_vector,
    _clip_coefficients,
    decision_to_features,
)
from cybersecurity_assessor.evidence.sources.sweep import (  # noqa: E402
    SCORE_PRECHECK_THRESHOLD,
    SCORE_SURFACE_THRESHOLD,
)
from cybersecurity_assessor.models import SweepDecision, SweepWeights  # noqa: E402

log = logging.getLogger("recalibrate_sweep_weights")

DEFAULT_MIN_AUC = 0.70


def _format_weights_table(
    old: list[float], new: list[float], names: tuple[str, ...] = FEATURE_NAMES
) -> str:
    """Pretty-print an old-vs-new weights comparison so the operator can
    eyeball the magnitude of the change before deciding to ``--activate``.
    """
    lines = [f"  {'signal':<12} {'old':>8} {'new':>8} {'delta':>8}"]
    for name, o, n in zip(names, old, new):
        lines.append(f"  {name:<12} {o:>8.4f} {n:>8.4f} {n - o:>+8.4f}")
    return "\n".join(lines)


def _collect_all_features(session: Session) -> tuple[list[list[float]], list[int], int]:
    """Pull every SweepDecision, return (X, y, skipped_count).

    Unlike the online updater, batch refit ignores ``consumed_for_training``
    — we're rebuilding from scratch, not advancing a streaming cursor.
    Rows whose ``signals_json`` is unparseable are skipped and counted.
    """
    rows = session.exec(select(SweepDecision)).all()
    X: list[list[float]] = []
    y: list[int] = []
    skipped = 0
    for r in rows:
        fr = decision_to_features(r)
        if fr is None:
            skipped += 1
            continue
        X.append(list(fr.features))
        y.append(fr.label)
    return X, y, skipped


def recalibrate(
    *,
    activate: bool,
    dry_run: bool,
    min_auc: float,
) -> int:
    """Run one batch refit. Returns a shell exit code (0 = success)."""
    init_db()

    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import cross_val_score
    except ImportError as e:
        log.error(
            "scikit-learn / numpy not installed — install backend dev extras: %s", e
        )
        return 4

    with Session(engine) as session:
        X_list, y_list, skipped = _collect_all_features(session)
        n = len(X_list)
        log.info("collected %d usable decisions (%d unparseable rows skipped)", n, skipped)

        if n < MIN_DECISIONS_FOR_BATCH_FIT:
            log.error(
                "refusing to fit: have %d decisions, need >= %d (set MIN_DECISIONS_FOR_BATCH_FIT lower in code if you really want this)",
                n,
                MIN_DECISIONS_FOR_BATCH_FIT,
            )
            return 2

        X = np.asarray(X_list, dtype=np.float64)
        y = np.asarray(y_list, dtype=np.int64)

        unique_labels = sorted(set(y.tolist()))
        if len(unique_labels) < 2:
            log.error(
                "refusing to fit: all %d decisions have label=%s (need both 0 and 1)",
                n,
                unique_labels[0] if unique_labels else "?",
            )
            return 3

        active = session.exec(
            select(SweepWeights).where(SweepWeights.is_active.is_(True)).limit(1)  # type: ignore[union-attr]
        ).first()
        old_vec = _active_weights_to_vector(active)

        clf = LogisticRegression(
            penalty="l2",
            C=1.0,
            max_iter=1000,
            solver="liblinear",
            random_state=42,
        )

        # 5-fold CV AUC computed BEFORE the final fit so we report
        # generalization, not training accuracy.
        try:
            cv_scores = cross_val_score(clf, X, y, cv=5, scoring="roc_auc")
            cv_auc = float(cv_scores.mean())
            cv_std = float(cv_scores.std())
        except ValueError as e:
            # Happens when one CV fold ends up with a single class — the
            # corpus is large enough in aggregate but too skewed for k=5.
            log.warning(
                "5-fold CV failed (%s) — falling back to 3-fold", e
            )
            cv_scores = cross_val_score(clf, X, y, cv=3, scoring="roc_auc")
            cv_auc = float(cv_scores.mean())
            cv_std = float(cv_scores.std())

        log.info("CV AUC = %.4f (std %.4f) across %d folds", cv_auc, cv_std, len(cv_scores))

        if cv_auc < min_auc:
            log.error(
                "refusing to write: CV AUC %.4f < threshold %.4f. "
                "Features aren't separating included/excluded decisions well. "
                "Re-run with --min-auc <lower> to override, or investigate label noise.",
                cv_auc,
                min_auc,
            )
            return 5

        # Fit on the full corpus to produce the final coefficients.
        clf.fit(X, y)
        raw_coefs = clf.coef_.flatten().tolist()
        clipped, warnings_ = _clip_coefficients(raw_coefs)
        intercept = float(clf.intercept_[0])

        print()
        print("Weights diff (active → proposed batch_lr):")
        print(_format_weights_table(old_vec, clipped))
        print()
        print(f"  CV AUC:       {cv_auc:.4f} ± {cv_std:.4f}")
        print(f"  Intercept:    {intercept:+.4f}")
        print(f"  Decisions:    {n}")
        if warnings_:
            print()
            print("  Clipping warnings:")
            for w in warnings_:
                print(f"    - {w}")
        print()

        if dry_run:
            log.info("--dry-run set; not writing SweepWeights row")
            return 0

        notes_lines = [
            f"Batch L2 logistic regression on {n} decisions",
            f"5-fold CV AUC = {cv_auc:.4f} (std {cv_std:.4f})",
            f"parent active row = {'id=' + str(active.id) if active else 'none (no prior active row)'}",
        ]
        if warnings_:
            notes_lines.append("WARN: " + "; ".join(warnings_))

        new_row = SweepWeights(
            source="batch_lr",
            weight_host=clipped[0],
            weight_control_id=clipped[1],
            weight_family=clipped[2],
            weight_crm_keyword=clipped[3],
            weight_doc_prefix=clipped[4],
            weight_priority_link=clipped[5],
            intercept=intercept,
            surface_threshold=(
                active.surface_threshold if active else SCORE_SURFACE_THRESHOLD
            ),
            precheck_threshold=(
                active.precheck_threshold if active else SCORE_PRECHECK_THRESHOLD
            ),
            n_decisions_seen=n,
            auc=cv_auc,
            parent_weights_id=active.id if active else None,
            notes="\n".join(notes_lines),
            is_active=False,  # operator flips after review; --activate flips here
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
            "wrote SweepWeights id=%s (source=batch_lr, is_active=%s)",
            new_row.id,
            new_row.is_active,
        )
        if not activate:
            print(
                f"New row id={new_row.id} written with is_active=False. "
                "Review in the UI and toggle active when ready, "
                "or re-run with --activate to promote in one step."
            )
        return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Batch-refit sweep weights from SweepDecision history. "
            "By default writes a new SweepWeights row with is_active=False so "
            "the operator can review CV AUC before promoting."
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
        help="Print the proposed weights + AUC and exit without writing.",
    )
    p.add_argument(
        "--min-auc",
        type=float,
        default=DEFAULT_MIN_AUC,
        help=(
            f"Minimum 5-fold CV AUC required to write the new row "
            f"(default {DEFAULT_MIN_AUC:.2f}). Set to 0 to disable the gate."
        ),
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
    return recalibrate(
        activate=args.activate,
        dry_run=args.dry_run,
        min_auc=args.min_auc,
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
