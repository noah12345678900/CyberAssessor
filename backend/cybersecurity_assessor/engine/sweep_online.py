"""Online + batch logistic-regression updater for sweep weights.

The boundary-aware sweep scorer (``evidence.sources.sweep.score_candidate``)
is an additive linear model over six binary features — one per signal type
that can fire: ``host``, ``control``, ``family``, ``crm-kw``, ``doc-prefix``,
``priority``. Hand-tuned weights live on the v1 ``SweepWeights`` row seeded
at DB init; this module learns from the assessor's check/uncheck behavior
in ``SweepTriageDialog`` to drift those weights toward the operator's
revealed preferences.

Train/serve split (per the ML architecture rule):

  * **Inference** (``score_candidate``) loads ``SweepWeights`` from DB and
    performs vector math — no sklearn import at the hot path.
  * **Training** (``update_weights_online`` here, ``recalibrate_sweep_weights``
    script) imports ``sklearn.linear_model`` lazily, only when fitting.

Why we recover features from ``signals_json`` instead of re-scoring against
the fingerprint snapshot: the signals list is what the scorer emitted at
decision time and is the ground truth of which feature columns fired. Re-
running ``score_candidate`` against the snapshot would re-derive identical
indicators (since signals deterministically reflect which weighted terms
contributed) but would require reconstructing a live ``BoundaryFingerprint``
from the snapshot dict — extra surface area for no information gain.

Coefficient sign constraint: all six sweep signals are *positive* evidence
that a candidate is on-boundary. Negative coefficients would be the model
saying "files that look on-boundary are less likely to be kept" — which
means the labels are too noisy to trust. Clip negatives to zero and log a
warning rather than persist a sign-flipped row that would corrupt scoring.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from sqlmodel import Session, select

from ..evidence.sources.sweep import (
    SCORE_PRECHECK_THRESHOLD,
    SCORE_SURFACE_THRESHOLD,
    _W_CONTROL_ID,
    _W_CRM_KEYWORD,
    _W_DOC_PREFIX,
    _W_FAMILY,
    _W_HOST,
    _W_PRIORITY_LINK,
)
from ..models import SweepDecision, SweepWeights

log = logging.getLogger(__name__)


# Feature ordering is load-bearing — must match the SweepWeights column
# layout so weight[i] corresponds to feature[i]. Don't reorder without
# bumping a schema version.
FEATURE_NAMES: tuple[str, ...] = (
    "host",
    "control",
    "family",
    "crm-kw",
    "doc-prefix",
    "priority",
)

# Minimum decisions before the online updater will fit. Below this, an
# SGD partial_fit can swing wildly off one user click. Returns None and
# leaves the rows unconsumed for the next pass.
MIN_DECISIONS_FOR_ONLINE_FIT = 25

# Minimum decisions for the batch script — higher bar because the operator
# is being asked to flip is_active on the result.
MIN_DECISIONS_FOR_BATCH_FIT = 50


@dataclass(frozen=True)
class FeatureRow:
    """One training row — binary features + label.

    Derived from a persisted ``SweepDecision`` via ``decision_to_features``.
    Kept as a dataclass (not a numpy array) so callers can inspect /
    log / serialize without depending on numpy.
    """

    decision_id: int
    features: tuple[float, ...]  # length == len(FEATURE_NAMES)
    label: int  # 0/1, 1 == assessor kept it (included)


def _signal_prefix(signal: str) -> str:
    """``"host:server01"`` → ``"host"``. Returns empty string on malformed input."""
    if ":" not in signal:
        return ""
    return signal.split(":", 1)[0].strip().lower()


def decision_to_features(decision: SweepDecision) -> FeatureRow | None:
    """Convert one ``SweepDecision`` row into a binary feature vector.

    Returns ``None`` if the row's ``signals_json`` is unparseable or
    empty — the caller should skip it rather than fit a zero-vector that
    would teach the model "no signals → kept" which is the opposite of
    what we want. An explicit ``"[]"`` (deliberate "no signals fired,
    candidate surfaced anyway") IS processed — that's a legitimate
    training row. The distinction is empty/None ``signals_json``
    (corruption or migration bug) vs. JSON-encoded empty list (real
    operator decision data).
    """
    try:
        signals = json.loads(decision.signals_json)
    except (TypeError, ValueError):
        log.warning(
            "decision_to_features: skipping decision %s — unparseable signals_json",
            decision.id,
        )
        return None
    if not isinstance(signals, list):
        return None

    prefixes_present = {_signal_prefix(s) for s in signals if isinstance(s, str)}
    features = tuple(1.0 if name in prefixes_present else 0.0 for name in FEATURE_NAMES)
    return FeatureRow(
        decision_id=decision.id or -1,
        features=features,
        label=1 if decision.included else 0,
    )


def _clip_coefficients(coefs: list[float]) -> tuple[list[float], list[str]]:
    """Clip negative coefficients to zero (sign constraint) and report.

    Returns ``(clipped, warnings)``. Warnings is a list of human-readable
    notes the caller can persist to ``SweepWeights.notes`` so an operator
    auditing a refit can see which signals got pinned.
    """
    warnings: list[str] = []
    out: list[float] = []
    for name, c in zip(FEATURE_NAMES, coefs):
        if c < 0:
            warnings.append(
                f"clipped negative coefficient for {name!r} ({c:.4f} -> 0.0); "
                "likely noisy labels or correlated features"
            )
            out.append(0.0)
        else:
            out.append(float(c))
    return out, warnings


def _hand_tuned_init_vector() -> list[float]:
    """Initial coefficient vector matching the v1 hand-tuned weights.

    Used to warm-start the SGD partial_fit so the first update doesn't
    have to crawl up from zero on a 25-row mini-batch.
    """
    return [
        _W_HOST,
        _W_CONTROL_ID,
        _W_FAMILY,
        _W_CRM_KEYWORD,
        _W_DOC_PREFIX,
        _W_PRIORITY_LINK,
    ]


def _active_weights_to_vector(weights: SweepWeights | None) -> list[float]:
    """Extract the 6-vector of weights from a SweepWeights row.

    Returns the hand-tuned defaults when ``weights is None`` so the
    SGD warm start always has a sensible starting point.
    """
    if weights is None:
        return _hand_tuned_init_vector()
    return [
        float(weights.weight_host),
        float(weights.weight_control_id),
        float(weights.weight_family),
        float(weights.weight_crm_keyword),
        float(weights.weight_doc_prefix),
        float(weights.weight_priority_link),
    ]


def collect_unconsumed_features(
    session: Session, *, max_rows: int = 5000
) -> list[FeatureRow]:
    """Pull SweepDecision rows that haven't fed a partial_fit yet.

    Capped at ``max_rows`` per call so a backlog of tens of thousands
    doesn't blow up the sidecar's memory on the first online update
    after a long quiet period. Subsequent calls will eat the rest.
    """
    rows = session.exec(
        select(SweepDecision)
        .where(SweepDecision.consumed_for_training.is_(False))  # type: ignore[union-attr]
        .order_by(SweepDecision.created_at)  # type: ignore[arg-type]
        .limit(max_rows)
    ).all()
    out: list[FeatureRow] = []
    for r in rows:
        fr = decision_to_features(r)
        if fr is not None:
            out.append(fr)
    return out


def _mark_consumed(session: Session, decision_ids: list[int]) -> None:
    """Flip ``consumed_for_training=True`` on the rows we just fit.

    Done in a single UPDATE for the common case; loops only if the input
    list is small enough that the loop cost is negligible.
    """
    if not decision_ids:
        return
    rows = session.exec(
        select(SweepDecision).where(SweepDecision.id.in_(decision_ids))  # type: ignore[union-attr]
    ).all()
    for r in rows:
        r.consumed_for_training = True
        session.add(r)
    session.commit()


def update_weights_online(session: Session) -> SweepWeights | None:
    """Online SGD update from un-consumed SweepDecision rows.

    Imports sklearn lazily — the sidecar pays the ~30MB numpy/sklearn
    import cost only on the first triage batch that triggers this. Writes
    a new ``SweepWeights`` row with ``source="sgd_online"``,
    ``parent_weights_id=<currently active id>``, and ``is_active=False``.

    Returns the new row, or ``None`` if no update was performed (not
    enough decisions, or sklearn unavailable in this environment).
    """
    features = collect_unconsumed_features(session)
    if len(features) < MIN_DECISIONS_FOR_ONLINE_FIT:
        log.info(
            "update_weights_online: %d decisions queued, need >= %d — skipping",
            len(features),
            MIN_DECISIONS_FOR_ONLINE_FIT,
        )
        return None

    try:
        import numpy as np
        from sklearn.linear_model import SGDClassifier
    except ImportError:
        log.warning(
            "update_weights_online: sklearn not installed — skipping online update"
        )
        return None

    active = session.exec(
        select(SweepWeights).where(SweepWeights.is_active.is_(True)).limit(1)  # type: ignore[union-attr]
    ).first()

    X = np.array([f.features for f in features], dtype=np.float64)
    y = np.array([f.label for f in features], dtype=np.int64)

    if len(set(y.tolist())) < 2:
        # Online SGD with one class doesn't produce a usable decision
        # boundary — flag the rows consumed so we don't re-attempt next
        # pass, then bail. The next batch with both labels will train.
        log.info(
            "update_weights_online: %d decisions all single-class — marking consumed and skipping",
            len(features),
        )
        _mark_consumed(session, [f.decision_id for f in features])
        return None

    warm = np.array(_active_weights_to_vector(active), dtype=np.float64).reshape(1, -1)
    clf = SGDClassifier(
        loss="log_loss",
        learning_rate="optimal",
        random_state=42,
        max_iter=10,
        tol=1e-4,
        warm_start=True,
    )
    # partial_fit needs the class list up front since we may be feeding a
    # mini-batch missing one class on a later iteration.
    clf.partial_fit(X, y, classes=np.array([0, 1]))
    clf.coef_ = warm + (clf.coef_ - warm) * 0.5  # blend toward warm start
    clf.partial_fit(X, y)  # second pass after the blend

    raw_coefs = clf.coef_.flatten().tolist()
    clipped, warnings_ = _clip_coefficients(raw_coefs)
    intercept = float(clf.intercept_[0]) if clf.intercept_.size else 0.0
    n_seen = (active.n_decisions_seen if active else 0) + len(features)

    notes_lines = [
        f"SGD online update from {len(features)} new decisions",
        f"warm-started from {'active row id=' + str(active.id) if active else 'hand-tuned defaults'}",
    ]
    if warnings_:
        notes_lines.append("WARN: " + "; ".join(warnings_))

    new_row = SweepWeights(
        source="sgd_online",
        weight_host=clipped[0],
        weight_control_id=clipped[1],
        weight_family=clipped[2],
        weight_crm_keyword=clipped[3],
        weight_doc_prefix=clipped[4],
        weight_priority_link=clipped[5],
        intercept=intercept,
        surface_threshold=active.surface_threshold if active else SCORE_SURFACE_THRESHOLD,
        precheck_threshold=active.precheck_threshold if active else SCORE_PRECHECK_THRESHOLD,
        n_decisions_seen=n_seen,
        parent_weights_id=active.id if active else None,
        notes="\n".join(notes_lines),
        is_active=False,
    )
    session.add(new_row)
    session.commit()
    session.refresh(new_row)

    _mark_consumed(session, [f.decision_id for f in features])

    log.info(
        "update_weights_online: wrote SweepWeights id=%s from %d decisions",
        new_row.id,
        len(features),
    )
    return new_row
