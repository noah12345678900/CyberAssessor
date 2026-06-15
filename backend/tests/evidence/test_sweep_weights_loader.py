"""Unit tests for :func:`load_active_weights` and the ``weights=`` plumbing
on :func:`score_candidate`.

What these tests pin down:

1. ``load_active_weights`` returns the row carrying ``is_active=True``,
   ignores inactive history rows, and returns ``None`` on an empty DB.
   That last case is load-bearing — the kernel pattern lets unit tests
   call ``score_candidate`` without a session, falling back to the
   hand-tuned defaults baked into ``sweep.py``.

2. ``score_candidate(weights=row)`` uses the row's per-feature weights
   instead of the module constants. We exercise this by constructing a
   ``SweepWeights`` whose values are *deliberately different* from the
   hand-tuned defaults and verifying the score reflects the override.

3. ``score_candidate(weights=None)`` (or omitted) falls back to the
   ``_W_*`` constants. The "no DB" path must keep working byte-for-byte
   so we don't have to thread a session through every code path that
   wants a one-off score.

We do NOT exercise ``init_db()`` here — that path is owned by
``db._seed_initial_sweep_weights`` and is covered indirectly by every
test that boots the sidecar. These tests keep the surface minimal: just
the loader contract and the weights-plumbing in the scorer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.evidence.sources.sweep import (  # noqa: E402
    BoundaryFingerprint,
    _W_CONTROL_ID,
    _W_CRM_KEYWORD,
    _W_DOC_PREFIX,
    _W_FAMILY,
    _W_HOST,
    _W_PRIORITY_LINK,
    load_active_weights,
    score_candidate,
)
from cybersecurity_assessor.models import SweepWeights  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite, no shared state between tests. Same pattern as
    the other evidence tests.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _make_weights(
    *,
    source: str = "manual",
    is_active: bool = True,
    weight_host: float = _W_HOST,
    weight_control_id: float = _W_CONTROL_ID,
    weight_family: float = _W_FAMILY,
    weight_crm_keyword: float = _W_CRM_KEYWORD,
    weight_doc_prefix: float = _W_DOC_PREFIX,
    weight_priority_link: float = _W_PRIORITY_LINK,
) -> SweepWeights:
    """Tiny builder so each test asserts on what it actually varies."""
    return SweepWeights(
        source=source,
        weight_host=weight_host,
        weight_control_id=weight_control_id,
        weight_family=weight_family,
        weight_crm_keyword=weight_crm_keyword,
        weight_doc_prefix=weight_doc_prefix,
        weight_priority_link=weight_priority_link,
        intercept=0.0,
        surface_threshold=0.30,
        precheck_threshold=0.60,
        n_decisions_seen=0,
        is_active=is_active,
    )


# ---------------------------------------------------------------------------
# load_active_weights
# ---------------------------------------------------------------------------


def test_load_active_weights_returns_none_on_empty_db(session):
    """Empty DB → None. The scorer treats this as "use hand-tuned defaults"
    so unit tests against a fresh schema keep working without a seed step.
    """
    assert load_active_weights(session) is None


def test_load_active_weights_returns_the_active_row(session):
    """A single ``is_active=True`` row is returned by the loader."""
    row = _make_weights(weight_host=0.99)
    session.add(row)
    session.commit()
    session.refresh(row)

    loaded = load_active_weights(session)
    assert loaded is not None
    assert loaded.id == row.id
    assert loaded.weight_host == pytest.approx(0.99)


def test_load_active_weights_ignores_inactive_history_rows(session):
    """Multiple SweepWeights rows are normal — only the active one is returned.

    Mirrors the production state after an SGD update or batch refit:
    history rows linger with ``is_active=False`` until the operator promotes
    one.
    """
    # Two historical rows, neither active.
    session.add(_make_weights(source="sgd_online", is_active=False, weight_host=0.11))
    session.add(_make_weights(source="batch_lr", is_active=False, weight_host=0.22))
    # The active row.
    active = _make_weights(source="manual", is_active=True, weight_host=0.40)
    session.add(active)
    session.commit()
    session.refresh(active)

    loaded = load_active_weights(session)
    assert loaded is not None
    assert loaded.id == active.id
    assert loaded.weight_host == pytest.approx(0.40)


# ---------------------------------------------------------------------------
# score_candidate weights= plumbing
# ---------------------------------------------------------------------------


def test_score_candidate_defaults_to_hand_tuned_constants():
    """Without ``weights=``, the scorer must use ``_W_HOST`` etc. verbatim.

    A file matching ONLY the host signal should score exactly ``_W_HOST``.
    If this drifts, it means someone introduced an implicit weight
    transformation in the no-weights path — caller code that uses the
    score for thresholding (UI prechecks, evidence ingestion gating)
    would silently change behavior.
    """
    fp = BoundaryFingerprint(
        workbook_id=1,
        host_tokens=frozenset({"server01"}),
    )
    score, signals, _ccis = score_candidate(
        "policy.pdf", "/x/policy.pdf", "server01 mentioned here", fp
    )
    assert score == pytest.approx(_W_HOST)
    assert signals == ["host:server01"]


def test_score_candidate_uses_supplied_weights_row():
    """An explicit ``weights=row`` overrides every per-feature constant.

    Set ``weight_host`` to a distinctive 0.77 — score on a host-only match
    must be 0.77, not 0.40. Belt-and-suspenders: also override
    ``weight_family`` so a combined match exercises both replacements,
    not a partial fall-through.
    """
    weights = _make_weights(weight_host=0.77, weight_family=0.05)

    fp = BoundaryFingerprint(
        workbook_id=1,
        host_tokens=frozenset({"server01"}),
        control_families=frozenset({"AC"}),
    )
    score, signals, _ = score_candidate(
        "access control policy.pdf",  # "access control" keyword → family:AC
        "/x/access control policy.pdf",
        "server01 listed in inventory",
        fp,
        weights=weights,
    )
    # host (0.77) + family (0.05) = 0.82, capped at 1.0 (no cap hit here).
    assert score == pytest.approx(0.77 + 0.05)
    assert "host:server01" in signals
    assert "family:AC" in signals


def test_score_candidate_weights_none_is_equivalent_to_omitting_it():
    """``weights=None`` is the documented kernel default. Must match omission
    bit-for-bit so callers that conditionally build a row don't have to
    branch on ``None``.
    """
    fp = BoundaryFingerprint(
        workbook_id=1,
        host_tokens=frozenset({"server01"}),
        control_families=frozenset({"AC"}),
    )
    with_none = score_candidate(
        "access control policy.pdf",
        "/x/access control policy.pdf",
        "server01 listed in inventory",
        fp,
        weights=None,
    )
    omitted = score_candidate(
        "access control policy.pdf",
        "/x/access control policy.pdf",
        "server01 listed in inventory",
        fp,
    )
    assert with_none == omitted


def test_score_candidate_loaded_weights_round_trip(session):
    """End-to-end: persist a row, ``load_active_weights`` it back, pass it to
    ``score_candidate``. Catches any plumbing bug where the loaded row's
    fields don't match the constructor — e.g. an SQLModel column rename
    that the loader missed.
    """
    persisted = _make_weights(weight_host=0.55, weight_family=0.10)
    session.add(persisted)
    session.commit()

    loaded = load_active_weights(session)
    assert loaded is not None

    fp = BoundaryFingerprint(
        workbook_id=1,
        host_tokens=frozenset({"server01"}),
        control_families=frozenset({"AC"}),
    )
    score, _signals, _ccis = score_candidate(
        "access control policy.pdf",
        "/x/access control policy.pdf",
        "server01",
        fp,
        weights=loaded,
    )
    assert score == pytest.approx(0.55 + 0.10)
