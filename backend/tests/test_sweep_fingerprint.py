"""Tests for build_boundary_fingerprint — workbook-decoupled signatures.

Workbook-decoupling slice (2026-06-05): the builder used to take a
required ``workbook_id``; it now accepts either ``workbook_id`` OR
``system_context_id`` (or both, with the route layer enforcing
at-least-one and this layer doing belt-and-suspenders).

This module pins the pending-mode signal extraction so a regression
shows up here rather than as an empty SweepResult in the UI. The
control-family / CRM / baseline branches are exercised by the existing
sweep behavior tests — here we focus on:

  - At-least-one ValueError contract.
  - system_context_id resolves the right SystemContext.
  - SystemContext.extracted_tokens get merged into host_tokens.
  - workbook_id alone falls back to the pending singleton when the
    workbook has no SystemContext of its own (just-promoted edge case).
  - Stale system_context_id → empty fingerprint (no crash).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.evidence.sources.sweep import (  # noqa: E402
    build_boundary_fingerprint,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Evidence,
    EvidenceKind,
    SystemContext,
    SystemContextSourceType,
    Workbook,
)


@pytest.fixture
def session(tmp_path: Path):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


# ---------------------------------------------------------------------------
# Contract: at least one id required
# ---------------------------------------------------------------------------


def test_raises_when_both_ids_none(session):
    with pytest.raises(ValueError, match="at least one"):
        build_boundary_fingerprint(session=session)


# ---------------------------------------------------------------------------
# Pending-mode: system_context_id only
# ---------------------------------------------------------------------------


def test_pending_mode_lifts_extracted_tokens_into_host_tokens(session):
    """A pending SystemContext's extracted_tokens drive the sweep — they
    ARE the boundary signal when no workbook is open."""
    ctx = SystemContext(
        workbook_id=None,
        source_type=SystemContextSourceType.FREEFORM_MARKDOWN,
        source_ref="freeform",
        extracted_tokens=["WebApp01", "DB-Prod"],
        confidence=0.7,
    )
    session.add(ctx)
    session.commit()
    session.refresh(ctx)

    fp = build_boundary_fingerprint(session=session, system_context_id=ctx.id)

    # Tokens are lowercased and merged.
    assert fp.system_context_id == ctx.id
    assert fp.workbook_id is None
    assert "webapp01" in fp.host_tokens
    assert "db-prod" in fp.host_tokens
    # No baseline → empty in-scope sets (per overlay-default-local).
    assert fp.in_scope_control_ids == frozenset()
    assert fp.control_families == frozenset()


def test_pending_mode_filters_short_and_stopword_extracted_tokens(session):
    """SC merge length + stopword filter (sweep.py:615-621, 2026-06-07).

    The extraction LLM occasionally returns narrative noise alongside
    real boundary tokens. Without a floor here, words like "the" or "do"
    would score +_W_HOST (0.40) against every artifact that mentions
    them — exactly the surface-credit failure mode that erodes 3PAO
    trust in the boundary signal (per
    feedback_defensibility_over_velocity).

    Asymmetric threshold pin: SC tokens use len>=3 (NOT the narrative
    path's len>=4) because real env labels like ``iat``, ``vpc``, ``aws``
    are 3 chars and load-bearing. A regression that raises the SC floor
    to len>=4 would silently drop these from the boundary fingerprint.
    """
    ctx = SystemContext(
        workbook_id=None,
        source_type=SystemContextSourceType.FREEFORM_MARKDOWN,
        source_ref="freeform",
        extracted_tokens=[
            "iat",          # real 3-char env label — MUST survive
            "prod",         # real 4-char env label — MUST survive
            "real-host01",  # real hostname — MUST survive
            "the",          # stopword — MUST be filtered
            "policy",       # stopword — MUST be filtered
            "do",           # sub-3-char — MUST be filtered
            "",             # empty — defensive, MUST be skipped
            "   ",          # whitespace — defensive, MUST be skipped
        ],
        confidence=0.6,
    )
    session.add(ctx)
    session.commit()
    session.refresh(ctx)

    fp = build_boundary_fingerprint(session=session, system_context_id=ctx.id)

    # Real tokens survive — 3-char env labels are load-bearing.
    assert "iat" in fp.host_tokens
    assert "prod" in fp.host_tokens
    assert "real-host01" in fp.host_tokens

    # Noise filtered — never reaches host_tokens, never gets +0.40 credit.
    assert "the" not in fp.host_tokens
    assert "policy" not in fp.host_tokens
    assert "do" not in fp.host_tokens
    assert "" not in fp.host_tokens


def test_pending_mode_merges_host_inventory_with_extracted_tokens(session):
    """Evidence.host_inventory tokens accumulate ALONGSIDE the
    SystemContext.extracted_tokens — not either-or. Both are host
    signals at weight _W_HOST=0.40 (deliberate, per the docstring)."""
    ctx = SystemContext(
        workbook_id=None,
        source_type=SystemContextSourceType.FREEFORM_MARKDOWN,
        source_ref="freeform",
        extracted_tokens=["from-ctx"],
        confidence=0.5,
    )
    session.add(ctx)
    # Evidence with a host_inventory blob — already-ingested rows
    # contribute hostnames even in pending mode.
    ev = Evidence(
        path="file:///doc.pdf",
        sha256="abc",
        kind=EvidenceKind.PDF,
        size_bytes=10,
        host_inventory=json.dumps(["From-Inventory", "shared01"]),
    )
    session.add(ev)
    session.commit()
    session.refresh(ctx)

    fp = build_boundary_fingerprint(session=session, system_context_id=ctx.id)
    assert {"from-ctx", "from-inventory", "shared01"} <= fp.host_tokens


# ---------------------------------------------------------------------------
# Workbook-mode fallback to pending singleton
# ---------------------------------------------------------------------------


def test_workbook_without_systemcontext_falls_back_to_pending_singleton(
    session, tmp_path
):
    """Just-promoted edge case: route hands us a workbook but the pending
    SystemContext hasn't been reparented yet — builder reaches back for
    the pending row so the sweep still picks up its extracted_tokens."""
    p = tmp_path / "wb.xlsx"
    p.write_bytes(b"x")
    wb = Workbook(path=str(p), filename=p.name)
    session.add(wb)

    pending = SystemContext(
        workbook_id=None,
        source_type=SystemContextSourceType.FREEFORM_MARKDOWN,
        source_ref="freeform",
        extracted_tokens=["pending-host"],
        confidence=0.5,
    )
    session.add(pending)
    session.commit()
    session.refresh(wb)
    session.refresh(pending)

    fp = build_boundary_fingerprint(session=session, workbook_id=wb.id)

    assert fp.workbook_id == wb.id
    # Pending singleton's tokens flowed through.
    assert "pending-host" in fp.host_tokens
    # And the returned fingerprint's system_context_id points at the
    # pending row so SweepRun bookkeeping can attribute downstream.
    assert fp.system_context_id == pending.id


def test_workbook_systemcontext_takes_precedence_over_pending(session, tmp_path):
    """Workbook-bound SystemContext wins; pending singleton is ignored
    when the workbook already has its own row."""
    p = tmp_path / "wb.xlsx"
    p.write_bytes(b"x")
    wb = Workbook(path=str(p), filename=p.name)
    session.add(wb)
    session.commit()
    session.refresh(wb)

    pending = SystemContext(
        workbook_id=None,
        source_type=SystemContextSourceType.FREEFORM_MARKDOWN,
        source_ref="freeform",
        extracted_tokens=["pending-token"],
        confidence=0.4,
    )
    bound = SystemContext(
        workbook_id=wb.id,
        source_type=SystemContextSourceType.FREEFORM_MARKDOWN,
        source_ref="freeform",
        extracted_tokens=["bound-token"],
        confidence=0.8,
    )
    session.add(pending)
    session.add(bound)
    session.commit()
    session.refresh(bound)

    fp = build_boundary_fingerprint(session=session, workbook_id=wb.id)
    assert fp.system_context_id == bound.id
    assert "bound-token" in fp.host_tokens
    # Pending tokens MUST NOT bleed through — that would silently
    # widen the boundary signal across workbooks.
    assert "pending-token" not in fp.host_tokens


# ---------------------------------------------------------------------------
# Defensive: stale ids don't crash
# ---------------------------------------------------------------------------


def test_unknown_system_context_id_returns_empty_fingerprint(session):
    """Caller passes a deleted/never-existed id → builder logs and
    returns a fingerprint with no signals (rather than 500ing the
    sweep route). Matches the workbook_id behavior at line 445."""
    fp = build_boundary_fingerprint(session=session, system_context_id=999_999)
    assert fp.system_context_id == 999_999
    assert fp.host_tokens == frozenset()
    assert fp.in_scope_control_ids == frozenset()
