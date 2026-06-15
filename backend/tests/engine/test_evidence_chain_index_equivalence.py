"""Equivalence tests for the indexed vs. legacy ``rewrite_evidence_chain``
paths.

The supersession kernel exposes two ways to rewrite a narrative that
cites a superseded ``Evidence`` row:

* **Legacy** — ``rewrite_evidence_chain(session, text, workbook_id=W)``
  queries the session, walks each chain to the head, builds candidates,
  rewrites. One full table scan + N+1 head lookups per call.

* **Indexed** — caller pre-builds an ``EvidenceChainIndex`` once per
  batch with :func:`build_evidence_chain_index` and passes it as
  ``index=`` on subsequent calls. Session-free, lock-free, pure CPU.

The indexed path is the assess-batch hot path (kernel funnels four
finalize paths through ``Assessor._locked_rewrite_evidence_chain``).
For the perf swap to be safe, the indexed path MUST produce identical
``EvidenceChainResult`` output to the legacy path for the same
``(text, workbook_id)`` — same rewritten text, same hit list in the
same order with the same ``stale_ref`` / ``current_ref`` /
``stale_evidence_id`` / ``current_evidence_id`` per hit.

These three tests pin that contract. The existing matching-precision
tests in ``test_evidence_chain_rewriter.py`` continue to exercise the
legacy path directly without modification (plan D3), so they
implicitly cover the indexed path too via this equivalence.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Make the backend package importable from any pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402 -- registers tables
from cybersecurity_assessor.engine.supersession import (  # noqa: E402
    EvidenceChainIndex,
    build_evidence_chain_index,
    rewrite_evidence_chain,
)
from cybersecurity_assessor.models import Evidence, EvidenceKind  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures + helpers (mirror test_evidence_chain_rewriter.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _add(
    session: Session,
    *,
    path: str,
    title: str,
    doc_number: str | None = None,
    workbook_id: int | None = None,
    superseded_by_id: int | None = None,
    sha: str | None = None,
) -> Evidence:
    ev = Evidence(
        path=path,
        sha256=sha or f"sha-{path}",
        kind=EvidenceKind.PDF,
        size_bytes=1,
        title=title,
        doc_number=doc_number,
        workbook_id=workbook_id,
        superseded_by_id=superseded_by_id,
    )
    session.add(ev)
    session.flush()
    return ev


def _hit_tuple(hit) -> tuple:
    """Project a hit to a comparable tuple — equivalence cares about all four
    fields, in order."""
    return (
        hit.stale_ref,
        hit.current_ref,
        hit.stale_evidence_id,
        hit.current_evidence_id,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_indexed_path_matches_legacy_path_basic(session):
    """One stale doc_number + one stale title chain → both paths emit
    identical ``rewritten_text`` and identical hit list (same order, same
    fields).

    This is the core equivalence contract: anything a real narrative
    triggers on the legacy path must trigger the same way on the indexed
    path. Two seed chains exercise both candidate sources (doc_number and
    title) at once so a single test catches divergence in either.
    """
    # Chain 1: doc_number-anchored.
    new_doc = _add(
        session,
        path="file:///docs/new-acct.pdf",
        title="Example System Account Management Plan Rev B",
        doc_number="USD00099999",
    )
    _add(
        session,
        path="file:///docs/old-acct.pdf",
        title="Example System Account Management Plan Rev A",
        doc_number="USD00088888",
        superseded_by_id=new_doc.id,
    )
    # Chain 2: title-anchored (no doc_number on the stale row so the
    # candidate is built from the title path; ≥ 12 chars + not blocklisted).
    new_title = _add(
        session,
        path="file:///docs/new-baseline.pdf",
        title="Example System Configuration Baseline Rev 4",
    )
    _add(
        session,
        path="file:///docs/old-baseline.pdf",
        title="Example System Configuration Baseline Rev 3",
        superseded_by_id=new_title.id,
    )

    text = (
        "Per USD00088888 privileged users are reviewed quarterly. "
        "The Example System Configuration Baseline Rev 3 governs all hardening settings."
    )

    legacy = rewrite_evidence_chain(session, text)
    index = build_evidence_chain_index(session, workbook_id=None)
    indexed = rewrite_evidence_chain(None, text, index=index)

    assert legacy.changed
    assert indexed.changed
    assert legacy.rewritten_text == indexed.rewritten_text
    assert [_hit_tuple(h) for h in legacy.hits] == [
        _hit_tuple(h) for h in indexed.hits
    ]


def test_indexed_path_matches_legacy_path_workbook_scope(session):
    """``workbook_id`` scoping is preserved by the indexed path.

    Two overlapping chains — one scoped to ``workbook_id=1``, one
    workbook-agnostic (``workbook_id=None``, org-wide policy library).
    A narrative citing both stale refs gets rewritten differently
    depending on the scope. Build the index with ``workbook_id=1`` and
    confirm it returns exactly the subset the legacy path returns for
    that workbook (scoped chain + agnostic chain rewrite; foreign
    workbook's chain does NOT rewrite).
    """
    # Scoped chain (workbook 1).
    wb1_new = _add(
        session,
        path="file:///wb1/new.pdf",
        title="WB1 New",
        doc_number="USD00011111",
        workbook_id=1,
    )
    _add(
        session,
        path="file:///wb1/old.pdf",
        title="WB1 Old",
        doc_number="USD00011110",
        workbook_id=1,
        superseded_by_id=wb1_new.id,
    )
    # Foreign chain (workbook 2) — must NOT rewrite when asking from wb 1.
    wb2_new = _add(
        session,
        path="file:///wb2/new.pdf",
        title="WB2 New",
        doc_number="USD00022221",
        workbook_id=2,
    )
    _add(
        session,
        path="file:///wb2/old.pdf",
        title="WB2 Old",
        doc_number="USD00022220",
        workbook_id=2,
        superseded_by_id=wb2_new.id,
    )
    # Workbook-agnostic chain (None) — must rewrite for any workbook.
    glob_new = _add(
        session,
        path="file:///global/new.pdf",
        title="Global New",
        doc_number="USD00033331",
        workbook_id=None,
    )
    _add(
        session,
        path="file:///global/old.pdf",
        title="Global Old",
        doc_number="USD00033330",
        workbook_id=None,
        superseded_by_id=glob_new.id,
    )

    text = (
        "Per USD00011110 (workbook 1) reviews happen quarterly. "
        "Per USD00022220 (workbook 2) reviews happen monthly. "
        "Per USD00033330 (global) reviews happen weekly."
    )

    legacy = rewrite_evidence_chain(session, text, workbook_id=1)
    index = build_evidence_chain_index(session, workbook_id=1)
    indexed = rewrite_evidence_chain(None, text, index=index)

    assert legacy.rewritten_text == indexed.rewritten_text
    assert [_hit_tuple(h) for h in legacy.hits] == [
        _hit_tuple(h) for h in indexed.hits
    ]
    # Sanity-check the underlying behavior: workbook 1's stale ref + the
    # global stale ref were rewritten; workbook 2's was not.
    assert "USD00011111" in indexed.rewritten_text  # wb1 rewritten
    assert "USD00033331" in indexed.rewritten_text  # global rewritten
    assert "USD00022220" in indexed.rewritten_text  # wb2 untouched
    assert "USD00022221" not in indexed.rewritten_text


def test_indexed_path_no_session_required(session):
    """The indexed path is session-free: closing the session after build
    must not break a subsequent rewrite.

    Pins the perf claim — the whole point of the index is that the hot
    rewrite loop touches zero DB. If the rewriter still secretly hit the
    session, this test would raise (``DetachedInstanceError``, or worse
    if the engine has been disposed). It also documents the API contract
    for callers: "you can build the index, drop the session, and keep
    rewriting from the snapshot."
    """
    new = _add(
        session,
        path="file:///docs/new.pdf",
        title="Detached Plan New",
        doc_number="USD00077777",
    )
    _add(
        session,
        path="file:///docs/old.pdf",
        title="Detached Plan Old",
        doc_number="USD00077776",
        superseded_by_id=new.id,
    )

    index = build_evidence_chain_index(session, workbook_id=None)
    assert isinstance(index, EvidenceChainIndex)
    assert index.candidates  # at least one candidate seeded

    # Tear the session down BEFORE rewriting. If the rewriter touches the
    # session it will blow up here.
    session.close()

    text = "Per USD00077776 reviews happen quarterly."
    result = rewrite_evidence_chain(None, text, index=index)

    assert result.changed
    assert "USD00077777" in result.rewritten_text
    assert "USD00077776" not in result.rewritten_text
