"""Golden tests for the evidence-chain supersession walk (deterministic kernel #3).

``engine.supersession`` catches stale doc citations the LLM cannot know
about on its own: when an older artifact is superseded by a newer one
(``Evidence.superseded_by_id``), narratives citing the old doc are rewritten
to the current one. Without this, an LLM that pulled a legacy doc title out
of col U (previous results) would carry the dead reference straight into
col Q.

Supersession is fully data-driven — the ingest-time tracker links Rev A → Rev B
by ``doc_number``, and these tests stand up an in-memory SQLite session
(StaticPool, matching the other engine test files) so the self-FK chain walk
runs against a real ``Evidence`` table. (An earlier manual legacy→current
phrase registry was removed; the chain rewriter needs no seeded phrases.)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Ensure the backend package is importable when pytest is launched from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine.supersession import (  # noqa: E402
    resolve_current_evidence_id,
)
from cybersecurity_assessor.models import Evidence, EvidenceKind  # noqa: E402


# ---------------------------------------------------------------------------
# resolve_current_evidence_id — supersession chain walk
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite for the Evidence-table chain-walk tests."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _make_evidence(
    session: Session,
    *,
    path: str,
    superseded_by_id: int | None = None,
) -> Evidence:
    """Create + flush an Evidence row so ``id`` is assigned."""
    ev = Evidence(
        path=path,
        sha256="0" * 64,
        kind=EvidenceKind.PDF,
        size_bytes=1,
        superseded_by_id=superseded_by_id,
    )
    session.add(ev)
    session.flush()  # assigns ev.id without committing the txn
    return ev


def test_resolve_current_evidence_id_terminal_row_returns_input(session):
    """No supersession set → ``resolve_current_evidence_id`` returns input id.

    Pins the early-return for the ``superseded_by_id is None`` branch. Most
    Evidence rows in the wild are terminal (current); this is the hot path.
    If it ever started walking past terminal, queries that resolve "show me
    the canonical evidence for this row" would touch the DB once per row
    when they should be a single get + early return.
    """
    ev = _make_evidence(session, path="file:///tmp/current.pdf")

    assert resolve_current_evidence_id(session, ev.id) == ev.id


def test_resolve_current_evidence_id_walks_one_hop_chain(session):
    """A → B chain → ``resolve_current_evidence_id(A.id) == B.id``.

    Pins the normal one-hop chain walk. Chains are 1-2 deep in practice
    (a legacy doc → its current replacement); the one-hop case is
    overwhelmingly the common one.
    """
    current = _make_evidence(session, path="file:///tmp/current_doc.pdf")
    legacy = _make_evidence(
        session,
        path="file:///tmp/legacy_doc.pdf",
        superseded_by_id=current.id,
    )

    assert resolve_current_evidence_id(session, legacy.id) == current.id


def test_resolve_current_evidence_id_walks_multi_hop_chain(session):
    """A → B → C chain → ``resolve_current_evidence_id(A.id) == C.id``.

    Two-hop chains do happen (a doc gets superseded once, then the
    replacement is itself replaced). Pin that the loop actually iterates;
    a regression that turned the for-loop into ``if`` would silently
    return the middle of the chain on every two-hop case.
    """
    c = _make_evidence(session, path="file:///tmp/c.pdf")
    b = _make_evidence(session, path="file:///tmp/b.pdf", superseded_by_id=c.id)
    a = _make_evidence(session, path="file:///tmp/a.pdf", superseded_by_id=b.id)

    assert resolve_current_evidence_id(session, a.id) == c.id


def test_resolve_current_evidence_id_breaks_cycle(session):
    """A → B → A cycle → returns the last-seen id without infinite-looping.

    Pins the cycle guard. A cycle is a data bug (assessor manually pointed
    a "current" row back at its predecessor) but it MUST NOT hang the
    assessment pass. The guard returns the id we were about to revisit —
    not necessarily semantically "right" but deterministic and bounded.
    """
    a = _make_evidence(session, path="file:///tmp/a.pdf")
    b = _make_evidence(session, path="file:///tmp/b.pdf", superseded_by_id=a.id)
    # Close the cycle: a → b.
    a.superseded_by_id = b.id
    session.add(a)
    session.flush()

    # Starting at A: A → B → (would revisit A) → returns B (the last good id
    # before we would have looped back).
    result = resolve_current_evidence_id(session, a.id)
    assert result == b.id


def test_resolve_current_evidence_id_missing_row_returns_input(session):
    """Input id has no Evidence row → returns input id unchanged.

    Pins the ``row is None`` branch. Caller hands in a stale id (e.g. an
    Evidence row that was deleted between the parent query and this
    resolver call); the function MUST return a valid int rather than raise
    — downstream code uses the return value to set ``citation_evidence_id``
    on a Citation row, and a raise would abort the whole assessor pass for
    an unrelated row.
    """
    # 999_999 is well past any flushed id in this clean session.
    assert resolve_current_evidence_id(session, 999_999) == 999_999


def test_resolve_current_evidence_id_max_hops_caps_walk(session):
    """Chain deeper than ``max_hops`` → loop exits, returns the last-walked id.

    Pins the final ``return current_id`` — the fall-through after the
    for-loop exhausts ``max_hops``. Real chains aren't this deep, but the
    cap is the second line of defense behind the cycle guard (in case bad
    data produces a long-but-non-cyclic chain). Drop the cap and a
    million-row pathological chain would hold the txn open scanning
    Evidence; pin the cap so future-us doesn't "simplify" the resolver by
    removing the for-loop bound.
    """
    # Build a 4-deep chain: a → b → c → d (d is terminal).
    d = _make_evidence(session, path="file:///tmp/d.pdf")
    c = _make_evidence(session, path="file:///tmp/c.pdf", superseded_by_id=d.id)
    b = _make_evidence(session, path="file:///tmp/b.pdf", superseded_by_id=c.id)
    a = _make_evidence(session, path="file:///tmp/a.pdf", superseded_by_id=b.id)

    # With max_hops=2 we can only walk a → b → c; the loop exits with
    # current_id = c.id and falls through to ``return current_id``.
    assert resolve_current_evidence_id(session, a.id, max_hops=2) == c.id
    # And the natural max_hops (8) is more than enough for this chain.
    assert resolve_current_evidence_id(session, a.id) == d.id
