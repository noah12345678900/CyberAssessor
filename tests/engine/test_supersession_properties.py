"""Property tests for the evidence-chain supersession walk.

Supersession is data-driven: the ingest-time tracker links an older
artifact to a newer one (``Evidence.superseded_by_id``), and
``resolve_current_evidence_id`` walks that self-FK chain to the terminal
(current) row. These properties pin the walker's invariants:

  * terminates within ``max_hops`` for any chain length,
  * never raises on a missing row,
  * breaks cycles deterministically and logs them.

(An earlier manual legacy→current phrase registry was removed; supersession
needs no seeded phrases.)
"""

from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine

from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine.supersession import (  # noqa: E402
    resolve_current_evidence_id,
)
from cybersecurity_assessor.models import Evidence, EvidenceKind  # noqa: E402


# ---------------------------------------------------------------------------
# resolve_current_evidence_id — chain walker
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _add_evidence(session: Session, **kw) -> Evidence:
    ev = Evidence(
        kind=kw.pop("kind", EvidenceKind.DOCX),
        path=kw.pop("path", "doc.docx"),
        sha256=kw.pop("sha256", "0" * 64),
        size_bytes=kw.pop("size_bytes", 1),
        **kw,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def test_resolve_returns_same_id_when_no_chain(session):
    ev = _add_evidence(session)
    assert resolve_current_evidence_id(session, ev.id) == ev.id


def test_resolve_walks_to_terminal(session):
    a = _add_evidence(session, path="a.docx")
    b = _add_evidence(session, path="b.docx")
    c = _add_evidence(session, path="c.docx")
    a.superseded_by_id = b.id
    b.superseded_by_id = c.id
    session.add(a)
    session.add(b)
    session.commit()
    assert resolve_current_evidence_id(session, a.id) == c.id


def test_resolve_breaks_cycle_safely(session):
    """A 2-row cycle must terminate without recursion, returning a stable id."""
    a = _add_evidence(session, path="a.docx")
    b = _add_evidence(session, path="b.docx")
    a.superseded_by_id = b.id
    b.superseded_by_id = a.id
    session.add(a)
    session.add(b)
    session.commit()
    result = resolve_current_evidence_id(session, a.id, max_hops=8)
    # Result must be one of the two ids — not a stack overflow, not an exception.
    assert result in {a.id, b.id}


def test_resolve_respects_max_hops(session):
    """A chain longer than max_hops returns the last hop visited, not the terminal."""
    chain: list[Evidence] = [_add_evidence(session, path=f"e{i}.docx") for i in range(6)]
    for prev, nxt in zip(chain, chain[1:]):
        prev.superseded_by_id = nxt.id
        session.add(prev)
    session.commit()
    # With max_hops=2, we walk e0 -> e1 -> e2, then stop. Result should be e2.
    out = resolve_current_evidence_id(session, chain[0].id, max_hops=2)
    assert out == chain[2].id


def test_resolve_missing_row_returns_input(session):
    """A nonexistent id should not crash — it just returns what was passed in."""
    assert resolve_current_evidence_id(session, 9_999_999) == 9_999_999


@given(n=st.integers(min_value=0, max_value=12))
def test_resolve_terminates_for_any_chain_length(n):
    """For any linear chain length, the walker returns a valid id, never raises."""
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        chain: list[Evidence] = [
            _add_evidence(session, path=f"e{i}.docx") for i in range(n + 1)
        ]
        for prev, nxt in zip(chain, chain[1:]):
            prev.superseded_by_id = nxt.id
            session.add(prev)
        session.commit()
        out = resolve_current_evidence_id(session, chain[0].id)
        assert out in {e.id for e in chain}


def test_resolve_logs_cycle_detection(session, caplog):
    """Cycle path must emit a warning so an operator can find the bad data."""
    a = _add_evidence(session, path="a.docx")
    b = _add_evidence(session, path="b.docx")
    a.superseded_by_id = b.id
    b.superseded_by_id = a.id
    session.add(a)
    session.add(b)
    session.commit()
    with caplog.at_level("WARNING", logger="cybersecurity_assessor.engine.supersession"):
        resolve_current_evidence_id(session, a.id)
    assert any("cycle detected" in r.message for r in caplog.records)


def test_resolve_logs_max_hops_exhaustion(session, caplog):
    """Reaching max_hops without a terminal must emit a warning."""
    chain: list[Evidence] = [_add_evidence(session, path=f"e{i}.docx") for i in range(5)]
    for prev, nxt in zip(chain, chain[1:]):
        prev.superseded_by_id = nxt.id
        session.add(prev)
    session.commit()
    with caplog.at_level("WARNING", logger="cybersecurity_assessor.engine.supersession"):
        resolve_current_evidence_id(session, chain[0].id, max_hops=2)
    assert any("max_hops=2 reached" in r.message for r in caplog.records)
