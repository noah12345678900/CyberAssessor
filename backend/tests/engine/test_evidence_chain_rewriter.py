"""Evidence-chain rewriter — patent-supporting catch for stale Evidence refs.

The deterministic doc-phrase rewriter in ``engine.supersession`` knows about
~30 hard-coded T1→T2 phrases. The evidence-chain rewriter is its sibling:
it walks ``Evidence.superseded_by_id`` chains the supersession tracker built
at ingest, and rewrites narrative text that names a retired evidence row
(by doc_number or title) to point at the chain head instead.

Together the two rewriters give the patent's "every stale citation gets
deterministically corrected before the validator sees it" claim full
coverage — phrase-based AND chain-based.

These tests pin the matching precision (doc_number = word-boundary case-
sensitive; title = case-insensitive but length/blocklist-gated),
idempotency, multi-hop chain resolution, and the workbook_id scope filter.
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

from cybersecurity_assessor import models  # noqa: F401,E402 -- registers tables
from cybersecurity_assessor.engine.supersession import (  # noqa: E402
    rewrite_evidence_chain,
)
from cybersecurity_assessor.models import Evidence, EvidenceKind  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures + helpers
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


# ---------------------------------------------------------------------------
# Doc-number matching (word-boundary, case-sensitive)
# ---------------------------------------------------------------------------


def test_rewrites_stale_doc_number_to_chain_head(session):
    """A narrative citing the retired doc_number gets the chain head's ref."""
    new = _add(
        session,
        path="file:///docs/new.pdf",
        title="Example System Account Management Plan Rev B",
        doc_number="USD00099999",
    )
    _add(
        session,
        path="file:///docs/old.pdf",
        title="Example System Account Management Plan Rev A",
        doc_number="USD00088888",
        superseded_by_id=new.id,
    )

    text = "Per USD00088888 the privileged users are reviewed quarterly."
    result = rewrite_evidence_chain(session, text)

    assert result.changed
    assert "USD00099999" in result.rewritten_text
    assert "USD00088888" not in result.rewritten_text
    assert len(result.hits) == 1
    hit = result.hits[0]
    assert hit.stale_ref == "USD00088888"
    assert hit.current_ref == "USD00099999"


def test_doc_number_is_case_sensitive(session):
    """Doc-number matching is case-sensitive — narrative prose doesn't trigger it."""
    new = _add(
        session,
        path="file:///docs/new.pdf",
        title="New",
        doc_number="USD00077777",
    )
    _add(
        session,
        path="file:///docs/old.pdf",
        title="Old",
        doc_number="USD00066666",
        superseded_by_id=new.id,
    )

    # Lowercase "usd" should NOT match — USD-numbers are uppercase by spec.
    text = "we usd00066666 reviewed every account"
    result = rewrite_evidence_chain(session, text)
    assert not result.changed


def test_doc_number_respects_word_boundary(session):
    """A doc_number embedded in a longer token does not match."""
    new = _add(
        session,
        path="file:///docs/new.pdf",
        title="New",
        doc_number="USD00055555",
    )
    _add(
        session,
        path="file:///docs/old.pdf",
        title="Old",
        doc_number="USD00044444",
        superseded_by_id=new.id,
    )

    # USD00044444X is a different token — must not match.
    text = "see USD00044444X-supplement.pdf for details"
    result = rewrite_evidence_chain(session, text)
    assert not result.changed


# ---------------------------------------------------------------------------
# Title matching (case-insensitive, length/blocklist-gated)
# ---------------------------------------------------------------------------


def test_rewrites_stale_title_case_insensitive(session):
    """Titles match case-insensitively; rewritten to head's doc_number when set."""
    new = _add(
        session,
        path="file:///docs/new.pdf",
        title="Account Management Plan Rev B",
        doc_number="USD00050010",
    )
    _add(
        session,
        path="file:///docs/old.pdf",
        title="SDA T1 O&I Account Management User Guide",
        doc_number=None,
        superseded_by_id=new.id,
    )

    text = (
        "Per sda t1 o&i account management user guide section 4.2, all privileged "
        "accounts require quarterly attestation."
    )
    result = rewrite_evidence_chain(session, text)

    assert result.changed
    # The doc_number of the chain head wins as the preferred ref.
    assert "USD00050010" in result.rewritten_text
    assert "user guide" not in result.rewritten_text.lower()


def test_short_title_is_skipped(session):
    """Titles below the length floor (12 chars) do not match — false-positive guard."""
    new = _add(
        session,
        path="file:///docs/new.pdf",
        title="A longer canonical title that has plenty of bytes",
        doc_number="USD00033333",
    )
    _add(
        session,
        path="file:///docs/old.pdf",
        title="Notes",  # 5 chars, generic
        doc_number=None,
        superseded_by_id=new.id,
    )

    text = "See Notes from the prior assessor's review of CCI-000015."
    result = rewrite_evidence_chain(session, text)
    assert not result.changed


def test_generic_title_on_blocklist_is_skipped(session):
    """Titles on the generic blocklist are skipped even if long enough."""
    new = _add(
        session,
        path="file:///docs/new.pdf",
        title="Real specific replacement document title",
        doc_number="USD00022222",
    )
    _add(
        session,
        path="file:///docs/old.pdf",
        title="Documentation",  # exactly the blocklisted form, ≥ 12 chars
        doc_number=None,
        superseded_by_id=new.id,
    )

    text = "The Documentation we reviewed described the access control flow."
    result = rewrite_evidence_chain(session, text)
    assert not result.changed


# ---------------------------------------------------------------------------
# Multi-hop chain resolution
# ---------------------------------------------------------------------------


def test_multi_hop_chain_resolves_to_head_in_one_pass(session):
    """A → B → C: a narrative naming A is rewritten directly to C, no two-step."""
    c = _add(
        session,
        path="file:///docs/c.pdf",
        title="Rev C",
        doc_number="USD00010003",
    )
    b = _add(
        session,
        path="file:///docs/b.pdf",
        title="Rev B",
        doc_number="USD00010002",
        superseded_by_id=c.id,
    )
    _add(
        session,
        path="file:///docs/a.pdf",
        title="Rev A",
        doc_number="USD00010001",
        superseded_by_id=b.id,
    )

    text = "Per USD00010001 access reviews happen quarterly."
    result = rewrite_evidence_chain(session, text)

    assert result.changed
    assert "USD00010003" in result.rewritten_text
    assert "USD00010001" not in result.rewritten_text
    assert "USD00010002" not in result.rewritten_text


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_idempotent_running_twice_yields_same_output(session):
    """Running the rewriter on already-rewritten text produces no new hits."""
    new = _add(
        session,
        path="file:///docs/new.pdf",
        title="New Title",
        doc_number="USD00099991",
    )
    _add(
        session,
        path="file:///docs/old.pdf",
        title="Old Title",
        doc_number="USD00099990",
        superseded_by_id=new.id,
    )

    text = "Per USD00099990 reviews happen quarterly."
    once = rewrite_evidence_chain(session, text)
    twice = rewrite_evidence_chain(session, once.rewritten_text)

    assert once.changed
    assert not twice.changed
    assert twice.rewritten_text == once.rewritten_text


# ---------------------------------------------------------------------------
# workbook_id scoping
# ---------------------------------------------------------------------------


def test_workbook_id_filter_excludes_other_workbooks(session):
    """Chains belonging to a different workbook are invisible to the rewriter."""
    new = _add(
        session,
        path="file:///wb2/new.pdf",
        title="WB2 New",
        doc_number="USD00088881",
        workbook_id=2,
    )
    _add(
        session,
        path="file:///wb2/old.pdf",
        title="WB2 Old",
        doc_number="USD00088880",
        workbook_id=2,
        superseded_by_id=new.id,
    )

    text = "Per USD00088880 reviews happen quarterly."
    # Asking from workbook_id=1 must not rewrite a workbook_id=2 chain.
    result = rewrite_evidence_chain(session, text, workbook_id=1)
    assert not result.changed


def test_workbook_id_filter_includes_workbook_agnostic_rows(session):
    """Rows with workbook_id=None resolve across workbooks (org-wide policy library)."""
    new = _add(
        session,
        path="file:///global/new.pdf",
        title="Global New",
        doc_number="USD00077771",
        workbook_id=None,
    )
    _add(
        session,
        path="file:///global/old.pdf",
        title="Global Old",
        doc_number="USD00077770",
        workbook_id=None,
        superseded_by_id=new.id,
    )

    text = "Per USD00077770 reviews happen quarterly."
    result = rewrite_evidence_chain(session, text, workbook_id=42)
    assert result.changed
    assert "USD00077771" in result.rewritten_text


# ---------------------------------------------------------------------------
# Defensive paths
# ---------------------------------------------------------------------------


def test_empty_text_returns_no_hits(session):
    result = rewrite_evidence_chain(session, "")
    assert not result.changed
    assert result.rewritten_text == ""


def test_none_session_is_noop():
    """No session → no-op (preserves Assessor(llm=None) test contract)."""
    result = rewrite_evidence_chain(None, "Per USD00099999 reviews happen.")
    assert not result.changed
    assert "USD00099999" in result.rewritten_text


def test_no_superseded_rows_returns_no_hits(session):
    """No chain rows in DB → fast bail."""
    _add(
        session,
        path="file:///docs/current.pdf",
        title="Current",
        doc_number="USD00066661",
    )
    result = rewrite_evidence_chain(session, "Per USD00066661 reviews happen.")
    assert not result.changed
