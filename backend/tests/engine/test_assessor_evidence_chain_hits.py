"""End-to-end: evidence-chain rewriter fires on all four finalize paths.

The chain rewriter (``supersession.rewrite_evidence_chain``) is unit-tested in
``test_evidence_chain_rewriter.py`` — that suite pins matching precision,
multi-hop resolution, idempotency, and workbook_id scoping in isolation. This
file pins the integration claim that's its sibling: the rewriter is actually
**wired in** at every place ``Assessor`` finalizes a Decision, and each
rewrite is recorded as a ``SupersessionHit`` with source ``"evidence_chain"``
on the Decision's ``supersession_log``.

The call sites (mirroring ``test_assessor_logs_short_circuits.py`` /
``test_assessor_e2e.py``):

  1. **LLM accept** — ``_run`` path. Validator-accepted LLM proposal whose
     narrative cites a now-superseded evidence row.
  2. **Rule #8a structural** — ``_finalize_rule_decision`` path. Col-L names
     a now-superseded internal source; the auto-generated narrative quotes
     col-L verbatim, so the chain rewriter fires on the templated text.
  3. **CRM inherited** — ``_finalize_crm_decision`` path. The CRM-supplied
     narrative names a now-superseded artifact.

Rule #8c (SDA Controls mapping) intentionally does NOT participate in
evidence-chain rewriting as of KERNEL_VERSION 0.8.0: the PSC-as-evidence
fix means the no-artifact gap narrative never quotes the shall-statement
(rule #11.2) and the artifact-present path defers to the LLM (covered by
call site 1). There is therefore no templated external-ref text for the
chain rewriter to act on in the 8c path, and no 8c-specific test here.

Plus a negative test pinning the no-op-without-session contract: when
``Assessor`` is built without ``cache_session=`` (the kernel-pure mode used
by every test in ``test_assessor_e2e.py`` that pre-dates this slice), the
rewriter MUST silently skip rather than blow up. Otherwise this slice would
break the entire pre-existing assessor test suite.

Each test stages an ``Evidence`` row whose title appears verbatim in the
relevant narrative path, plus a current chain-head row with a USD
doc_number; the rewriter substitutes the doc_number into the narrative
and emits one ``evidence_chain`` hit. The persisted-narrative assertion
("stale ref is gone, USD-number is present") is the operator-facing claim:
col Q lands on the current ref regardless of which finalize path produced
the verdict.
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

from cybersecurity_assessor import models  # noqa: F401,E402 -- register tables
from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    Assessor,
    LlmProposal,
)
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.models import (  # noqa: E402
    ComplianceStatus,
    Evidence,
    EvidenceKind,
)
from tests.engine.test_assessor_e2e import StubLlmClient, _row  # noqa: E402


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


def _add_evidence(
    session: Session,
    *,
    title: str,
    doc_number: str | None = None,
    superseded_by_id: int | None = None,
    workbook_id: int | None = None,
    path_suffix: str | None = None,
) -> Evidence:
    """Insert + flush an Evidence row with explicit superseded_by_id.

    Bypasses the auto-supersession tracker (``apply_supersession_at_ingest``)
    so the test owns the chain shape rather than relying on Policy A/B
    heuristics matching what we want. The tracker is exercised by
    ``test_supersession_tracker.py``; here we're testing the *consumer*.
    """
    sfx = path_suffix or title.replace(" ", "_")[:40]
    ev = Evidence(
        path=f"file:///docs/{sfx}.pdf",
        sha256=f"sha-{sfx}",
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


def _stage_chain(
    session: Session,
    *,
    legacy_title: str,
    current_doc_number: str,
    current_title: str | None = None,
) -> tuple[Evidence, Evidence]:
    """Stage a legacy → current chain. Returns (current_head, legacy)."""
    current = _add_evidence(
        session,
        title=current_title or f"{legacy_title} Rev B",
        doc_number=current_doc_number,
        path_suffix=f"{current_doc_number}_new",
    )
    legacy = _add_evidence(
        session,
        title=legacy_title,
        doc_number=None,
        superseded_by_id=current.id,
        path_suffix=f"{current_doc_number}_old",
    )
    session.commit()
    return current, legacy


# ---------------------------------------------------------------------------
# 1. LLM accept path
# ---------------------------------------------------------------------------


def test_llm_accept_path_records_evidence_chain_hit(session):
    """An LLM-accepted narrative citing a retired Evidence row gets rewritten.

    Validator runs AFTER the rewrite — so the narrative the validator sees
    (and that lands on the Decision) names the chain head, not the retired
    row. Cite-verifier checks the USD-number token is present in the
    evidence bundle, so the test bundle includes USD00099991.
    """
    _, _legacy = _stage_chain(
        session,
        legacy_title="Example System Account Management Procedure Manual",
        current_doc_number="USD00099991",
    )

    proposal = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Account roster reviewed quarterly per the Example System Account Management "
            "Procedure Manual; verified via inspection of the December 2025 "
            "review minutes."
        ),
        confidence=1.0,
    )
    stub = StubLlmClient([proposal])
    assessor = Assessor(llm=stub, cache_session=session)

    decision = assessor.assess(
        _row(),
        # Cite-verifier needs the rewritten USD token literally present.
        tagged_evidence=(
            "## Tagged evidence\n"
            "- USD00099991 Example System Account Management Procedure Manual Rev B — "
            "covers account ops.\n"
        ),
    )

    assert decision.accepted is True
    assert decision.source == "llm"
    chain_hits = [h for h in decision.supersession_log if h.source == "evidence_chain"]
    assert len(chain_hits) == 1
    hit = chain_hits[0]
    assert hit.stale_ref == "Example System Account Management Procedure Manual"
    assert hit.current_ref == "USD00099991"
    # Persisted narrative: stale title gone, current doc-number present.
    assert "USD00099991" in decision.narrative
    assert "Example System Account Management Procedure Manual" not in decision.narrative


# ---------------------------------------------------------------------------
# 2. Rule #8a structural path
# ---------------------------------------------------------------------------


def test_rule_8a_structural_records_evidence_chain_hit(session):
    """Col-M names a now-superseded internal source; auto-narrative quotes it.

    Owner convention: Column L is the Remote/Yes flag; the inheritance SOURCE
    is in Column M. ``rules._format_8a_structural_narrative`` embeds that
    Column-M source, and the rewriter scans the templated text and rewrites the
    source to the chain head's doc_number.
    """
    _stage_chain(
        session,
        legacy_title="Example System Account Management Procedure Manual",
        current_doc_number="USD00099992",
    )

    # Column L = Remote (flag); Column M = the legacy source title verbatim.
    # → rule_8a structural fires (triggered on Column M).
    row = _row(
        inherited="Remote",
        remote_inheritance="Example System Account Management Procedure Manual",
    )
    stub = StubLlmClient([])  # rule_8a → LLM must not be called
    assessor = Assessor(llm=stub, cache_session=session)

    decision = assessor.assess(row)

    assert decision.source == "rule_8a"
    assert decision.accepted is True
    assert decision.status is ComplianceStatus.COMPLIANT
    assert stub.calls == []
    chain_hits = [h for h in decision.supersession_log if h.source == "evidence_chain"]
    assert len(chain_hits) == 1
    hit = chain_hits[0]
    assert hit.stale_ref == "Example System Account Management Procedure Manual"
    assert hit.current_ref == "USD00099992"
    assert "USD00099992" in decision.narrative
    assert "Example System Account Management Procedure Manual" not in decision.narrative


# ---------------------------------------------------------------------------
# 3. CRM short-circuit path (inherited)
# ---------------------------------------------------------------------------


def test_crm_inherited_path_records_evidence_chain_hit(session):
    """CRM-supplied narrative cites a now-superseded artifact.

    CRM short-circuit (provider/inherited/not_applicable) builds the
    Decision narrative from the CRM entry's text; the chain rewriter
    runs over that text before the Decision is returned.
    """
    _stage_chain(
        session,
        legacy_title="Example System Account Management Procedure Manual",
        current_doc_number="USD00099994",
    )

    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="inherited",
                narrative=(
                    "Inherited from the parent ATO; controls are operated per "
                    "Example System Account Management Procedure Manual section 4."
                ),
                source_baseline_id=1,
            )
        }
    )
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub, cache_session=session)

    decision = assessor.assess(_row(control_id="AC-2"), crm_context=crm)

    assert decision.source == "crm_inherited"
    assert decision.accepted is True
    assert decision.status is ComplianceStatus.COMPLIANT
    assert stub.calls == []
    chain_hits = [h for h in decision.supersession_log if h.source == "evidence_chain"]
    assert len(chain_hits) == 1
    hit = chain_hits[0]
    assert hit.stale_ref == "Example System Account Management Procedure Manual"
    assert hit.current_ref == "USD00099994"
    assert "USD00099994" in decision.narrative
    assert "Example System Account Management Procedure Manual" not in decision.narrative


# ---------------------------------------------------------------------------
# 5. Negative — session-free Assessor must NOT touch the rewriter
# ---------------------------------------------------------------------------


def test_session_free_assessor_is_noop_for_evidence_chain(session):
    """``Assessor(llm=...)`` without cache_session must skip the rewriter.

    This preserves the legacy contract every pre-existing test in
    ``test_assessor_e2e.py`` relies on: the orchestrator is kernel-pure
    when no session is plumbed in. Stage the same Rule-#8a scenario as
    Test 2, but instantiate the Assessor without ``cache_session=`` —
    the chain block must short-circuit to a no-op, leaving the legacy
    title in the narrative.
    """
    _stage_chain(
        session,
        legacy_title="Example System Account Management Procedure Manual",
        current_doc_number="USD00099995",
    )

    row = _row(
        inherited="Remote",
        remote_inheritance="Example System Account Management Procedure Manual",
    )
    stub = StubLlmClient([])
    # NOTE: no cache_session=
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row)

    assert decision.source == "rule_8a"
    assert decision.accepted is True
    chain_hits = [h for h in decision.supersession_log if h.source == "evidence_chain"]
    assert chain_hits == []
    # Legacy title still present — proof the rewriter was a no-op.
    assert "Example System Account Management Procedure Manual" in decision.narrative
    assert "USD00099995" not in decision.narrative
