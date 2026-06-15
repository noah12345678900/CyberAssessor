"""Tests for ``Assessor.assess`` Step 1.65 no-evidence short-circuit.

Step D (2026-06-11) — this short-circuit used to mint a confident
Non-Compliant (``source="rule_no_evidence"``, ``status=NON_COMPLIANT``,
``confidence=1.0``, ``needs_review=False``). Measured against the
human-reviewed gold workbook that was wrong on 88% of the rows it
touched: a missed retrieval is indistinguishable from a real gap at
this layer, so asserting failure on zero evidence is a false
Non-Compliant — the worst error class under FPR-first. The path now
*abstains* (``source="abstain"``, ``status=None``, ``proposed_status``
None, ``confidence=None``, ``needs_review=True``) so the row is held for
manual review and suppressed from the export, rather than shipped as a
fabricated failure. These tests pin the abstain contract.

The live SQLite at ``~/.cybersecurity-assessor/assessor.sqlite`` proved
the rule never fired in production: 0 rows with confidence 1.0 across
297 assessments, despite 91 of those rows landing on objectives with
zero ``evidencetag`` entries. Root cause: ``_build_evidence_block``
returns a NON-empty string for an untagged objective in two situations:

  1. **Coverage-only block** — for the six coverage-eligible families
     (CM-8, CM-6, CA-3, CA-7, PM-5, RA-5) the block contains
     ``## asset_coverage_report`` even when no artifacts were
     retrieved. The wrapper is workbook-wide instructional context,
     identical across every CM-8 CCI in the run — not per-objective
     evidence.
  2. **CRM hybrid responsibility-split prepend** — assembled inside
     ``Assessor.assess`` at Step 1.5 for hybrid-owned controls. The
     prepend is decision framing ("provider handles X; customer
     handles Y"), not retrieved artifact text.

The legacy gate (``tagged_evidence is None or not tagged_evidence.strip()``)
can't tell wrapper-only bundles from real-artifact bundles — both
slipped through and reached the LLM, which then wrote a confident NC
narrative without citing any actual artifact.

The structural fix passes an ``EvidenceBlock`` envelope from the
route-layer producer to the assessor. The producer KNOWS which kind
of content it appended (artifacts vs coverage wrapper vs hybrid
prepend) and exposes booleans + ``is_only_context``. The assessor
reads the structural signal instead of reverse-engineering it from a
free-form string.

What we pin:

  1. **Wrapper-only bundle abstains** — coverage-only and hybrid-only
     ``EvidenceBlock`` inputs short-circuit to an ABSTAIN
     (``source="abstain"``, ``status=None``, ``proposed_status`` None,
     ``confidence=None``, ``needs_review=True``). The StubLlmClient is
     never called, the Decision carries the templated context-only
     narrative opening and a ``"no-evidence:"`` ``review_reason``.
  2. **``text is None`` abstains** — the no-bundle-at-all path still
     short-circuits (the original case the gate was written for), now to
     the same abstain contract rather than a confident NC.
  3. **Real artifacts bypass the rule** — when ``has_artifacts=True``
     the LLM IS consulted, so the structural change does not regress
     the rich-evidence path.
  4. **Legacy string-only callers still work** — passing
     ``tagged_evidence="..."`` without an ``evidence_block`` still
     reaches the LLM for non-empty strings and still short-circuits
     for whitespace/None. The structural gate is additive, not a
     forced migration.

These four pinning cases are precisely the production blind spots the
live DB revealed (1, 2) plus the regression boundaries we don't want
to break (3, 4).
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

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    Assessor,
    LlmProposal,
)
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.engine.evidence_bundle import EvidenceBlock  # noqa: E402
from cybersecurity_assessor.engine.measurement import RunRecorder  # noqa: E402
from cybersecurity_assessor.models import ComplianceStatus, Workbook  # noqa: E402

# Canonical test helpers from the e2e suite.
from tests.engine.test_assessor_e2e import StubLlmClient, _row  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite with StaticPool — same pattern as test_assessor_e2e."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def workbook(session: Session) -> Workbook:
    wb = Workbook(path="/tmp/test_no_evidence.xlsx", filename="test.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


# Coverage-block payload identical in shape to what
# ``render_coverage_block`` emits for CM-8 / CA-3 / etc. The exact
# wording is not load-bearing for this test — what matters is that
# ``has_artifacts=False`` AND ``text is not None`` (the production
# failure mode where the wrapper alone slipped past the legacy gate).
_COVERAGE_ONLY_TEXT = (
    "## asset_coverage_report\n"
    "Declared inventory: 12 hosts. Scan coverage: 0 hosts (0%).\n"
    "Reconcile any scan-missing hosts before signing off."
)


# CRM hybrid prepend identical in shape to what
# ``Assessor._render_hybrid_block`` emits. Again the wording is not
# load-bearing — only the absence of any per-objective artifact text.
_HYBRID_ONLY_TEXT = (
    "## responsibility_split\n"
    "Provider handles tenant federation and SSO key rotation.\n"
    "Customer handles local AD group membership and approval workflow."
)


# Mixed-bundle payload — the regression boundary. Real artifact text
# followed by the coverage wrapper. ``has_artifacts=True``, so the
# rule MUST NOT fire even though the wrapper is also present.
_MIXED_TEXT = (
    "## tagged_evidence\n"
    "- title: USD00050010 Example System Account Management Plan Rev -\n"
    "  kind: policy\n"
    "  relevance: 0.85 (source=auto)\n"
    '  text: """\n'
    "Section 3.2: All privileged accounts are reviewed monthly. "
    "Reviews are documented in the AcctMgmt-001 register and "
    "signed by the ISSM.\n"
    '"""\n'
    "\n"
    "## asset_coverage_report\n"
    "Declared inventory: 12 hosts. Scan coverage: 12 hosts (100%)."
)


# ---------------------------------------------------------------------------
# Case 1: coverage-only EvidenceBlock → short-circuits
# ---------------------------------------------------------------------------


def test_coverage_only_block_short_circuits_llm_not_called(session, workbook):
    """``has_artifacts=False`` + coverage wrapper alone → rule_no_evidence.

    This is the CM-8 / CA-3 / PM-5 production blind spot. The wrapper
    was being treated as evidence by the legacy string-emptiness gate,
    so the LLM was burning calls to confidently NC a row it had nothing
    to reason about.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="CM-8")
    block = EvidenceBlock(
        text=_COVERAGE_ONLY_TEXT,
        has_artifacts=False,
        has_coverage=True,
        has_findings=False,
        has_hosts=False,
    )
    # Empty queue: any LLM call would AssertionError out of StubLlmClient.
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        recorder=recorder,
        tagged_evidence=block.text,
        evidence_block=block,
    )

    # LLM bypassed.
    assert stub.calls == []
    # Abstain fingerprint matches _finalize_no_evidence_decision → _abstain.
    assert decision.source == "abstain"
    assert decision.status is None
    assert decision.proposed_status is None
    assert decision.confidence is None
    assert decision.needs_review is True
    assert decision.accepted is True
    assert decision.retries == 0
    assert decision.review_reason.startswith("no-evidence:")
    # Context-only bundle gets the discriminating narrative: workbook-wide
    # context WAS available (asset_coverage_report), so claiming "no
    # artifacts were retrieved" would be indefensible to a 3PAO. The abstain
    # verdict is identical to the zero-candidate path — only the wording
    # differs.
    assert decision.narrative.startswith(
        "Workbook-wide context was available for this CCI"
    )
    # Recorder sees the abstain — exports and suspicion banner read from
    # here, so the gate must thread through. accepted=True means the row is
    # written; abstained=True is what the export gates filter on.
    assert len(recorder.outcomes) == 1
    assert recorder.outcomes[0].accepted is True
    assert recorder.outcomes[0].abstained is True


# ---------------------------------------------------------------------------
# Case 2: hybrid-prepend-only EvidenceBlock → short-circuits
# ---------------------------------------------------------------------------


def test_hybrid_prepend_only_block_short_circuits_llm_not_called(session, workbook):
    """``has_artifacts=False`` + CRM hybrid prepend alone → rule_no_evidence.

    The hybrid prepend is decision framing, not retrieved evidence.
    Per the approved plan it must NOT rescue an empty bundle: without
    artifacts the LLM has nothing customer-side to assess, so the rule
    fires regardless of how many context wrappers are stacked above it.

    Note: this is constructed directly as an EvidenceBlock to test the
    structural gate independently of where the hybrid prepend actually
    gets assembled (which is inside ``Assessor._run`` at Step 1.5, not
    the route-layer producer). The gate must short-circuit on the
    booleans alone, not on the source of the wrapper text.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="AC-2")
    block = EvidenceBlock(
        text=_HYBRID_ONLY_TEXT,
        has_artifacts=False,
        has_coverage=False,
        has_findings=False,
        has_hosts=False,
    )
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        recorder=recorder,
        tagged_evidence=block.text,
        evidence_block=block,
    )

    assert stub.calls == []
    assert decision.source == "abstain"
    assert decision.status is None
    assert decision.proposed_status is None
    assert decision.confidence is None
    assert decision.needs_review is True
    assert decision.review_reason.startswith("no-evidence:")
    # Hybrid responsibility-split prepend is a context wrapper too →
    # is_only_context bundle → discriminating context-only narrative.
    assert decision.narrative.startswith(
        "Workbook-wide context was available for this CCI"
    )


# ---------------------------------------------------------------------------
# Case 3: text=None EvidenceBlock → short-circuits
# ---------------------------------------------------------------------------


def test_none_text_block_short_circuits_llm_not_called(session, workbook):
    """``text=None`` (no bundle assembled at all) → rule_no_evidence.

    This is the original case the gate was written for — preserved
    under the structural path so callers that get back an empty
    envelope from the producer still hit the rule.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="AC-2")
    block = EvidenceBlock(
        text=None,
        has_artifacts=False,
        has_coverage=False,
        has_findings=False,
        has_hosts=False,
    )
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        recorder=recorder,
        tagged_evidence=None,
        evidence_block=block,
    )

    assert stub.calls == []
    assert decision.source == "abstain"
    assert decision.status is None
    assert decision.proposed_status is None
    assert decision.confidence is None
    assert decision.needs_review is True
    assert decision.review_reason.startswith("no-evidence:")


# ---------------------------------------------------------------------------
# Case 4: real artifacts + wrapper → LLM IS called (regression boundary)
# ---------------------------------------------------------------------------


def test_mixed_block_with_artifacts_does_not_short_circuit(session, workbook):
    """``has_artifacts=True`` (even with coverage wrapper also present) → LLM runs.

    The whole point of the structural gate is that wrappers no longer
    masquerade as evidence — but they also must not block the rule from
    standing aside when REAL evidence is present alongside. This is the
    regression boundary: stack a coverage wrapper on top of a tagged
    artifact and confirm the rule does NOT fire.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="CM-8", procedures="Examine asset inventory.")
    block = EvidenceBlock(
        text=_MIXED_TEXT,
        has_artifacts=True,
        has_coverage=True,
        has_findings=False,
        has_hosts=False,
    )
    proposal = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "USD00050010 documents monthly privileged-account review by the "
            "ISSM, observed in the 2026 AcctMgmt-001 register sample."
        ),
        confidence=0.9,
    )
    # Queue several copies — dual-pass + validator retry surface may
    # consume more than one. We don't pin the exact count; what we ARE
    # pinning is that the LLM was consulted AT LEAST ONCE (no short-circuit).
    stub = StubLlmClient([proposal] * 5)
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        recorder=recorder,
        tagged_evidence=block.text,
        evidence_block=block,
    )

    # LLM consulted — the rule deferred to it because real artifacts existed.
    assert len(stub.calls) >= 1
    # The rule's signature MUST be absent on this path.
    assert decision.source != "rule_no_evidence"
    assert decision.confidence != 1.0 or decision.source != "rule_no_evidence"


# ---------------------------------------------------------------------------
# Case 5: legacy string-only callers — backward-compat boundary
# ---------------------------------------------------------------------------


def test_legacy_string_only_empty_short_circuits(session, workbook):
    """Legacy callers (no ``evidence_block`` kwarg) still get the gate.

    Old fixtures and the single-CCI test path pass ``tagged_evidence``
    as a bare string. The structural gate is additive — when no
    EvidenceBlock is supplied, the old whitespace check still runs so
    these callers keep their pre-refactor behavior.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="AC-2")
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        recorder=recorder,
        tagged_evidence=None,  # no evidence_block — legacy path
    )

    assert stub.calls == []
    assert decision.source == "abstain"
    assert decision.status is None
    assert decision.confidence is None
    assert decision.needs_review is True
    assert decision.review_reason.startswith("no-evidence:")


def test_legacy_string_only_with_text_reaches_llm(session, workbook):
    """Legacy callers passing non-empty text still reach the LLM.

    This is the other half of the backward-compat boundary: a string
    that looks like evidence to the legacy gate gets through, exactly
    as it did before the refactor. We can't structurally distinguish
    wrapper-only from artifact-only on this path (that's the whole
    reason for the EvidenceBlock); legacy callers accept that trade.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="AC-2", procedures="Examine local enforcement.")
    proposal = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "USD00050010 documents monthly review of privileged accounts; "
            "observed in the 2026 audit log sample."
        ),
        confidence=0.9,
    )
    stub = StubLlmClient([proposal] * 5)
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        recorder=recorder,
        tagged_evidence=(
            "## tagged_evidence\n"
            "- USD00050010 Example System Account Management Plan Rev - — covers ops.\n"
        ),
        # No evidence_block — legacy string-only call.
    )

    # LLM was consulted via the legacy fallback path.
    assert len(stub.calls) >= 1
    assert decision.source != "rule_no_evidence"


# ---------------------------------------------------------------------------
# Case 6: CRM customer + EvidenceBlock with no artifacts → short-circuits
# ---------------------------------------------------------------------------


def test_customer_crm_with_empty_block_short_circuits(session, workbook):
    """Customer responsibility doesn't override the no-evidence rule.

    Customer-owned controls go through the LLM by default (no CRM
    short-circuit), but if the bundle is empty Step 1.65 still fires
    AFTER the CRM check declines. This pins that the two short-circuits
    compose correctly — customer + empty bundle = rule_no_evidence, not
    a wasted LLM call.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="AC-2")
    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="customer",
                narrative=None,
                source_baseline_id=1,
            )
        }
    )
    block = EvidenceBlock(
        text=None,
        has_artifacts=False,
        has_coverage=False,
        has_findings=False,
        has_hosts=False,
    )
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        recorder=recorder,
        tagged_evidence=None,
        evidence_block=block,
        crm_context=crm,
    )

    assert stub.calls == []
    assert decision.source == "abstain"
    assert decision.status is None
    assert decision.confidence is None
    assert decision.needs_review is True
    assert decision.review_reason.startswith("no-evidence:")
