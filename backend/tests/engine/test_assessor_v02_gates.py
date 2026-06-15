"""Synthetic tests for v0.2 precision-over-recall gates in ``Assessor._run``.

The end-to-end test file (``test_assessor_e2e.py``) covers the v0.1 happy
paths plus the abstain-on-exhaustion + no-llm-client contracts that v0.2
re-shaped. This file pins the six **new** v0.2 mechanisms whose first
production caller is the assessor pipeline itself — gaps that would let a
low-conviction guess or hallucinated cite leak into the export path:

    1. Rule 8c SDA mapping demotion (no artifact → deterministic NC gap +
       POA&M, no LLM call; artifact present → scope-hint prepend → LLM)
    2. Dual-pass status disagreement → abstain
    3. Boundary conflict (narrative says outside boundary but status != NA)
    4. Low-confidence validator-passed proposal → implicit abstain
    5. Literal cite-verification (USD/SV/CCI/control-id tokens) → abstain
    6. Telemetry counters (AssessmentRun.abstained, .dual_pass_disagreements)

Per plan ``hashed-launching-frost.md`` verification step 10: *"new tests
for ``_verify_cites``, ``_abstain``, ``_finalize_sda_gap_decision``,
``_boundary_conflict``"*. The stale-reference and NA-reconsideration
gates (``find_stale_references`` + ``na_reconsideration_warning``) are
exercised via monkeypatch because in steady-state the rewrite layer
pre-empts the stale-finder (they share ``_COMPILED_PATTERNS``) and
NA-reconsideration only fires on prior-results text that real fixtures
don't carry. These tests pin the v0.2 pivot: stale-ref + NA-recon do
**NOT** abstain — they flag ``rewrite_requested=True`` on a TRUSTED
verdict so the row flows through POAM/CCIS/SAR with a "Cite refresh
requested" note. Boundary conflict still abstains because that
contradiction questions the verdict itself, not just the citation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

# Backend package importable when pytest is launched from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine import supersession  # noqa: E402
from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    Assessor,
    LlmProposal,
)
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.engine.measurement import RunRecorder  # noqa: E402
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    AssessmentRun,
    ComplianceStatus,
    Workbook,
)

# Reuse helpers from the e2e suite — same StubLlmClient + _row factory.
from tests.engine.test_assessor_e2e import StubLlmClient, _row  # noqa: E402


# Non-empty tagged-evidence bundle for tests that exercise downstream LLM /
# abstain / dual-pass logic. The v0.2 no-evidence short-circuit in
# Assessor._run (Step 1.65) deterministically returns Non-Compliant when the
# bundle is None / whitespace, BEFORE the LLM is called — so every test that
# wants to reach the LLM path must pass non-empty evidence. USD00050010 is
# baked in because several narratives in this file cite that token and the
# v0.2 cite-verifier would reject any narrative whose USD/SV/CCI/AC- tokens
# aren't literally present in the evidence bundle.
_PLACEHOLDER_EVIDENCE = (
    "## Tagged evidence\n"
    "- USD00050010 Example System Account Management Plan Rev - — covers account ops.\n"
)


# ---------------------------------------------------------------------------
# Custom stub for dual-pass disagreement (returns two DISTINCT proposals)
# ---------------------------------------------------------------------------


class DualPassDistinctStub(StubLlmClient):
    """Pops TWO proposals per ``propose_twice`` call instead of duplicating one.

    The base ``StubLlmClient.propose_twice`` returns ``(p, p)`` to keep the
    pre-v0.2 e2e tests semantics intact (one proposal per attempt). For
    disagreement testing we need pass1 and pass2 to differ — so this
    subclass pops both off the queue.
    """

    def propose_twice(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
    ) -> tuple[LlmProposal, LlmProposal]:
        p1 = self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
            crm_responsibility=crm_responsibility,
            boundary_brief=boundary_brief,
        )
        p2 = self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
            crm_responsibility=crm_responsibility,
            boundary_brief=boundary_brief,
        )
        return (p1, p2)


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


# ---------------------------------------------------------------------------
# 1. Rule 8c — verified SDA Controls mapping short-circuits before LLM
# ---------------------------------------------------------------------------


def _install_synthetic_sda_mapping(monkeypatch) -> None:
    """Install a fictional verified SDA mapping so the Rule 8c path can be
    exercised without baking program data into the test suite.

    The shipped registry (``_SSAA_TO_SDA_MAPPINGS``) ships **empty** — it held
    one program's verbatim CCI→SDA-Controls Req# mappings and was scrubbed. The
    global is read at call time (``lookup_verified_sda_mapping`` iterates it
    live), so patching it here drives the Rule 8c demotion/short-circuit logic.
    CCI-001485 / AU-2 / Req #29 is synthetic reference data — CCI numbers are
    public DISA reference and SSAA is generic federal RMF terminology.
    """
    mapping = supersession.VerifiedSdaMapping(
        cci_id="CCI-001485",
        control_id="au-2",
        sda_req_number="#29",
        shall_statement=(
            "The system shall generate audit records for the defined "
            "auditable events."
        ),
    )
    monkeypatch.setattr(supersession, "_SSAA_TO_SDA_MAPPINGS", [mapping])


def test_rule_8c_no_artifact_is_non_compliant_gap_not_compliant(monkeypatch):
    """CCI-001485 hits the SDA-mapping whitelist but NO artifact is tagged.

    This pins the PSC-as-evidence fix. A program-specific control mapping
    only establishes that the requirement is IN SCOPE — it is never proof
    the requirement was implemented. Pre-0.8.0 Rule 8c short-circuited to
    COMPLIANT by restating the SDA Controls shall-statement as the
    narrative; that used the program-control requirement text as evidence,
    which is the major bug. The new contract: with no customer-side artifact
    the deterministic verdict is Non-Compliant (in-scope-but-undemonstrated)
    and a POA&M is opened — still no LLM call.

    Pins: ``source='rule-8c'`` (VerdictSource routing unchanged),
    ``rule='sda-mapping-undemonstrated'``, ``status=Non-Compliant``,
    ``confidence=1.0``, ``needs_review=False`` (NC flows to exports), the
    narrative carries the Req # provenance token plus "POA&M", and
    ``stub.calls == []`` (empty-queue stub AssertionErrors if the LLM runs).
    """
    _install_synthetic_sda_mapping(monkeypatch)
    row = _row(cci_id="CCI-001485", control_id="AU-2")
    stub = StubLlmClient([])  # any LLM call → AssertionError
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row)

    assert decision.source == "rule-8c"
    assert decision.rule == "sda-mapping-undemonstrated"
    assert decision.accepted is True
    assert decision.status is ComplianceStatus.NON_COMPLIANT
    assert decision.confidence == 1.0
    assert decision.needs_review is False
    # Narrative carries the verified SDA Req # token so reviewers see scope
    # provenance, and "POA&M" so the gap classifier / advisory fires.
    assert "Req #29" in (decision.narrative or "")
    assert "POA&M" in (decision.narrative or "")
    assert stub.calls == []


def test_rule_8c_with_artifact_threads_scope_hint_and_calls_llm(monkeypatch):
    """CCI-001485 with a customer-side artifact → mapping demoted to a hint.

    When artifacts ARE tagged, the SDA mapping is no longer a verdict — it
    is a scope/applicability hint prepended to the evidence bundle, and the
    assessor falls through to the LLM (Step 2) which judges the artifacts on
    their own merits. Pins: the LLM IS consulted (the stub proposal is
    consumed) and the scope-hint block reaches the model's evidence view,
    explicitly disclaiming evidentiary weight.
    """
    _install_synthetic_sda_mapping(monkeypatch)
    row = _row(cci_id="CCI-001485", control_id="AU-2")
    proposal = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Audit event selection examined and confirmed via the tagged "
            "audit configuration export; required events are generated."
        ),
        citations=[],
        confidence=0.9,
    )
    stub = StubLlmClient([proposal])
    assessor = Assessor(llm=stub)

    artifact = (
        "## Tagged evidence\n"
        "- Audit configuration export — shows the system generates the "
        "AU-2 d required audit events.\n"
    )
    decision = assessor.assess(row, tagged_evidence=artifact)

    # LLM was consulted (mapping did NOT short-circuit the verdict).
    assert stub.calls, "expected the LLM to be called on the artifact path"
    # The scope hint reached the model's evidence view, disclaiming weight.
    prompt_evidence = stub.calls[-1].get("tagged_evidence") or ""
    assert "program_control_scope" in prompt_evidence
    assert "NOT evidence of implementation" in prompt_evidence
    assert "Audit configuration export" in prompt_evidence


# ---------------------------------------------------------------------------
# 1b. No-evidence short-circuit — empty bundle abstains (needs_review)
# ---------------------------------------------------------------------------


def test_no_evidence_short_circuits_to_abstain():
    """Empty / missing tagged_evidence → abstain (needs_review), no LLM call.

    Step D (2026-06-11): zero evidence is *Unknown*, not a finding. When
    the evidence pipeline returned nothing for a CCI (no artifacts, no CRM
    hybrid prepend, no SDA verified mapping, no rule-8 trigger), the
    assessor must NOT spend tokens asking the LLM to invent a verdict —
    AND must not assert a confident Non-Compliant, which measured 88%
    wrong against the gold workbook (a missed retrieval is not an
    implementation gap). The row short-circuits to an ABSTAIN instead:
    ``source='abstain'``, ``status=None``, ``proposed_status=None``,
    ``confidence=None``, ``needs_review=True``, ``stub.calls == []``.
    """
    stub = StubLlmClient([])  # any LLM call → AssertionError
    assessor = Assessor(llm=stub)

    decision = assessor.assess(_row())

    assert decision.source == "abstain"
    assert decision.accepted is True
    assert decision.status is None
    assert decision.proposed_status is None
    assert decision.confidence is None
    assert decision.needs_review is True
    assert decision.review_reason.startswith("no-evidence:")
    assert decision.retries == 0
    assert stub.calls == []


def test_whitespace_only_evidence_also_short_circuits_to_abstain():
    """``tagged_evidence='   \\n  '`` is the same as None — abstain, no LLM call.

    Defensive: the assess() caller may pass an empty string from a
    builder that produces ``"".join(...)`` over zero items. The guard
    uses ``.strip()`` so any whitespace-only string is treated as
    "no evidence" and routed through the same Step D abstain path.
    """
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(_row(), tagged_evidence="   \n  ")

    assert decision.source == "abstain"
    assert decision.status is None
    assert decision.needs_review is True
    assert decision.review_reason.startswith("no-evidence:")
    assert stub.calls == []


# ---------------------------------------------------------------------------
# 2. Dual-pass status disagreement → abstain
# ---------------------------------------------------------------------------


def test_dual_pass_status_disagreement_abstains(session, monkeypatch):
    """Pass1 Compliant + Pass2 Non-Compliant → abstain (precision mechanism #4).

    Pins ``review_reason`` prefix + the recorder's
    ``dual_pass_disagreement`` outcome flag, which the persistence site
    in ``routes/controls.py`` rolls up to
    ``AssessmentRun.dual_pass_disagreements``.

    Dual-pass is OFF by default (see ``DUAL_PASS_ENABLED`` docstring in
    assessor.py — it was the largest source of needs_review noise). The
    mechanism itself still exists, so this test monkeypatches the flag
    on to pin behavior for the case where an operator re-enables it.
    """
    monkeypatch.setattr(
        "cybersecurity_assessor.engine.assessor.DUAL_PASS_ENABLED", True
    )
    wb = Workbook(path="/tmp/dual.xlsx", filename="dual.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)

    pass1 = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Configured to enforce account management; observed in the "
            "deployed system during quarterly inspection."
        ),
        confidence=0.9,
    )
    pass2 = LlmProposal(
        status=ComplianceStatus.NON_COMPLIANT,
        narrative=(
            "Sweep located no current evidence; reassess after evidence "
            "collection. Tracked via POA&M."
        ),
        confidence=0.7,
    )
    stub = DualPassDistinctStub([pass1, pass2])
    assessor = Assessor(llm=stub)

    recorder = RunRecorder.start(session, workbook_id=wb.id)
    decision = assessor.assess(
        _row(), recorder=recorder, tagged_evidence=_PLACEHOLDER_EVIDENCE
    )
    run = recorder.finish()

    assert decision.source == "abstain"
    assert decision.needs_review is True
    assert decision.review_reason is not None
    assert decision.review_reason.startswith("dual-pass-disagreement:")
    # Both pass statuses surface in the triage hint so the reviewer doesn't
    # have to re-run.
    assert "Compliant" in decision.review_reason
    assert "Non-Compliant" in decision.review_reason
    # Both passes' token usage was booked and both proposals consumed.
    assert len(stub.calls) == 2

    persisted = session.exec(
        select(AssessmentRun).where(AssessmentRun.id == run.id)
    ).one()
    assert persisted.dual_pass_disagreements == 1
    assert persisted.abstained == 1


# ---------------------------------------------------------------------------
# 3. Boundary conflict → abstain
# ---------------------------------------------------------------------------


def test_boundary_conflict_with_compliant_status_abstains():
    """Narrative says 'outside the boundary' but status=Compliant → abstain.

    The ``_boundary_conflict`` regex fires on a narrative that proposes a
    Compliant verdict while explicitly conceding the asset is outside the
    boundary. Only Not Applicable is a valid status for that phrasing — so
    the assessor abstains so the reviewer resolves the contradiction.
    """
    # Use a narrative the validator will accept on its own merits — the
    # boundary phrase is the only contradiction we want to test, not the
    # validator's restatement / class-mismatch logic.
    bad = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Account management procedures are documented in USD00050010 "
            "Example System Account Management Plan and verified via quarterly inspection, "
            "though the affected component is outside the boundary of the "
            "assessment per the system context document."
        ),
        confidence=0.85,
    )
    stub = StubLlmClient([bad])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(_row(), tagged_evidence=_PLACEHOLDER_EVIDENCE)

    assert decision.source == "abstain"
    assert decision.needs_review is True
    assert decision.review_reason is not None
    assert decision.review_reason.startswith("boundary-conflict:")
    assert "outside the boundary" in decision.review_reason
    assert "Compliant" in decision.review_reason


# ---------------------------------------------------------------------------
# 4. Low-confidence validator-passed proposal → implicit abstain
# ---------------------------------------------------------------------------


def test_low_confidence_validator_passed_proposal_abstains():
    """Validator OK but confidence < threshold → abstain ('low-confidence: …').

    A model that hedges below the precision threshold (default 0.35 — see
    ``CONFIDENCE_THRESHOLD`` docstring in assessor.py) is not trusted even
    when the narrative passes validation. The reviewer sees the row in
    the queue; exports gate it out. Implements mechanism #1 of the
    precision-over-recall contract.
    """
    p = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Configured to enforce account management; observed in the "
            "deployed system during quarterly inspection."
        ),
        confidence=0.2,
    )
    stub = StubLlmClient([p])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(_row(), tagged_evidence=_PLACEHOLDER_EVIDENCE)

    assert decision.source == "abstain"
    assert decision.needs_review is True
    assert decision.review_reason is not None
    # Format: "low-confidence: 0.20 < 0.35"
    assert decision.review_reason.startswith("low-confidence:")
    assert "0.20" in decision.review_reason
    assert "0.35" in decision.review_reason
    # Fix 3 (KERNEL_VERSION 0.5.0) — hard-abstain coerces ``status`` to None
    # so a reviewer cannot accidentally ship an unverified verdict; the
    # LLM's intended guess is preserved on ``proposed_status`` for the
    # reviewer UI + calibration export. Confidence stays on the row so the
    # reviewer can see the rejected score.
    assert decision.status is None
    assert decision.proposed_status is ComplianceStatus.COMPLIANT
    assert decision.confidence == 0.2


# ---------------------------------------------------------------------------
# 5. Cite-verification (UNSUPPORTED_DOC_CITATION) exhausts to abstain
# ---------------------------------------------------------------------------


def test_cite_verification_unsupported_doc_citation_exhausts_to_abstain():
    """Narrative cites USD99999999 but evidence only has USD12345678 → abstain.

    Mechanism #2: the validator's ``_verify_cites`` scans the narrative for
    USD / SV / CCI / control-id tokens and rejects any that are NOT
    literally present (case-insensitive substring) in the tagged evidence
    text. After ``max_retries`` failed corrective rounds the row abstains
    with ``review_reason`` carrying the
    ``validator-exhausted: unsupported_doc_citation: …`` trail.
    """
    evidence_text = (
        "## Tagged evidence\n"
        "- USD12345678 Network Diagram Rev A — covers boundary devices.\n"
        "- USD00050010 Example System Account Management Plan Rev - — covers account ops.\n"
    )
    # Every retry cites the same nonexistent USD doc → validator keeps
    # rejecting → exhausted → abstain.
    bad = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Account management procedures are documented in USD99999999 "
            "and verified via quarterly inspection."
        ),
        confidence=0.9,
    )
    stub = StubLlmClient([bad, bad, bad])  # initial + 2 retries
    assessor = Assessor(llm=stub, max_retries=2)

    decision = assessor.assess(_row(), tagged_evidence=evidence_text)

    assert decision.source == "abstain"
    assert decision.needs_review is True
    assert decision.review_reason is not None
    assert decision.review_reason.startswith("validator-exhausted:")
    assert "unsupported_doc_citation" in decision.review_reason
    # The hallucinated token surfaces in the triage hint so the reviewer
    # doesn't have to grep through the rejection log.
    assert "USD99999999" in decision.review_reason
    # Every rejection logged at least one UNSUPPORTED_DOC_CITATION entry.
    classes = {r.rejection_class for r in decision.rejection_log}
    assert "unsupported_doc_citation" in classes


def test_cite_verification_accepts_when_cited_token_present():
    """Narrative citing USD12345678 + evidence contains it → accepted.

    Negative-control for the above: pins that ``_verify_cites`` doesn't
    over-reject when the cited token actually IS in the evidence text.
    Without this, a regression that broke the case-insensitive substring
    check would convert every cited narrative into a false abstain.
    """
    evidence_text = (
        "## Tagged evidence\n"
        "- USD12345678 Network Diagram Rev A — covers boundary devices.\n"
    )
    good = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Boundary controls are documented in USD12345678 and verified "
            "via quarterly inspection."
        ),
        confidence=0.9,
    )
    stub = StubLlmClient([good])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(_row(), tagged_evidence=evidence_text)

    assert decision.accepted is True
    assert decision.source == "llm"
    assert decision.needs_review is False


# ---------------------------------------------------------------------------
# 6. Stale-reference + NA-reconsideration safety-nets (monkeypatched — both
#    flag rewrite_requested on a TRUSTED verdict; neither abstains)
# ---------------------------------------------------------------------------


def test_stale_reference_safety_net_flags_rewrite_requested(monkeypatch):
    """find_stale_references returning non-empty post-rewrite → rewrite_requested.

    In steady-state ``rewrite_narrative`` and ``find_stale_references`` share
    the same compiled patterns, so the rewrite always pre-empts the
    safety-net. We monkeypatch find_stale_references to return a synthetic
    SupersessionEntry — pinning the v0.2 pivot: stale-ref hits do NOT
    abstain (that would block downstream POAM/CCIS/SAR flow for a
    citation-only issue). Instead the verdict is TRUSTED and accepted,
    and ``rewrite_requested`` / ``rewrite_requested_refs`` carry the
    legacy → current pair so the exporter can attach a "Cite refresh
    requested" note. Boundary conflict (test 3) still abstains because
    that contradiction questions the verdict itself.
    """
    fake_entry = supersession.SupersessionEntry(
        legacy="HYPOTHETICAL Legacy Doc",
        current="USD00099999 Current Doc",
        sharepoint_folder="/sites/test/",
        notes=None,
    )
    monkeypatch.setattr(
        supersession,
        "find_stale_references",
        lambda text: [fake_entry] if text else [],
    )

    good = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Boundary controls are documented in USD00050010 Example System Account "
            "Management Plan and verified via quarterly inspection."
        ),
        confidence=0.9,
    )
    stub = StubLlmClient([good])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(_row(), tagged_evidence=_PLACEHOLDER_EVIDENCE)

    # Verdict is TRUSTED — accepted, not abstained.
    assert decision.accepted is True
    assert decision.source in ("llm", "llm_after_retry")
    assert decision.needs_review is False
    assert decision.status is ComplianceStatus.COMPLIANT
    # Rewrite-requested flag + legacy→current pair surface for the exporter.
    assert decision.rewrite_requested is True
    assert decision.rewrite_requested_refs is not None
    assert ("HYPOTHETICAL Legacy Doc", "USD00099999 Current Doc") in (
        decision.rewrite_requested_refs
    )


def test_na_reconsideration_flags_rewrite_requested(monkeypatch):
    """NA-reconsideration warning post-rewrite → rewrite_requested (no abstain).

    Sibling of the stale-reference safety-net test. In steady state
    ``na_reconsideration_warning`` only fires on prior-results text that
    the synthetic ``_row`` factory doesn't carry, so we monkeypatch it
    to return a synthetic warning. Also monkeypatch
    ``find_stale_references`` to an empty list to isolate this branch
    (otherwise both branches could contribute and ``rewrite_requested_refs``
    wouldn't be cleanly ``None``).

    Pins the v0.2 pivot for NA-reconsideration: the warning flags
    ``rewrite_requested=True`` on a TRUSTED Not Applicable verdict — refs
    stay ``None`` because NA-reconsideration doesn't carry a legacy→current
    pair (the exporter renders a generic "Cite refresh requested" note
    instead). The verdict still flows through POAM/CCIS/SAR with the
    callout attached; only boundary conflict abstains.
    """
    fake_warning = supersession.ReconsiderationWarning(
        cci_id="CCI-000001",
        severity="warning",
        message="Prior results suggest this CCI may no longer be NA — re-verify.",
    )
    monkeypatch.setattr(
        supersession,
        "na_reconsideration_warning",
        lambda cci_id, current_status, prior_results_text: fake_warning,
    )
    monkeypatch.setattr(
        supersession,
        "find_stale_references",
        lambda text: [],
    )

    na_proposal = LlmProposal(
        status=ComplianceStatus.NOT_APPLICABLE,
        narrative=(
            "Control is not applicable because the system does not have the "
            "affected component; it is implemented by AWS GovCloud and "
            "inherited under the platform ATO."
        ),
        confidence=0.9,
    )
    stub = StubLlmClient([na_proposal])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(_row(), tagged_evidence=_PLACEHOLDER_EVIDENCE)

    # Verdict is TRUSTED — accepted, not abstained.
    assert decision.accepted is True
    assert decision.source in ("llm", "llm_after_retry")
    assert decision.needs_review is False
    assert decision.status is ComplianceStatus.NOT_APPLICABLE
    # Rewrite-requested flag fires; refs is None because NA-reconsideration
    # has no legacy→current pair (exporter falls back to the generic note).
    assert decision.rewrite_requested is True
    assert decision.rewrite_requested_refs is None


# ---------------------------------------------------------------------------
# 7. Telemetry — abstained + dual_pass_disagreements counters persist
# ---------------------------------------------------------------------------


def test_telemetry_counters_track_abstained_and_dual_pass(session, monkeypatch):
    """Run a mixed batch; AssessmentRun rolls up abstain + dual-pass counts.

    Two CCIs:
      1. Clean compliant proposal (accepted, no abstain, no disagreement)
      2. Dual-pass disagreement (abstain + dual_pass_disagreement)

    Pins that the recorder sums ``CciOutcome.abstained`` into
    ``AssessmentRun.abstained`` and ``.dual_pass_disagreement`` into
    ``.dual_pass_disagreements`` — the counters the v0.2 patent-supporting
    accuracy claim depends on for the reviewer dashboard.

    Dual-pass is OFF by default (see ``DUAL_PASS_ENABLED`` docstring in
    assessor.py); monkeypatch it on so the disagreement path actually
    fires and the counters get exercised.
    """
    monkeypatch.setattr(
        "cybersecurity_assessor.engine.assessor.DUAL_PASS_ENABLED", True
    )
    wb = Workbook(path="/tmp/telemetry.xlsx", filename="telemetry.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)

    clean = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Configured to enforce account management; observed in the "
            "deployed system during quarterly inspection."
        ),
        confidence=0.9,
    )
    disagree_pass1 = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Configured to enforce account management; observed in the "
            "deployed system during quarterly inspection."
        ),
        confidence=0.9,
    )
    disagree_pass2 = LlmProposal(
        status=ComplianceStatus.NON_COMPLIANT,
        narrative="Sweep located no current evidence; tracked via POA&M.",
        confidence=0.7,
    )

    recorder = RunRecorder.start(session, workbook_id=wb.id)

    # Run 1 — clean compliant. Dual-pass returns (clean, clean) via
    # base-class duplicate semantics.
    stub1 = StubLlmClient([clean])
    assessor = Assessor(llm=stub1)
    d1 = assessor.assess(
        _row(cci_id="CCI-000001", control_id="AC-2"),
        recorder=recorder,
        tagged_evidence=_PLACEHOLDER_EVIDENCE,
    )
    assert d1.accepted is True
    assert d1.needs_review is False

    # Run 2 — dual-pass disagreement.
    stub2 = DualPassDistinctStub([disagree_pass1, disagree_pass2])
    assessor2 = Assessor(llm=stub2)
    d2 = assessor2.assess(
        _row(cci_id="CCI-000002", control_id="AC-2"),
        recorder=recorder,
        tagged_evidence=_PLACEHOLDER_EVIDENCE,
    )
    assert d2.source == "abstain"

    run = recorder.finish()

    persisted = session.exec(
        select(AssessmentRun).where(AssessmentRun.id == run.id)
    ).one()
    # 2 CCIs total, 1 abstain (the disagreement), 1 disagreement.
    assert persisted.ccis_accepted == 2  # both rows persisted (abstain too)
    assert persisted.abstained == 1
    assert persisted.dual_pass_disagreements == 1


# ---------------------------------------------------------------------------
# 8. Dual-narrative wiring -- advisory hygiene flows through to Decision +
#    RunRecorder without expanding the retry budget (v0.2)
# ---------------------------------------------------------------------------
#
# The unit suite (tests/test_validator.py) pins ``validate_dual_narratives``
# itself; these tests pin the *wiring*: that ``Assessor._run`` consumes the
# result, surfaces ``notes`` to the operator-visible Decision, and logs
# every ``flagged`` reason as a ``ValidatorRejection`` on the CciOutcome
# (so the patent-supporting accuracy telemetry records the catch). The
# verdict must STILL be accepted -- dual-narrative is advisory only.


def test_dual_narrative_clean_emits_no_notes_in_decision():
    """Clean split halves -> Decision.notes carries no leak warning, accepted."""
    p = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Configured to enforce account management; observed in the "
            "deployed system during quarterly inspection."
        ),
        narrative_on_prem=(
            "Local hardening applied via SCAP baseline; verified per SSP §4.1."
        ),
        narrative_cloud=(
            "Inherited from AWS GovCloud per FedRAMP authorization."
        ),
        confidence=0.9,
    )
    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="hybrid",
                narrative=None,
                source_baseline_id=1,
            )
        }
    )
    stub = StubLlmClient([p])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        _row(), crm_context=crm, tagged_evidence=_PLACEHOLDER_EVIDENCE
    )

    # Verdict accepted; no dual-narrative warning words leak through.
    assert decision.accepted is True
    assert decision.source in ("llm", "llm_after_retry")
    joined_notes = " ".join(decision.notes or [])
    assert "provider-only language" not in joined_notes
    assert "on-prem-only language" not in joined_notes
    assert "customer-owned" not in joined_notes
    assert "both narrative halves" not in joined_notes
    # Dual fields preserved for the UI detail page.
    assert decision.narrative_on_prem is not None
    assert decision.narrative_cloud is not None


def test_provider_language_in_onprem_half_surfaces_note_and_rejection(session):
    """on-prem half contains 'inherited from AWS' -> note + DUAL_NARRATIVE_MISLABEL.

    Wiring contract:
      * Decision.accepted stays True (advisory, not retry-triggering)
      * Decision.notes contains 'provider-only language'
      * RunRecorder's CciOutcome.rejections contains an entry whose
        rejection_class == 'dual_narrative_mislabel' so the run-level
        validator_rejections counter rolls up the flag
    """
    wb = Workbook(path="/tmp/dual-wiring.xlsx", filename="dual-wiring.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)

    p = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Configured to enforce account management; observed in the "
            "deployed system during quarterly inspection."
        ),
        # Provider-only phrase landed in the WRONG half -- this is the
        # exact swap-the-halves LLM error the wiring is meant to catch.
        narrative_on_prem=(
            "Inherited from AWS GovCloud per FedRAMP authorization."
        ),
        narrative_cloud=(
            "Local SCAP baseline applied; verified per SSP §4.1."
        ),
        confidence=0.9,
    )
    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="hybrid",
                narrative=None,
                source_baseline_id=1,
            )
        }
    )
    stub = StubLlmClient([p])
    assessor = Assessor(llm=stub)

    recorder = RunRecorder.start(session, workbook_id=wb.id)
    decision = assessor.assess(
        _row(),
        crm_context=crm,
        recorder=recorder,
        tagged_evidence=_PLACEHOLDER_EVIDENCE,
    )
    run = recorder.finish()  # noqa: F841 -- aggregated counters checked below

    # Verdict still accepted -- dual-narrative is advisory.
    assert decision.accepted is True
    assert decision.source in ("llm", "llm_after_retry")
    # Operator-visible note carries the leak warning.
    assert any("provider-only language" in n for n in (decision.notes or [])), (
        f"expected provider-only leak note; got {decision.notes!r}"
    )
    # CciOutcome recorded the flagged reason as a ValidatorRejection.
    outcomes = recorder.outcomes
    assert len(outcomes) == 1
    classes = {r.rejection_class for r in outcomes[0].rejections}
    assert "dual_narrative_mislabel" in classes, (
        f"expected dual_narrative_mislabel in rejections; got {classes!r}"
    )
    # Run-level rejection counter rolled up the flag (validator_rejections
    # sums len(rejections) across every CCI -- one mislabel here = +1).
    persisted = session.exec(
        select(AssessmentRun).where(AssessmentRun.id == run.id)
    ).one()
    assert persisted.validator_rejections >= 1


def test_crm_customer_with_populated_cloud_half_surfaces_note(session):
    """CRM=customer but cloud half populated -> mismatch note + rejection.

    Pins the cross-check wiring: when CRM responsibility says "customer"
    (full local ownership) the cloud half is expected empty, and a
    populated one is operator-flagged.
    """
    wb = Workbook(path="/tmp/dual-crm.xlsx", filename="dual-crm.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)

    p = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Configured to enforce account management; observed in the "
            "deployed system during quarterly inspection."
        ),
        narrative_on_prem=(
            "Local hardening applied per SSP §4.1."
        ),
        # CRM says customer -- this cloud text shouldn't exist.
        narrative_cloud=(
            "Some unexpected cloud-side text the LLM shouldn't have emitted."
        ),
        confidence=0.9,
    )
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
    stub = StubLlmClient([p])
    assessor = Assessor(llm=stub)

    recorder = RunRecorder.start(session, workbook_id=wb.id)
    decision = assessor.assess(
        _row(),
        crm_context=crm,
        recorder=recorder,
        tagged_evidence=_PLACEHOLDER_EVIDENCE,
    )
    recorder.finish()

    assert decision.accepted is True
    assert any("customer-owned" in n for n in (decision.notes or [])), (
        f"expected customer-owned mismatch note; got {decision.notes!r}"
    )
    classes = {r.rejection_class for r in recorder.outcomes[0].rejections}
    assert "dual_narrative_mislabel" in classes
