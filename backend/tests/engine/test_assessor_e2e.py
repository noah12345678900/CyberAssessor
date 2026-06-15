"""End-to-end tests for the per-CCI assessor orchestrator.

This is the integration claim the three component-golden suites (rules,
validator, supersession) can't pin alone: the four patent-supporting
guards must **compose correctly** when the orchestrator wires them
together. Each test below exercises one named path through ``Assessor._run``
using a deterministic ``StubLlmClient`` so the kernel logic stays under
test without burning tokens.

Paths covered:
    1. Rule #8a short-circuits before the LLM is called at all.
    2. Rule #8b short-circuits before the LLM is called at all.
    3. CRM provider/inherited/not_applicable short-circuits (no LLM).
    4. CRM hybrid enrichment prepends the responsibility-split block.
    5. LLM first-attempt accepted (clean compliant narrative).
    6. LLM rejected then accepted after one corrective round.
    7. LLM exhausts retries → unresolved Decision, full rejection_log.
    8. Supersession rewrite happens BEFORE validation (stale ref pulled
       forward before the validator sees it).
    9. RunRecorder captures rejection + supersession measurements end-to-end.

Notes on assertions:
    * ``Decision.source`` strings are the contract the UI / export layer
      key off — ``"rule_8a"``, ``"rule_8b"``, ``"crm_provider"``,
      ``"crm_inherited"``, ``"crm_not_applicable"``, ``"llm"``,
      ``"llm_after_retry"``, ``"unresolved"``. Each test pins the exact
      string so a rename would surface immediately.
    * The stub records every call so we can also assert on what was
      passed to the LLM (e.g. that ``corrective_context`` was non-None
      on retry, or that the hybrid block was prepended to
      ``tagged_evidence``).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

# Ensure the backend package is importable when pytest is launched from any cwd.
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


# ---------------------------------------------------------------------------
# Stub LLM client + helpers
# ---------------------------------------------------------------------------


class StubLlmClient:
    """Returns canned proposals in order; records every call for assertions.

    The orchestrator's :class:`LlmClient` protocol only requires ``propose``,
    so this stub is the minimum surface. Each call pops one proposal off
    the queue — a test that wants to assert "the LLM was not called" sets
    an empty queue and verifies ``calls == []`` after assess returns.
    """

    def __init__(self, proposals: list[LlmProposal]) -> None:
        self._queue = list(proposals)
        self.calls: list[dict] = []

    def propose(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
    ) -> LlmProposal:
        self.calls.append(
            {
                "row": row,
                "corrective_context": corrective_context,
                "prior_attempts": list(prior_attempts) if prior_attempts else None,
                "tagged_evidence": tagged_evidence,
                "crm_responsibility": crm_responsibility,
                "boundary_brief": boundary_brief,
            }
        )
        if not self._queue:
            raise AssertionError(
                "StubLlmClient queue exhausted — test asked for more proposals "
                "than were canned. Inspect .calls to see what the orchestrator "
                "was actually asking for."
            )
        return self._queue.pop(0)

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
        """Dual-pass surface for v0.2 — returns the SAME proposal twice.

        Tests in this file pre-date the dual-pass mechanism. They canned one
        proposal per assess() attempt, so emitting the same proposal for
        both passes preserves test semantics: pass1.status == pass2.status
        (no disagreement → no abstain), and the orchestrator keeps using
        pass 1's narrative. Tests that want to exercise the disagreement
        path call propose_twice directly with two queued items.
        """
        p = self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
            crm_responsibility=crm_responsibility,
            boundary_brief=boundary_brief,
        )
        return (p, p)


# Non-empty tagged-evidence bundle for tests that exercise the LLM path. The
# v0.2 no-evidence short-circuit in Assessor._run (Step 1.65) deterministically
# returns Non-Compliant when the bundle is None / whitespace, BEFORE the LLM
# is called — so every test below that wants to reach the LLM / abstain /
# no-llm-client path must pass non-empty evidence. USD00050010 is baked in
# because several narratives in this file cite that token and the v0.2
# cite-verifier would reject narratives whose USD/SV/CCI/AC- tokens aren't
# literally present in the evidence bundle.
_PLACEHOLDER_EVIDENCE = (
    "## Tagged evidence\n"
    "- USD00050010 Example System Account Management Plan Rev - — covers account ops.\n"
)


def _install_synthetic_supersession(monkeypatch) -> None:
    """Install a fictional legacy→current rewrite entry so the supersession
    integration tests can exercise the rewrite path end-to-end through
    ``Assessor.assess``.

    The shipped registry (``_LEGACY_TO_CURRENT`` / ``_COMPILED_PATTERNS``)
    ships **empty** — it held one program's verbatim doc map and was scrubbed
    so no program data is baked into the app. The supersession globals are read
    at call time (``rewrite_narrative`` iterates ``_COMPILED_PATTERNS`` live),
    so patching them here drives the full rewrite path. The synthetic entry's
    ``current`` cites USD00050010, which is present in ``_PLACEHOLDER_EVIDENCE``
    so the post-rewrite narrative survives the v0.2 cite-verifier.
    """
    entry = supersession.SupersessionEntry(
        legacy="SDA T1 O&I Account Management User Guide",
        current="USD00050010 Example System Account Management Plan Rev -",
        sharepoint_folder=None,
        notes=None,
    )
    monkeypatch.setattr(supersession, "_LEGACY_TO_CURRENT", [entry])
    monkeypatch.setattr(
        supersession,
        "_COMPILED_PATTERNS",
        [(re.compile(re.escape(entry.legacy), re.IGNORECASE), entry)],
    )


def _row(
    *,
    procedures: str | None = None,
    guidance: str | None = None,
    inherited: str | None = None,
    definition: str | None = None,
    cci_id: str | None = "CCI-000001",
    control_id: str = "AC-2",
    results: str | None = None,
    previous_results: str | None = None,
) -> CcisRow:
    """Minimal CcisRow with sensible defaults for orchestrator tests."""
    return CcisRow(
        excel_row=10,
        required=True,
        control_id=control_id,
        ap_acronym=f"{control_id}.1",
        cci_id=cci_id,
        implementation_status=None,
        designation=None,
        narrative=None,
        definition=definition,
        guidance=guidance,
        procedures=procedures,
        inherited=inherited,
        remote_inheritance=None,
        status=None,
        date_tested=None,
        tester=None,
        results=results,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=previous_results,
    )


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
# Rule #8 short-circuits (LLM must not be called)
# ---------------------------------------------------------------------------


def test_rule_8a_short_circuits_llm_not_called():
    """Col K = 'automatically compliant' → source='rule_8a', stub.calls == []."""
    row = _row(procedures="This CCI is automatically compliant; no system-level evidence required.")
    stub = StubLlmClient([])  # empty queue — any call would AssertionError
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row)

    assert decision.source == "rule_8a"
    assert decision.rule == "8a"
    assert decision.accepted is True
    assert decision.status is ComplianceStatus.COMPLIANT
    assert decision.retries == 0
    assert stub.calls == []  # LLM never consulted


def test_rule_8b_short_circuits_llm_not_called():
    """Col Q scope-exclusion trigger → source='rule_8b', stub.calls == [].

    Post-v0.11.0, rule_8b NA fires from a documented scope exclusion in the
    assessor's own col Q/U rationale — NOT from CSP/provider language in the
    DISA template text of col K/J (that path is inert by design; CSP
    inheritance now maps to Compliant via rule_8a). See
    test_rules_golden.py::test_8b_scope_exclusion_in_col_q.
    """
    row = _row(results="Not required for GOCO; this CCI is out of the assessed boundary.")
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row)

    assert decision.source == "rule_8b"
    assert decision.rule == "8b"
    assert decision.accepted is True
    assert decision.status is ComplianceStatus.NOT_APPLICABLE
    assert stub.calls == []


# ---------------------------------------------------------------------------
# CRM short-circuits (LLM must not be called for provider/inherited/NA)
# ---------------------------------------------------------------------------


def test_crm_provider_short_circuits():
    """CRM responsibility=provider → source='crm_provider', NA, stub.calls == []."""
    row = _row(control_id="AC-2")
    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="provider",
                narrative=None,
                source_baseline_id=1,
            )
        }
    )
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, crm_context=crm)

    assert decision.source == "crm_provider"
    assert decision.accepted is True
    assert decision.status is ComplianceStatus.NOT_APPLICABLE
    assert stub.calls == []


def test_crm_inherited_short_circuits():
    """CRM responsibility=inherited → source='crm_inherited', COMPLIANT, stub.calls == []."""
    row = _row(control_id="AC-2")
    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="inherited",
                narrative="Inherited from the parent authorizing system.",
                source_baseline_id=1,
            )
        }
    )
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, crm_context=crm)

    assert decision.source == "crm_inherited"
    assert decision.accepted is True
    assert decision.status is ComplianceStatus.COMPLIANT
    assert stub.calls == []


def test_crm_hybrid_prepends_responsibility_split_block():
    """CRM responsibility=hybrid → LLM IS called, with the split block prepended.

    Hybrid is NOT a short-circuit (the customer half still needs assessment),
    but the orchestrator must inject a ``## responsibility_split`` block into
    ``tagged_evidence`` so the LLM scopes its narrative to the customer side.
    """
    row = _row(control_id="AC-2", definition="Account management requirements.")
    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="hybrid",
                narrative="Customer owns role-assignment workflow; provider owns directory service.",
                source_baseline_id=1,
            )
        }
    )
    stub = StubLlmClient(
        [
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "Customer-side role-assignment workflow is documented in "
                    "USD00050010 §3.2 and verified via inspection of the production roster."
                ),
                confidence=1.0,
            )
        ]
    )
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        crm_context=crm,
        # v0.2 cite-verification: any literal USD/SV/CCI/AC- token in the
        # accepted narrative must appear verbatim in the evidence text. The
        # bundle below mentions USD00050010 so the LLM's narrative passes.
        tagged_evidence=(
            "## evidence_bundle\n(some tags here)\n- USD00050010 §3.2 (role-assignment workflow)"
        ),
    )

    assert decision.accepted is True
    assert decision.source == "llm"
    # The stub captured what the orchestrator actually passed.
    assert len(stub.calls) == 1
    sent_evidence = stub.calls[0]["tagged_evidence"]
    assert sent_evidence is not None
    assert sent_evidence.startswith("## responsibility_split"), (
        f"hybrid block must be first; got: {sent_evidence[:80]!r}"
    )
    # And the original evidence bundle must still be there (not clobbered).
    assert "## evidence_bundle" in sent_evidence


def test_crm_not_applicable_short_circuits():
    """CRM responsibility=not_applicable → source='crm_not_applicable', NA, no LLM."""
    row = _row(control_id="AC-2")
    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="not_applicable",
                narrative=None,
                source_baseline_id=1,
            )
        }
    )
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, crm_context=crm)

    assert decision.source == "crm_not_applicable"
    assert decision.status is ComplianceStatus.NOT_APPLICABLE
    assert stub.calls == []


# ---------------------------------------------------------------------------
# LLM happy path + retry loop
# ---------------------------------------------------------------------------


def test_llm_first_attempt_accepted():
    """Stub returns a clean compliant narrative on call 1 → accepted, retries=0."""
    row = _row()  # no rule-#8 triggers
    stub = StubLlmClient(
        [
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "Account roster reviewed quarterly and documented in USD00050010 §3.2; "
                    "verified via inspection of the December 2025 review minutes."
                ),
                confidence=1.0,
            )
        ]
    )
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, tagged_evidence=_PLACEHOLDER_EVIDENCE)

    assert decision.accepted is True
    assert decision.source == "llm"
    assert decision.retries == 0
    assert decision.rejection_log == []
    assert len(stub.calls) == 1
    # Initial corrective_context is only set for UNCLEAR_8C; a plain row has none.
    assert stub.calls[0]["corrective_context"] is None
    assert stub.calls[0]["prior_attempts"] is None


def test_llm_rejected_then_accepted_after_corrective_round():
    """First proposal trips regex-restatement; second is clean → llm_after_retry, retries=1."""
    row = _row()
    stub = StubLlmClient(
        [
            # Attempt 1: regex-restatement pattern ("the system shall ... as required").
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "The system shall enforce least privilege as required by the control objective."
                ),
                confidence=1.0,
            ),
            # Attempt 2: clean affirming narrative citing USD doc.
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "Account roster reviewed quarterly per USD00050010 §3.2; verified via "
                    "inspection of the December 2025 review minutes."
                ),
                confidence=1.0,
            ),
        ]
    )
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, tagged_evidence=_PLACEHOLDER_EVIDENCE)

    assert decision.accepted is True
    assert decision.source == "llm_after_retry"
    assert decision.retries == 1
    # The "system shall ... as required" narrative trips TWO rejections per
    # attempt: requirement_restatement (regex hit) AND status_narrative_mismatch
    # (classifies as AMBIGUOUS). The validator surfaces every rejection it finds
    # rather than short-circuiting on the first — both get logged so the patent's
    # accuracy-claim measurement counts the true number of caught failures.
    assert len(decision.rejection_log) == 2
    classes = {r.rejection_class for r in decision.rejection_log}
    assert "requirement_restatement" in classes
    assert "status_narrative_mismatch" in classes
    # Two LLM calls; the second got a non-None corrective_context derived from the rejections.
    assert len(stub.calls) == 2
    assert stub.calls[0]["corrective_context"] is None
    assert stub.calls[1]["corrective_context"] is not None
    assert "rejected by the deterministic validator" in stub.calls[1]["corrective_context"]
    # And the second call saw the prior attempt in its history. Dual-pass
    # is off by default (see DUAL_PASS_ENABLED docstring in assessor.py), so
    # each rejected attempt books one proposal into the attempts buffer.
    assert stub.calls[1]["prior_attempts"] is not None
    assert len(stub.calls[1]["prior_attempts"]) == 1


def test_llm_exhausts_retries_abstains():
    """3 restatement narratives in a row → v0.2 abstain (validator-exhausted).

    v0.1 returned ``accepted=False, source='unresolved'`` and the row vanished.
    v0.2's precision contract converts validator exhaustion into an
    ``accepted=True, source='abstain', needs_review=True`` row so the reviewer
    sees the gap instead of it silently dropping. See plan
    ``hashed-launching-frost.md`` Mechanism 1.
    """
    bad = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative="The system shall enforce least privilege as required by the control objective.",
        confidence=1.0,
    )
    # max_retries=2 → 3 total attempts (initial + 2 retries).
    stub = StubLlmClient([bad, bad, bad])
    assessor = Assessor(llm=stub, max_retries=2)

    decision = assessor.assess(_row(), tagged_evidence=_PLACEHOLDER_EVIDENCE)

    # v0.2: abstain instead of drop. Row gets written (accepted=True) but the
    # export gates keep needs_review rows out of the eMASS workbook and POAM.
    assert decision.accepted is True
    assert decision.source == "abstain"
    assert decision.needs_review is True
    assert decision.review_reason is not None
    assert decision.review_reason.startswith("validator-exhausted")
    assert decision.retries == 2
    # 3 attempts × 2 rejections each (requirement_restatement + status_narrative_mismatch
    # from the AMBIGUOUS classification) → 6 ValidatorRejection records.
    assert len(decision.rejection_log) == 6
    classes = {r.rejection_class for r in decision.rejection_log}
    assert classes == {"requirement_restatement", "status_narrative_mismatch"}
    assert len(stub.calls) == 3


# ---------------------------------------------------------------------------
# Supersession integration — rewrite happens BEFORE validation
# ---------------------------------------------------------------------------


def test_supersession_rewrite_before_validation(monkeypatch):
    """LLM cites legacy 'SDA T1 O&I Account Management User Guide' → narrative gets rewritten.

    The accepted Decision must contain the USD doc reference, not the legacy
    one, AND ``supersession_log`` must record the (stale, current) pair. The
    fact that the validator approved at all proves the rewrite happened
    BEFORE validation — a stale-only narrative might fail the primary-citation
    note path but more importantly we'd see the wrong text in ``narrative``.

    The shipped registry ships empty (scrubbed of program data); a synthetic
    legacy→current entry is installed so the rewrite path is exercised without
    baking program data into the test suite.
    """
    _install_synthetic_supersession(monkeypatch)
    row = _row()
    stub = StubLlmClient(
        [
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "Account management procedures are documented in the SDA T1 O&I "
                    "Account Management User Guide §3.2 and verified via inspection."
                ),
            )
        ]
    )
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, tagged_evidence=_PLACEHOLDER_EVIDENCE)

    assert decision.accepted is True
    # Legacy ref is gone, current ref is present.
    assert "SDA T1 O&I Account Management User Guide" not in decision.narrative
    assert "USD00050010" in decision.narrative
    # Supersession log captured exactly one rewrite, with source="llm".
    assert len(decision.supersession_log) == 1
    hit = decision.supersession_log[0]
    assert hit.stale_ref == "SDA T1 O&I Account Management User Guide"
    assert "USD00050010" in hit.current_ref
    assert hit.source == "llm"


# ---------------------------------------------------------------------------
# RunRecorder integration — measurements flow end-to-end
# ---------------------------------------------------------------------------


def test_recorder_captures_rejection_and_supersession(session, monkeypatch):
    """Pass a real RunRecorder + Workbook; after assess, run row reflects 1 rejection + 1 supersession.

    Pins the patent's accuracy-claim plumbing: every rejection the validator
    raised must surface on ``AssessmentRun.validator_rejections`` and every
    supersession rewrite must surface on ``AssessmentRun.supersession_hits``.

    The shipped registry ships empty (scrubbed of program data); a synthetic
    legacy→current entry is installed so attempt 2's legacy citation triggers
    exactly one rewrite.
    """
    _install_synthetic_supersession(monkeypatch)
    # Seed a workbook the recorder can FK to.
    wb = Workbook(path="/tmp/test.xlsx", filename="test.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)

    recorder = RunRecorder.start(session, workbook_id=wb.id)

    stub = StubLlmClient(
        [
            # Attempt 1: regex-restatement → 1 rejection.
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "The system shall enforce least privilege as required by the control objective."
                ),
            ),
            # Attempt 2: clean, but cites a LEGACY doc so supersession rewrites it.
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "Procedures are documented in the SDA T1 O&I Account Management "
                    "User Guide §3.2 and verified via quarterly inspection."
                ),
            ),
        ]
    )
    assessor = Assessor(llm=stub)

    decision = assessor.assess(_row(), recorder=recorder, tagged_evidence=_PLACEHOLDER_EVIDENCE)

    assert decision.accepted is True
    assert decision.retries == 1

    run = recorder.finish()

    # Re-read from DB to prove the aggregations persisted (not just in-memory).
    persisted = session.exec(select(AssessmentRun).where(AssessmentRun.id == run.id)).one()
    # Attempt 1 raised 2 rejections (requirement_restatement + status_narrative_mismatch
    # from AMBIGUOUS classification); attempt 2 was accepted. The recorder sums every
    # ValidatorRejection record, not "attempts that were rejected".
    assert persisted.validator_rejections == 2
    assert persisted.supersession_hits == 1
    assert persisted.retry_count == 1
    assert persisted.ccis_accepted == 1
    assert persisted.llm_calls == 1  # one CCI processed (not one LLM call)


# ---------------------------------------------------------------------------
# No-LLM-configured edge case
# ---------------------------------------------------------------------------


def test_no_llm_client_abstains_when_rule8_declines():
    """Assessor(llm=None) on a non-rule-8 row → v0.2 abstain (no-llm-client).

    v0.1 dropped the row as ``unresolved``; v0.2 writes an abstain row so the
    reviewer queue surfaces the gap. The review_reason is the canonical
    no-llm-client string emitted by ``_run()`` when rule #8 declines and no
    LLM is wired (preview-only call sites).
    """
    assessor = Assessor(llm=None)  # explicit; matches preview-only call sites

    decision = assessor.assess(_row(), tagged_evidence=_PLACEHOLDER_EVIDENCE)

    assert decision.accepted is True
    assert decision.source == "abstain"
    assert decision.needs_review is True
    assert decision.review_reason == (
        "no-llm-client: rule #8 did not fire and no LLM client is configured"
    )
    assert decision.status is None


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


def test_max_retries_clamps_negative_to_zero():
    """Negative ``max_retries`` is clamped to 0 → exactly one attempt.

    Pins the construction guard at ``Assessor.__init__`` (assessor.py:297,
    ``self._max_retries = max(0, max_retries)``). A negative value must
    NOT loop indefinitely or raise — the orchestrator treats it as "zero
    retries allowed". With a mismatched proposal that the validator
    rejects, that single attempt exhausts immediately and the v0.2
    precision-over-recall path writes an abstain row (needs_review=True).

    Ported from the legacy root-level ``tests/test_assessor.py`` (deleted
    2026-06-05) — the rest of that file's tests were duplicates of this
    e2e suite, but this construction guard had no equivalent here.
    """
    bad = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative="No artifact found; POA&M opened.",
        confidence=1.0,
    )
    stub = StubLlmClient([bad])
    assessor = Assessor(llm=stub, max_retries=-5)

    decision = assessor.assess(_row(), tagged_evidence=_PLACEHOLDER_EVIDENCE)

    # With clamp=0, the single attempt's mismatched proposal exhausts
    # immediately → abstain row. retries counter stays at 0 since no
    # actual retry happened. LLM was called exactly once.
    assert decision.accepted is True
    assert decision.source == "abstain"
    assert decision.needs_review is True
    assert decision.retries == 0
    assert len(stub.calls) == 1
