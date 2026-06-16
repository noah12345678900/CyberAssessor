"""Supplementary assessor tests covering the outcome-accumulator and rule-#8c paths.

``test_assessor_e2e.py`` pins the named source strings (rule_8a, llm, crm_*,
unresolved) and the recorder happy-path. This file fills in the branches that
suite doesn't reach — every one of these is patent-load-bearing plumbing that
would silently regress if not pinned:

* **Recorder ↔ rule-#8 short-circuit.** The rule path has its own
  ``outcome.accepted`` / ``retries_before_accept`` write site
  (assessor.py:430-431). The e2e suite only exercises this via the LLM
  happy path; if the rule-path branch broke, ``ccis_accepted`` on
  ``AssessmentRun`` would silently undercount the deterministic verdicts.
* **Recorder ↔ exhaust-retries.** The exhaust path has its own
  ``outcome.accepted = False`` / ``retries_before_accept = max_retries``
  write site (assessor.py:347-349). e2e exhausts retries but without a
  recorder, so the persisted-aggregates angle is untested.
* **CRM supersession.** A CRM overlay narrative may cite a legacy doc
  number (the CRM author is a human writing free text — nothing forces
  current-doc references). The orchestrator runs CRM narratives through
  the supersession map specifically so col Q lands on the current ref
  regardless of source (assessor.py:521-533). If this branch regressed,
  stale doc names would slip into NA / Inherited rows without warning.
* **CRM ↔ recorder.** Same as rule-#8: CRM short-circuit has its own
  outcome-write block (assessor.py:535-537); exercise it.
* **UNCLEAR_8C → LLM corrective context.** The whole point of rule #8c
  is that the orchestrator hands the LLM a non-default-to-Compliant
  hint up front (assessor.py:596) AND keeps reminding it on every retry
  (assessor.py:634). The plugin's hard rule — "when in doubt, ASK" — is
  enforced HERE; if either branch regressed, the LLM would silently
  default to Compliant on bare "inherited from" rows.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine import supersession, validator  # noqa: E402
from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    Assessor,
    LlmProposal,
)
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.engine.measurement import RunRecorder  # noqa: E402
from cybersecurity_assessor.engine.validator import (  # noqa: E402
    NarrativeClass,
    RejectionReason,
    ValidationResult,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    AssessmentRun,
    ComplianceStatus,
    Workbook,
)

# Reuse the StubLlmClient and _row helpers from the e2e suite — copy-import
# them rather than re-derive so a future change to the stub surfaces uniformly.
from tests.engine.test_assessor_e2e import _PLACEHOLDER_EVIDENCE, StubLlmClient, _row  # noqa: E402


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


@pytest.fixture
def workbook(session) -> Workbook:
    wb = Workbook(path="/tmp/test.xlsx", filename="test.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


# ---------------------------------------------------------------------------
# Recorder ↔ rule-#8 short-circuit
# ---------------------------------------------------------------------------


def test_recorder_records_accepted_for_rule_8a_short_circuit(session, workbook):
    """Rule_8a verdict with recorder → ccis_accepted=1, retry_count=0, no LLM call.

    Pins assessor.py:430-431 (outcome.accepted = accepted; retries = 0 inside
    ``_finalize_rule_decision``). Without this branch, deterministic rule-#8
    verdicts would not count toward the run's acceptance rate — the patent's
    accuracy claim would underreport its own deterministic wins.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(procedures="This CCI is automatically compliant; no system-level evidence required.")
    stub = StubLlmClient([])  # any LLM call would AssertionError
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, recorder=recorder)
    assert decision.source == "rule_8a"
    assert decision.accepted is True
    assert stub.calls == []

    run = recorder.finish()
    persisted = session.exec(select(AssessmentRun).where(AssessmentRun.id == run.id)).one()
    assert persisted.ccis_accepted == 1
    assert persisted.retry_count == 0
    assert persisted.validator_rejections == 0
    assert persisted.supersession_hits == 0
    # llm_calls counts CCIs processed, not actual LLM invocations — see
    # measurement.py:165 (``len(self._outcomes)``). Pin to 1 for the same
    # reason test_recorder_captures_rejection_and_supersession pins it to 1.
    assert persisted.llm_calls == 1


def test_recorder_records_accepted_for_rule_8b_short_circuit(session, workbook):
    """Rule_8b with recorder → same accumulator path as 8a (assessor.py:430-431).

    Pinning both 8a and 8b explicitly because the source-string branch in
    ``_run`` is per-verdict; a regression that broke only 8b's outcome would
    pass the 8a test alone.

    Post-v0.11.0 the 8b NA trigger is a documented scope exclusion in col Q/U
    (the assessor's own rationale), not CSP language in col K/J — so this row
    carries the exclusion in col Q. See
    test_rules_golden.py::test_8b_scope_exclusion_in_col_q.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(results="Not required for GOCO; this CCI is out of the assessed boundary.")
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, recorder=recorder)
    assert decision.source == "rule_8b"
    assert decision.accepted is True

    run = recorder.finish()
    persisted = session.exec(select(AssessmentRun).where(AssessmentRun.id == run.id)).one()
    assert persisted.ccis_accepted == 1
    assert persisted.retry_count == 0


# ---------------------------------------------------------------------------
# Recorder ↔ exhaust-retries
# ---------------------------------------------------------------------------


def test_recorder_records_abstain_when_retries_exhausted(session, workbook):
    """3 bad attempts WITH recorder → ccis_accepted=0, retry_count=max_retries.

    v0.2: validator-exhaustion no longer drops the row silently as "unresolved".
    Instead the orchestrator returns an abstain Decision (accepted=True,
    source="abstain", needs_review=True), and the recorder books it as a
    non-accepted outcome (ccis_accepted unchanged) with retry_count pinned
    to max_retries on the exhausted-loop fall-through. The e2e suite covers
    the Decision shape on exhaust; this test pins the persisted-row shape so
    accuracy metrics correctly report the validator-never-accepted rate.
    """
    bad = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative="The system shall enforce least privilege as required by the control objective.",
        confidence=1.0,
    )
    stub = StubLlmClient([bad, bad, bad])  # max_retries=2 → 3 total attempts
    assessor = Assessor(llm=stub, max_retries=2)
    recorder = RunRecorder.start(session, workbook_id=workbook.id)

    decision = assessor.assess(
        _row(), recorder=recorder, tagged_evidence=_PLACEHOLDER_EVIDENCE
    )
    # v0.2 abstain contract — accepted=True (so the row is persisted with
    # needs_review=True) but source="abstain", not "unresolved".
    assert decision.accepted is True
    assert decision.source == "abstain"
    assert decision.needs_review is True
    assert decision.review_reason is not None
    assert decision.review_reason.startswith("validator-exhausted")

    run = recorder.finish()
    persisted = session.exec(select(AssessmentRun).where(AssessmentRun.id == run.id)).one()
    # v0.2 abstain contract — kernel/recorder layer only. accepted=True is
    # the kernel's *request* that the route persist the row; whether the
    # route honors that is pinned in
    # tests/routes/test_assess_persistence.py (the DB-write boundary). The
    # recorder counters checked here (ccis_accepted, abstained) fire inside
    # _abstain_decision itself (engine/assessor.py:1310-1327) and are
    # independent of any DB write — so this test asserts only what is true
    # at the engine layer. The historical version of this comment claimed
    # the row was persisted; that claim was false (it gated on
    # status is not None and narrative — the silent-drop bug,
    # feedback_abstain_status_none_drops.md) and the assertion never
    # would have caught the regression.
    assert persisted.ccis_accepted == 1
    assert persisted.abstained == 1
    # 3 attempts × 2 rejections each (requirement_restatement + status_narrative_mismatch
    # from AMBIGUOUS) — matches the count pinned in test_llm_exhausts_retries_abstains.
    assert persisted.validator_rejections == 6
    # retry_count is the SUM of retries_before_accept across all outcomes; on
    # exhaust we set it to max_retries (2), not max_retries+1 — the "initial
    # attempt" is not a retry. This is the value the patent's retry-to-accept
    # ratio uses; pin it explicitly so the meaning doesn't drift.
    assert persisted.retry_count == 2


# ---------------------------------------------------------------------------
# CRM supersession + recorder
# ---------------------------------------------------------------------------




def test_recorder_records_accepted_for_crm_short_circuit(session, workbook):
    """CRM provider/inherited/NA with recorder → ccis_accepted=1.

    Pins assessor.py:535-537. The CRM short-circuit has its OWN
    outcome-write block (separate from the rule-#8 and LLM paths); a
    regression that broke this branch would underreport CRM verdicts in
    the same way #8 underreporting would underreport rule-#8 verdicts.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="AC-2")
    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="provider",
                narrative=None,  # use default template — no supersession to interfere
                source_baseline_id=1,
            )
        }
    )
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, crm_context=crm, recorder=recorder)
    assert decision.source == "crm_provider"
    assert decision.accepted is True

    run = recorder.finish()
    persisted = session.exec(select(AssessmentRun).where(AssessmentRun.id == run.id)).one()
    assert persisted.ccis_accepted == 1
    assert persisted.retry_count == 0
    assert persisted.supersession_hits == 0


# ---------------------------------------------------------------------------
# UNCLEAR_8C → LLM corrective context
# ---------------------------------------------------------------------------


def _bare_inherited_row() -> CcisRow:
    """Row that trips rule 8c (UNCLEAR_8C) — bare 'inherited from' with no source.

    Per rules._BARE_INHERITED_FROM, the trigger is a literal "inherited from"
    in col J or K that does NOT match any of the qualified phrases (e.g.
    "inherited from DoW", "inherited from AWS", etc.). Use a vague suffix
    so neither the 8a-internal nor 8b-external trigger fires.
    """
    return _row(procedures="This control is inherited from another system.")


def test_unclear_8c_passes_initial_corrective_context_to_llm():
    """UNCLEAR_8C → stub.calls[0]['corrective_context'] contains the 8c hint.

    Pins assessor.py:596 (``_initial_corrective_context`` returns the 8c
    hint string for UNCLEAR_8C verdicts). Without this, the LLM would see
    a bare "inherited from" row with no orchestration hint and silently
    default to Compliant — the exact failure mode rule #8c exists to prevent.
    """
    row = _bare_inherited_row()
    stub = StubLlmClient(
        [
            LlmProposal(
                status=ComplianceStatus.NON_COMPLIANT,
                narrative=(
                    "No artifact found naming the inheritance source; gap identified "
                    "for the next POA&M cycle to clarify whether the source is "
                    "internal (DoW Enterprise) or external (CSP)."
                ),
                confidence=1.0,
            )
        ]
    )
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, tagged_evidence=_PLACEHOLDER_EVIDENCE)
    assert decision.accepted is True
    assert decision.source == "llm"

    # The hint MUST land in the first LLM call's corrective_context. Pin the
    # load-bearing phrases verbatim — these are the exact strings the plugin's
    # rule #8c text uses, so a paraphrase here would mean the plugin and the
    # ported kernel diverged.
    assert len(stub.calls) == 1
    ctx = stub.calls[0]["corrective_context"]
    assert ctx is not None
    assert "Rule #8c triggered" in ctx
    assert "Do NOT default to Compliant or Not Applicable" in ctx
    # And the trigger column is named so the LLM can locate the offending text.
    assert "col K" in ctx or "col J" in ctx


def test_unclear_8c_reminder_appended_on_retry():
    """UNCLEAR_8C + first proposal rejected → retry's corrective_context has the 8c reminder.

    Pins assessor.py:634 (``_build_corrective_context`` appends the 8c
    reminder when the verdict was UNCLEAR_8C). The orchestrator must keep
    reminding the LLM about #8c across the whole retry chain — losing it
    on retry would let the LLM "forget" and default to Compliant on the
    second attempt, the exact regression the reminder defends against.
    """
    row = _bare_inherited_row()
    stub = StubLlmClient(
        [
            # Attempt 1: regex-restatement → rejected, triggers a retry.
            LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=(
                    "The system shall enforce inheritance from the parent system as required."
                ),
                confidence=1.0,
            ),
            # Attempt 2: clean gap-describing narrative.
            LlmProposal(
                status=ComplianceStatus.NON_COMPLIANT,
                narrative=(
                    "No artifact found naming the inheritance source; gap identified "
                    "for the next POA&M cycle."
                ),
                confidence=1.0,
            ),
        ]
    )
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, tagged_evidence=_PLACEHOLDER_EVIDENCE)
    assert decision.accepted is True
    assert decision.source == "llm_after_retry"

    # Both calls' corrective_context include the 8c verdict — the initial via
    # _initial_corrective_context, the retry via _build_corrective_context.
    assert len(stub.calls) == 2
    initial_ctx = stub.calls[0]["corrective_context"]
    retry_ctx = stub.calls[1]["corrective_context"]
    assert initial_ctx is not None and "Rule #8c triggered" in initial_ctx
    # The retry reminder phrasing is distinct from the initial hint — pin it
    # verbatim so a refactor that drops the reminder would surface here even
    # if the rest of the corrective-context plumbing was intact.
    assert retry_ctx is not None
    assert "rule #8c is still in effect" in retry_ctx
    # And the rejection details still land in the retry context — the 8c
    # reminder ADDS to the corrective context, doesn't replace it.
    assert "rejected by the deterministic validator" in retry_ctx


# ---------------------------------------------------------------------------
# Defensive-guard branches in _finalize_rule_decision
# ---------------------------------------------------------------------------
#
# Rule #8 templates are deterministic — under normal operation
# ``supersession.rewrite_narrative(auto.narrative)`` returns zero hits and
# ``validator.validate(...)`` returns zero rejections. The orchestrator
# nonetheless runs the auto-generated narrative through both kernels, and
# walks any hits/rejections back onto the Decision log AND the recorder
# outcome. Those loops (assessor.py:390-399 and 417-426) are reachable
# only if the underlying formatter ever produces text that trips a kernel
# guard — that is a formatter bug, but the orchestrator's defensive
# write-through is the audit-log guarantee. Pin both paths via monkeypatch
# so a refactor that drops "if outcome is not None: outcome.X.append(...)"
# would surface here before silently dropping audit events on real bugs.




def test_defensive_guard_logs_validator_rejection_when_rule8_template_unexpectedly_invalid(
    session, workbook, monkeypatch
):
    """Inject a validator rejection on the rule-#8 narrative → Decision log + recorder both see it.

    Pins assessor.py:417-426. Rule-#8 templates are designed to pass the
    validator (the orchestrator passes ``row=None`` to skip Jaccard, and
    the templates avoid the regex restatement patterns). If a regression
    in the formatter ever produced text the validator rejects, the
    orchestrator's response MUST be to log the rejection as a
    ValidatorRejection — not to silently write the bad text. This is
    the kernel's "formatter bug surfaces in the audit log" guarantee
    and the only branch where ``Decision.accepted`` can be False for a
    rule-#8 row.

    Inject by monkeypatching ``validator.validate`` to return a
    rejection regardless of input — the only deterministic way to reach
    this branch from a rule-#8 row.
    """
    row = _row(procedures="This CCI is automatically compliant; no system-level evidence required.")

    def _fake_validate(*, proposed_status, proposed_narrative, row=None) -> ValidationResult:
        return ValidationResult(
            ok=False,
            classified_as=NarrativeClass.AMBIGUOUS,
            rejections=[
                (
                    RejectionReason.FORMAT_VIOLATION,
                    "simulated formatter regression in rule-#8 template",
                )
            ],
            notes=[],
        )

    monkeypatch.setattr(validator, "validate", _fake_validate)

    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    stub = StubLlmClient([])  # rule_8a short-circuits
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, recorder=recorder)

    assert decision.source == "rule_8a"
    # When the validator rejects a rule-#8 template, accepted MUST be False
    # and status/narrative MUST NOT be written (assessor.py:435-437) — the
    # whole point of the defensive branch is to refuse to write bad text.
    assert decision.accepted is False
    assert decision.status is None
    assert decision.narrative is None

    # The rejection landed on the Decision log with the formatter-bug
    # corrective_context envelope (assessor.py:422). Pin the prefix
    # verbatim — the UI surfaces this string so the developer can spot
    # which rule's template misbehaved.
    assert len(decision.rejection_log) == 1
    rej = decision.rejection_log[0]
    assert rej.rejection_class == RejectionReason.FORMAT_VIOLATION.value
    assert "rule=8a" in rej.original_output
    assert rej.corrective_context.startswith("Rule #8a formatter produced invalid text:")
    assert "simulated formatter regression" in rej.corrective_context

    # AND the recorder picked it up — proving the "if outcome is not None"
    # branch at assessor.py:425-426 fired. Counts toward validator_rejections
    # on the run aggregate so the patent's accuracy metrics reflect even
    # the formatter-bug rejections, not just LLM rejections.
    run = recorder.finish()
    persisted = session.exec(select(AssessmentRun).where(AssessmentRun.id == run.id)).one()
    assert persisted.validator_rejections == 1
    # Rejected rule-#8 row counts as NOT accepted (assessor.py:430).
    assert persisted.ccis_accepted == 0
