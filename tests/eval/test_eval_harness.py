"""LLM eval harness — data-driven regression eval for ``Assessor.assess``.

Each JSON file under ``cases/`` is one frozen ``(CcisRow,
tagged_evidence, LLM-stub-proposals) → expected (status, source,
needs_review, narrative regex)`` tuple. The runner parameterizes over
every case file so adding a new case is a one-file diff and the test ID
matches the filename (``pytest -k <case_name>`` selects one).

Why this exists: every other test in ``backend/tests/engine/`` is
either unit-golden (one mechanism in isolation) or full-integration
(end-to-end happy / sad path). Neither catches "the LLM client output
changed but the verdict didn't" — that's the precision regression
``project_ccis_assessor_priorities_v01plus.md`` ranks as gap #3.

The cases pin **current kernel behavior**. If a prompt change in
``engine/assessor.py`` flips a case, the failure forces a deliberate
decision: either the new behavior is intended (update the case +
``description`` field), or the prompt change regressed precision
(revert).

Scope of v0.1 scaffold: deterministic stub LLM, 5 seed cases covering
rule_8b NA, no-evidence NC, LLM-accepted Compliant, low-confidence
abstain, self-signaled abstain. Live-LLM mode (same cases against a
real Claude client behind a ``live_llm`` marker) is the obvious next
slice once the format is pinned.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

# Make the backend package importable from any pytest cwd. Top-level
# conftest already does this, but mirror it here so this file works in
# isolation (e.g. ``pytest tests/eval/test_eval_harness.py``).
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine.assessor import Assessor  # noqa: E402
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402
from cybersecurity_assessor.models import ComplianceStatus  # noqa: E402

# Sibling-module import — tests/eval/ has __init__.py so this file IS part
# of a package, but pytest's rootdir-based discovery doesn't put ``tests``
# itself on sys.path (no ``tests/__init__.py``). Adding tests/eval/ to
# sys.path lets us use a flat import without colliding with stdlib ``eval``
# or requiring ``tests/`` to become a package (which would alter rootdir
# discovery for unrelated suites).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from _stubs import LlmProposal, StubLlmClient  # noqa: E402

from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.engine.evidence_bundle import (  # noqa: E402
    EvidenceBlock,
)

CASES_DIR = Path(__file__).parent / "cases"
CASE_FILES = sorted(CASES_DIR.glob("*.json"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_row(ccis_dict: dict[str, Any]) -> CcisRow:
    """Build a minimal ``CcisRow`` from a case-file ccis_row block.

    Mirrors ``_row(...)`` at
    ``backend/tests/engine/test_rules_golden.py:50`` — well-formed defaults
    for fields the eval doesn't exercise so case JSON only has to declare
    what matters. Unknown keys raise ``TypeError`` from ``CcisRow(...)``
    so a typo in the case file fails loudly instead of silently dropping
    a constraint.
    """
    defaults: dict[str, Any] = {
        "excel_row": 10,
        "required": True,
        "control_id": "AC-2",
        "ap_acronym": "AC-2.1",
        "cci_id": "CCI-000001",
        "implementation_status": None,
        "designation": None,
        "narrative": None,
        "definition": None,
        "guidance": None,
        "procedures": None,
        "inherited": None,
        "remote_inheritance": None,
        "status": None,
        "date_tested": None,
        "tester": None,
        "results": None,
        "previous_status": None,
        "previous_date": None,
        "previous_tester": None,
        "previous_results": None,
    }
    defaults.update(ccis_dict)
    return CcisRow(**defaults)


def _build_proposal(raw: dict[str, Any]) -> LlmProposal:
    """Build an ``LlmProposal`` from a case-file proposal dict.

    ``status`` arrives as a string (e.g. ``"Compliant"``) — coerce to
    ``ComplianceStatus``. Everything else flows through verbatim; unknown
    keys raise ``TypeError`` from the dataclass constructor.
    """
    raw = dict(raw)  # don't mutate the caller's dict
    if "status" in raw and isinstance(raw["status"], str):
        raw["status"] = ComplianceStatus(raw["status"])
    return LlmProposal(**raw)


def _build_crm_context(entries: list[dict[str, Any]] | None) -> CrmContext | None:
    """Build a ``CrmContext`` from a case-file ``crm_entries`` list.

    Each entry dict is splatted into ``CrmEntry(...)`` directly — the case
    file mirrors the constructor signature so unknown keys raise
    ``TypeError`` loudly. Returns ``None`` when the case has no
    ``crm_entries`` block so the assessor sees the same default-no-CRM
    path it gets when callers omit ``crm_context`` entirely.

    Mirrors the inline CRM construction at the ``test_force_llm_keeps_
    hybrid_crm_prepend`` test (lines 387-396) so the case-file path and
    the kernel-invariant tests share the same shape — the difference
    is just that case files declare it in JSON.

    Multiple entries land in ``CrmContext.by_control`` keyed by
    ``control_id`` (OSCAL canonical form, lowercased). The last entry
    wins on duplicate keys, matching ``build_crm_context``'s latest-wins
    semantics for real CRM overlays.
    """
    if not entries:
        return None
    by_control: dict[str, CrmEntry] = {}
    for entry in entries:
        crm_entry = CrmEntry(**entry)
        by_control[crm_entry.control_id] = crm_entry
    return CrmContext(by_control=by_control)


def _build_evidence_block(raw: dict[str, Any] | None) -> EvidenceBlock | None:
    """Build an ``EvidenceBlock`` from a case-file ``evidence_block`` dict.

    The dict is splatted into the ``EvidenceBlock(...)`` constructor
    directly — case JSON mirrors the dataclass signature so a typo'd
    field raises ``TypeError`` loudly instead of silently dropping the
    signal. Returns ``None`` when the case has no ``evidence_block``
    block so the assessor sees the same legacy-no-block path it gets
    when callers omit ``evidence_block`` entirely (preserves the
    deterministic short-circuit's pre-Audit-v1 behavior).

    Cases that need ``evidence_shown`` payloads (Audit v1 per-chunk
    persistence) aren't supported here yet — that requires the route
    layer's hashed-chunk pipeline which isn't reproducible from JSON.
    Eval cases focus on the BOOLEAN signals the validator gates on
    (``has_nonscan_artifact`` for the corroboration rule, etc.).
    """
    if not raw:
        return None
    return EvidenceBlock(**raw)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_cases_directory_is_not_empty():
    """Sanity guard — the harness is useless without cases.

    A misconfigured directory (wrong glob, missing files, accidental
    rename of ``cases/``) would otherwise present as ``parametrize(
    [])`` and pytest reports zero tests collected without failing.
    This test fails loudly so CI catches the empty corpus.
    """
    assert CASE_FILES, (
        f"No JSON case files found under {CASES_DIR}. "
        "The eval harness requires at least one case — see README.md."
    )


@pytest.mark.parametrize("case_path", CASE_FILES, ids=lambda p: p.stem)
def test_eval_case(case_path: Path) -> None:
    """Drive one frozen case end-to-end through ``Assessor.assess``.

    Each ``expected.*`` key is asserted only if present in the case
    JSON, so a case can opt out of (say) narrative-regex pinning without
    having to declare a no-op. ``source_in`` accepts a list of
    equivalent source strings (``["llm", "llm_after_retry"]``) for cases
    where either path is fine.
    """
    case = json.loads(case_path.read_text(encoding="utf-8"))
    row = _build_row(case["ccis_row"])
    proposals = [_build_proposal(p) for p in case.get("llm_stub_proposals", [])]
    stub = StubLlmClient(proposals)
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        tagged_evidence=case.get("tagged_evidence"),
        crm_context=_build_crm_context(case.get("crm_entries")),
        evidence_block=_build_evidence_block(case.get("evidence_block")),
    )

    exp = case["expected"]

    # status — string compare via the enum so "Compliant" matches
    # ComplianceStatus.COMPLIANT cleanly. ``None`` expected (hard
    # abstain pre-route coercion) is honored explicitly.
    if "status" in exp:
        expected_status = exp["status"]
        if expected_status is None:
            assert decision.status is None, (
                f"Expected hard abstain (status=None) but got {decision.status!r}"
            )
        else:
            assert decision.status == ComplianceStatus(expected_status), (
                f"Expected status={expected_status!r} but got "
                f"{decision.status!r}; review_reason={decision.review_reason!r}"
            )

    if "proposed_status" in exp:
        # Fix 3 (KERNEL_VERSION 0.5.0) — hard-abstain rows coerce status=None
        # but preserve the LLM's guess on proposed_status so the reviewer UI
        # and calibration export know what verdict was intended. A pre-fix
        # replay would ship status=<value> with proposed_status=None, so
        # pinning the field independently catches a regression of the
        # coercion contract.
        expected_proposed = exp["proposed_status"]
        if expected_proposed is None:
            assert decision.proposed_status is None, (
                f"Expected proposed_status=None but got {decision.proposed_status!r}"
            )
        else:
            assert decision.proposed_status == ComplianceStatus(expected_proposed), (
                f"Expected proposed_status={expected_proposed!r} but got "
                f"{decision.proposed_status!r}"
            )

    if "source_in" in exp:
        assert decision.source in exp["source_in"], (
            f"Expected source in {exp['source_in']!r} but got "
            f"{decision.source!r}; notes={decision.notes!r}"
        )

    if "needs_review" in exp:
        assert decision.needs_review is exp["needs_review"], (
            f"Expected needs_review={exp['needs_review']!r} but got "
            f"{decision.needs_review!r}; review_reason={decision.review_reason!r}"
        )

    if "accepted" in exp:
        # Kernel-side precondition for the persistence-boundary fix pinned
        # at backend/tests/routes/test_abstain_coercion.py. The historical
        # silent-drop bug (feedback_abstain_status_none_drops.md) ended at
        # _coerce_abstain_persistence_fields in routes/controls.py, but the
        # ONLY reason that helper ever sees an abstain row is that the
        # kernel's _abstain() at engine/assessor.py:1654 returns
        # accepted=True. If a future refactor flips that to False (or makes
        # any other Decision path silently drop the accepted flag), the
        # persistence-boundary helper never fires and the row vanishes
        # before the SQL gate ever runs. Per-case pin so abstain cases
        # specifically can assert the contract; happy-path Compliant cases
        # don't need it (the cache write at assessor.py:1339 gates on the
        # Decision being LLM-accepted, which is itself the contract).
        assert decision.accepted is exp["accepted"], (
            f"Expected accepted={exp['accepted']!r} but got "
            f"{decision.accepted!r}; source={decision.source!r} "
            f"needs_review={decision.needs_review!r}"
        )

    if "llm_calls" in exp:
        assert len(stub.calls) == exp["llm_calls"], (
            f"Expected {exp['llm_calls']} LLM call(s) but stub recorded "
            f"{len(stub.calls)}. This usually means a deterministic "
            f"short-circuit (rule 8a/8b/no-evidence/CRM) fired (or "
            f"didn't fire) when the case expected the opposite."
        )

    if "narrative_contains_regex" in exp:
        assert decision.narrative is not None, (
            "Expected a narrative to match regex but decision.narrative is None"
        )
        pattern = exp["narrative_contains_regex"]
        assert re.search(pattern, decision.narrative), (
            f"Narrative did not match regex {pattern!r}.\n"
            f"Narrative was: {decision.narrative!r}"
        )

    if "review_reason_contains_regex" in exp:
        assert decision.review_reason is not None, (
            "Expected review_reason to match regex but it is None"
        )
        pattern = exp["review_reason_contains_regex"]
        assert re.search(pattern, decision.review_reason), (
            f"review_reason did not match regex {pattern!r}.\n"
            f"review_reason was: {decision.review_reason!r}"
        )

    if "rejection_classes_contains" in exp:
        # Some validator paths trigger MULTIPLE rejection classes per
        # attempt (e.g. REQUIREMENT_RESTATEMENT forces classify_narrative
        # → AMBIGUOUS, which also fires STATUS_NARRATIVE_MISMATCH). The
        # `review_reason` only echoes the LAST rejection's class, so a
        # regex on review_reason can't distinguish "this fired because
        # of restatement detection" from "this fired because the
        # narrative was just incoherent." This assertion walks
        # decision.rejection_log directly so a case can pin the
        # *primary* mechanism that drove the abstain regardless of
        # downstream effects.
        classes_seen = {r.rejection_class for r in decision.rejection_log}
        expected_classes = exp["rejection_classes_contains"]
        if isinstance(expected_classes, str):
            expected_classes = [expected_classes]
        missing = [c for c in expected_classes if c not in classes_seen]
        assert not missing, (
            f"Expected rejection_classes {expected_classes!r} to all appear "
            f"in decision.rejection_log; missing={missing!r}; "
            f"got={sorted(classes_seen)!r}"
        )

    if "dual_narrative_flags_contains" in exp:
        # Unlike rejection_log entries (which trigger retry or abstain),
        # dual_narrative_flags are ADVISORY — the verdict in `status` is
        # still accepted while the on-prem/cloud halves are flagged for
        # human review. Walking decision.dual_narrative_flags directly
        # lets a case pin the validator's swap-the-halves / CRM-mismatch
        # detection (validator.validate_dual_narratives at
        # engine/validator.py:530-600) without asserting against
        # rejection_log, which stays empty on the LLM-accept path that
        # this advisory layer rides on top of.
        flags_seen = set(decision.dual_narrative_flags or [])
        expected_flags = exp["dual_narrative_flags_contains"]
        if isinstance(expected_flags, str):
            expected_flags = [expected_flags]
        missing = [c for c in expected_flags if c not in flags_seen]
        assert not missing, (
            f"Expected dual_narrative_flags {expected_flags!r} to all appear "
            f"in decision.dual_narrative_flags; missing={missing!r}; "
            f"got={sorted(flags_seen)!r}"
        )

    if "llm_prompt_evidence_contains_regex" in exp:
        # Inspects the tagged_evidence string passed INTO the LLM (what the
        # assessor sent), not the narrative coming OUT. This is the only
        # case-file-driven way to pin prompt enrichment paths — the hybrid
        # CRM prepend at assessor.py:752-763 (`## responsibility_split`
        # header), the in-process_drawings injection, etc. Decision-only
        # assertions can't distinguish "the LLM saw the prepend and chose
        # accordingly" from "the LLM happened to land on the right verdict
        # without seeing it" — this assertion forces the prompt-shape
        # invariant explicitly.
        #
        # Asserts against the FIRST recorded call (stub.calls[0]) — that's
        # the dual-pass pass-1, where prompt enrichment is applied
        # identically to pass-2 because the assessor calls propose_twice
        # with a single tagged_evidence argument. Cases that need to assert
        # on a retry path's enrichment should pin the retry path separately
        # once we add a `llm_prompt_evidence_contains_regex_call_index`
        # extension; not needed for any current case.
        assert stub.calls, (
            "Expected llm_prompt_evidence_contains_regex to match but the "
            "stub recorded zero calls — a deterministic short-circuit fired "
            "before the LLM was consulted. Cross-check with llm_calls."
        )
        sent_evidence = stub.calls[0]["tagged_evidence"]
        assert sent_evidence is not None, (
            "Expected tagged_evidence in the first LLM call but it was None"
        )
        pattern = exp["llm_prompt_evidence_contains_regex"]
        assert re.search(pattern, sent_evidence), (
            f"LLM prompt evidence did not match regex {pattern!r}.\n"
            f"tagged_evidence sent was: {sent_evidence!r}"
        )


# ---------------------------------------------------------------------------
# force_llm flag — kernel-level invariants for the eval harness's
# `llm-forced` mode. These are NOT case-file driven because the flag is a
# kernel contract, not a precision regression target: the eval CLI relies
# on these invariants holding to interpret per-bucket agreement numbers.
# If one of these tests flips, the eval's "engine-only vs llm-forced"
# comparison loses its meaning.
# ---------------------------------------------------------------------------


def test_force_llm_does_not_bypass_rule_8a() -> None:
    """Rule 8a (col K assertion) MUST short-circuit even with force_llm=True.

    Gates 1-2 encode the user's own attestations (cols K/J); LLM-overriding
    them models the wrong intent — the assessor's job isn't to dispute the
    user's "automatically compliant" call, it's to *trust* that call as a
    deterministic input. Pinning this here means the eval's `llm-forced`
    mode reports an honest baseline: a Rule_8a oracle row will agree under
    `llm-forced` for the structural reason (gate 1 fired), not because the
    LLM independently picked Compliant.

    Empty stub queue + zero recorded calls is the assertion: any LLM call
    would either raise (queue exhausted) or show up in stub.calls.
    """
    row = _build_row({
        "control_id": "AT-1",
        "ap_acronym": "AT-1.1",
        "cci_id": "CCI-000100",
        "procedures": (
            "This CCI is automatically compliant per the DoD-level "
            "awareness training program; no system-level test required."
        ),
    })
    stub = StubLlmClient([])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        tagged_evidence="## Tagged evidence\n- placeholder\n",
        force_llm=True,
    )

    assert decision.status == ComplianceStatus.COMPLIANT
    assert decision.source == "rule_8a"
    assert decision.needs_review is False
    assert len(stub.calls) == 0, (
        f"Rule 8a must short-circuit under force_llm=True; "
        f"stub recorded {len(stub.calls)} unexpected call(s)."
    )


def test_force_llm_bypasses_no_evidence_short_circuit() -> None:
    """No-evidence rows MUST reach the LLM under force_llm=True.

    Default behavior (Step 1.65 at engine/assessor.py:767): tagged_evidence
    is None → mint Non-Compliant deterministically, never call the LLM.
    Under force_llm=True the assessor should hand the empty bundle to the
    LLM instead — that's exactly the comparison the eval wants to make
    ("did the engine miss something the LLM would have found?").

    The stub's queued proposal is a valid Compliant narrative so we can
    observe the LLM path running through (validator accepts it, decision
    returns LLM-sourced). If the kernel still short-circuits, decision.source
    would be 'rule_no_evidence' and stub.calls would be empty — both
    asserted below.
    """
    row = _build_row({
        "control_id": "AC-2",
        "ap_acronym": "AC-2.1",
        "cci_id": "CCI-000015",
        "procedures": "Examine the account management plan.",
    })
    proposal = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Examined the program's account management approach; "
            "confirmed via the implementation guidance that the "
            "required account types are documented in the plan."
        ),
        confidence=0.9,
    )
    stub = StubLlmClient([proposal])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        tagged_evidence=None,  # would normally fire Step 1.65
        force_llm=True,
    )

    assert len(stub.calls) >= 1, (
        "force_llm=True must defeat the no-evidence short-circuit so the "
        "LLM is consulted; stub recorded zero calls — Step 1.65 still fired."
    )
    assert decision.source in {"llm", "llm_after_retry"}, (
        f"Expected LLM-sourced verdict but got source={decision.source!r}; "
        "force_llm should have routed past Step 1.65."
    )


def test_force_llm_keeps_hybrid_crm_prepend() -> None:
    """CRM hybrid prepend (lines 746-752) must fire under force_llm=True.

    The hybrid prepend is enrichment, not a short-circuit — it injects the
    responsibility-split block into the prompt so the LLM scopes its
    narrative to the customer-owned half. force_llm bypasses gates 3-6 but
    must NOT bypass this enrichment, because the eval's `llm-forced` mode
    on a hybrid-CRM oracle row needs to compare like-for-like with the
    `current` mode (both prompts should carry the responsibility split).

    Asserts the stub's recorded tagged_evidence contains the marker
    string '## responsibility_split' — the literal header rendered by
    _render_hybrid_block at engine/assessor.py:1996.
    """
    row = _build_row({
        "control_id": "AC-2",
        "ap_acronym": "AC-2.1",
        "cci_id": "CCI-000015",
        "procedures": "Examine the account management approach.",
    })
    # Hybrid in cloud scope → the all-inheritable short-circuit at line
    # 727-735 declines and we fall into the hybrid-prepend branch.
    crm_entry = CrmEntry(
        control_id="ac-2",  # matches OSCAL canonical form after normalize
        responsibility="hybrid",
        narrative="Customer manages tenant-scoped account types; provider runs the IAM control plane.",
        source_baseline_id=999,
    )
    crm_context = CrmContext(by_control={"ac-2": crm_entry})

    proposal = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Examined the customer-side account management evidence; "
            "confirmed via the tagged artifact that tenant account types "
            "are documented in the plan for the customer-owned scope."
        ),
        confidence=0.85,
    )
    stub = StubLlmClient([proposal])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        tagged_evidence="## Tagged evidence\n- USD00099999 Account Management Plan Rev B\n",
        crm_context=crm_context,
        force_llm=True,
    )

    assert len(stub.calls) >= 1, "force_llm hybrid path must still call the LLM"
    sent_evidence = stub.calls[0]["tagged_evidence"]
    assert sent_evidence is not None
    assert "## responsibility_split" in sent_evidence, (
        "Hybrid CRM prepend must inject the responsibility_split header "
        f"under force_llm=True; prompt evidence was: {sent_evidence!r}"
    )
    # Decision should be LLM-sourced — proves force_llm routed past the
    # gates 3-6 wrapper and did NOT take the CRM short-circuit at 727-735.
    assert decision.source in {"llm", "llm_after_retry"}, (
        f"Expected LLM-sourced verdict but got source={decision.source!r}"
    )


def test_dual_pass_disagreement_triggers_abstain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.6.0 challenger CHALLENGE-flip MUST abstain with ``dual-pass-disagreement:`` reason.

    Pins the dual-pass disagreement branch at
    ``engine/assessor.py:1014-1037`` (commit ``eabae66``). When
    ``DUAL_PASS_ENABLED=True`` and the challenger (pass 1) returns a
    different status than the initial verdict (pass 0), the orchestrator
    MUST:

      * Flip ``outcome.dual_pass_disagreement = True`` (line 1016).
      * Build a detail string with both statuses and confidences:
        ``"pass0=<status> (conf=<f>), pass1=<status> (conf=<f>)"``.
      * Route through ``_abstain(..., f"dual-pass-disagreement: {detail}", ...)``
        which (per Fix 3 hard-abstain contract at line 1693-1694)
        coerces ``Decision.status`` to ``None`` and preserves pass 0's
        status on ``Decision.proposed_status``.
      * Append ``pass0_narrative=<repr>`` and ``pass1_narrative=<repr>``
        to ``Decision.notes`` so the auditor sees both rationales
        without having to dig into the per-pass trace payload.

    Why this is a bespoke test, not a JSON case
    -------------------------------------------
    ``DUAL_PASS_ENABLED = False`` at ``engine/assessor.py:404`` ships
    the challenger pattern but gates it off pending live-LLM eval
    signal. JSON case files cannot monkeypatch a module-level
    constant, so the companion ``abstain_self_signaled.json`` case
    explicitly defers this path:

        "if/when dual-pass is re-enabled by default, add a sibling
         'abstain_dual_pass_disagreement.json' that queues two
         distinct proposals."

    Until then, this bespoke test is the only guard against silent
    regressions of the v0.6.0 challenger CHALLENGE branch.
    ``active_kernel_config()`` reads the module attribute on every
    call, so ``monkeypatch.setattr`` is observed by the kernel
    fingerprint as well (no cache poisoning across tests).

    Stub-shape note
    ---------------
    The default ``StubLlmClient.propose_twice`` pops ONE proposal and
    returns ``(p, p)`` -- a CONFIRM-only shape by construction. To
    exercise the CHALLENGE path we override it with a local subclass
    that pops TWO distinct proposals, matching the contract the
    docstring at ``_stubs.py:29-30`` describes ("supply two different
    proposals back-to-back").

    Mutation differentiation
    ------------------------
    Flipping ``pass0.status != pass1.status`` (line 1014) to ``==``
    makes the disagreement branch only fire when the two passes
    AGREE -- which they never do in this test -- so the orchestrator
    would build the CONFIRM composite at 1042-1054 instead, return a
    trusted ``COMPLIANT`` verdict, and the ``assert decision.status is
    None`` line below would fail loudly. Other mutations the suite
    catches:

      * Deleting ``outcome.dual_pass_disagreement = True`` -- not
        asserted here (would need an ``Outcome`` round-trip), but
        the abstain reason / notes / status assertions still pin the
        load-bearing observable behavior.
      * Removing ``pass0_narrative=`` / ``pass1_narrative=`` from
        ``notes`` -- caught by the two ``startswith`` checks.
      * Swapping ``status=pass0.status`` for ``pass1.status`` on the
        _abstain call (line 1027) -- caught by the
        ``proposed_status == COMPLIANT`` assertion (pass 0 is
        Compliant, pass 1 is Non-Compliant).
    """
    # Late import so monkeypatch targets the same module object the
    # orchestrator reads from at call time. ``active_kernel_config()``
    # at assessor.py:438-449 re-reads the module global on every call,
    # so the flip takes effect for the duration of the test scope and
    # is reverted automatically by pytest's monkeypatch teardown.
    import cybersecurity_assessor.engine.assessor as assessor_module

    monkeypatch.setattr(assessor_module, "DUAL_PASS_ENABLED", True)

    row = _build_row({
        "control_id": "AC-2",
        "ap_acronym": "AC-2.1",
        "cci_id": "CCI-000015",
        "procedures": "Examine the account management plan and confirm coverage.",
    })

    # Pass 0 (initial verdict): Compliant with affirming-language
    # narrative the validator will accept.
    pass0 = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Examined the program's account management plan; "
            "confirmed via section 2 that the required account types "
            "are documented in the plan for all personnel categories."
        ),
        confidence=0.9,
    )
    # Pass 1 (challenger CHALLENGE): different status -> triggers the
    # disagreement abstain. Narrative shape doesn't matter for this
    # branch -- the orchestrator routes to _abstain before the
    # validator runs against either narrative.
    pass1 = LlmProposal(
        status=ComplianceStatus.NON_COMPLIANT,
        narrative=(
            "On re-review the plan does not enumerate every account "
            "type; missing documentation for privileged role "
            "provisioning means the control is not fully implemented."
        ),
        confidence=0.8,
    )

    class _DualPassDisagreementStub(StubLlmClient):
        """Pops TWO distinct proposals per propose_twice call.

        The base ``StubLlmClient.propose_twice`` returns ``(p, p)``
        for the agreement case; this override matches the
        disagreement-case contract described in the base stub's
        docstring. Kept inline (not exported to ``_stubs.py``) because
        no other test currently needs it -- promoting it would be
        speculative abstraction per the working agreement.
        """

        def propose_twice(
            self,
            *,
            row,
            corrective_context=None,
            prior_attempts=None,
            tagged_evidence=None,
            crm_responsibility=None,
            boundary_brief=None,
        ):
            p0 = self.propose(
                row=row,
                corrective_context=corrective_context,
                prior_attempts=prior_attempts,
                tagged_evidence=tagged_evidence,
                crm_responsibility=crm_responsibility,
                boundary_brief=boundary_brief,
            )
            p1 = self.propose(
                row=row,
                corrective_context=corrective_context,
                prior_attempts=prior_attempts,
                tagged_evidence=tagged_evidence,
                crm_responsibility=crm_responsibility,
                boundary_brief=boundary_brief,
            )
            return (p0, p1)

    stub = _DualPassDisagreementStub([pass0, pass1])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row,
        tagged_evidence=(
            "## Tagged evidence\n"
            "- USD00099999 Example System Account Management Plan Rev B\n"
        ),
    )

    # Hard-abstain contract (Fix 3, assessor.py:1693-1694): status
    # coerced to None so the abstain row never lands in the workbook
    # as an authoritative verdict; pass 0's status preserved on
    # proposed_status so calibration telemetry / reviewer triage can
    # see what the LLM intended before the kernel overruled it.
    assert decision.status is None, (
        f"hard-abstain must coerce status to None; got {decision.status!r}"
    )
    assert decision.proposed_status == ComplianceStatus.COMPLIANT, (
        f"proposed_status should preserve pass 0's verdict (Compliant); "
        f"got {decision.proposed_status!r}"
    )
    assert decision.source == "abstain", (
        f"dual-pass disagreement must route through _abstain; "
        f"got source={decision.source!r}"
    )
    assert decision.accepted is True, (
        "abstain rows are still written so the reviewer sees them in "
        "the queue; accepted=True is the precision-over-recall contract"
    )
    assert decision.needs_review is True, (
        "abstain rows MUST flip needs_review=True so export gates "
        "(ccis_writer, poam.exporter) keep them out of the workbook"
    )

    # Both passes must have been consumed -- propose_twice on our
    # subclass pops twice. If the orchestrator regressed to calling
    # ``propose`` (single-pass) instead of ``propose_twice``, len(calls)
    # would be 1 and the disagreement branch would never have been
    # reached.
    assert len(stub.calls) == 2, (
        f"orchestrator should consume both pass 0 and pass 1 via "
        f"propose_twice; stub recorded {len(stub.calls)} call(s)"
    )

    # Review reason carries the load-bearing pattern from line 1020-1023.
    # Regex captures both status values so a mutation flipping the
    # ``pass0.status`` / ``pass1.status`` ordering in the detail string
    # (e.g. swapping the f-string slots) fires here.
    assert decision.review_reason is not None
    assert re.search(
        r"dual-pass-disagreement:\s*pass0=Compliant\b.*pass1=Non-Compliant\b",
        decision.review_reason,
    ), (
        f"review_reason missing dual-pass-disagreement signature; "
        f"got {decision.review_reason!r}"
    )

    # Both narratives captured in notes (lines 1031-1034). The auditor
    # uses these to compare pass 0's affirming claim against pass 1's
    # CHALLENGE rationale without inspecting the per-pass trace payload.
    assert any(n.startswith("pass0_narrative=") for n in decision.notes), (
        f"notes missing pass0_narrative= entry; got notes={decision.notes!r}"
    )
    assert any(n.startswith("pass1_narrative=") for n in decision.notes), (
        f"notes missing pass1_narrative= entry; got notes={decision.notes!r}"
    )
