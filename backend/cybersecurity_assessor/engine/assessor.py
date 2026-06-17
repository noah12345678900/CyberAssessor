"""Per-CCI assessment orchestrator (patent kernel wiring).

This is the load-bearing entry point for v0.1's accuracy claim. It glues
together the four deterministic components that have been ported from the
plugin so that every column-Q narrative either:

  (a) comes from rule #8 (no LLM call at all — deterministic), or
  (b) comes from the LLM, then survives supersession rewrite and rule
      #11 validation, with up to ``max_retries`` corrective rounds.

The orchestrator deliberately does NOT touch Excel or the SQL catalog.
It returns a ``Decision`` object that the caller (FastAPI route or batch
runner) can pass to ``excel.ccis_writer.write_single`` and/or persist as
an ``Assessment`` row. Keeping the boundary clean lets us:

  * Unit-test the kernel without xlwings / Excel / DB fixtures.
  * Swap the LLM client in tests for a deterministic stub.
  * Bypass the LLM entirely when rule #8 fires (still record the run).

The retry loop is BOUNDED. Per the patent application's accuracy claim
we measure "retry-to-acceptance ratio" — an unbounded loop would let a
broken prompt rack up infinite spend. ``max_retries=2`` matches what
the plugin currently uses in practice (one corrective round handles
~95% of restatement and mismatch rejections; the second handles the
rest; beyond that we surface the failure to the assessor).
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Protocol

from ..excel.ccis_reader import (
    CcisRow,
    _ccis_to_oscal_control_id,
    _normalize_control,
)
from ..baselines.scope_labels import ON_PREM_LABEL, is_on_prem
from ..models import ComplianceStatus, NarrativeClass
from . import decision_cache, rules, supersession, validator
from .crm_context import CrmContext, CrmEntry, ImplementationSlice
from .evidence_bundle import EvidenceBlock
from .evidence_ranker import OVERFLOW_ESCALATE
from .measurement import (
    CrmShortCircuit,
    RuleShortCircuit,
    RunRecorder,
    SupersessionHit,
    ValidatorRejection,
)

if TYPE_CHECKING:
    from sqlmodel import Session

# ---------------------------------------------------------------------------
# LLM client contract
# ---------------------------------------------------------------------------


@dataclass
class LlmProposal:
    """One (status, narrative) pair returned by the LLM client.

    Token fields flow through to the run recorder for operational
    telemetry and cost math. ``input_tokens`` is the BASE (non-cache)
    input count only — cache reads land in ``cache_read_tokens`` so the
    pricing module can apply the ~10% cache-read rate accurately. The
    AnthropicClient splits them before constructing the proposal. ``raw``
    is the unparsed model output kept so a rejected proposal can be
    logged verbatim in ``ValidatorRejection``.

    ``confidence`` is the model's self-reported 0.0-1.0 score for the
    proposed verdict. Default 0.5 when the model omits it (parse-time
    fallback) — uncalibrated for v0.2 but lets the assessor distinguish
    "high-conviction" from "guessed it because I had to". ``abstain`` is
    the model's explicit "I can't pick a status without guessing" signal
    (contradiction / conflicting evidence only — evidence ABSENCE is a
    Non-Compliant finding, not an abstain). Server-side abstain reasons
    (parse error, cite hallucination, validator exhaustion, dual-pass
    disagreement, supersession/boundary contradiction) are detected
    elsewhere, never carried on the proposal itself.

    Audit v1 fields:
    * ``model`` / ``model_version`` — what we requested vs. what Anthropic
      actually served (alias resolution can substitute a dated version).
    * ``request_id`` — Anthropic ``response.id`` for replay correlation.
    * ``raw_response_json`` — the full parsed response payload, kept for
      the AssessmentTrace row. Defaults empty so non-Anthropic stubs
      (tests, OpenAI client) don't have to populate it.
    * ``system_prompt_sha`` — sha256 of the system prompt that drove this
      call. Captured here so the Decision/route layer doesn't have to
      reach back into the client to populate the trace.
    * ``citations`` — present only when ``audit_citations_enabled`` is on.
      List of {narrative_field, claim, evidence_id, source_quote} dicts
      as emitted by the model; assessor turns these into
      AssessmentCitation rows during persistence.
    """

    status: ComplianceStatus
    narrative: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    raw: str | None = None
    confidence: float | None = None
    abstain: bool = False
    # Dual-narrative fields surfaced by the LLM for hybrid systems. Either
    # may be None — see prompts/assess_control.md "Dual-narrative contract"
    # and Assessment.narrative_on_prem / narrative_cloud in models.py.
    narrative_on_prem: str | None = None
    narrative_cloud: str | None = None
    # Full per-scope narrative map keyed by the actual scope_label. When the
    # model emits this, the engine prefers it over collapsing the two halves
    # above via the binary on-prem/cloud split — letting AWS GovCloud and
    # Azure Government each carry their own boundary-situated narrative. None
    # when the model didn't emit it (or emitted an empty/garbage map); the
    # engine falls back to the on_prem/cloud halves in that case.
    narratives_by_scope: dict[str, str] | None = None
    # Audit v1 — see class docstring for field semantics. All default to
    # empty/None so stubs and pre-Audit codepaths keep working unchanged.
    model: str = ""
    model_version: str = ""
    request_id: str = ""
    raw_response_json: dict = field(default_factory=dict)
    system_prompt_sha: str = ""
    temperature: float = 0.0
    max_tokens: int = 0
    citations: list[dict] = field(default_factory=list)
    # Rendered user-message string verbatim — what build_user_message
    # produced for this call. Captured on the proposal so the assessor
    # can mint a TracePayload without reaching back into the client to
    # re-render (rendering is non-trivial and depends on the same row +
    # corrective_context + tagged_evidence the client just consumed).
    # Empty default keeps stubs (tests) and pre-Audit codepaths working.
    user_message: str = ""


# ---------------------------------------------------------------------------
# Audit v1 — trace + evidence-shown payloads
# ---------------------------------------------------------------------------


@dataclass
class TracePayload:
    """One LLM call's trace, captured by Assessor and persisted by routes.

    Shape mirrors models.AssessmentTrace (one row per LLM call). Single-pass
    Decisions carry one TracePayload (pass_index=0); dual-pass Decisions
    carry two (pass_index=0 for temp 0.0, pass_index=1 for temp 0.3).
    Deterministic short-circuit Decisions (rule 8a/8b/8c, CRM provider/
    inherited/NA, no-llm-client) carry zero TracePayloads — no LLM call to
    trace.

    ``user_message`` is the rendered prompt body verbatim (Anthropic user
    role content). ``system_prompt_sha`` keys into PromptSnapshot for the
    deduplicated full text. ``raw_response_json`` is JSON-serialized at
    capture time so it survives the asdict round-trip through the decision
    cache.
    """

    system_prompt_sha: str
    user_message: str
    model: str
    model_version: str
    temperature: float
    max_tokens: int
    request_id: str
    raw_response_json: str  # JSON-dumped at capture so cache round-trip is safe
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    pass_index: int = 0
    # Audit v1 — citation array as emitted by the model (flag-gated:
    # populated only when ``audit_citations_enabled`` is on; empty list
    # otherwise). Each element is a {narrative_field, claim, evidence_id,
    # source_quote} dict. Per-pass so dual-pass disagreements can be
    # audited independently; ``_persist_audit_trail`` materializes the
    # pass_index=0 set into AssessmentCitation rows (pass 2's citations
    # are kept in the raw_response_json for forensic replay but don't
    # round-trip into the citations table — pass 1 is the canonical
    # accepted pass in the matching-status branch).
    citations: list[dict] = field(default_factory=list)


@dataclass
class EvidenceShownPayload:
    """One evidence chunk as it was literally shown to the model.

    Mirrors models.AssessmentEvidenceShown. ``chunk_text`` is the snippet
    after head+tail truncation (what the LLM actually saw, NOT the full
    file text). ``chunk_sha`` is sha256(chunk_text) so an auditor can
    verify the exact bytes rather than trusting the file-level Evidence.sha256.

    ``order_index`` is the position in the rendered evidence block (0-indexed
    by the bundle's natural ordering — typically highest-relevance first).
    ``relevance`` and ``tag_source`` are denormalized from EvidenceTag at
    capture time so a later retag doesn't rewrite history.

    Token-budget ranker (evidence_ranker.py) audit fields:
    * ``disposition`` — "examined" (rendered into the prompt the model saw)
      or "deferred" (over the token budget, NOT sent to the model but
      recorded here so nothing is silently dropped). Defaults to "examined"
      for the no-ranker / legacy path.
    * ``rank_score`` — the tag relevance used as the primary admission
      ordering signal; denormalized for the audit row.
    * ``deferred_reason`` — set only on deferred chunks (e.g.
      "token-budget-exceeded") so a 3PAO/JAB reviewer can see exactly why
      an artifact was held back. None for examined chunks.

    All three carry defaults so every existing constructor — and the
    DecisionCache rehydration path (``_rehydrate_dataclass``) — keeps
    working without change.
    """

    evidence_id: int
    chunk_sha: str
    chunk_text: str
    order_index: int
    relevance: float | None = None
    tag_source: str | None = None
    disposition: str = "examined"
    rank_score: float | None = None
    deferred_reason: str | None = None


class LlmClient(Protocol):
    """Minimum surface the orchestrator needs from the LLM client.

    The real client (``llm.client.AnthropicClient``) implements this with
    prompt caching. Tests pass a deterministic stub that returns canned
    proposals so the kernel logic stays under test without burning tokens.
    """

    def propose(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
    ) -> LlmProposal:  # pragma: no cover - protocol
        ...

    def propose_twice(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
    ) -> tuple[LlmProposal, LlmProposal]:  # pragma: no cover - protocol
        """Dual-pass: two proposals from the same model at temp 0.0 + 0.3.

        Assessor compares the two; status disagreement → abstain. System
        prompt is cached so pass 2 only pays the cache-read rate on the
        prompt prefix. Stubs may implement this by calling propose()
        twice with the same args — the contract is "two proposals", not
        "two distinct samples".

        ``crm_responsibility`` is the resolved CRM responsibility string
        ("customer", "provider", "hybrid", "inherited") looked up by the
        orchestrator from the active CRM context. None signals no CRM
        attached or no entry for this control — the prompt builder emits
        ``crm_responsibility: absent`` so the system prompt's default
        rule has a concrete signal to bind to (prevents cloud-narrative
        hallucination on on-prem-only rows).
        """
        ...


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class Decision:
    """Final outcome for one CCI after the patent kernel runs.

    ``accepted`` is True iff the orchestrator produced a (status,
    narrative) pair the validator approved. If False, ``rejection_log``
    holds every attempt that failed and the caller should surface them
    to the assessor for manual resolution (never silently write a
    rejected pair to the workbook — that's the plugin's hard rule).

    v0.2 abstain plumbing:
    * ``needs_review`` flips True when the verdict is NOT trusted —
      validator exhausted, LLM parse error, cite hallucination after
      retries, dual-pass status disagreement, supersession-stale or
      boundary-conflict in the proposed narrative. The row is still
      written (so the reviewer sees it in the queue) but ``status`` is
      whatever the LLM proposed (or NON_COMPLIANT for parse errors),
      and exports gate it out.
    * ``review_reason`` is a one-line triage hint surfaced in the UI
      callout. Format: ``"<bucket>: <detail>"`` (e.g.
      ``"dual-pass-disagreement: pass0=Compliant, pass1=Non-Compliant"``).
    * ``confidence`` is the LLM's self-reported 0.0-1.0 score; None for
      deterministic short-circuits (those are 1.0 by construction).
    """

    cci_id: str
    excel_row: int
    accepted: bool
    status: ComplianceStatus | None
    narrative: str | None
    narrative_class: NarrativeClass
    source: str  # "rule_8a", "rule_8b", "llm", "llm_after_retry", "unresolved", "crm_*"
    rule: str | None  # "8a" / "8b" / "8c" / None
    # Dual-narrative output. ``narrative`` remains the canonical merged text
    # exporters write to CCIS column Q. ``narrative_on_prem`` /
    # ``narrative_cloud`` carry the per-side text the UI detail page renders.
    # Population follows the responsibility-driven matrix documented on
    # Assessment.narrative_on_prem in models.py.
    narrative_on_prem: str | None = None
    narrative_cloud: str | None = None
    # Generalized N-boundary narrative map: scope_label -> narrative text.
    # ``narrative_on_prem`` / ``narrative_cloud`` are the legacy two-boundary
    # special case; this dict is the open-ended form keyed by the same
    # ``scope_label`` values that ride on each ``ImplementationSlice`` (e.g.
    # "AWS GovCloud", "Azure Gov", ON_PREM_LABEL). ``plan_implementations``
    # reads it to give each per-scope ImplementationPlan its own narrative;
    # an empty map (the default) means every customer-owned slice falls back
    # to the canonical ``narrative``. JSON-native, so it round-trips through
    # DecisionCache via asdict/Decision(**raw) with no special handling.
    narratives_by_scope: dict[str, str] = field(default_factory=dict)
    retries: int = 0
    rejection_log: list[ValidatorRejection] = field(default_factory=list)
    supersession_log: list[SupersessionHit] = field(default_factory=list)
    # Populated when the row was decided by a CRM overlay short-circuit
    # (responsibility provider/inherited/not_applicable). Route handlers
    # without a RunRecorder can read it directly off the Decision; route
    # handlers with a RunRecorder can also iterate ``recorder.outcomes``
    # to find ``CciOutcome.crm_short_circuit`` for the same data.
    crm_short_circuit: CrmShortCircuit | None = None
    notes: list[str] = field(default_factory=list)
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # v0.2 precision-over-recall gates. needs_review is the "verdict
    # untrusted" flag; review_reason is the triage hint; confidence is
    # the LLM self-report. See feedback_precision_over_recall.md.
    needs_review: bool = False
    review_reason: str | None = None
    confidence: float | None = None
    # v0.2 hard-abstain contract (eval finding #3, fix 3). When the
    # kernel decides to abstain — validator exhausted, dual-pass
    # disagreement, parse error, etc. — ``status`` is coerced to None so
    # the row never lands in the workbook as an authoritative verdict.
    # The LLM's last proposed status is preserved here for calibration
    # telemetry: "how often does the LLM's guess agree with the human
    # reviewer's eventual call on abstain rows?" Mirrors the contract
    # pinned at tests/eval/test_eval_harness.py:174 ("Expected hard
    # abstain (status=None) but got <status>"). None for non-abstain
    # paths (status is the trusted verdict there).
    proposed_status: ComplianceStatus | None = None
    # v0.2 citation-hygiene flag (NOT an abstain). Retained as an outcome
    # field for downstream POAM/SAR/CCIS exporters; the manual stale-cite
    # and NA-reconsideration signals that used to set it were removed with
    # the manual supersession registry, so it now stays False (evidence-
    # chain rewrites correct the narrative in place instead).
    # rewrite_requested_refs is the list of (legacy, current) pairs the
    # exporter renders; None when rewrite_requested is False.
    rewrite_requested: bool = False
    rewrite_requested_refs: list[tuple[str, str]] | None = None
    # v0.2 decision-cache provenance. When a Decision was replayed from
    # the DecisionCache table, ``source`` keeps its original semantic
    # value ("llm", "llm_after_retry", "crm:hybrid_verified", "sda_8c")
    # so export queries still see the verdict's true origin, while this
    # field is stamped "cache_hit" so telemetry can distinguish a fresh
    # decision from a replayed one without losing that distinction.
    # None on every fresh decision; set by ``decision_cache.replay()``.
    cache_source: str | None = None
    # v0.2 dual-narrative advisory flags. List of RejectionReason values
    # (e.g. ["dual_narrative_mislabel"]) emitted by
    # ``validator.validate_dual_narratives`` on the LLM-accept path. Always
    # advisory — the verdict in ``status`` is still trusted because column Q
    # passed ``validate()``; this list records the per-row leak / CRM-mismatch
    # signal so the persisted Assessment row can be queried for "show me every
    # row whose dual halves looked swapped" without joining to the rejection
    # log. Empty for short-circuit decisions (rules / CRM / abstain) and for
    # LLM rows that came back clean. The persistence layer mirrors it onto
    # Assessment.dual_narrative_flagged (bool) + Assessment.dual_narrative_flag_reasons
    # (JSON-as-string) so the "one SQL query away" patent claim extends to
    # this advisory class without dragging in the rejections table.
    dual_narrative_flags: list[str] = field(default_factory=list)
    # Audit v1 — verdict-to-evidence traceability payloads. Persisted by the
    # route layer into AssessmentTrace / AssessmentEvidenceShown rows tied
    # to the resulting Assessment.id.
    #
    # ``trace_payload`` is a list (not Optional) because dual-pass yields two
    # entries (pass_index=0 + pass_index=1), single-pass yields one, and
    # deterministic short-circuits yield zero — keeping the route persistence
    # loop branch-free.
    #
    # ``evidence_shown`` is the chunk-level snapshot of what the model
    # literally saw, populated by ``build_tagged_evidence``. Same for both
    # passes (the prompt prefix is cached and identical), so we capture
    # once. Deterministic short-circuits leave this empty — no LLM saw
    # the evidence on those rows.
    #
    # Both fields round-trip through ``DecisionCache`` via asdict + JSON;
    # ``_deserialize_decision`` rehydrates the dataclasses on cache replay
    # so the route can persist trace rows uniformly regardless of whether
    # this was a fresh decision or a cache hit (in the latter case the
    # trace describes the original LLM call — audit-true, since no new
    # call was made).
    trace_payload: list[TracePayload] = field(default_factory=list)
    evidence_shown: list[EvidenceShownPayload] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


DEFAULT_MAX_RETRIES = 2

# v0.2 precision-over-recall knobs. Module-level so callers can flip them
# in tests / batch runs without round-tripping through AppConfig. These are
# CODE-LEVEL tuning constants by design (see KernelConfig docstring): the
# decision-cache fingerprint hashes them, so any change auto-invalidates
# prior cache entries and forces fresh evaluation under the new contract.
# DUAL_PASS_ENABLED: True → every LLM proposal is run twice (temp 0.0 +
# temp 0.3) and the assessor abstains on status disagreement. Off by
# default — empirically dual-pass disagreement was the largest source of
# needs_review demotion, swamping the real "sketchy" cases the reviewer
# actually needs to look at. The validator + confidence floor already
# guard against confidently-wrong verdicts; dual-pass added wall-clock
# and review noise without proportional precision gain. Flip back to True
# in tests that exercise the disagreement path.
#
# fix #3 (2026-06-10) — EVAL-GATE, deliberately NOT flipped:
# The precondition for re-enabling dual-pass has now landed: fix #1 made
# the challenger pass meaningfully different from a re-roll by hard-gating
# each citation's ``source_quote`` against the tagged evidence
# (UNSUPPORTED_QUOTE rejection, ``audit_citations_enabled`` default ON).
# That removes the prior objection that dual-pass disagreement was mostly
# verdict noise rather than fabricated-support noise. BUT flipping this
# default to True is a precision *claim*, and a precision claim is only
# defensible with a measurement. The gate is a scripts/eval_workbook.py
# replay comparing OFF vs ON on a labeled workbook (set
# ``DUAL_PASS_ENABLED = True`` for the ON arm — the fingerprint guarantees
# the two arms don't share cache) and confirming the demotion-to-real-
# catch ratio actually improves. Until that replay exists, default stays
# OFF; do NOT flip it on intuition. (See feedback_model_choice_needs_eval
# — same eval-before-tuning discipline.)
# CONFIDENCE_THRESHOLD: proposals with self-reported confidence below
# this number are treated as implicit abstains even if abstain=False.
# Lowered from 0.6 → 0.35 so only genuinely sketchy verdicts (model
# self-reports near-coin-flip) get demoted. The prompt's abstain contract
# (conflicting evidence, true coin-flip) is the primary precision gate;
# this floor is the safety net, not the first line of defense.
DUAL_PASS_ENABLED = False
CONFIDENCE_THRESHOLD = 0.35


@dataclass(frozen=True)
class KernelConfig:
    """Versioned snapshot of the kernel's runtime tuning knobs.

    Patent-defensibility (v0.3 audit item #4): the constants above are the
    *source of truth* — keeping them at module level preserves the
    monkeypatch contract our v0.2 gates tests rely on. But for the
    decision-cache fingerprint we need a *content-addressed* view of the
    active configuration so any operator (or test) flip of a knob
    automatically invalidates prior cache entries — without anyone having
    to remember to bump ``KERNEL_VERSION`` by hand.

    Read order: ``active_kernel_config()`` snapshots the *current* module
    values into an instance of this dataclass on every call (so a
    monkeypatched value is observed). ``kernel_config_signature()`` hashes
    that snapshot; ``decision_cache.fingerprint()`` includes the hash in
    its payload. A change to either constant changes the signature,
    invalidates the cache for that knob value, and the next call cleanly
    misses → fresh LLM evaluation under the new contract.
    """

    confidence_threshold: float
    dual_pass_enabled: bool


def active_kernel_config() -> KernelConfig:
    """Snapshot the module-level tuning constants into a KernelConfig.

    Read on every call (not memoized) so test ``monkeypatch.setattr`` on
    the underlying module constants is observed. Cheap — two attribute
    reads plus a dataclass instantiation.
    """
    return KernelConfig(
        confidence_threshold=CONFIDENCE_THRESHOLD,
        dual_pass_enabled=DUAL_PASS_ENABLED,
    )


def kernel_config_signature() -> str:
    """Stable sha256 of the active kernel configuration.

    Sorted-keys JSON over the KernelConfig fields → byte-stable hash that
    changes iff any tuning knob changes. Truncated to 12 chars for log
    readability — collision risk at two knobs is negligible.
    """
    cfg = active_kernel_config()
    payload = {
        "confidence_threshold": cfg.confidence_threshold,
        "dual_pass_enabled": cfg.dual_pass_enabled,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:12]

# Boundary-conflict heuristic (Mechanism 5). Narratives that explicitly
# say the asset / control is "outside the boundary" / "out of scope" but
# carry any status OTHER than Not Applicable are internally contradictory
# — the LLM is hedging. Abstain so the reviewer resolves it. Per
# feedback_boundary_reasoning.md this is a regex-only gate (no schema
# boundary tag) — we surface the conflict and let the reviewer decide.
_BOUNDARY_PHRASE_RE = re.compile(
    r"\b(outside (?:the )?boundary|out of scope|not in scope|not within (?:the )?boundary)\b",
    re.IGNORECASE,
)

# CRM responsibilities that let us skip the LLM entirely. ``customer``
# always falls through to a real assessment; ``hybrid`` falls through
# with an extra responsibility-split block. With the dual-scope CRM
# (cloud + on-prem), we short-circuit only when EVERY specified scope
# is in this set — a mixed verdict (e.g. cloud=provider, on-prem=customer)
# still requires the LLM to assess the customer-owned half.
_CRM_SHORT_CIRCUIT_SET = frozenset({"provider", "inherited", "not_applicable"})


def _boundary_conflict(
    narrative: str | None, status: ComplianceStatus | None
) -> str | None:
    """Return a triage message when the narrative says out-of-boundary but
    the proposed status is anything other than Not Applicable. None when
    there's no conflict (either NA, no narrative, or no boundary phrase).
    """
    if status == ComplianceStatus.NOT_APPLICABLE:
        return None
    if status is None or not narrative:
        return None
    m = _BOUNDARY_PHRASE_RE.search(narrative)
    if m:
        return (
            f"narrative says '{m.group(0)}' but status is {status.value}, "
            "not Not Applicable"
        )
    return None


# ---------------------------------------------------------------------------
# Multi-implementation planning (v0.2)
# ---------------------------------------------------------------------------
#
# ``plan_implementations`` is the deterministic fan-out that turns one
# Decision + N CRM-derived ImplementationSlices into N ImplementationPlan
# rows for ``persist_assessment_with_impls`` to write. Branches:
#
#   * provider / inherited           -> COMPLIANT; narrative is the CRM's
#                                       verbatim text (generic stub only if
#                                       the CRM left it blank).
#   * not_applicable                 -> NOT_APPLICABLE; same passthrough.
#   * customer / hybrid              -> mirror the Decision (status +
#                                       per-scope narrative if the LLM
#                                       supplied one via narratives_by_scope,
#                                       else canonical decision.narrative);
#                                       DROPPED entirely on hard abstain
#                                       (decision.status is None) so the
#                                       reviewer-flagged parent doesn't get
#                                       falsely-promoted children under it.
#
# Pinned end-to-end by tests/engine/test_plan_implementations_boundary.py
# (the four-control boundary fixture) and tests/engine/
# test_impl_persistence_edges.py (the rollup / compose contracts).

_INHERITABLE_RESPONSIBILITIES = frozenset({"provider", "inherited"})
_CUSTOMER_OWNED_RESPONSIBILITIES = frozenset({"customer", "hybrid"})


@dataclass(frozen=True)
class ImplementationPlan:
    """Per-scope plan row -- the in-memory shape that ``persist_assessment_with_impls``
    converts to an :class:`AssessmentImplementation` SQL row.

    Lives in the engine layer (not models.py) on purpose: the planning
    branch logic is pure, has no DB dependency, and is unit-tested in
    isolation. The persistence helper does the SQLModel translation.
    """

    scope_label: str
    responsibility: str
    status: ComplianceStatus | None
    narrative: str
    evidence_refs: str | None = None
    source_baseline_id: int | None = None


def _fallback_inheritance_narrative(slice_: ImplementationSlice) -> str:
    """Synthetic stub when a provider/inherited/NA CRM slice has no narrative.

    Includes the ``scope_label`` so an auditor scanning the eMASS export
    can tell which platform's CRM was sparse without diffing files. The
    stub is intentionally NOT the Decision narrative (that would mislabel
    an inheritance row as a customer-side affirmation -- pinned by
    ``test_inheritance_blank_narrative_falls_back_to_generic_stub``).
    """
    resp = slice_.responsibility or "covered"
    if resp == "not_applicable":
        return (
            f"{slice_.scope_label}: control is not applicable to this "
            f"implementation per the attached CRM."
        )
    return (
        f"{slice_.scope_label}: customer inherits this control from the "
        f"provider per the attached CRM ({resp})."
    )


def narratives_by_scope_from_proposal(
    *,
    slices: list[ImplementationSlice],
    narrative_on_prem: str | None,
    narrative_cloud: str | None,
    llm_by_scope: dict[str, str] | None = None,
) -> dict[str, str]:
    """Map the LLM's per-side narratives onto the customer-owned scopes.

    Two sources, in priority order:

    1. **``llm_by_scope`` (preferred).** The model can emit a full
       ``narratives_by_scope`` object keyed by the actual scope_label. When
       present, each customer-owned slice takes its matching entry verbatim —
       so AWS GovCloud and Azure Government each get their OWN boundary-situated
       narrative instead of sharing the single ``narrative_cloud`` slot. A
       multi-cloud program is exactly where the binary on-prem/cloud collapse
       lost fidelity (Defects 2 & 3); the per-scope map fixes it.
    2. **Binary on_prem/cloud split (fallback).** When the model didn't emit
       the map (older prompt versions / models, or a single-boundary row), fall
       back to the deterministic split with no extra round-trip:
         * the on-prem slice               -> ``narrative_on_prem``
         * any other (cloud) customer slice -> ``narrative_cloud``

    Both sources are filtered to customer-owned slices only. Provider /
    inherited / NA slices are intentionally skipped — those carry the CRM's
    verbatim narrative, so leaving them out of the map lets
    :func:`plan_implementations` fall through to the CRM text rather than
    overwriting an inheritance row with a customer-side affirmation. Even when
    the LLM supplies a value for a non-customer-owned scope, we drop it here so
    the inheritance text wins. Per-scope resolution is the load-bearing half of
    the boundary-context guarantee: the reviewer must see which boundary each
    narrative applies to, and the seam gap must land on the on-prem slice — not
    be diluted into one blob.

    Returns an empty dict when there are no customer-owned slices or no source
    text is populated; the empty map means every slice falls back to the
    canonical narrative (the single-boundary path), so callers can set it
    unconditionally.
    """
    by_scope: dict[str, str] = {}
    for sl in slices:
        if sl.responsibility not in _CUSTOMER_OWNED_RESPONSIBILITIES:
            continue
        # Prefer the LLM's per-scope text for this exact label; fall back to
        # the binary half only when the map is absent or has no entry for it.
        text: str | None = None
        if llm_by_scope is not None:
            text = llm_by_scope.get(sl.scope_label)
        if not (text and text.strip()):
            text = narrative_on_prem if is_on_prem(sl.scope_label) else narrative_cloud
        if text and text.strip():
            by_scope[sl.scope_label] = text.strip()
    return by_scope


def stitch_scope_narrative(narratives_by_scope: dict[str, str] | None) -> str | None:
    """Render per-scope narratives as one labeled column-Q block.

    PRESENTATION-ONLY. This is the visual / save-time form of the canonical
    narrative for a multi-boundary control: each scope gets its own labeled
    paragraph so a reviewer reading the eMASS workbook cell (or the GUI) sees
    which boundary every statement applies to::

        AWS GovCloud:

        <cloud-side narrative>

        On-Premises:

        <on-prem residual narrative>

    It does NOT change how the verdict is classified or validated — those run
    on the single ``Decision.narrative`` upstream (the "not logically" half of
    the contract). Callers apply this only at the persistence / display
    boundary, and only when ``narratives_by_scope`` carries ≥2 populated
    scopes; with 0 or 1 scope there is nothing to stitch and the caller keeps
    the plain canonical narrative.

    Ordering mirrors the impl-slice convention the rest of the app renders in:
    cloud platforms first (insertion order, which the CRM layer already emits
    clouds-first), the synthesized ``On-Premises`` slice last. Returns ``None``
    when fewer than two scopes have text, so callers can fall back with a
    simple ``stitch_scope_narrative(...) or narrative``.
    """
    if not narratives_by_scope:
        return None
    populated = {
        label: text.strip()
        for label, text in narratives_by_scope.items()
        if text and text.strip()
    }
    if len(populated) < 2:
        return None

    cloud = [lbl for lbl in populated if not is_on_prem(lbl)]
    onprem = [lbl for lbl in populated if is_on_prem(lbl)]
    ordered = cloud + onprem

    return "\n\n".join(f"{label}:\n\n{populated[label]}" for label in ordered)


def plan_implementations(
    decision: Decision,
    slices: list[ImplementationSlice],
) -> list[ImplementationPlan]:
    """Fan one Decision out into per-scope ImplementationPlan rows.

    See module-level comment for branch semantics. Returns ``[]`` when
    *slices* is empty (the legacy single-impl path -- the parent
    Assessment carries the verdict on its own and no impl rows are
    written).
    """
    plans: list[ImplementationPlan] = []
    by_scope = decision.narratives_by_scope or {}

    for sl in slices:
        resp = sl.responsibility
        if resp in _INHERITABLE_RESPONSIBILITIES:
            narrative = (sl.narrative or "").strip() or _fallback_inheritance_narrative(sl)
            plans.append(
                ImplementationPlan(
                    scope_label=sl.scope_label,
                    responsibility=resp,
                    status=ComplianceStatus.COMPLIANT,
                    narrative=narrative,
                    evidence_refs=None,
                    source_baseline_id=sl.source_baseline_id,
                )
            )
            continue

        if resp == "not_applicable":
            narrative = (sl.narrative or "").strip() or _fallback_inheritance_narrative(sl)
            plans.append(
                ImplementationPlan(
                    scope_label=sl.scope_label,
                    responsibility=resp,
                    status=ComplianceStatus.NOT_APPLICABLE,
                    narrative=narrative,
                    evidence_refs=None,
                    source_baseline_id=sl.source_baseline_id,
                )
            )
            continue

        if resp in _CUSTOMER_OWNED_RESPONSIBILITIES or resp == "customer":
            # Customer-owned (customer / hybrid): mirror the Decision.
            # Hard abstain (status is None) drops the slice so the
            # reviewer-flagged parent doesn't gain falsely-promoted
            # children. The per-scope narrative wins when the LLM
            # populated narratives_by_scope; otherwise fall back to the
            # canonical decision.narrative so callers that don't set the
            # per-scope map still produce non-empty impl rows.
            if decision.status is None:
                continue
            # Phantom-scope guard. The synthesized On-Premises slice
            # (crm_context appends it whenever any cloud scope is customer-
            # owned) carries NO CRM baseline (source_baseline_id is None) and
            # no CRM narrative — it is a placeholder for "assume residual
            # customer work on-prem", NOT an assessed scope. Without its OWN
            # per-scope narrative (which only exists when the LLM actually had
            # on-prem evidence to assess), it must NOT inherit the control's
            # COMPLIANT verdict — that would let one evidenced cloud scope
            # silently pass an evidence-less on-prem footprint. Emit it as an
            # abstain (status=None) so it surfaces for review instead. A real
            # CRM-derived customer scope (source_baseline_id set) is unaffected;
            # the synthesized slice with a genuine per-scope narrative is also
            # unaffected (it was assessed). Precision over recall.
            per_scope_narrative = by_scope.get(sl.scope_label)
            is_synthesized_onprem = (
                sl.source_baseline_id is None and is_on_prem(sl.scope_label)
            )
            if is_synthesized_onprem and not per_scope_narrative:
                plans.append(
                    ImplementationPlan(
                        scope_label=sl.scope_label,
                        responsibility=resp,
                        status=None,
                        narrative=(
                            "Residual on-premises customer responsibility is "
                            "assumed for this control but no on-premises evidence "
                            "was assessed; flagged for reviewer follow-up. The "
                            "cloud-scope verdict does not extend to the on-premises "
                            "footprint."
                        ),
                        evidence_refs=None,
                        source_baseline_id=sl.source_baseline_id,
                    )
                )
                continue
            narrative = per_scope_narrative or decision.narrative or ""
            plans.append(
                ImplementationPlan(
                    scope_label=sl.scope_label,
                    responsibility=resp,
                    status=decision.status,
                    narrative=narrative,
                    evidence_refs=None,
                    source_baseline_id=sl.source_baseline_id,
                )
            )
            continue

        # Unknown responsibility (defensive): treat as customer-owned so
        # the auditor sees the row; pin loudly with the raw responsibility
        # value so a future CRM responsibility vocabulary expansion shows
        # up in tests rather than silently dropping rows.
        if decision.status is None:
            continue
        plans.append(
            ImplementationPlan(
                scope_label=sl.scope_label,
                responsibility=resp or "customer",
                status=decision.status,
                narrative=decision.narrative or "",
                evidence_refs=None,
                source_baseline_id=sl.source_baseline_id,
            )
        )

    return plans


def compose_rolled_narrative(plans: list[ImplementationPlan]) -> str:
    """Compose the parent ``Assessment.narrative_q`` from per-scope plans.

    Format is ``"{scope_label}: {narrative}"`` joined by newlines -- the
    template the validator template-phrase table (see
    ``feedback_validator_template_phrase_drift.md``) expects so the
    post-persist validator doesn't classify the composition as ambiguous.

    Returns ``""`` when *plans* is empty OR when every plan narrative is
    blank/whitespace. The persistence helper (impl_persistence.py:117)
    gates assignment on a truthy return so the empty-string case doesn't
    destroy the parent narrative_q.
    """
    parts: list[str] = []
    for p in plans:
        if not p.narrative or not p.narrative.strip():
            continue
        parts.append(f"{p.scope_label}: {p.narrative.strip()}")
    return "\n".join(parts)


def compute_rollup_status(
    statuses: list[ComplianceStatus | None],
) -> ComplianceStatus | None:
    """Worst-of rollup across per-scope ImplementationPlan statuses.

    Precedence (worst -> best):
        NON_COMPLIANT > COMPLIANT > NOT_APPLICABLE

    Returns ``None`` (undetermined / needs-review) when EVERY contributing
    status is ``None``. There is no dedicated "undetermined" enum value, so
    ``None`` is this codebase's representation of an abstain -- the parent's
    ``needs_review`` flag carries the real signal in that case. Returning a
    confident ``NOT_APPLICABLE`` here would be a defensibility footgun: an
    all-abstain set of impl rows would silently roll up to a clean NA verdict
    a 3PAO could not defend, hiding the reviewer signal. Precision over
    recall -- when we know nothing, we say nothing.

    ValueError on empty input -- callers must never invoke the rollup with
    zero impls (the persistence helper gates on ``if plans:`` before
    calling). NOTE: ``impl_persistence.persist_assessment_with_impls`` keeps
    a belt-and-suspenders guard (``decision.status is not None``) and only
    assigns this return value to ``Assessment.status`` for non-abstain
    decisions, so a ``None`` return is never written to the parent column.
    """
    if not statuses:
        raise ValueError("compute_rollup_status requires at least one status")
    if any(s is ComplianceStatus.NON_COMPLIANT for s in statuses):
        return ComplianceStatus.NON_COMPLIANT
    if any(s is ComplianceStatus.COMPLIANT for s in statuses):
        return ComplianceStatus.COMPLIANT
    if any(s is ComplianceStatus.NOT_APPLICABLE for s in statuses):
        return ComplianceStatus.NOT_APPLICABLE
    # All contributing statuses were None: undetermined, not a confident NA.
    return None


class Assessor:
    """Stateless orchestrator. Construct once per process, call ``assess``
    once per CCI. State lives in the supplied ``RunRecorder``.
    """

    def __init__(
        self,
        *,
        llm: LlmClient | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        cache_session: "Session | None" = None,
    ) -> None:
        self._llm = llm
        self._max_retries = max(0, max_retries)
        # v0.2 decision-cache opt-in. The kernel stays session-free by
        # default — route handlers that want re-run free pass their
        # SQLModel session here. Tests instantiate Assessor(llm=...) with
        # no cache_session and bypass the cache entirely, which keeps the
        # legacy test contract intact (no cache pollution between tests).
        self._cache_session = cache_session
        # The route's SQLModel session is shared across worker threads in
        # the parallel assess-batch fan-out, and SQLAlchemy Sessions are
        # NOT thread-safe — even concurrent reads can corrupt internal
        # transaction state (the symptom is IllegalStateChangeError on a
        # subsequent commit because another thread put the session into a
        # CLOSED state mid-flight). This lock serializes every session
        # access the kernel makes from worker code: cache lookup, cache
        # store, AND the four supersession.rewrite_evidence_chain reads.
        # Contention is negligible — each call is sub-ms against SQLite
        # WAL while the parallelized part (the LLM round-trip) is 5-30s.
        self._cache_lock = threading.Lock()
        # Per-batch supersession candidate index. Primed once by the route
        # handler before the parallel fan-out via prime_evidence_chain_index;
        # consulted by _locked_rewrite_evidence_chain to skip N full table
        # scans + N×head-lookup N+1 round trips for an N-CCI batch. Left
        # None on the session-free / CLI / single-shot paths, which keeps
        # the legacy DB-driven rewrite path intact.
        self._evidence_chain_index: "supersession.EvidenceChainIndex | None" = None
        # fix #2 2026-06-10 -- per-worker decision-cache sessions.
        # The decision_cache table (lookup / bump_hit / store) is a self-
        # contained, idempotent store: store() is INSERT-OR-IGNORE on the
        # fingerprint PK and bump_hit() is a monotonic hit counter. None of
        # its three operations need to participate in the route session's
        # transaction. Sharing ONE SQLModel session across the 8 assess-
        # batch workers forced every cache op to serialize behind
        # ``_cache_lock`` (SQLAlchemy Sessions are not thread-safe), so the
        # sub-ms cache round-trips queued up against each other AND against
        # the RunRecorder commits that share the same lock. Giving each
        # worker its own ``Session(engine)`` lets the cache ops run lock-
        # free and isolated — SQLite WAL + busy_timeout handle the writer
        # contention at the storage layer. ``_tls`` holds the per-thread
        # session; ``_worker_sessions`` is the registry the route drains via
        # ``close_worker_sessions`` once the executor finishes (the pool
        # reuses 8 threads, so without explicit cleanup their sessions would
        # leak connections until GC). The registry lock guards only the
        # list mutation, never a DB call, so it never contends with cache
        # work. ``self._cache_session`` survives as the gate flag (None =>
        # caching disabled, the legacy test contract) and as the session
        # for the priming read + the rare session-bound rewrite branch.
        self._tls = threading.local()
        self._worker_sessions: list["Session"] = []
        self._worker_session_registry_lock = threading.Lock()

    def _worker_cache_session(self) -> "Session | None":
        """Return this thread's private decision-cache session.

        Returns ``None`` when no ``cache_session`` was supplied at
        construction (test / CLI bypass path) so callers fall through to
        the no-cache branch exactly as before. Otherwise lazily creates one
        ``Session(engine)`` per calling thread, registers it for end-of-
        batch cleanup, and reuses it on subsequent calls from the same
        worker. Safe to call from the main thread too (the single-shot
        ``/assess`` path), where it simply creates one session on that
        thread.
        """
        if self._cache_session is None:
            return None
        sess = getattr(self._tls, "cache_session", None)
        if sess is None:
            from ..db import engine
            from sqlmodel import Session as _Session

            sess = _Session(engine)
            self._tls.cache_session = sess
            with self._worker_session_registry_lock:
                self._worker_sessions.append(sess)
        return sess

    def close_worker_sessions(self) -> None:
        """Close every per-thread decision-cache session from this batch.

        Called by the assess-batch route in a ``finally`` after the
        ``ThreadPoolExecutor`` drains. The thread pool reuses its 8 worker
        threads, so each accumulates one long-lived cache session via
        ``_worker_cache_session``; this releases their SQLite connections
        back to the pool deterministically instead of waiting for GC.
        Idempotent — a second call (or a call on a never-fanned-out
        single-shot Assessor) finds an empty registry and no-ops. Resets
        ``_tls`` so a subsequent batch on the same Assessor instance starts
        with fresh per-thread sessions.
        """
        with self._worker_session_registry_lock:
            sessions = list(self._worker_sessions)
            self._worker_sessions.clear()
        for sess in sessions:
            try:
                sess.close()
            except Exception:  # noqa: BLE001 -- best-effort connection release
                pass
        self._tls = threading.local()

    @property
    def session_lock(self) -> threading.Lock:
        """Public accessor for the kernel's session lock.

        Route handlers that share the same SQLModel session between
        ``Assessor`` and ``RunRecorder`` must pass this lock into
        ``RunRecorder.start(..., session_lock=...)`` so both owners
        serialize through ONE lock. Without that, a worker mid-
        ``decision_cache.lookup`` (under ``_cache_lock``) races a worker
        mid-``recorder._commit_outcome`` (under recorder's own lock),
        and SQLAlchemy raises ``InvalidRequestError: This session is in
        'prepared' state`` on the next autoflush. See measurement.py
        ``RunRecorder.__init__`` for the full rationale.
        """
        return self._cache_lock

    def prime_evidence_chain_index(self, workbook_id: int | None) -> None:
        """Pre-build the supersession candidate index for one assess-batch.

        Called once per ``/api/controls/assess-batch`` request by the route
        handler BEFORE the 8-worker parallel fan-out starts. Subsequent
        ``_locked_rewrite_evidence_chain`` calls then skip the per-row DB
        queries and use the cached, frozen index — eliminates N full-table
        scans + N×head-lookup N+1 round trips for an N-CCI batch (the
        kernel funnels four finalize paths through that one chokepoint).

        Mirrors the ``crm_context = build_crm_context(...)`` precedent in
        ``routes/controls.py`` at line 1247: build once per batch, reuse
        across every CCI.

        No-op when the test / single-shot path passed no ``cache_session``
        so the session-free ``Assessor(llm=...)`` contract stays intact.
        """
        if self._cache_session is None:
            return
        with self._cache_lock:
            self._evidence_chain_index = supersession.build_evidence_chain_index(
                self._cache_session, workbook_id=workbook_id,
            )

    def _locked_rewrite_evidence_chain(
        self, narrative: str, workbook_id: int | None
    ) -> "supersession.EvidenceChainResult":
        """Thread-safe wrapper around ``supersession.rewrite_evidence_chain``.

        Three branches:

        1. **Indexed fast path** — when ``prime_evidence_chain_index`` has
           run for this batch, hand the cached ``EvidenceChainIndex`` to
           the rewriter and skip the session entirely. Pure CPU work on a
           frozen dataclass with pre-compiled regexes; safe to read from
           multiple workers without the lock, no DB contention with cache
           lookups/stores or recorder commits in sibling workers.

        2. **Session-free legacy** — no cache session at all (test path or
           ``Assessor(llm=...)`` direct construction). Rewriter no-ops.

        3. **Session-bound legacy** — cache session is plumbed but the
           index was never primed (CLI / ``/assess`` single-shot endpoint
           / future test paths). All four call sites must serialize
           through ``_cache_lock`` to avoid SQLAlchemy
           ``IllegalStateChangeError`` from concurrent session use.
        """
        if self._evidence_chain_index is not None:
            return supersession.rewrite_evidence_chain(
                None, narrative, index=self._evidence_chain_index,
            )
        if self._cache_session is None:
            return supersession.rewrite_evidence_chain(
                None, narrative, workbook_id=workbook_id,
            )
        with self._cache_lock:
            return supersession.rewrite_evidence_chain(
                self._cache_session, narrative, workbook_id=workbook_id,
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess(
        self,
        row: CcisRow,
        *,
        recorder: RunRecorder | None = None,
        tagged_evidence: str | None = None,
        evidence_block: EvidenceBlock | None = None,
        crm_context: CrmContext | None = None,
        workbook_id: int | None = None,
        boundary_brief: str | None = None,
        override_epoch: int = 0,
        force_llm: bool = False,
    ) -> Decision:
        """Decide (status, narrative) for one CCIS row.

        Order of operations matches the plugin's command flow:
          1. Run rule #8 — if it returns a confident verdict we use it
             verbatim and never call the LLM.
          2. Otherwise (or for UNCLEAR_8C, where the LLM gets corrective
             context to escalate carefully), call the LLM.
          3. Rewrite the proposed narrative through the supersession map
             so any stale doc references are corrected before validation.
          4. Run rule #11 validation. If accepted, we're done.
          5. If rejected and retries remain, build a corrective-context
             string from the rejections and call the LLM again.
          6. If still rejected after ``max_retries`` retries, surface as
             ``unresolved`` so the assessor can rewrite manually.

        ``recorder`` is optional — when None, the kernel still runs but
        no measurements are persisted (handy for previews / UI hover
        cards that just want a status prediction).

        ``tagged_evidence`` is the pre-rendered evidence block (from
        ``engine.evidence_bundle.build_tagged_evidence`` and, for CM-8 /
        CA-3 / PM-5 CCIs, also the asset cross-check block). The kernel
        itself is session-free, so building the bundle is the caller's
        job — the route handler that constructs ``Assessor.assess(...)``
        joins the DB and passes the resulting string through here.

        ``evidence_block`` is the structured envelope produced by
        ``routes.controls._build_evidence_block``. When supplied it
        gates Step 1.65 on the producer-side ``is_only_context`` flag
        — the only way to tell apart "per-objective artifact text" from
        "workbook-wide context wrappers (coverage report / CRM hybrid
        prepend)". Without it, the gate falls back to a string-emptiness
        check which lets coverage-only and hybrid-only bundles slip
        through and reach the LLM with nothing decision-quality in them.
        Legacy single-CCI callers that only have the rendered string can
        keep passing ``tagged_evidence=`` alone (string-only behavior is
        unchanged).

        ``crm_context`` is the per-workbook CRM lookup snapshot built by
        the route via ``engine.crm_context.build_crm_context``. When
        absent, CRM short-circuit + hybrid-prompt enrichment are skipped
        and the kernel behaves exactly as before. Provider / Inherited /
        Not Applicable entries short-circuit without an LLM call; Hybrid
        entries prepend a ``## responsibility_split`` block to
        ``tagged_evidence`` so the LLM assesses only the customer half.

        ``override_epoch`` (default 0) is the per-objective manual-override
        counter (``engine.override_epoch``). It is forwarded verbatim into
        the decision-cache fingerprint so that after a reviewer manually
        edits a verdict, the next re-run misses the content-addressed cache
        and re-assesses fresh instead of replaying the superseded Decision.
        The route looks it up; the kernel just threads it through.

        ``force_llm`` (default False) is an EVAL-ONLY escape hatch. When
        True, the kernel skips gates 3-6 (CRM short-circuit, Rule 8c SDA
        mapping, no-evidence, decision-cache replay) and always calls the
        LLM if one is wired. Gates 1-2 (Rule 8a/8b) stay unconditional —
        col K/J are the user's own attestations, not engine inferences,
        so LLM-overriding them models the wrong intent. The CRM hybrid
        prepend at Step 1.5 still fires (it enriches LLM context; it is
        not a short-circuit). Production callers must NEVER set this
        True; it exists so ``scripts/eval_workbook.py`` can measure
        engine accuracy against a forced-LLM baseline.
        """
        ctx = recorder.cci(row.cci_id or row.control_id) if recorder else None
        outcome = ctx.__enter__() if ctx else None
        try:
            decision = self._run(
                row, outcome, tagged_evidence, crm_context, workbook_id,
                evidence_block=evidence_block,
                boundary_brief=boundary_brief,
                override_epoch=override_epoch,
                force_llm=force_llm,
            )
        finally:
            if ctx is not None:
                ctx.__exit__(None, None, None)
        return decision

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def _run(
        self,
        row: CcisRow,
        outcome,
        tagged_evidence: str | None = None,
        crm_context: CrmContext | None = None,
        workbook_id: int | None = None,
        *,
        evidence_block: EvidenceBlock | None = None,
        boundary_brief: str | None = None,
        override_epoch: int = 0,
        force_llm: bool = False,
    ) -> Decision:
        cci = row.cci_id or row.control_id

        # ---- Step 1: deterministic rule #8 -----------------------------
        auto = rules.classify_row(row)
        if auto.verdict == rules.AutoStatusVerdict.COMPLIANT_8A:
            return self._finalize_rule_decision(
                row, cci, auto, source="rule_8a", outcome=outcome,
                workbook_id=workbook_id,
            )
        if auto.verdict == rules.AutoStatusVerdict.NOT_APPLICABLE_8B:
            return self._finalize_rule_decision(
                row, cci, auto, source="rule_8b", outcome=outcome,
                workbook_id=workbook_id,
            )

        # ---- Step 1.5: CRM overlay short-circuit / hybrid enrichment ---
        # Order matters: rule #8 wins over CRM (a rule-#8-eligible CCI is
        # deterministic regardless of who owns the control), so we only
        # consider CRM after #8 has declined to fire. Customer / no entry
        # is a no-op — the assessor proceeds to the LLM exactly as before.
        #
        # Dual-scope semantics: the CRM may specify a cloud verdict and/or
        # an on-prem verdict. We short-circuit only when EVERY specified
        # scope is inheritable (provider/inherited/NA). If one scope is
        # customer-owned and the other is provider-owned, the LLM still
        # has to assess the customer-owned half — but we prepend the
        # responsibility-split block so it knows the boundary.
        crm_entry = self._lookup_crm(row, crm_context)
        # Per-scope slices for the boundary-aware narrative map. Resolved once
        # here so the accepted-Decision build can key the LLM's per-side
        # narratives onto the actual customer-owned scope labels (e.g.
        # "AWS GovCloud" + On-Premises) rather than a generic two-slot split.
        crm_slices = self._lookup_crm_slices(row, crm_context)
        if crm_entry is not None:
            cloud_r = crm_entry.responsibility
            onprem_r = crm_entry.responsibility_onprem
            specified = [r for r in (cloud_r, onprem_r) if r]
            all_inheritable = bool(specified) and all(
                r in _CRM_SHORT_CIRCUIT_SET for r in specified
            )
            # Multi-scope_label masking guard (FIXME(crm-audit) in
            # crm_context.build_crm_context): ``crm_entry`` is the legacy
            # latest-attach-wins single row, so when two CRMs cover the same
            # control under different scope_labels (e.g. AWS GovCloud
            # "customer" + Azure "inherited") it keeps only the newest attach.
            # ``crm_slices`` (by_control_impls) preserves EVERY scope plus the
            # synthesized On-Premises customer slice. If any slice is
            # customer/hybrid, real customer-side work exists on at least one
            # boundary and the control must NOT short-circuit to
            # COMPLIANT-by-inheritance — route to the LLM with a slice-aware
            # responsibility-split block so each boundary is assessed and the
            # per-scope impl rows (cloud platforms first, On-Premises last)
            # carry distinct verdicts/narratives. Precision over recall:
            # never let "inherited" on the latest attach silently drop the
            # customer half of an earlier-attached scope.
            slice_has_customer_work = any(
                sl.responsibility in _CUSTOMER_OWNED_RESPONSIBILITIES
                for sl in crm_slices
            )
            # Empty-slices masking guard. In a multi-tenant workbook (2+ CRM
            # baselines) a control with NO per-scope slices means scope
            # attribution is missing/unreliable for it (e.g. a CRM lacked a
            # scope_label, or only one tenant's row parsed). The single
            # ``crm_entry`` is latest-attach-wins, so trusting its "inherited"
            # value here would mark the control COMPLIANT-by-inheritance with no
            # LLM, masking the other tenant's customer obligation — the exact
            # bug the slice guard exists to prevent. When slices are empty but
            # the workbook is multi-tenant, force the LLM path. A single-CRM
            # workbook (count < 2) keeps the legacy short-circuit: no second
            # tenant to mask.
            multi_tenant_unattributed = (
                crm_context is not None
                and not crm_slices
                and crm_context.distinct_scope_label_count >= 2
            )
            # Q2 "Both paths" / N/A guard: an evidenced control must never
            # auto-NA. _finalize_crm_decision resolves the combined status to
            # COMPLIANT only when "inherited" is among the specified scopes,
            # else NOT_APPLICABLE — so "would auto-NA" ⟺ "inherited" not in
            # specified. When the CRM would short-circuit to NA but the
            # evidence bundle actually carries implementation artifacts,
            # suppress the short-circuit and fall through to the LLM, which
            # assesses the artifacts on their merits. (CCI-002418: provider
            # CRM tag + a real Red Hat STIG hit must not collapse to NA.)
            evidence_present = (
                evidence_block is not None
                and evidence_block.text is not None
                and evidence_block.has_artifacts
            )
            would_auto_na = "inherited" not in specified
            suppress_na_short_circuit = (
                all_inheritable and would_auto_na and evidence_present
            )
            # Bug(a) — cloud inheritance must NOT serve as on-prem
            # implementation proof. User directive: "CRM can be referenced
            # for boundary data but not as implementation proofs for the
            # on-prem because those implementations are for the cloud."
            # When the CRM specifies only a cloud scope (onprem_r is None)
            # and that cloud scope is inheritable, the control would
            # short-circuit to COMPLIANT-by-inheritance for the WHOLE
            # control — wrongly crediting the cloud provider's work to the
            # on-prem footprint. Per overlay-default-local, a control with
            # NO on-prem CRM entry is 100% customer-owned on the on-prem
            # side. So when on-prem evidence is actually present, suppress
            # the short-circuit and fall through to the LLM with the
            # responsibility-split block: the cloud half keeps its inherited
            # verdict, the on-prem half is assessed locally on the
            # artifacts. When NO on-prem evidence exists, cloud inheritance
            # stands (avoids spurious on-prem Non-Compliant rows for
            # genuinely cloud-only controls — recall protection).
            suppress_onprem_implicit = (
                all_inheritable and onprem_r is None and evidence_present
            )
            suppress_short_circuit = (
                suppress_na_short_circuit
                or suppress_onprem_implicit
                or slice_has_customer_work
                or multi_tenant_unattributed
            )
            if not force_llm and all_inheritable and not suppress_short_circuit:
                return self._finalize_crm_decision(
                    row, cci, crm_entry, outcome=outcome,
                    workbook_id=workbook_id,
                )
            # Hybrid in either scope, OR distinct verdicts across scopes, OR a
            # suppressed short-circuit (evidence overrode an inheritable tag,
            # or cloud-only inheritance can't cover present on-prem evidence)
            # → prepend the responsibility-split block so the LLM sees it
            # alongside the artifact bundle. Asset cross-check (when present)
            # is appended later in the bundle build, so the two don't collide.
            needs_hybrid_block = (
                "hybrid" in specified
                or (
                    cloud_r is not None
                    and onprem_r is not None
                    and cloud_r != onprem_r
                )
                or suppress_short_circuit
            )
            if needs_hybrid_block:
                # Slice-aware block when the customer-side work is spread
                # across multiple scope_labels (the masking case the legacy
                # entry-based block can't see — it only knows the latest
                # attach). Enumerates every scope so the LLM assesses each
                # boundary and the impl rows render cloud-first/on-prem-last.
                # Otherwise the entry-based block covers the single-CRM
                # dual-column (cloud + on-prem) case as before.
                if slice_has_customer_work:
                    hybrid_block = self._render_hybrid_block_from_slices(
                        crm_entry.control_id, crm_slices
                    )
                else:
                    hybrid_block = self._render_hybrid_block(
                        crm_entry,
                        onprem_implicit_customer=suppress_onprem_implicit,
                    )
                tagged_evidence = (
                    f"{hybrid_block}\n\n{tagged_evidence}"
                    if tagged_evidence
                    else hybrid_block
                )

        # ---- Step 1.65: No-evidence short-circuit ----------------------
        # If we got here with no per-objective artifact text, none of the
        # deterministic rules fired AND there's nothing for the LLM to
        # reason about. Step D (2026-06-11): zero evidence is *Unknown*,
        # not a finding — a missed retrieval looks identical to a real gap
        # at this layer, and asserting NON_COMPLIANT on it was wrong 88% of
        # the time against the gold workbook. Short-circuit to an ABSTAIN
        # (needs_review, no proposed status) instead, so the row is held
        # for manual review rather than shipped as a false failure. Still
        # avoids burning an LLM call on a row with nothing to reason about.
        #
        # Structural gate (preferred path): when the caller supplies an
        # ``EvidenceBlock``, the producer has already separated retrieved
        # artifact text from workbook-wide context wrappers (the
        # ``## asset_coverage_report`` block for CM-8/CM-6/CA-3/CA-7/PM-5/RA-5
        # and the CRM hybrid responsibility-split prepend appended just
        # above at Step 1.5). We fire the rule when ``text is None`` OR
        # when the bundle is non-empty but contains only those wrappers
        # (``is_only_context``). A plain string-emptiness check can't
        # distinguish the two and lets coverage-only / hybrid-only
        # bundles reach the LLM with nothing decision-quality in them —
        # which is the failure mode that left 91 untagged CCIs assessed
        # by the model at confidence 0.7-0.9 in production.
        #
        # Legacy fallback (string-only callers): old fixtures and the
        # single-CCI test path pass ``tagged_evidence`` without a block.
        # We keep the old whitespace check for them — those paths never
        # produced wrapper-only bundles, so the precision loss is nil.
        if not force_llm:
            if evidence_block is not None:
                if evidence_block.text is None or evidence_block.is_only_context:
                    # ``text is None`` → genuine zero-candidate sweep;
                    # ``is_only_context`` → only workbook-wide context
                    # wrappers survived. Both abstain (needs_review); the
                    # narrative/notes discriminate so a 3PAO sees which one.
                    return self._finalize_no_evidence_decision(
                        row,
                        cci,
                        outcome=outcome,
                        context_only=evidence_block.is_only_context,
                    )
            elif tagged_evidence is None or not tagged_evidence.strip():
                return self._finalize_no_evidence_decision(row, cci, outcome=outcome)

        # ---- Step 1.67: Evidence-budget overflow escalation ------------
        # The token-budget ranker (evidence_ranker.rank_artifacts) partitions
        # an objective's tagged evidence into examined (shown to the model)
        # and deferred (over budget, NOT shown). classify_overflow grades the
        # deferred tail: OVERFLOW_ESCALATE means at least one *high-relevance*
        # artifact was held back — the LLM would be reasoning over a subset
        # that excludes decisive evidence. Per feedback_precision_over_recall
        # we withhold the verdict rather than let the model finalize on a
        # truncated view: abstain to needs_review with the classifier's
        # human-readable reason. FINALIZE_ON_EXAMINED (deferred tail is all
        # low-relevance corroboration) and NONE fall through and assess
        # normally on the examined set.
        #
        # We still thread the full evidence_shown payload (examined AND
        # deferred audit rows) into the abstain so _persist_audit_trail
        # records exactly what was held back and why — the deferred rows are
        # the traceability guarantee that replaced the old silent drop.
        # Gated on ``not force_llm`` to match the other deterministic gates:
        # eval force-LLM runs deliberately exercise the model on whatever
        # examined set the budget admitted.
        if (
            not force_llm
            and evidence_block is not None
            and evidence_block.overflow is not None
            and evidence_block.overflow.strategy == OVERFLOW_ESCALATE
        ):
            return self._abstain(
                row,
                cci,
                f"evidence-budget-overflow: {evidence_block.overflow.reason}",
                outcome=outcome,
                rule=auto.rule,
                notes=[
                    "Evidence exceeded the token budget; "
                    f"{evidence_block.overflow.deferred_count} high-relevance "
                    "artifact(s) were deferred. Verdict withheld so decisive "
                    "evidence is not silently excluded.",
                ],
                evidence_shown=list(evidence_block.evidence_shown),
            )

        # ---- Step 1.7: Decision-cache lookup (v0.2) ---------------------
        # All deterministic short-circuits (rule 8a/8b, CRM provider/
        # inherited/NA, SDA 8c) returned above are cheap to recompute and
        # are NOT cached. From this point on we're about to burn an LLM
        # call — check the cache first. A fingerprint hit replays the
        # previously-accepted Decision verbatim (with cache_source stamped
        # so telemetry can distinguish replay from fresh) and skips the
        # LLM entirely. Misses fall through to the normal pipeline.
        # Compute fingerprint unconditionally — it's sub-ms and feeds both
        # the cache lookup AND the calibration entry (which needs the fp
        # even on cache-disabled runs to tie reviewer accepts back to a
        # specific (row, evidence, CRM, kernel, prompt) tuple).
        # Audit v1 — thread the audit_citations flag into the fingerprint
        # so flipping the toggle in Settings actually evicts the cache.
        # Without this, a cached Decision from a flag=OFF run satisfies a
        # flag=ON lookup, the assessor calls decision_cache.replay() and
        # skips the LLM call entirely — the citations addendum in
        # build_user_message never fires and AssessmentCitation stays
        # empty even though the operator opted in. _audit_citations lives
        # on both AnthropicClient and OpenAIClient; getattr makes the
        # no-llm-client path (legacy tests) tolerant.
        cache_fp = decision_cache.fingerprint(
            row=row,
            tagged_evidence=tagged_evidence,
            crm_context=crm_context,
            audit_citations=getattr(self._llm, "_audit_citations", False),
            boundary_brief=boundary_brief,
            override_epoch=override_epoch,
        )
        if outcome is not None:
            outcome.fingerprint = cache_fp
        worker_cache_session = self._worker_cache_session() if not force_llm else None
        if worker_cache_session is not None:
            # fix #2 -- run lookup + bump on this worker's PRIVATE session,
            # no ``_cache_lock``. Each thread owns its session, so the
            # lookup-and-bump pair can't corrupt a sibling's transaction
            # state, and ``bump_hit``'s commit lands on an isolated
            # connection (SQLite WAL serializes the actual write). The hit
            # counter is advisory telemetry, so the benign read-modify-write
            # race between two workers replaying the same fingerprint at most
            # under-counts a hit — never a correctness issue.
            cached = decision_cache.lookup(worker_cache_session, cache_fp)
            if cached is not None:
                decision_cache.bump_hit(worker_cache_session, cached)
                replayed = decision_cache.replay(cached)
                if outcome is not None:
                    outcome.cache_hit = True
                return replayed

        # ---- Step 2: LLM (with corrective context if UNCLEAR_8C) -------
        if self._llm is None:
            # No client wired — abstain (needs_review) rather than
            # silently failing. Reviewer sees the row in the queue with a
            # clear reason; export gates keep it out of the workbook.
            return self._abstain(
                row,
                cci,
                "no-llm-client: rule #8 did not fire and no LLM client is configured",
                outcome=outcome,
                rule=auto.rule,
                notes=["No LLM client configured; rule #8 did not fire."],
            )

        initial_context = self._initial_corrective_context(auto)
        attempts: list[LlmProposal] = []
        # Audit v1 — every LLM call appends a TracePayload here (one for
        # single-pass, two for dual-pass). Persisted by the route layer
        # so a row with N attempts (initial + retries, ×2 in dual-pass)
        # ends up with N AssessmentTrace rows, ordered by pass_index +
        # arrival. Empty list when rule #8 short-circuits before any
        # LLM call — that's the intended "no LLM, no trace" path.
        trace_payload: list[TracePayload] = []
        # Evidence-shown payloads — the per-chunk source citations for
        # what the LLM literally saw. Snapshotted once here (rather than
        # rebuilt at each abstain/accept site) so the persistence layer
        # gets a stable list regardless of which exit path fires. Empty
        # tuple → empty list when no evidence_block was passed (legacy
        # test paths that don't go through routes._build_evidence_block).
        evidence_shown_list: list[EvidenceShownPayload] = (
            list(evidence_block.evidence_shown) if evidence_block is not None else []
        )
        supersession_log: list[SupersessionHit] = []
        rejection_log: list[ValidatorRejection] = []
        notes: list[str] = []
        last_status: ComplianceStatus | None = None
        last_narrative: str | None = None
        last_confidence: float | None = None

        # CRM responsibility signal threaded into every LLM call below.
        # The system prompt has an "absent → customer (on-prem only)"
        # default rule, but without an explicit ``crm_responsibility:
        # <value>`` line in the user message the rule had no signal to
        # bind to and the LLM hallucinated cloud narratives on no-CRM
        # rows. None here → builder emits "absent" sentinel. When the
        # CRM specifies separate cloud + on-prem verdicts we ship the
        # cloud-side value as the headline (matches the existing dual-
        # scope ``responsibility`` / ``responsibility_onprem`` split —
        # the hybrid block rendered above already carries the on-prem
        # half verbatim, so the prompt has both signals when needed).
        crm_responsibility = crm_entry.responsibility if crm_entry else None

        corrective_context = initial_context
        for attempt_no in range(self._max_retries + 1):
            # Dual-pass when enabled: pass 0 is the initial verdict at
            # temp 0.0; pass 1 is the *challenger* — same temp 0.0, but
            # the user message embeds pass 0's verdict + narrative + the
            # citations it emitted, and asks the model to CONFIRM or
            # CHALLENGE. Status mismatch (a CHALLENGE) → abstain
            # immediately (precision-over-recall mechanism #4). Status
            # match (a CONFIRM) → keep pass 0's narrative + citations as
            # canonical and the LOWER confidence floor; the persister
            # reads citations only from ``pass_index == 0`` so pass 0
            # MUST remain the source of truth for the Assessment row.
            if DUAL_PASS_ENABLED:
                pass0, pass1 = self._llm.propose_twice(
                    row=row,
                    corrective_context=corrective_context,
                    prior_attempts=attempts or None,
                    tagged_evidence=tagged_evidence,
                    crm_responsibility=crm_responsibility,
                    boundary_brief=boundary_brief,
                )
                # Record BOTH passes' token usage — the cache amortizes
                # input but output is still per-call.
                for pass_idx, p in enumerate((pass0, pass1)):
                    attempts.append(p)
                    if outcome is not None:
                        outcome.input_tokens += p.input_tokens
                        outcome.output_tokens += p.output_tokens
                        outcome.cache_read_tokens += p.cache_read_tokens
                    # Audit v1 — capture per-call trace. pass_index 0 is
                    # the initial verdict, pass_index 1 is the challenger.
                    # raw_response_json is JSON-dumped here so the Decision
                    # can round-trip through the asdict-based decision
                    # cache without choking on dict-inside-dataclass.
                    trace_payload.append(
                        TracePayload(
                            system_prompt_sha=p.system_prompt_sha,
                            user_message=p.user_message,
                            model=p.model,
                            model_version=p.model_version,
                            temperature=p.temperature,
                            max_tokens=p.max_tokens,
                            request_id=p.request_id,
                            raw_response_json=json.dumps(
                                p.raw_response_json, default=str
                            ),
                            input_tokens=p.input_tokens,
                            output_tokens=p.output_tokens,
                            cache_read_tokens=p.cache_read_tokens,
                            pass_index=pass_idx,
                            citations=list(p.citations or []),
                        )
                    )

                # Parse-error sentinel propagates abstain=True with the
                # ``[parse_error]`` narrative prefix. Either pass blowing
                # up means we can't trust the verdict.
                if pass0.abstain or pass1.abstain:
                    bad = pass0 if pass0.abstain else pass1
                    is_parse_error = bad.narrative.startswith("[parse_error]")
                    # A PARSE ERROR is not a clinical "I can't decide" — it's
                    # the model returning malformed JSON, which on a row that
                    # had no real evidence to begin with would otherwise leave
                    # the raw "[parse_error]" string overwriting what should
                    # have been a clean no-evidence verdict (and "fix itself"
                    # only on a lucky re-run). When the evidence bundle carried
                    # no decision-quality artifact, fall back to the
                    # deterministic no-evidence Non-Compliant verdict instead of
                    # surfacing the parse error — the row never should have
                    # reached the LLM. (has_artifacts/has_findings/has_hosts
                    # are the producer's structural signal; absent an
                    # EvidenceBlock we conservatively treat a parse error as a
                    # transient model fault and still abstain so we don't assert
                    # NC on a row that genuinely had evidence the model choked
                    # on.)
                    if is_parse_error and evidence_block is not None and (
                        evidence_block.text is None
                        or evidence_block.is_only_context
                    ):
                        return self._finalize_no_evidence_decision(
                            row, cci, outcome=outcome,
                            context_only=evidence_block.is_only_context,
                        )
                    reason_prefix = (
                        "llm-parse-error" if is_parse_error else "llm-abstain"
                    )
                    return self._abstain(
                        row, cci,
                        f"{reason_prefix}: {bad.narrative[:300]}",
                        outcome=outcome,
                        status=bad.status,
                        confidence=bad.confidence,
                        rule=auto.rule,
                        retries=attempt_no,
                        rejection_log=rejection_log,
                        supersession_log=supersession_log,
                        notes=notes,
                        trace_payload=trace_payload,
                        evidence_shown=evidence_shown_list,
                    )

                if pass0.status != pass1.status:
                    # Challenger flipped the verdict — treat as a
                    # CHALLENGE outcome and abstain. The auditor sees both
                    # passes in the trace and can decide manually.
                    if outcome is not None:
                        outcome.dual_pass_disagreement = True
                    detail = (
                        f"pass0={pass0.status.value} (conf={pass0.confidence}), "
                        f"pass1={pass1.status.value} (conf={pass1.confidence})"
                    )
                    return self._abstain(
                        row, cci,
                        f"dual-pass-disagreement: {detail}",
                        outcome=outcome,
                        status=pass0.status,
                        confidence=0.0,
                        rule=auto.rule,
                        retries=attempt_no,
                        rejection_log=rejection_log,
                        supersession_log=supersession_log,
                        notes=notes + [
                            f"pass0_narrative={pass0.narrative[:250]!r}",
                            f"pass1_narrative={pass1.narrative[:250]!r}",
                        ],
                        trace_payload=trace_payload,
                        evidence_shown=evidence_shown_list,
                    )

                # CONFIRM — pass 0 is canonical. Narrative + raw come
                # from pass 0 so they line up with pass 0's citations
                # (the persister only reads citations from pass_index==0).
                # Use the LOWER confidence so a high-conviction-then-low
                # pair can't smuggle a guess through the threshold.
                proposal = LlmProposal(
                    status=pass0.status,
                    narrative=pass0.narrative,
                    input_tokens=0,  # already booked above
                    output_tokens=0,
                    cache_read_tokens=0,
                    raw=pass0.raw,
                    confidence=min(
                        pass0.confidence if pass0.confidence is not None else 0.5,
                        pass1.confidence if pass1.confidence is not None else 0.5,
                    ),
                    abstain=False,
                    # Pass 0 is canonical for the dual-narrative + per-scope
                    # fields too — carry them through so the CONFIRM path
                    # doesn't silently drop the on-prem/cloud halves and the
                    # per-boundary map (which would collapse a hybrid verdict
                    # back to a single column-Q narrative downstream).
                    narrative_on_prem=pass0.narrative_on_prem,
                    narrative_cloud=pass0.narrative_cloud,
                    narratives_by_scope=pass0.narratives_by_scope,
                )
            else:
                proposal = self._llm.propose(
                    row=row,
                    corrective_context=corrective_context,
                    prior_attempts=attempts or None,
                    tagged_evidence=tagged_evidence,
                    crm_responsibility=crm_responsibility,
                    boundary_brief=boundary_brief,
                )
                attempts.append(proposal)
                if outcome is not None:
                    outcome.input_tokens += proposal.input_tokens
                    outcome.output_tokens += proposal.output_tokens
                    outcome.cache_read_tokens += proposal.cache_read_tokens
                # Audit v1 — single-pass call always carries pass_index=0.
                # Same JSON-dump-at-capture rule as the dual-pass branch.
                trace_payload.append(
                    TracePayload(
                        system_prompt_sha=proposal.system_prompt_sha,
                        user_message=proposal.user_message,
                        model=proposal.model,
                        model_version=proposal.model_version,
                        temperature=proposal.temperature,
                        max_tokens=proposal.max_tokens,
                        request_id=proposal.request_id,
                        raw_response_json=json.dumps(
                            proposal.raw_response_json, default=str
                        ),
                        input_tokens=proposal.input_tokens,
                        output_tokens=proposal.output_tokens,
                        cache_read_tokens=proposal.cache_read_tokens,
                        pass_index=0,
                        citations=list(proposal.citations or []),
                    )
                )

                # Single-pass parse-error / self-abstain shortcut.
                if proposal.abstain:
                    reason_prefix = (
                        "llm-parse-error"
                        if proposal.narrative.startswith("[parse_error]")
                        else "llm-abstain"
                    )
                    return self._abstain(
                        row, cci,
                        f"{reason_prefix}: {proposal.narrative[:300]}",
                        outcome=outcome,
                        status=proposal.status,
                        confidence=proposal.confidence,
                        rule=auto.rule,
                        retries=attempt_no,
                        rejection_log=rejection_log,
                        supersession_log=supersession_log,
                        notes=notes,
                        trace_payload=trace_payload,
                        evidence_shown=evidence_shown_list,
                    )

            # Supersession rewrite happens BEFORE validation so the
            # validator sees the corrected narrative — otherwise an
            # otherwise-good narrative citing a superseded doc would pass
            # validation and the stale ref would slip into col Q.
            #
            # Patent-aligned stale-EVIDENCE catch: scans the narrative for
            # references to Evidence rows that have been auto-superseded at
            # ingest (Rev A → Rev B), per workbook. No-op when the route
            # hasn't plumbed a session — keeps Assessor(llm=...) tests
            # session-free. Lock-wrapped because workers share
            # self._cache_session.
            narrative = proposal.narrative
            chain = self._locked_rewrite_evidence_chain(
                narrative, workbook_id=workbook_id,
            )
            narrative = chain.rewritten_text
            for chit in chain.hits:
                hit = SupersessionHit(
                    cci=cci,
                    stale_ref=chit.stale_ref,
                    current_ref=chit.current_ref,
                    source="evidence_chain",
                )
                supersession_log.append(hit)
                if outcome is not None:
                    outcome.supersession_hits.append(hit)

            result = validator.validate(
                proposed_status=proposal.status,
                proposed_narrative=narrative,
                row=row,
                evidence_text=tagged_evidence,
                # v0.3 corroboration gate: thread the EvidenceBlock's
                # ``has_nonscan_artifact`` signal so the validator can
                # reject a COMPLIANT verdict that cites a STIG rule but
                # has no policy/baseline corroborator. ``None`` when the
                # caller didn't pass an EvidenceBlock (legacy paths),
                # which skips the rule -- exactly the "don't reject what
                # the caller can't yet measure" stance the validator
                # docstring describes. See feedback_corroborate_stig_findings.md.
                corroboration_present=(
                    evidence_block.has_nonscan_artifact
                    if evidence_block is not None
                    else None
                ),
                # fix #1 -- audit-v1 source_quote hard gate. ``proposal`` is
                # the canonical proposal (pass0 in dual-pass); its citations
                # are the audit-trail rows that will be persisted. When the
                # audit layer is off these are empty and the validator skips
                # the gate; when on, each source_quote is verified verbatim
                # against the tagged evidence so a fabricated quote is rejected
                # and retried rather than shipped into the SAR.
                citations=list(proposal.citations or []),
            )
            notes.extend(result.notes)
            last_status = proposal.status
            last_narrative = narrative
            last_confidence = proposal.confidence

            # N/A guard (Q2 "Both paths"): an evidenced control must never be
            # Not Applicable. N/A is reserved for controls whose applicability
            # makes no sense in any boundary. When the LLM proposes NA but the
            # evidence bundle carries real implementation artifacts, the right
            # verdict is Compliant or Non-Compliant — never NA. The validator's
            # class-match passes NA↔NA, so this is a separate gate ahead of
            # result.ok: reject and retry so the model re-decides on the
            # artifacts. (CCI-002418: a Red Hat STIG hit + FedRAMP SC-8 cite +
            # affirming TLS-1.2+ narrative must not collapse to NA.) On retry
            # exhaustion the loop falls through to the terminal abstain, which
            # is correct — needs_review beats a confidently-wrong NA.
            if (
                proposal.status == ComplianceStatus.NOT_APPLICABLE
                and evidence_block is not None
                and evidence_block.text is not None
                and evidence_block.has_artifacts
            ):
                na_msg = (
                    "Status Not Applicable is invalid here: the evidence bundle "
                    "carries implementation artifacts, so this control is IN "
                    "SCOPE and must be assessed as Compliant or Non-Compliant. "
                    "N/A is reserved for controls whose applicability makes no "
                    "sense in any boundary. Re-decide on the tagged evidence."
                )
                corrective_context = self._build_corrective_context(
                    row=row,
                    auto=auto,
                    rejections=[
                        (validator.RejectionReason.STATUS_NARRATIVE_MISMATCH, na_msg)
                    ],
                    last_status=proposal.status,
                    last_narrative=narrative,
                )
                rej = ValidatorRejection(
                    cci=cci,
                    rejection_class=validator.RejectionReason.STATUS_NARRATIVE_MISMATCH.value,  # type: ignore[arg-type]
                    original_output=(
                        f"status={proposal.status.value!r} narrative={narrative!r}"
                    ),
                    corrective_context=na_msg,
                )
                rejection_log.append(rej)
                if outcome is not None:
                    outcome.rejections.append(rej)
                continue

            if result.ok:
                # Implicit-abstain gate: even a validator-approved verdict
                # is treated as needs_review when the LLM's self-reported
                # confidence is below the precision-over-recall threshold.
                if (
                    proposal.confidence is not None
                    and proposal.confidence < CONFIDENCE_THRESHOLD
                ):
                    return self._abstain(
                        row, cci,
                        f"low-confidence: {proposal.confidence:.2f} < {CONFIDENCE_THRESHOLD:.2f}",
                        outcome=outcome,
                        status=proposal.status,
                        narrative=narrative,
                        narrative_class=result.classified_as,
                        confidence=proposal.confidence,
                        rule=auto.rule,
                        retries=attempt_no,
                        rejection_log=rejection_log,
                        supersession_log=supersession_log,
                        notes=notes,
                        trace_payload=trace_payload,
                        evidence_shown=evidence_shown_list,
                    )

                # ----------------------------------------------------------
                # Mechanism 5 — boundary gate.
                #
                # Boundary conflict (narrative says outside-boundary but
                # status != NA) abstains — that contradiction questions the
                # verdict itself. Per feedback_boundary_reasoning.md.
                #
                # ``rewrite_requested`` is retained as an outcome field for
                # downstream POAM/SAR/CCIS consumers; the manual stale-cite
                # and NA-reconsideration signals that used to set it were
                # removed with the manual supersession registry. Evidence-
                # chain rewrites (above) already corrected the narrative in
                # place, so no separate "cite refresh" demotion is needed.
                # ----------------------------------------------------------
                rewrite_requested_local = False
                rewrite_requested_refs_local: list[tuple[str, str]] | None = None

                boundary = _boundary_conflict(narrative, proposal.status)
                if boundary is not None:
                    return self._abstain(
                        row, cci,
                        f"boundary-conflict: {boundary}",
                        outcome=outcome,
                        status=proposal.status,
                        narrative=narrative,
                        narrative_class=result.classified_as,
                        confidence=proposal.confidence,
                        rule=auto.rule,
                        retries=attempt_no,
                        rejection_log=rejection_log,
                        supersession_log=supersession_log,
                        notes=notes,
                        trace_payload=trace_payload,
                        evidence_shown=evidence_shown_list,
                    )

                source = "llm" if attempt_no == 0 else "llm_after_retry"
                if outcome is not None:
                    outcome.retries_before_accept = attempt_no
                    outcome.accepted = True
                    outcome.rewrite_requested = rewrite_requested_local
                    # Calibration telemetry — validator-passed proposal so
                    # proposed_status and final_status are the same value;
                    # supersession may have rewritten the narrative but the
                    # status itself is what the reviewer accepts or rejects.
                    outcome.stated_confidence = proposal.confidence
                    outcome.proposed_status = proposal.status.value
                    outcome.final_status = proposal.status.value
                # Dual-narrative passthrough: when the LLM emitted only the
                # single ``narrative`` field (old prompt versions / models),
                # fall back to that text for the on-prem side so the UI never
                # renders an empty box for a customer-owned control.
                proposal_on_prem = proposal.narrative_on_prem
                proposal_cloud = proposal.narrative_cloud
                if proposal_on_prem is None and proposal_cloud is None:
                    proposal_on_prem = narrative

                # Boundary-aware per-scope narrative map. Key the LLM's two
                # per-side halves onto the actual customer-owned scope labels
                # so plan_implementations renders a verdict situated in EACH
                # boundary (the seam gap lands on the on-prem slice) rather
                # than collapsing every slice onto the canonical column-Q
                # text. Empty when no multi-boundary CRM slices exist — the
                # single-boundary path falls back to ``narrative``.
                proposal_by_scope = narratives_by_scope_from_proposal(
                    slices=crm_slices,
                    narrative_on_prem=proposal_on_prem,
                    narrative_cloud=proposal_cloud,
                    llm_by_scope=proposal.narratives_by_scope,
                )

                # v0.2 dual-narrative hygiene -- advisory (NOTE level).
                # Column Q (above) already passed ``validate()``; this pass
                # catches swap-the-halves LLM errors and CRM/responsibility
                # mismatches without expanding the retry budget. The CRM
                # responsibility is the canonical cloud-preferred value (same
                # mapping the short-circuit uses) when the entry exists; we
                # special-case dual-scope-distinct to "hybrid" so the cross-
                # check fires the hybrid branch rather than misclassifying.
                crm_resp_for_check: str | None = None
                if crm_entry is not None:
                    cloud_r2 = crm_entry.responsibility
                    onprem_r2 = crm_entry.responsibility_onprem
                    if cloud_r2 and onprem_r2 and cloud_r2 != onprem_r2:
                        crm_resp_for_check = "hybrid"
                    else:
                        crm_resp_for_check = cloud_r2 or onprem_r2
                dual_result = validator.validate_dual_narratives(
                    narrative_on_prem=proposal_on_prem,
                    narrative_cloud=proposal_cloud,
                    crm_responsibility=crm_resp_for_check,
                )
                notes.extend(dual_result.notes)
                if outcome is not None:
                    for flagged_reason in dual_result.flagged:
                        outcome.rejections.append(
                            ValidatorRejection(
                                cci=cci,
                                rejection_class=flagged_reason.value,  # type: ignore[arg-type]
                                original_output=(
                                    f"on_prem={proposal_on_prem!r} "
                                    f"cloud={proposal_cloud!r}"
                                ),
                                corrective_context=(
                                    "Dual-narrative advisory; verdict still "
                                    "accepted, halves flagged for review."
                                ),
                            )
                        )

                # Distinct-only: dual_result.flagged can repeat the same
                # RejectionReason if both the leak rule AND the CRM
                # mismatch rule fire on one row. The persisted advisory
                # list de-dupes so the JSON column stays compact and
                # downstream "row had a flag of class X?" queries don't
                # need DISTINCT inside the JSON membership check.
                dual_flag_values: list[str] = []
                seen_flags: set[str] = set()
                for flagged_reason in dual_result.flagged:
                    val = flagged_reason.value
                    if val not in seen_flags:
                        seen_flags.add(val)
                        dual_flag_values.append(val)
                decision = Decision(
                    cci_id=cci,
                    excel_row=row.excel_row,
                    accepted=True,
                    status=proposal.status,
                    narrative=narrative,
                    narrative_class=result.classified_as,
                    source=source,
                    rule=auto.rule,
                    retries=attempt_no,
                    rejection_log=rejection_log,
                    supersession_log=supersession_log,
                    notes=notes,
                    confidence=proposal.confidence,
                    rewrite_requested=rewrite_requested_local,
                    rewrite_requested_refs=rewrite_requested_refs_local,
                    narrative_on_prem=proposal_on_prem,
                    narrative_cloud=proposal_cloud,
                    narratives_by_scope=proposal_by_scope,
                    dual_narrative_flags=dual_flag_values,
                    # Audit v1 — the trace blobs that justify this verdict
                    # ride along on the Decision so the route layer
                    # persists Assessment + AssessmentTrace +
                    # AssessmentEvidenceShown atomically. Bare lists match
                    # the Decision.trace_payload / evidence_shown annotation
                    # (Decision is a plain @dataclass, not frozen) and match
                    # the convention every _abstain call site already uses.
                    trace_payload=trace_payload,
                    evidence_shown=evidence_shown_list,
                )
                # Cache LLM-accepted Decisions. Abstain rows are
                # deliberately re-evaluated on the next run (per the
                # decision_cache module docstring) so the cache write
                # only fires on the trusted-verdict path. fix #2 -- store
                # on this worker's PRIVATE session, no ``_cache_lock``.
                # store() is idempotent (INSERT-OR-IGNORE on the fingerprint
                # PK), so even if two workers somehow produce the same
                # fingerprint the second write is a no-op rather than a
                # conflict; the commit lands on an isolated connection.
                if cache_fp is not None:
                    worker_store_session = self._worker_cache_session()
                    if worker_store_session is not None:
                        decision_cache.store(worker_store_session, cache_fp, decision)
                return decision

            # Rejected — log every rejection and prep the next round.
            corrective_context = self._build_corrective_context(
                row=row,
                auto=auto,
                rejections=result.rejections,
                last_status=proposal.status,
                last_narrative=narrative,
            )
            for reason, msg in result.rejections:
                rej = ValidatorRejection(
                    cci=cci,
                    rejection_class=reason.value,  # type: ignore[arg-type]
                    original_output=f"status={proposal.status.value!r} narrative={narrative!r}",
                    corrective_context=msg,
                )
                rejection_log.append(rej)
                if outcome is not None:
                    outcome.rejections.append(rej)

        # Exhausted retries — abstain (needs_review) so the reviewer sees
        # the row in the queue with the last rejection's hint. Per the
        # precision-over-recall contract this is an assessor-failure case:
        # the validator could not produce a passing verdict.
        last_rejection_summary = "no rejections recorded"
        if rejection_log:
            last_rej = rejection_log[-1]
            last_rejection_summary = (
                f"{last_rej.rejection_class}: {last_rej.corrective_context[:200]}"
            )
        return self._abstain(
            row, cci,
            f"validator-exhausted: {last_rejection_summary}",
            outcome=outcome,
            status=last_status,
            narrative=last_narrative,
            confidence=last_confidence,
            rule=auto.rule,
            retries=self._max_retries,
            rejection_log=rejection_log,
            supersession_log=supersession_log,
            notes=notes + [
                f"Validator rejected all {self._max_retries + 1} attempts. "
                "Row written as needs_review; export gates suppress it."
            ],
            trace_payload=trace_payload,
            evidence_shown=evidence_shown_list,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _finalize_rule_decision(
        self,
        row: CcisRow,
        cci: str,
        auto: rules.AutoStatusResult,
        *,
        source: str,
        outcome,
        workbook_id: int | None = None,
    ) -> Decision:
        """Wrap a rule-#8 verdict as a Decision. Still runs the narrative
        through the evidence-chain rewrite + validation so the auto-generated
        text is held to the same bar as LLM output.
        """
        narrative = auto.narrative or ""
        supersession_log: list[SupersessionHit] = []

        # Patent-aligned stale-EVIDENCE catch (see _run for context).
        # Rule-#8 narratives are templated, but the templates sometimes
        # inline col-U text verbatim — so a retired evidence reference can
        # still slip in here. Session-free Assessor (test path) skips this.
        # Lock-wrapped because workers share self._cache_session.
        chain = self._locked_rewrite_evidence_chain(
            narrative, workbook_id=workbook_id,
        )
        narrative = chain.rewritten_text
        for chit in chain.hits:
            hit = SupersessionHit(
                cci=cci,
                stale_ref=chit.stale_ref,
                current_ref=chit.current_ref,
                source="evidence_chain",
            )
            supersession_log.append(hit)
            if outcome is not None:
                outcome.supersession_hits.append(hit)

        # Pass row=None so the Jaccard restatement check is skipped for
        # deterministic rule-#8 templates. The templates echo the trigger
        # phrase by construction (rule_8a quotes col K's "automatically
        # compliant"), which would always trip Jaccard ≥ 0.70 overlap.
        # The regex restatement patterns + classification + status/class
        # match + inheritance-source checks still run.
        result = validator.validate(
            proposed_status=auto.status,
            proposed_narrative=narrative,
            row=None,
        )
        # Rule #8 narratives are generated by deterministic templates;
        # they should always pass. If they don't, that's a bug in the
        # formatter — log it as a rejection so the run record surfaces
        # the regression rather than silently writing bad text.
        rejection_log: list[ValidatorRejection] = []
        for reason, msg in result.rejections:
            rej = ValidatorRejection(
                cci=cci,
                rejection_class=reason.value,  # type: ignore[arg-type]
                original_output=f"rule={auto.rule} narrative={narrative!r}",
                corrective_context=f"Rule #{auto.rule} formatter produced invalid text: {msg}",
            )
            rejection_log.append(rej)
            if outcome is not None:
                outcome.rejections.append(rej)

        accepted = result.ok
        if outcome is not None:
            outcome.accepted = accepted
            outcome.retries_before_accept = 0
            # Telemetry — attach a RuleShortCircuit record so the run row's
            # rule_8a_short_circuits / rule_8b_short_circuits counters
            # reflect this verdict. Gated on:
            #   * accepted: a rejected rule narrative (formatter bug) is
            #     not actually a short-circuit — the row will fall through
            #     to abstain or LLM. Don't credit those.
            #   * auto.rule in {"8a","8b"}: 8c is the ambiguous-escalation
            #     verdict; it goes to the LLM, not a short-circuit path.
            #   * trigger_phrase + trigger_column non-None: invariant from
            #     rules.classify_row, but guarded so a future change to
            #     the rules engine can't silently produce malformed records.
            if (
                accepted
                and auto.rule in ("8a", "8b")
                and auto.trigger_phrase is not None
                and auto.trigger_column is not None
            ):
                outcome.rule_short_circuit = RuleShortCircuit(
                    cci=cci,
                    rule=auto.rule,  # type: ignore[arg-type]
                    trigger_phrase=auto.trigger_phrase,
                    trigger_column=auto.trigger_column,  # type: ignore[arg-type]
                )
        # Rule #8a/8b are deterministic short-circuits. Mirror the merged
        # narrative into narrative_on_prem so the UI detail page shows the
        # rule-generated text in the on-prem section; cloud stays None
        # because the rule logic decides locally vs externally already.
        accepted_narrative = narrative if accepted else None
        return Decision(
            cci_id=cci,
            excel_row=row.excel_row,
            accepted=accepted,
            status=auto.status if accepted else None,
            narrative=accepted_narrative,
            narrative_class=result.classified_as,
            source=source,
            rule=auto.rule,
            retries=0,
            rejection_log=rejection_log,
            supersession_log=supersession_log,
            notes=result.notes,
            narrative_on_prem=accepted_narrative,
        )

    # ------------------------------------------------------------------
    # No-evidence helper (deterministic NC)
    # ------------------------------------------------------------------

    def _finalize_no_evidence_decision(
        self,
        row: CcisRow,
        cci: str,
        *,
        outcome,
        context_only: bool = False,
    ) -> Decision:
        """Deterministic NON-COMPLIANT when no artifacts exist to examine.

        Fires when the tagged-evidence bundle is empty AFTER rule #8a/8b,
        CRM short-circuit, CRM hybrid enrichment, and SDA 8c have all
        declined — i.e. retrieval surfaced nothing decision-quality for
        this objective.

        Verdict policy (2026-06-17): "no evidence" → Non-Compliant with a
        ``no-evidence`` marker, NOT an abstain. Rationale (owner decision):
        in RMF practice a control with no implementation evidence is a
        finding the assessor must run down — and the natural workflow is to
        review the Non-Compliant rows at the end of the assessment. A real
        gap stays NC and gets a POA&M; a forgot-to-upload / missed-tag case
        shows as NC, the assessor adds the artifact and reassesses, and it
        flips to Compliant. That is the normal review loop and is far less
        work than clicking through every row individually.

        This SUPERSEDES the prior abstain behavior (Step D, 2026-06-11),
        which was anchored to an eval ("88% of rule_no_evidence rows
        disagreed with the gold reviewer") that turned out to be a
        TAGGER/RETRIEVAL artifact of one workbook, not a durable truth —
        the engine failed to retrieve evidence that existed. The retrieval
        tiers have since improved, and a second eval on a genuinely
        evidence-empty workbook showed ~80% agreement with NC. So the
        false-NC concern is mitigated by (a) better retrieval and (b) the
        end-of-assessment NC review the user performs regardless.

        ``source="rule_no_evidence"`` so the UI can render a distinct
        "No evidence" marker, and the ``review_reason`` carries the
        ``no-evidence`` prefix so these rows are filterable/auditable even
        though they now carry a real status. ``context_only`` keeps the
        narrative honest about what retrieval produced (zero candidates vs
        workbook-context-only). No LLM call is made.

        The narrative includes accepted gap phrases ("no evidence found",
        "POA&M") so the validator's gap-narrative gate classifies it as a
        legitimate Non-Compliant finding rather than ambiguous text.
        """
        if context_only:
            reason = (
                "no-evidence: workbook-wide context was retrieved for this "
                "CCI but no per-objective artifact substantiating the "
                "control objective — Non-Compliant (no evidence to examine)."
            )
            narrative = (
                "No evidence found substantiating this control objective: "
                "workbook-wide context was available, but no implementing "
                "artifact was located for this CCI. Non-Compliant pending "
                "submission of implementation evidence; POA&M required."
            )
            note = (
                "No-evidence Non-Compliant (context-only bundle): only "
                "workbook-wide context wrappers (asset coverage report / "
                "CRM responsibility split) were present after rule #8a/8b, "
                "CRM short-circuit, CRM hybrid enrichment, and SDA 8c "
                "declined — no per-objective artifact, finding, or host to "
                "examine. No LLM call made."
            )
        else:
            reason = (
                "no-evidence: zero artifacts retrieved for this CCI — "
                "Non-Compliant (no evidence to examine)."
            )
            narrative = (
                "No evidence found for this control objective: no artifacts "
                "were located for this CCI. With no evidence of "
                "implementation to examine, the control is assessed "
                "Non-Compliant pending submission of evidence; POA&M required."
            )
            note = (
                "No-evidence Non-Compliant (zero-candidate sweep): tagged-"
                "evidence bundle was empty after rule #8a/8b, CRM short-"
                "circuit, CRM hybrid enrichment, and SDA 8c declined. No LLM "
                "call made."
            )

        # Validate the templated NC narrative through the same gate as every
        # other verdict so a formatter drift surfaces as a rejection rather
        # than persisting bad text. row=None skips the Jaccard restatement
        # check (the template is deterministic, not a parroted requirement).
        result = validator.validate(
            proposed_status=ComplianceStatus.NON_COMPLIANT,
            proposed_narrative=narrative,
            row=None,
        )
        rejection_log: list[ValidatorRejection] = []
        for rej_reason, msg in result.rejections:
            rej = ValidatorRejection(
                cci=cci,
                rejection_class=rej_reason.value,  # type: ignore[arg-type]
                original_output=f"rule=no_evidence narrative={narrative!r}",
                corrective_context=(
                    f"no-evidence formatter produced invalid text: {msg}"
                ),
            )
            rejection_log.append(rej)
            if outcome is not None:
                outcome.rejections.append(rej)
        accepted = result.ok
        if outcome is not None:
            outcome.accepted = accepted
            outcome.retries_before_accept = 0

        accepted_narrative = narrative if accepted else None
        return Decision(
            cci_id=cci,
            excel_row=row.excel_row,
            accepted=accepted,
            status=ComplianceStatus.NON_COMPLIANT if accepted else None,
            narrative=accepted_narrative,
            narrative_class=result.classified_as,
            source="rule_no_evidence",
            rule=None,
            retries=0,
            rejection_log=rejection_log,
            supersession_log=[],
            notes=(result.notes or []) + [note],
            narrative_on_prem=accepted_narrative,
            confidence=1.0,
            review_reason=reason,
        )

    # ------------------------------------------------------------------
    # Abstain helper (v0.2 precision-over-recall)
    # ------------------------------------------------------------------

    def _abstain(
        self,
        row: CcisRow,
        cci: str,
        reason: str,
        *,
        outcome,
        confidence: float | None = None,
        status: ComplianceStatus | None = None,
        narrative: str | None = None,
        narrative_class: NarrativeClass = NarrativeClass.AMBIGUOUS,
        rule: str | None = None,
        retries: int = 0,
        rejection_log: list[ValidatorRejection] | None = None,
        supersession_log: list[SupersessionHit] | None = None,
        notes: list[str] | None = None,
        trace_payload: list[TracePayload] | None = None,
        evidence_shown: list[EvidenceShownPayload] | None = None,
    ) -> Decision:
        """Mint a ``needs_review=True`` Decision for the abstain paths.

        Per ``feedback_precision_over_recall.md``: abstain is reserved for
        assessor-failure / contradiction cases (validator exhaustion, LLM
        parse error, cite hallucination after retry, dual-pass status
        disagreement, supersession-stale or boundary-conflict). It is NOT
        for evidence absence — that's a Non-Compliant finding the LLM
        produces directly.

        We return ``accepted=True`` so the persistence site in
        ``routes/controls.py`` writes the row — the export gates
        (ccis_writer, poam.exporter) filter on ``needs_review`` to keep
        un-trusted verdicts out of the workbook / POAM bundle.

        Eval finding #3 (eval_v1.json) — hard-abstain status coercion.
        Prior behavior shipped the LLM's last proposed status as
        ``Decision.status`` even though ``needs_review=True``. That
        violated the contract pinned at tests/eval/test_eval_harness.py:174
        and silently fed un-validated verdicts to downstream consumers
        that don't check ``needs_review`` (older SAR exporter, calibration
        rollups). Now ``Decision.status`` is coerced to ``None`` on every
        abstain; the LLM's guess is preserved on ``Decision.proposed_status``
        so reviewers still have triage context and calibration can grade
        "did the LLM's guess agree with the human's eventual call?"
        without re-mining the rejection log.
        """
        if outcome is not None:
            outcome.accepted = True  # row was written; reviewer-gated
            outcome.abstained = True  # but verdict is NOT trusted
            outcome.retries_before_accept = retries
            # Calibration telemetry — populate only when this abstain was
            # informed by an LLM proposal (validator-exhausted, low-confidence,
            # boundary-conflict, unverified-cites, dual-pass-mismatch all
            # carry the LLM's emitted ``confidence``). No-llm-client /
            # rule-routed abstains pass confidence=None and stay out of the
            # calibration set — they have no LLM confidence to grade.
            if confidence is not None:
                outcome.stated_confidence = confidence
                outcome.proposed_status = status.value if status is not None else ""
                # final_status is None on abstain — the reviewer has not yet
                # provided a corrected status; the calibration write stores
                # the empty string for now and the reviewer endpoint fills
                # ``human_status`` later.
                outcome.final_status = ""
        return Decision(
            cci_id=cci,
            excel_row=row.excel_row,
            accepted=True,
            # Eval fix #3 — hard-abstain coercion. status is always None on
            # abstain; the LLM's last guess (if any) is preserved separately.
            status=None,
            proposed_status=status,
            narrative=narrative,
            narrative_class=narrative_class,
            source="abstain",
            rule=rule,
            retries=retries,
            rejection_log=rejection_log or [],
            supersession_log=supersession_log or [],
            notes=notes or [],
            needs_review=True,
            review_reason=reason,
            confidence=confidence,
            # Audit v1 — abstain rows still carry the trace + chunks that
            # informed the abstain decision. Empty defaults cover the
            # no-LLM-client and rule-routed abstains (they never made a
            # call and never saw evidence chunks).
            trace_payload=trace_payload or [],
            evidence_shown=evidence_shown or [],
        )

    # ------------------------------------------------------------------
    # CRM helpers
    # ------------------------------------------------------------------

    def _lookup_crm(
        self,
        row: CcisRow,
        crm_context: CrmContext | None,
    ) -> CrmEntry | None:
        """Resolve the CRM entry for this row's parent control, if any.

        ``CrmContext`` keys on OSCAL canonical control_id ("ac-2.1"), but
        ``CcisRow.control_id`` is the workbook form ("AC-2(1)"). Normalize
        through the same pipeline the catalog loader uses so a CRM authored
        against rev5 IDs resolves cleanly against rows authored against the
        workbook's display IDs.
        """
        if crm_context is None or not row.control_id:
            return None
        oscal_id = _ccis_to_oscal_control_id(_normalize_control(row.control_id))
        return crm_context.lookup(oscal_id)

    def _lookup_crm_slices(
        self,
        row: CcisRow,
        crm_context: CrmContext | None,
    ) -> list[ImplementationSlice]:
        """Resolve the per-scope implementation slices for this row's control.

        Mirrors :meth:`_lookup_crm`'s control-id normalization, but returns
        the multi-boundary ``ImplementationSlice`` group instead of the
        legacy single ``CrmEntry``. Empty list when no CRM with a non-null
        scope_label covers the control — the single-boundary path where the
        parent Assessment carries the verdict on its own.
        """
        if crm_context is None or not row.control_id:
            return []
        oscal_id = _ccis_to_oscal_control_id(_normalize_control(row.control_id))
        return crm_context.implementations(oscal_id)

    def _finalize_crm_decision(
        self,
        row: CcisRow,
        cci: str,
        entry: CrmEntry,
        *,
        outcome,
        workbook_id: int | None = None,
    ) -> Decision:
        """Build a Decision for a CRM row whose every specified scope is inheritable.

        The status is fixed by the CRM responsibility mapping (not
        interpreted from text); the CRM is authoritative and the validator
        NEVER flips it. But the narrative — whether the customer's own
        words from the CRM file or a default template — is routed through
        the SAME ``validator.validate`` gate the LLM-accept path uses, so
        col Q is guaranteed well-formed and classifiable before it ships to
        the SAR (finding #20: the CRM path previously bypassed the gate, so
        an unclassifiable CRM narrative reached the export un-checked).

        The gate only checks that the narrative reads as the class the
        verdict implies; it cannot change ``status``. Order:

        1. Validate (status, narrative) as-is. If ok, ship verbatim.
        2. If not ok, prepend a deterministic, classifiable lead-in keyed
           on the verdict and re-validate. This preserves the customer's
           verbatim words while giving the classifier a phrase it can
           anchor on (the adapter pattern).
        3. If it still fails (e.g. the author text collides with a second
           narrative class — a gap phrase under a Compliant verdict), emit
           a ``needs_review`` abstain so a human adjudicates rather than
           shipping an ambiguous narrative. The verbatim CRM text is kept
           on the abstain Decision as triage context.

        Dual-scope: when the CRM specifies both cloud and on-prem verdicts
        we compose per-scope narratives. The combined CCIS column Q narrative
        labels each half so the reviewer sees the split; the dual-scope
        ``narrative_cloud`` / ``narrative_on_prem`` fields on the Decision
        carry the unlabeled per-scope text for the rendering layer.
        """
        status_map = {
            "provider": ComplianceStatus.NOT_APPLICABLE,
            "inherited": ComplianceStatus.COMPLIANT,
            "not_applicable": ComplianceStatus.NOT_APPLICABLE,
        }
        class_map = {
            "provider": NarrativeClass.NA_JUSTIFYING,
            "inherited": NarrativeClass.COMPLIANCE_AFFIRMING,
            "not_applicable": NarrativeClass.NA_JUSTIFYING,
        }

        def _default_narrative(r: str, scope_label: str) -> str:
            # NOTE(finding-20): these default templates must contain LITERAL
            # phrases from validator.py's phrase tables so they classify
            # deterministically without relying on the fragile embedding
            # fallback. Provider/NA strings carry NA_PHRASES substrings
            # ("no local responsibility", "implemented by the cloud service
            # provider", "control is not applicable"); the inherited string
            # carries an AFFIRMING_PHRASES substring ("confirmed via"). If a
            # phrase below is edited, re-verify against validator.classify_narrative.
            return {
                "provider": (
                    f"Provider-owned per CRM overlay ({scope_label}, control "
                    f"{entry.control_id}). Implementation is the responsibility "
                    "of the service provider; there is no local responsibility "
                    "for this scope and customer assessment is not applicable -- "
                    "the objective is implemented by the cloud service provider."
                ),
                "inherited": (
                    f"Inherited from authorizing system per CRM overlay "
                    f"({scope_label}, control {entry.control_id}); the "
                    "inheriting authorization is confirmed via the CRM overlay "
                    "to cover this control objective for this scope."
                ),
                "not_applicable": (
                    f"Marked Not Applicable in the CRM overlay ({scope_label}, "
                    f"control {entry.control_id}). Control is not applicable to "
                    "this scope of the system authorization boundary or service "
                    "model."
                ),
            }[r]

        cloud_r = entry.responsibility
        onprem_r = entry.responsibility_onprem

        # Per-scope narratives — CRM-supplied text wins; otherwise the
        # default template, scope-labeled so a reviewer can tell where
        # each line came from.
        cloud_narr_text: str | None = None
        if cloud_r:
            cloud_narr_text = entry.narrative or _default_narrative(
                cloud_r, "cloud scope"
            )
        onprem_narr_text: str | None = None
        if onprem_r:
            onprem_narr_text = entry.narrative_onprem or _default_narrative(
                onprem_r, "on-prem scope"
            )

        # Combined status: any "inherited" scope means a real-world authorization
        # covers the objective (Compliant). Otherwise every specified scope is
        # provider/NA, so the control is Not Applicable to the customer.
        specified = [r for r in (cloud_r, onprem_r) if r]
        if "inherited" in specified:
            status = ComplianceStatus.COMPLIANT
            narrative_class = NarrativeClass.COMPLIANCE_AFFIRMING
        else:
            # First specified value drives class — both provider and
            # not_applicable map to NA_JUSTIFYING so this is consistent.
            status = status_map[specified[0]]
            narrative_class = class_map[specified[0]]

        # Compose the canonical (CCIS col Q) narrative. When both scopes
        # are specified AND agree on responsibility, emit one combined
        # line (the cloud narrative; default-text always references the
        # control_id so it reads cleanly). When they disagree, emit two
        # labeled lines so the reviewer sees the split.
        if cloud_r and onprem_r and cloud_r != onprem_r:
            narrative = (
                f"Cloud: {cloud_narr_text}\n"
                f"On-prem: {onprem_narr_text}"
            )
        elif cloud_r and onprem_r:
            # Both specified and equal — single narrative is enough, but
            # prefer the cloud text (CRM-authored or default; both
            # already mention the scope so it stays unambiguous).
            narrative = cloud_narr_text or onprem_narr_text or ""
        elif cloud_r:
            narrative = cloud_narr_text or ""
        else:
            narrative = onprem_narr_text or ""

        supersession_log: list[SupersessionHit] = []

        # Patent-aligned stale-EVIDENCE catch (see _run for context).
        # CRM narratives carry the customer's verbatim text and can name
        # specific evidence files; this catches retired Rev-A references
        # so col Q lands on the current ref regardless of source.
        # Lock-wrapped because workers share self._cache_session.
        chain = self._locked_rewrite_evidence_chain(
            narrative, workbook_id=workbook_id,
        )
        narrative = chain.rewritten_text
        for chit in chain.hits:
            hit = SupersessionHit(
                cci=cci,
                stale_ref=chit.stale_ref,
                current_ref=chit.current_ref,
                source="evidence_chain",
            )
            supersession_log.append(hit)
            if outcome is not None:
                outcome.supersession_hits.append(hit)

        # Record the short-circuit event so the route handler can persist
        # a CrmShortCircuitEvent row linked to the CrmSuspicionLog. Kernel
        # stays session-free — we only build the dataclass; the route
        # handler (which already holds the DB session) writes the row.
        # ``CrmShortCircuit.responsibility`` is the canonical (cloud-preferred)
        # verdict — the on-prem verdict, if distinct, lives in the per-scope
        # narrative fields on the Decision. The literal type stays unchanged
        # for backward-compat with the persistence layer.
        canonical_resp = cloud_r if cloud_r else onprem_r
        short_circuit = CrmShortCircuit(
            cci=cci,
            control_id=entry.control_id,
            responsibility=canonical_resp,  # type: ignore[arg-type]
            baseline_id=entry.source_baseline_id,
        )
        if outcome is not None:
            outcome.accepted = True
            outcome.retries_before_accept = 0
            outcome.crm_short_circuit = short_circuit

        # Dual-narrative on the Decision: each scope's text goes to its
        # named slot (the LLM prompt template already has matching
        # ``narrative_cloud`` / ``narrative_on_prem`` fields). For a
        # single-scope CRM we mirror the existing legacy behavior — see
        # the per-responsibility comment below for back-compat rationale.
        if cloud_r and onprem_r:
            narrative_cloud_out: str | None = cloud_narr_text
            narrative_on_prem_out: str | None = onprem_narr_text
        elif cloud_r:
            # Legacy single-cloud behavior: provider/inherited → cloud slot;
            # not_applicable → on-prem slot (treated as system-scope NA).
            if cloud_r in ("provider", "inherited"):
                narrative_cloud_out = narrative
                narrative_on_prem_out = None
            else:  # not_applicable
                narrative_cloud_out = None
                narrative_on_prem_out = narrative
        else:
            # On-prem-only CRM — narrative belongs on the on-prem slot.
            narrative_cloud_out = None
            narrative_on_prem_out = narrative

        # ------------------------------------------------------------------
        # Finding #20 — route the CRM narrative through the SAME validator
        # gate the LLM-accept path uses. The CRM is authoritative on the
        # VERDICT (status is never touched here); the gate only guarantees
        # the narrative is well-formed and classifies as the class the
        # verdict implies, so col Q can't ship an unclassifiable line.
        # ------------------------------------------------------------------
        gate = validator.validate(
            proposed_status=status,
            proposed_narrative=narrative,
        )
        if not gate.ok:
            # Adapter: prepend a deterministic, classifiable lead-in keyed on
            # the (authoritative) verdict and re-validate. Preserves the
            # customer's verbatim words while giving the classifier a phrase
            # it can anchor on. Lead-ins use LITERAL validator phrases
            # ("confirmed via" -> COMPLIANCE_AFFIRMING; "control is not
            # applicable" -> NA_JUSTIFYING) so this never leans on the
            # embedding fallback.
            _CRM_VALIDATION_LEAD_IN = {
                ComplianceStatus.COMPLIANT: (
                    "Control objective is confirmed via the inherited "
                    "authorization documented in the CRM overlay."
                ),
                ComplianceStatus.NOT_APPLICABLE: (
                    "Control is not applicable to the customer for this scope "
                    "per the CRM overlay."
                ),
            }
            lead_in = _CRM_VALIDATION_LEAD_IN.get(status)
            composed = f"{lead_in} {narrative}" if lead_in else narrative
            gate2 = (
                validator.validate(
                    proposed_status=status,
                    proposed_narrative=composed,
                )
                if lead_in
                else gate
            )
            if lead_in and gate2.ok:
                # Use the composed text for col Q AND mirror it into whichever
                # per-scope slot currently carries the canonical narrative so
                # the export and the dual-scope fields stay consistent.
                if narrative_cloud_out == narrative:
                    narrative_cloud_out = composed
                if narrative_on_prem_out == narrative:
                    narrative_on_prem_out = composed
                narrative = composed
            else:
                # Verbatim CRM text could not be made classifiable without
                # distorting it (typically a second narrative class collides
                # with the verdict). Precision over recall: abstain and let a
                # human adjudicate rather than ship an ambiguous narrative.
                reason = (
                    "CRM overlay narrative failed the post-rewrite validator "
                    f"gate (classified={gate.classified_as.value}); the "
                    "authoritative CRM verdict could not be paired with a "
                    "classifiable narrative. Reviewer must confirm the wording."
                )
                return self._abstain(
                    row,
                    cci,
                    reason,
                    outcome=outcome,
                    narrative=narrative,
                    supersession_log=supersession_log,
                    notes=[
                        f"CRM overlay short-circuit (cloud={cloud_r or '-'}, "
                        f"on-prem={onprem_r or '-'}); "
                        f"baseline_id={entry.source_baseline_id}.",
                        "Validator gate rejected the CRM narrative; verdict "
                        f"would have been {status.value}.",
                    ],
                )

        source_str = f"crm_{cloud_r or 'na'}"
        if onprem_r and onprem_r != cloud_r:
            source_str += f"+onprem_{onprem_r}"

        return Decision(
            cci_id=cci,
            excel_row=row.excel_row,
            accepted=True,
            status=status,
            narrative=narrative,
            narrative_class=narrative_class,
            source=source_str,
            rule=None,
            retries=0,
            supersession_log=supersession_log,
            crm_short_circuit=short_circuit,
            notes=[
                f"CRM overlay short-circuit (cloud={cloud_r or '-'}, "
                f"on-prem={onprem_r or '-'}); "
                f"baseline_id={entry.source_baseline_id}."
            ],
            narrative_on_prem=narrative_on_prem_out,
            narrative_cloud=narrative_cloud_out,
        )

    def _render_hybrid_block(
        self, entry: CrmEntry, *, onprem_implicit_customer: bool = False
    ) -> str:
        """Markdown block prepended to ``tagged_evidence`` for hybrid / mixed-scope rows.

        The LLM still runs through the normal pipeline (rule #8 already
        declined, so we need a real assessment), but it must scope its
        narrative to the customer-owned half of the responsibility split.

        Dual-scope: when the CRM specifies both cloud and on-prem
        verdicts (and they are not jointly inheritable — that case
        short-circuits before we get here), we name BOTH scopes and any
        CRM narrative the customer supplied for each, so the model can
        attribute its findings to the right deployment scope. Matches
        the prompt template's ``narrative_cloud`` / ``narrative_on_prem``
        output fields in ``llm/prompts/assess_control.md``.

        ``onprem_implicit_customer`` (bug(a)): the CRM specified only an
        inheritable cloud scope, but on-prem evidence is present. The CRM
        is silent on on-prem, so overlay-default-local makes the on-prem
        footprint 100% customer-owned. We synthesize an explicit on-prem
        section so the model assesses the on-prem artifacts locally and
        does NOT treat the cloud inheritance as on-prem implementation
        proof. The cloud verdict is boundary data only.
        """
        cloud_r = entry.responsibility
        onprem_r = entry.responsibility_onprem
        cloud_narr = entry.narrative
        onprem_narr = entry.narrative_onprem

        # Bug(a): cloud-only inheritable CRM + present on-prem evidence.
        # Make the boundary explicit — cloud inheritance covers only the
        # cloud footprint; the on-prem half is customer-owned by default
        # and must be assessed against the artifacts, never credited to
        # the cloud provider's inheritance.
        if onprem_implicit_customer and cloud_r and not onprem_r:
            cloud_text = cloud_narr or (
                f"Cloud scope is {cloud_r} per the CRM; provider-covered. "
                "This is boundary/responsibility data ONLY — it is not "
                "evidence that the on-prem footprint implements the control."
            )
            return (
                "## responsibility_split\n"
                f"control: {entry.control_id}\n"
                "scope: dual (cloud + on-prem)\n"
                f"cloud_responsibility: {cloud_r}\n"
                "customer_narrative_from_crm_cloud: |\n"
                f"  {cloud_text}\n"
                "on_prem_responsibility: customer (default-local — the CRM is "
                "silent on the on-prem scope, so the on-prem footprint is "
                "100% customer-owned)\n"
                "instructions: The cloud scope is inherited/provider-covered — "
                "narrate only that it is covered; do NOT use the cloud "
                "inheritance as proof for the on-prem footprint. ASSESS the "
                "on-prem scope on its own artifacts: if the on-prem artifacts "
                "demonstrate the control, return Compliant for the on-prem "
                "half; if they fall short, Non-Compliant with the specific "
                "on-prem gap. Use the prompt's narrative_cloud and "
                "narrative_on_prem output fields to keep the two scopes "
                "separate. Cite the CRM overlay only as the source of the "
                "responsibility split, not as on-prem implementation evidence."
            )

        # Helper: format one scope's line if specified, else empty string.
        def _scope_line(label: str, r: str | None, narr: str | None) -> str:
            if not r:
                return ""
            narr_text = narr or (
                f"No customer-side narrative supplied in the CRM for the "
                f"{label} scope; infer the customer half from the "
                "implementation guidance and the row's Implementation "
                "Narrative (col F)."
            )
            return (
                f"{label}_responsibility: {r}\n"
                f"customer_narrative_from_crm_{label}: |\n"
                f"  {narr_text}\n"
            )

        # Backward-compat: if only one scope is specified (legacy
        # single-column CRM with "hybrid"), still emit the original
        # generic line so prompt templates that key on the legacy
        # ``customer_narrative_from_crm:`` field continue to work.
        if cloud_r and not onprem_r:
            customer_text = cloud_narr or (
                "No customer-side narrative supplied in the CRM; infer the "
                "customer half from the implementation guidance and the row's "
                "Implementation Narrative (col F)."
            )
            return (
                "## responsibility_split\n"
                f"control: {entry.control_id}\n"
                f"responsibility: {cloud_r} (shared between customer and provider)\n"
                "customer_narrative_from_crm: |\n"
                f"  {customer_text}\n"
                "instructions: Assess ONLY the customer-owned portion. Do not "
                "narrate provider-side implementation. If the customer half is "
                "fully implemented per the artifacts, return Compliant; if not, "
                "Non-Compliant with the specific customer-side gap. Cite the CRM "
                "overlay as the source of the responsibility split."
            )

        # Dual-scope (or on-prem-only) hybrid/mixed.
        cloud_section = _scope_line("cloud", cloud_r, cloud_narr)
        onprem_section = _scope_line("on_prem", onprem_r, onprem_narr)
        return (
            "## responsibility_split\n"
            f"control: {entry.control_id}\n"
            "scope: dual (cloud + on-prem) — see per-scope lines below\n"
            f"{cloud_section}"
            f"{onprem_section}"
            "instructions: Assess ONLY the customer-owned portion of EACH "
            "scope listed. When a scope is provider/inherited/NA, narrate "
            "only that it is covered; do not assess implementation. When a "
            "scope is customer or hybrid, assess that scope's artifacts. "
            "Use the prompt's narrative_cloud and narrative_on_prem output "
            "fields to keep the two scopes' findings separate. Cite the CRM "
            "overlay as the source of the responsibility split."
        )

    def _render_hybrid_block_from_slices(
        self, control_id: str, slices: list[ImplementationSlice]
    ) -> str:
        """Slice-aware responsibility-split block for multi-scope_label CRMs.

        Used when two or more CRMs cover the same control under different
        scope_labels and at least one slice is customer-owned (the masking
        case the entry-based :meth:`_render_hybrid_block` cannot see, since
        ``CrmEntry`` keeps only the latest attach). Enumerates EVERY slice —
        cloud platforms first, the synthesized On-Premises slice last, the
        order ``crm_context.build_crm_context`` already guarantees — so the
        LLM assesses each boundary independently and emits one finding per
        scope. Inheritable scopes (provider/inherited/not_applicable) are
        named as covered but explicitly must NOT serve as implementation
        proof for any customer-owned scope.
        """
        lines = [
            "## responsibility_split",
            f"control: {control_id}",
            (
                "scope: multi (per-scope lines below; cloud platforms first, "
                "On-Premises last)"
            ),
        ]
        for sl in slices:
            narr = sl.narrative or (
                "No customer-side narrative supplied in the CRM for the "
                f"{sl.scope_label} scope; infer the customer half from the "
                "implementation guidance and the row's Implementation "
                "Narrative (col F)."
            )
            lines.append(f"- scope_label: {sl.scope_label}")
            lines.append(f"  responsibility: {sl.responsibility}")
            lines.append("  customer_narrative_from_crm: |")
            lines.append(f"    {narr}")
        lines.append(
            "instructions: Assess ONLY the customer-owned portion of EACH "
            "scope listed. When a scope is provider/inherited/not_applicable, "
            "narrate only that it is covered and do NOT use that inheritance "
            "as proof for any customer-owned scope. When a scope is customer "
            "or hybrid, assess that scope's artifacts on their own merits. "
            "Produce one finding per scope, keeping cloud platforms first and "
            "On-Premises last, using the prompt's per-scope narrative output "
            "fields. Cite the CRM overlay only as the source of the "
            "responsibility split, never as implementation evidence."
        )
        return "\n".join(lines)

    def _initial_corrective_context(self, auto: rules.AutoStatusResult) -> str | None:
        """Hand the LLM the rule-engine's hint so it doesn't have to
        re-derive what we already determined.

        For UNCLEAR_8C, the hint tells the LLM the narrative has bare
        "inherited from" with no source — so it knows to ask before
        guessing internal vs external (the plugin's hard rule).
        """
        if auto.verdict == rules.AutoStatusVerdict.UNCLEAR_8C:
            return (
                f"Rule #8c triggered: col {auto.trigger_column} says "
                f'"{auto.trigger_phrase}" but does not name the inheritance source. '
                "Do NOT default to Compliant or Not Applicable — the narrative "
                "must either name the internal source (8a → Compliant) or the "
                "external CSP and confirm zero local responsibility (8b → Not "
                "Applicable). If the row data does not support either, return "
                "status=Non-Compliant with a gap-describing narrative that "
                "explains the missing source attribution."
            )
        return None

    def _build_corrective_context(
        self,
        *,
        row: CcisRow,
        auto: rules.AutoStatusResult,
        rejections: list[tuple[validator.RejectionReason, str]],
        last_status: ComplianceStatus,
        last_narrative: str,
    ) -> str:
        """Turn the validator's rejection list into a prompt fragment the
        LLM can act on. Each rejection contributes its reason + message;
        the orchestrator also pins the current rule-#8 hint so the LLM
        doesn't drift back into the same failure mode.
        """
        parts: list[str] = []
        parts.append(
            "Your previous proposal was rejected by the deterministic validator "
            "(SKILL.md rule #11). Address EACH issue below before retrying."
        )
        for i, (reason, msg) in enumerate(rejections, start=1):
            parts.append(f"{i}. [{reason.value}] {msg}")
        parts.append(
            f'Previous proposal: status={last_status.value!r}, narrative='
            f'"""{last_narrative}"""'
        )
        if auto.verdict == rules.AutoStatusVerdict.UNCLEAR_8C:
            parts.append(
                "Reminder: rule #8c is still in effect — name the inheritance "
                "source explicitly or escalate as Non-Compliant."
            )
        return "\n".join(parts)
