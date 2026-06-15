"""Accuracy instrumentation for the assessment pipeline.

PURPOSE
-------
v0.1 patent kernel is accuracy, not cost. Every claim in the patent
application needs to be backed by concrete numbers recorded under controlled
conditions. This module owns that recordkeeping. It is intentionally
separated from the LLM client and rules engine so the measurements remain a
first-class, auditable artifact rather than a side effect of inference.

What we measure, and why each number matters for the patent:

1. **Validator rejections, by typed class.** Every time the deterministic
   post-validator (rules #8a/#8b/#11) rejects an LLM output and forces a
   retry, we log the rejection class, the original output, and the corrective
   context. The reduction in requirement-restatement rate (vs. an
   uninstrumented baseline run) is the core accuracy claim.

2. **Supersession-map hits.** Every time the LLM cites a stale USD document
   number and the supersession map redirects it to the current authoritative
   document, we record the (stale, current, control) triple. This is direct
   evidence of an accuracy improvement that a vanilla LLM cannot make.

3. **Retry-to-acceptance ratio.** How many corrective retries on average
   before the LLM produces a validator-passing output. A small, bounded
   number proves the corrective-context loop converges rather than oscillates.

4. **Operational telemetry (non-patent).** Token counts and dollar cost are
   still recorded so the user sees what each run costs, but they are not
   load-bearing for any patent claim and we make no comparative baseline
   here. The cost-reduction kernel is deferred to a later version.

All measurements are append-only and tied to a single AssessmentRun row so the
audit trail per patent-cited datapoint is one SQL query away.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from sqlmodel import Session

from ..llm.pricing import compute_cost
from ..models import AssessmentRun, CalibrationEntry

RejectionClass = Literal[
    "requirement_restatement",  # rule #11 -- output parrots col I/J/K
    "status_narrative_mismatch",  # rule #11 -- COMPLIANT narrative w/ NA verdict, etc.
    "missing_inheritance_marker",  # rule #8a/b -- claims inheritance without naming source
    "unsupported_doc_citation",  # cites a doc not in evidence index or supersession map
    "format_violation",  # output doesn't conform to expected schema
    # v0.2 hardening additions. Parity contract: every RejectionReason.value
    # in validator.py MUST appear here verbatim; test_validator.py enforces
    # this via test_rejection_reason_values_match_measurement_class.
    "dual_narrative_mislabel",  # on-prem half leaks provider language, or CRM mismatch
    "future_tense_compliance",  # "will be configured" + Compliant -- POA&M shaped as Compliant
    # v0.3 -- STIG-finding corroboration gate. Compliant verdict cites a
    # STIG rule (SV-#####r#_rule) but row has no non-scan corroborator
    # (policy / SSP / baseline / config doc). Scan-only evidence proves
    # one host was configured correctly at scan time; it does not prove
    # the control is implemented by policy or design. Source:
    # feedback_corroborate_stig_findings.md.
    "uncorroborated_stig_pass",
    # bug(c) 2026-06-10 -- narrative cites the eMASS workbook col-K assessment
    # procedures (the DISA examine/interview/test verification instructions)
    # as though they were an evidence artifact. They tell the assessor HOW to
    # verify; they are never the proof. Same audit-traceability failure as a
    # hallucinated doc cite. Detected by validator._ASSESSMENT_PROCEDURE_AS_SOURCE_RE.
    "assessment_procedure_as_source",
    # fix #1 2026-06-10 -- audit-v1 source_quote hard gate. A structured audit
    # citation's verbatim source_quote does not appear (case-insensitive,
    # whitespace-normalized) in the row's tagged evidence -- the model
    # fabricated a supporting quote. Distinct from unsupported_doc_citation
    # (doc names in free narrative); this checks the quote contents in the
    # structured audit-citation payload.
    "unsupported_quote",
]


@dataclass
class ValidatorRejection:
    cci: str
    rejection_class: RejectionClass
    original_output: str
    corrective_context: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SupersessionHit:
    """Recorded when the supersession map rescues a stale doc reference.

    `stale_ref` is what the LLM (or a prior assessment) cited; `current_ref`
    is what it was rewritten to. `source` distinguishes redirects we caught
    in LLM output ("llm") from redirects applied to historical narratives
    pulled from column U ("col_u_carryover").
    """

    cci: str
    stale_ref: str
    current_ref: str
    source: Literal[
        "llm",
        "col_u_carryover",
        "user_input",
        "crm_overlay",
        "sda_verified_mapping",
        "evidence_chain",
    ]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CrmShortCircuit:
    """Recorded when a CRM overlay short-circuits an assessment (no LLM call).

    Emitted by ``Assessor._finalize_crm_decision`` whenever a CRM
    responsibility of provider / inherited / not_applicable bypasses the
    LLM. The route handler persists these as ``CrmShortCircuitEvent``
    rows linked to a ``CrmSuspicionLog`` so the suspicion banner can
    answer "how many LLM calls did this CRM avoid?" — a key input to the
    operator's trust calculus when a CRM scores high on the suspicion
    heuristics.

    ``baseline_id`` ties back to the CRM baseline the entry came from so
    the route handler can group events under the correct overlay when
    multiple CRMs are attached to a workbook.
    """

    cci: str
    control_id: str
    responsibility: Literal["provider", "inherited", "not_applicable"]
    baseline_id: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RuleShortCircuit:
    """Recorded when a rule #8a/#8b deterministic verdict short-circuits
    the LLM path.

    Emitted by ``Assessor._finalize_rule_decision`` whenever the rules
    engine returns ``COMPLIANT_8A`` or ``NOT_APPLICABLE_8B``. Aggregated
    onto ``AssessmentRun.rule_8a_short_circuits`` /
    ``rule_8b_short_circuits`` so the operator can answer "how many LLM
    calls did the deterministic pre-filter avoid?" — the operational
    proof that the patent's rule-#8 layer is paying for itself.

    ``trigger_phrase`` and ``trigger_column`` mirror the same fields on
    ``rules.AutoStatusResult`` so a future audit can reconstruct exactly
    which col-J/K/L cell text fired the short-circuit. They are the
    deterministic equivalent of the LLM's ``stated_confidence``
    explanation — what the model would have had to explain, the rule
    proved structurally.

    Unlike ``CrmShortCircuit``, there is no per-event DB table for
    rule fires — Rule #8 is a pure function of row text, so an
    adversarial-audit query (the reason CrmShortCircuitEvent exists)
    has no equivalent failure mode here. Aggregate counters on
    ``AssessmentRun`` plus the per-outcome dataclass field are
    sufficient evidence.
    """

    cci: str
    rule: Literal["8a", "8b"]
    trigger_phrase: str
    trigger_column: Literal["J", "K", "L"]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CciOutcome:
    """Per-CCI result after the LLM + validator + supersession pass."""

    cci: str
    retries_before_accept: int = 0
    rejections: list[ValidatorRejection] = field(default_factory=list)
    supersession_hits: list[SupersessionHit] = field(default_factory=list)
    # At most one per CCI — short-circuits are mutually exclusive with
    # the LLM path. None when the row went through rule #8, the LLM, or
    # an unresolved escalation. Set when CRM responsibility was
    # provider / inherited / not_applicable.
    crm_short_circuit: CrmShortCircuit | None = None
    # At most one per CCI — set when rules.classify_row returned
    # COMPLIANT_8A or NOT_APPLICABLE_8B and ``_finalize_rule_decision``
    # accepted the templated narrative. Mutually exclusive with both
    # ``crm_short_circuit`` and the LLM path (rule #8 fires first in
    # Assessor._run; CRM short-circuit checks the rule outcome before
    # firing). Rolled up to AssessmentRun.rule_8a_short_circuits /
    # rule_8b_short_circuits in ``_apply_aggregates``.
    rule_short_circuit: RuleShortCircuit | None = None
    accepted: bool = False
    # v0.2 precision-over-recall flags. ``abstained`` is set True by the
    # assessor whenever the row gets written with ``needs_review=True``
    # (validator-exhausted, llm-parse-error, llm-abstain, dual-pass mismatch,
    # low-confidence, unverified-cites, stale-reference, boundary-conflict).
    # ``dual_pass_disagreement`` is the subset where the two passes returned
    # incompatible statuses — feeds the run-level counter used to monitor
    # whether the dual-pass gate is paying for itself.
    abstained: bool = False
    dual_pass_disagreement: bool = False
    # v0.2 citation-hygiene counter (NOT an abstain). Set True when the row
    # landed on a trusted verdict but the supersession catch-net flagged
    # stale doc cites OR the NA verdict was traced to a retired SSAA-era
    # citation. Rolled up to AssessmentRun.rewrites_requested so reviewers
    # can size the citation-refresh backlog without per-row queries.
    # Tracked separately from abstained because the reviewer workflow is
    # different — abstain = re-verify the verdict, rewrite-requested =
    # update the narrative citation in the next pass.
    rewrite_requested: bool = False
    # v0.2 decision-cache hit flag. Set True by ``Assessor._run`` when a
    # fingerprint lookup served the Decision from ``DecisionCache`` instead
    # of burning an LLM call. Mutually exclusive with retries/rejections
    # (cache hits return before the LLM path runs) — token counts on a
    # cache-hit outcome stay at zero, which is exactly the cost-claim
    # evidence the operator panel needs. Aggregated into
    # ``AssessmentRun.cache_hits`` by ``_apply_aggregates``.
    cache_hit: bool = False
    # Operational only — ``input_tokens`` is base (non-cache) input only;
    # cache reads are tracked separately so the pricing module can apply
    # the cache-read rate (~10% of base input) instead of treating them as
    # full-price input tokens.
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    # v0.2 calibration telemetry. Populated only when the verdict was
    # informed by an LLM proposal (LLM accept, LLM-derived abstain,
    # CRM-hybrid). Rule-based short-circuits (8a/8b/SDA 8c/CRM provider/
    # inherited/NA/no-llm-client abstain) leave these as None, and that
    # None is the signal ``_commit_outcome`` reads to skip writing a
    # ``CalibrationEntry``. ``stated_confidence`` is the LLM's self-reported
    # 0..1 score the calibration math grades against the reviewer accept
    # signal. ``fingerprint`` ties the entry back to the DecisionCache row
    # that produced (or would have produced) the verdict, so a future cache
    # replay can project the reviewer signal onto the replayed row. See
    # ``engine/calibration.py`` for the scoring contract.
    stated_confidence: float | None = None
    proposed_status: str | None = None
    final_status: str | None = None
    fingerprint: str | None = None


class RunRecorder:
    """Collects accuracy measurements for one AssessmentRun and flushes to SQLite.

    Usage:
        rec = RunRecorder.start(session, workbook_id=42)
        with rec.cci("CCI-000015") as o:
            o.retries_before_accept = 1
            o.rejections.append(ValidatorRejection(
                cci="CCI-000015",
                rejection_class="requirement_restatement",
                original_output="...",
                corrective_context="...",
            ))
            o.supersession_hits.append(SupersessionHit(
                cci="CCI-000015",
                stale_ref="USD00050010",
                current_ref="Example System Account Management Plan",
                source="col_u_carryover",
            ))
            o.accepted = True
            o.input_tokens = 1200
            o.output_tokens = 280
        rec.finish(cost_usd=0.0182)
    """

    def __init__(
        self,
        session: Session,
        run: AssessmentRun,
        *,
        model_id: str | None = None,
        session_lock: threading.Lock | None = None,
    ) -> None:
        self._session = session
        self._run = run
        # Active model id for incremental per-call pricing. When None
        # (callers/tests that don't supply one) the incremental cost flush
        # is skipped and ``finish(cost_usd=...)`` remains the sole writer —
        # preserving the prior behavior for cost-agnostic callers.
        self._model_id = model_id
        self._outcomes: list[CciOutcome] = []
        # v0.2 parallelization: the assess-batch route fans out per-CCI
        # ``Assessor.assess`` calls across a ThreadPoolExecutor so the LLM
        # I/O wait overlaps. Each worker thread enters ``rec.cci(...)`` and
        # on exit calls ``_commit_outcome`` which mutates ``_outcomes`` and
        # writes to the shared SQLModel session. Neither is thread-safe, so
        # we serialize the whole telemetry-flush path through one lock.
        # Contention is negligible — commit is millisecond-scale while the
        # LLM call (the part actually running in parallel) is 5-30s.
        #
        # ``session_lock`` is the shared-session bug fix: when the route
        # plumbs ``Assessor`` and ``RunRecorder`` against the SAME SQLModel
        # session, the route passes ``assessor.session_lock`` here so both
        # owners serialize through one lock. Without this, the Assessor's
        # ``_cache_lock`` and RunRecorder's internal lock are independent —
        # a thread mid-``session.get()`` under ``_cache_lock`` races a
        # thread mid-``session.commit()`` under the recorder lock, and
        # SQLAlchemy raises ``InvalidRequestError: This session is in
        # 'prepared' state`` on the next autoflush. Sharing the lock is
        # cheaper than per-thread sessions and keeps the kernel session-
        # free for tests that don't supply ``session_lock``.
        self._lock = session_lock if session_lock is not None else threading.Lock()

    @classmethod
    def start(
        cls,
        session: Session,
        *,
        workbook_id: int | None = None,
        notes: str | None = None,
        model_id: str | None = None,
        session_lock: threading.Lock | None = None,
    ) -> RunRecorder:
        run = AssessmentRun(
            workbook_id=workbook_id,
            started_at=datetime.now(timezone.utc),
            notes=notes,
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        return cls(session, run, model_id=model_id, session_lock=session_lock)

    @property
    def run_id(self) -> int | None:
        return self._run.id

    def cci(self, cci: str) -> _CciCtx:
        return _CciCtx(self, cci)

    def _commit_outcome(self, outcome: CciOutcome) -> None:
        # Lock the entire flush — ``_outcomes.append`` + aggregate recompute
        # + session.commit must be atomic under the parallel assess-batch
        # fan-out. See ``__init__`` for the rationale; without this lock the
        # session writes interleave and SQLModel raises.
        with self._lock:
            self._outcomes.append(outcome)
            # Flush partial aggregates after each CCI so the Runs page surfaces
            # live progress instead of staying at zeros until ``finish()`` fires
            # (which can be 25+ minutes for a full 300-CCI batch). When the
            # recorder was started with the active ``model_id`` it also reprices
            # ``cost_usd`` from the running token totals here, so in-progress
            # runs show non-zero cost instead of $0 until finish.
            self._apply_aggregates()
            try:
                self._session.add(self._run)
                self._session.commit()
            except Exception:
                # Don't let a telemetry-flush hiccup take down the assessment
                # run. The next CCI's commit (or ``finish()``) will catch up.
                self._session.rollback()
            # Calibration telemetry — only LLM-informed rows. Rule-based
            # short-circuits (8a/8b/SDA 8c/CRM provider/inherited/NA/
            # no-llm-client abstain) leave ``stated_confidence`` as None.
            # We isolate the calibration write in its own try/except so a
            # telemetry-flush hiccup doesn't take down the assessment run,
            # matching the run-row flush above.
            if (
                outcome.stated_confidence is not None
                and self._run.id is not None
            ):
                try:
                    entry = CalibrationEntry(
                        run_id=self._run.id,
                        cci_id=outcome.cci,
                        fingerprint=outcome.fingerprint or "",
                        stated_confidence=outcome.stated_confidence,
                        proposed_status=outcome.proposed_status or "",
                        final_status=outcome.final_status or "",
                        abstained=outcome.abstained,
                        rewrite_requested=outcome.rewrite_requested,
                        recorded_at=datetime.now(timezone.utc),
                    )
                    self._session.add(entry)
                    self._session.commit()
                except Exception:
                    self._session.rollback()

    @property
    def outcomes(self) -> list[CciOutcome]:
        """Read-only view of per-CCI outcomes for callers that need to
        persist beyond the AssessmentRun aggregates (e.g., the route
        handler writing CrmShortCircuitEvent rows after a batch run).
        """
        return list(self._outcomes)

    def _apply_aggregates(self) -> None:
        """Write per-CCI aggregates onto the run row. Shared by the
        incremental flush in ``_commit_outcome`` and the final flush in
        ``finish``. Does NOT touch ``finished_at`` — that is owned by
        ``finish``.

        When a ``model_id`` was supplied at ``start``, ``cost_usd`` is
        recomputed from the accumulated token totals on every flush so the
        Runs page shows non-zero cost on in-progress runs (the prior
        behavior priced cost only in ``finish``, leaving stuck in-progress
        runs at $0 despite hundreds of LLM calls). Without a ``model_id``,
        cost stays owned by ``finish(cost_usd=...)``.
        """
        total_in = sum(o.input_tokens for o in self._outcomes)
        total_out = sum(o.output_tokens for o in self._outcomes)
        total_cache_read = sum(o.cache_read_tokens for o in self._outcomes)
        total_rejections = sum(len(o.rejections) for o in self._outcomes)
        total_retries = sum(o.retries_before_accept for o in self._outcomes)
        total_supersession_hits = sum(len(o.supersession_hits) for o in self._outcomes)
        accepted = sum(1 for o in self._outcomes if o.accepted)
        abstained = sum(1 for o in self._outcomes if o.abstained)
        dual_pass_disagreements = sum(
            1 for o in self._outcomes if o.dual_pass_disagreement
        )
        rewrites_requested = sum(
            1 for o in self._outcomes if o.rewrite_requested
        )
        cache_hits = sum(1 for o in self._outcomes if o.cache_hit)
        rule_8a_short_circuits = sum(
            1
            for o in self._outcomes
            if o.rule_short_circuit is not None and o.rule_short_circuit.rule == "8a"
        )
        rule_8b_short_circuits = sum(
            1
            for o in self._outcomes
            if o.rule_short_circuit is not None and o.rule_short_circuit.rule == "8b"
        )
        # v0.2 — CRM short-circuit count. Third member of the kernel-skip
        # cohort alongside rule_8a/8b. Sentinel: ``crm_short_circuit`` is
        # set on CciOutcome only when the assessor took the provider/
        # inherited/not_applicable branch; customer/hybrid leave it None.
        crm_short_circuit_count = sum(
            1 for o in self._outcomes if o.crm_short_circuit is not None
        )

        # v0.2 — per-class rejection breakdown. Built fresh each flush so
        # incremental partial-aggregate writes match the final breakdown
        # exactly; cost is O(rejections) per CCI commit, negligible vs.
        # the LLM call we're aggregating around.
        rejections_by_class: dict[str, int] = {}
        for o in self._outcomes:
            for rej in o.rejections:
                rejections_by_class[rej.rejection_class] = (
                    rejections_by_class.get(rej.rejection_class, 0) + 1
                )

        self._run.llm_calls = len(self._outcomes)
        self._run.llm_input_tokens = total_in
        self._run.llm_output_tokens = total_out
        self._run.llm_cache_read_tokens = total_cache_read
        self._run.retry_count = total_retries
        self._run.validator_rejections = total_rejections
        self._run.supersession_hits = total_supersession_hits
        self._run.ccis_accepted = accepted
        self._run.abstained = abstained
        self._run.dual_pass_disagreements = dual_pass_disagreements
        self._run.rewrites_requested = rewrites_requested
        self._run.cache_hits = cache_hits
        self._run.rule_8a_short_circuits = rule_8a_short_circuits
        self._run.rule_8b_short_circuits = rule_8b_short_circuits
        self._run.crm_short_circuit_count = crm_short_circuit_count
        # Invariant: sum(per-class) == total. Tested in
        # test_measurement_properties.test_validator_rejection_breakdown_*
        self._run.validator_rejections_by_class = rejections_by_class

        # Incremental cost — same token-split convention the route's
        # final ``compute_cost`` uses (base input excludes cache reads).
        # Only when the recorder was told the active model; otherwise the
        # route's ``finish(cost_usd=...)`` remains the sole cost writer.
        if self._model_id is not None:
            self._run.cost_usd = compute_cost(
                self._model_id,
                input_tokens=total_in,
                output_tokens=total_out,
                cache_read_tokens=total_cache_read,
            )

    def finish(self, *, cost_usd: float | None = None) -> AssessmentRun:
        """Aggregate CCI-level measurements onto the AssessmentRun row.

        Holds the same lock as ``_commit_outcome`` — callers may invoke
        ``finish`` from the route thread while worker threads from the
        parallel batch fan-out are still trying to flush their final
        outcomes. Without the lock the two paths race on the session.
        """
        with self._lock:
            self._apply_aggregates()
            self._run.finished_at = datetime.now(timezone.utc)
            if cost_usd is not None:
                self._run.cost_usd = cost_usd

            self._session.add(self._run)
            self._session.commit()
            self._session.refresh(self._run)
            return self._run


class _CciCtx:
    def __init__(self, parent: RunRecorder, cci: str) -> None:
        self._parent = parent
        self._outcome = CciOutcome(cci=cci)

    def __enter__(self) -> CciOutcome:
        return self._outcome

    def __exit__(self, exc_type, exc, tb) -> None:
        self._parent._commit_outcome(self._outcome)
