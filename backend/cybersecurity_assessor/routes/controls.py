"""Per-control assessment endpoints (status, narrative, apply-to-workbook)."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlmodel import Session, delete, select

from ..config import load_config
from ..db import get_session
from . import _batch_progress
from ..engine import validator as v
from ..engine.assessor import Assessor, stitch_scope_narrative
from ..engine.crm_context import build_crm_context
from ..engine.evidence_bundle import EvidenceBlock
from ..engine.impl_persistence import persist_assessment_with_impls
from ..system_context import build_boundary_brief
from ..engine.inputs import (
    _is_coverage_control,
    build_evidence_block as _build_evidence_block,
)
from ..engine.measurement import CciOutcome, RunRecorder
from ..engine.override_epoch import bump_override_epoch, get_override_epoch
from ..excel import ccis_writer
from ..excel.ccis_reader import read_workbook_index
from ..excel.working_copy import get_or_create_working_copy
from ..llm.client import (
    MissingApiKeyError,
    _load_system_prompt,
    active_model_id,
    make_client,
)
from ..llm.pricing import compute_cost
from ..controls.odp_render import fetch_odp_history, resolve_odps
from ..models import (
    Assessment,
    AssessmentImplementation,
    AssessmentCitation,
    AssessmentEvidenceShown,
    AssessmentTrace,
    Baseline,
    BaselineControl,
    BaselineObjective,
    ComplianceStatus,
    Control,
    CrmShortCircuitEvent,
    CrmSuspicionLog,
    Evidence,
    Framework,
    NarrativeClass,
    Objective,
    Poam,
    PoamEvidence,
    PoamMilestone,
    PoamObjective,
    PromptSnapshot,
    RequirementMap,
    RequirementSource,
    VerdictSource,
    Workbook,
    _utcnow,
    iso_utc,
)
# Placeholder narrative for a hard abstain (status=None, narrative=None).
# Schema requires narrative_q NOT NULL (models.py:752), so the write site
# coerces blank narratives to this constant. Reviewer queue surfaces the
# row via needs_review=True; the placeholder is what they see in column Q
# until they edit the cell or accept the kernel's review_reason.
_ABSTAIN_NARRATIVE_PLACEHOLDER = "(abstain — pending human review)"


def _coerce_abstain_persistence_fields(
    decision,
) -> tuple[ComplianceStatus, str]:
    """Resolve (status, narrative_q) for an abstain row at the write site.

    The kernel's ``_abstain_decision`` contract
    (engine/assessor.py:1303-1308) says abstain rows must be persisted
    with ``needs_review=True`` so the reviewer can see what the assessor
    failed on. Schema requires NOT NULL status + narrative_q
    (models.py:749, 752), so a hard abstain (status=None, narrative=None)
    needs coercion at the write boundary — otherwise the row gets silently
    dropped by a ``status is not None and narrative`` gate and the
    reviewer never sees it (the original CCI-002124 / CCI-002127 bug,
    feedback_abstain_status_none_drops.md).

    Convention pinned by models.py:741-748: "NON_COMPLIANT for parse
    errors" — same posture here. A coerced verdict resting on
    needs_review=True is non-committal in the eyes of every export gate
    (ccis_writer, poam.exporter, controls/exporter); the reviewer is the
    only consumer that sees the placeholder and is expected to overwrite
    it. Narrative falls back to review_reason (already populated by every
    ``_abstain_decision`` call) and finally to a constant placeholder so
    the cell is never empty.

    Single source of truth for both Assessment-write sites in this
    module — same shape as ``_decision_to_verdict_source``. Soft abstains
    (kernel emitted a proposal but set needs_review=True) pass through
    untouched because both fields are already populated.
    """
    status = (
        decision.status
        if decision.status is not None
        else ComplianceStatus.NON_COMPLIANT
    )
    narrative = (
        decision.narrative
        or decision.review_reason
        or _ABSTAIN_NARRATIVE_PLACEHOLDER
    )
    # Multi-boundary presentation: when the kernel produced a per-scope
    # narrative map (≥2 customer-owned scopes), persist the canonical
    # column-Q cell as one labeled block (`AWS GovCloud:\n\n…\n\nOn-Premises:
    # \n\n…`) so the reviewer reading the eMASS cell / GUI sees which boundary
    # each statement covers. This is visual / save-time ONLY — classification
    # and validation already ran on the single ``decision.narrative`` upstream
    # (the "not logically" half of the contract). Single-boundary rows have
    # <2 scopes, ``stitch_scope_narrative`` returns None, and we keep the
    # plain narrative.
    narrative = stitch_scope_narrative(
        getattr(decision, "narratives_by_scope", None)
    ) or narrative
    return status, narrative


def _decision_to_verdict_source(decision) -> VerdictSource:
    """Map a kernel ``Decision`` to the persisted ``VerdictSource`` enum.

    Single source of truth for both Assessment-write sites in this module
    (single-control endpoint + batch endpoint). Order matters:

    1. ``cache_source == "cache_hit"`` wins first — a replayed Decision
       keeps its original ``source`` string ("llm", "crm_provider", …)
       for downstream telemetry, but the persisted row records the cache
       provenance so cost / re-use queries don't double-count cache hits
       as fresh LLM calls.
    2. ``needs_review`` wins next — every abstain path (validator-exhausted,
       LLM-parse-error, no-llm-client, dual-pass-mismatch, low-confidence,
       unverified-cites, stale-reference, boundary-conflict) maps to
       ``ABSTAIN`` regardless of the underlying source string.
    3. Otherwise dispatch on ``Decision.source``. The CRM family is
       matched by string prefix because hybrid scopes append an
       ``+onprem_*`` suffix that we collapse to ``CRM_HYBRID_MIXED``.
    4. Unknown source string returns ``ABSTAIN`` as a safety net so a
       new kernel emission site without a matching enum value at least
       routes the row to the reviewer queue rather than silently mis-tagging.
    """
    if getattr(decision, "cache_source", None) == "cache_hit":
        return VerdictSource.CACHE_HIT
    if getattr(decision, "needs_review", False):
        return VerdictSource.ABSTAIN
    src = decision.source or ""
    if src == "rule_8a":
        return VerdictSource.RULE_8A
    if src == "rule_8b":
        return VerdictSource.RULE_8B
    if src == "rule-8c":
        return VerdictSource.RULE_8C
    if src == "rule_no_evidence":
        return VerdictSource.RULE_NO_EVIDENCE
    if src == "llm":
        return VerdictSource.LLM_ACCEPT
    if src == "llm_after_retry":
        return VerdictSource.LLM_AFTER_RETRY
    if src.startswith("crm_"):
        # Hybrid: source carries a "+onprem_*" suffix when the two
        # scopes have different verdicts; collapse to a single bucket.
        if "+onprem_" in src:
            return VerdictSource.CRM_HYBRID_MIXED
        if src == "crm_provider":
            return VerdictSource.CRM_PROVIDER
        if src == "crm_inherited":
            return VerdictSource.CRM_INHERITED
        if src == "crm_not_applicable":
            return VerdictSource.CRM_NOT_APPLICABLE
        # Unknown crm_* variant — route to hybrid as the safe catch-all
        # (matches the "mixed / not jointly inheritable" semantics).
        return VerdictSource.CRM_HYBRID_MIXED
    # Safety net: unknown source string. The persisted row still gets
    # written but lands in the reviewer queue rather than silently
    # being mis-tagged as one of the trusted-kernel buckets.
    return VerdictSource.ABSTAIN


def _persist_crm_short_circuits(
    session: Session,
    *,
    workbook_id: int,
    outcomes: Iterable[CciOutcome],
) -> int:
    """Write a ``CrmShortCircuitEvent`` row for every outcome whose kernel
    decision was short-circuited by the CRM (provider / inherited /
    not_applicable). Resolves the latest ``CrmSuspicionLog`` for the
    ``(workbook, crm_baseline)`` pair so the event links back to the
    suspicion banner the assessor saw at decision time — nullable when no
    suspicion log exists yet (forward-only audit trail).

    The producer half lives in ``Assessor._finalize_crm_decision`` — it
    attaches a ``CrmShortCircuit`` dataclass to every ``CciOutcome`` for
    the three short-circuit responsibilities. The dataclass docstring
    pinned this writer as the consumer; until this helper landed, the
    rows were enumerated but never persisted, leaving the audit-trail
    table (and the assessor_marked_false_positive workflow) empty.

    Returns the number of rows added. Caller commits.
    """
    # Cache per-control_id lookups within a single batch — large
    # assess-batch runs touch many CCIs under the same control (one
    # per CCI), and the kernel only emits the control_id string.
    control_pk_cache: dict[str, int | None] = {}

    def _resolve_control_pk(control_id: str) -> int | None:
        if control_id in control_pk_cache:
            return control_pk_cache[control_id]
        pk = session.exec(
            select(Control.id).where(Control.control_id == control_id)
        ).first()
        control_pk_cache[control_id] = pk
        return pk

    # Cache per-baseline_id suspicion lookups too — within a single run
    # every short-circuit on the same CRM points at the same log row.
    suspicion_cache: dict[int, int | None] = {}

    def _resolve_suspicion_log_id(baseline_id: int) -> int | None:
        if baseline_id in suspicion_cache:
            return suspicion_cache[baseline_id]
        log_id = session.exec(
            select(CrmSuspicionLog.id)
            .where(
                CrmSuspicionLog.workbook_id == workbook_id,
                CrmSuspicionLog.crm_baseline_id == baseline_id,
            )
            .order_by(CrmSuspicionLog.computed_at.desc())
        ).first()
        suspicion_cache[baseline_id] = log_id
        return log_id

    written = 0
    for outcome in outcomes:
        sc = outcome.crm_short_circuit
        if sc is None:
            continue
        control_pk = _resolve_control_pk(sc.control_id)
        if control_pk is None:
            # Kernel emitted a short-circuit for a control that isn't in
            # the catalog. Skip — writing with a NULL FK would violate
            # the schema, and surfacing as an exception would mask the
            # actual assessment write. Log so it's visible in tailing.
            _log.warning(
                "CRM short-circuit for unknown control_id=%r (cci=%s) — "
                "no Control row; event skipped",
                sc.control_id,
                sc.cci,
            )
            continue
        session.add(
            CrmShortCircuitEvent(
                workbook_id=workbook_id,
                control_id_fk=control_pk,
                responsibility=sc.responsibility,
                suspicion_log_id=_resolve_suspicion_log_id(sc.baseline_id),
            )
        )
        written += 1
    return written


def _persist_audit_trail(
    session: Session,
    *,
    assessment_id: int,
    decision,
) -> None:
    """Write PromptSnapshot + AssessmentTrace + AssessmentEvidenceShown +
    AssessmentCitation rows for one decided Assessment.

    Idempotent on PromptSnapshot (insert-if-absent on sha256 PK). Caller owns
    the commit boundary — this helper stages rows on ``session`` only so the
    single-control and batch sites can use their existing commit cadence
    (per-row commit vs. one batched commit in ``finally``).

    Short-circuit decisions (rule_8a/8b/8c, CRM, no-llm-client) carry empty
    ``trace_payload`` and ``evidence_shown`` lists; the helper is a no-op in
    that case — exactly the right behavior, since there's no LLM call to
    trace and no per-objective evidence the model "saw".

    Citations are flag-gated upstream (build_user_message only asks for them
    when ``audit_citations_enabled`` is on) and live per-pass on
    TracePayload. We materialize the pass_index=0 set into AssessmentCitation
    rows — pass 0 is the canonical accepted pass in the matching-status
    dual-pass branch; pass 1's citations stay in ``raw_response_json`` for
    forensic replay but don't double-write into the citations table.
    Citations whose ``evidence_id`` doesn't resolve to a captured
    EvidenceShownPayload (model hallucinated an id, or the chunk was
    dropped by truncation) are silently skipped — the trace + raw response
    still record the failed cite for an auditor to inspect.

    Field-name skew: ``TracePayload.model_version`` →
    ``AssessmentTrace.anthropic_model_version``. Mapped explicitly below.

    Re-assess REPLACE-on-id: the single-CCI and batch routes reuse the same
    ``Assessment.id`` when a CCI is re-assessed (UPDATE in place, not
    INSERT). Without cleanup, every re-run would append a fresh set of
    AssessmentTrace + AssessmentEvidenceShown + AssessmentCitation rows
    alongside the prior ones — and the audit endpoint would return the
    union, defeating replay clarity (an auditor would see N runs' worth of
    chunks interleaved). We delete prior child rows here so each
    Assessment.id always carries exactly one run's trace/evidence/citations.
    Order matters: AssessmentCitation FKs AssessmentEvidenceShown, so
    citations go first, then evidence_shown, then traces. PromptSnapshot is
    NOT touched — it's deduped across thousands of assessments via the
    sha256 PK and a single drop here would orphan unrelated rows.
    """
    # Delete prior audit-trail child rows for this Assessment.id (re-assess
    # cleanup). No-op on a freshly-inserted Assessment because the where
    # clause matches zero rows.
    for stale in session.exec(
        select(AssessmentCitation).where(
            AssessmentCitation.assessment_id == assessment_id
        )
    ).all():
        session.delete(stale)
    for stale in session.exec(
        select(AssessmentEvidenceShown).where(
            AssessmentEvidenceShown.assessment_id == assessment_id
        )
    ).all():
        session.delete(stale)
    for stale in session.exec(
        select(AssessmentTrace).where(
            AssessmentTrace.assessment_id == assessment_id
        )
    ).all():
        session.delete(stale)
    # Flush the deletes so subsequent INSERTs against the same FKs don't
    # collide with the (already-removed) parent rows during autoflush
    # ordering. Caller still owns the outer commit.
    session.flush()

    seen_shas: set[str] = set()
    for tp in decision.trace_payload:
        if tp.system_prompt_sha and tp.system_prompt_sha not in seen_shas:
            seen_shas.add(tp.system_prompt_sha)
            # FK-parent guarantee via a connection-level idempotent insert
            # instead of an ORM identity-map probe. In the batch path the
            # shared session is committed mid-run by the decision cache and
            # RunRecorder (expire_on_commit=True), so a prior
            # ``session.get(PromptSnapshot, sha)`` could return a phantom
            # instance whose physical INSERT never landed — the subsequent
            # AssessmentTrace flush then failed the system_prompt_sha FK and
            # tore down the whole batch transaction. INSERT OR IGNORE writes
            # the parent row straight to the connection (no-op on the sha256
            # PK conflict), so the FK target is guaranteed present before any
            # trace flush, regardless of identity-map state.
            # _load_system_prompt is lru_cached — same in-memory text the
            # client used to compute the sha. Cheap repeat call.
            # created_at is a Python-side default_factory (ORM-only); a core
            # insert bypasses it, so supply it explicitly or the NOT NULL
            # column rejects the row.
            session.execute(
                sqlite_insert(PromptSnapshot.__table__)
                .values(
                    sha256=tp.system_prompt_sha,
                    text=_load_system_prompt(),
                    prompt_kind="assess_control",
                    created_at=_utcnow(),
                )
                .on_conflict_do_nothing(index_elements=["sha256"])
            )
        session.add(
            AssessmentTrace(
                assessment_id=assessment_id,
                system_prompt_sha=tp.system_prompt_sha,
                user_message=tp.user_message,
                model=tp.model,
                anthropic_model_version=tp.model_version,
                temperature=tp.temperature,
                max_tokens=tp.max_tokens,
                request_id=tp.request_id,
                raw_response_json=tp.raw_response_json,
                input_tokens=tp.input_tokens,
                output_tokens=tp.output_tokens,
                cache_read_tokens=tp.cache_read_tokens,
                pass_index=tp.pass_index,
            )
        )
    # Collect (evidence_id, chunk_text, shown_row) tuples so the citation
    # loop below can resolve evidence_id → AssessmentEvidenceShown.id after
    # flush, and pull the chunk_text it needs for offset math without a
    # second query. Dict keyed by evidence_id is last-write-wins for the
    # rare case where the same artifact is tagged twice on one objective —
    # citations only carry evidence_id (not order_index), so any of the
    # duplicate rows is a defensible target; we don't fabricate a finer
    # disambiguator the model didn't supply.
    shown_rows: list[tuple[int, str, AssessmentEvidenceShown]] = []
    for ep in decision.evidence_shown:
        row = AssessmentEvidenceShown(
            assessment_id=assessment_id,
            evidence_id=ep.evidence_id,
            chunk_sha=ep.chunk_sha,
            chunk_text=ep.chunk_text,
            order_index=ep.order_index,
            relevance=ep.relevance,
            tag_source=ep.tag_source,
            # Token-budget partition audit. An examined row is one the model
            # actually saw; a deferred row is over-budget and was NOT shown,
            # but is still recorded so "what was held back, and why" is
            # traceable. deferred_reason is null on examined rows.
            disposition=ep.disposition,
            rank_score=ep.rank_score,
            deferred_reason=ep.deferred_reason,
        )
        session.add(row)
        shown_rows.append((ep.evidence_id, ep.chunk_text, row))

    # Pass 0 is the canonical accepted pass in the matching-status dual-pass
    # branch and the only pass in single-pass mode — see the dual-pass
    # branch comment in assessor.py for the rationale. Skip the rest of
    # this helper entirely when there's no pass 0 (short-circuit decisions)
    # or it has no citations (flag off, or model emitted none).
    tp0 = next(
        (t for t in decision.trace_payload if t.pass_index == 0),
        None,
    )
    if tp0 is None or not tp0.citations or not shown_rows:
        return

    # Flush so the AssessmentEvidenceShown PKs are populated — citations
    # FK directly to those ids and we need them in-hand before staging
    # AssessmentCitation rows. Caller still owns the outer commit; flush
    # is a no-op transactionally.
    session.flush()
    evidence_to_shown_id: dict[int, int] = {}
    evidence_to_chunk_text: dict[int, str] = {}
    for evidence_id, chunk_text, row in shown_rows:
        # row.id is now populated by flush(); skip the rare race where it
        # isn't (e.g. an autoflush exception we're not surfacing here).
        if row.id is None:
            continue
        evidence_to_shown_id[evidence_id] = row.id
        evidence_to_chunk_text[evidence_id] = chunk_text

    # Read narrative text from the persisted Assessment row so the
    # claim-offset math runs against the same bytes that landed in the DB
    # (not whatever pre-sanitization form the LLM emitted). The assessor
    # writes the Assessment in the same transaction, so this get() hits
    # the in-flight session state — no extra round trip.
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        return

    # narrative_q / narrative_on_prem / narrative_cloud are the actual text
    # fields the LLM cites against. narrative_class is the verdict-kind enum
    # (not free text) so citations against it can't carry meaningful
    # offsets — we accept the row but leave start/end null. Anything else
    # the model invents (typo, hallucinated field) is silently skipped so
    # one bad citation can't poison the rest of the batch.
    narrative_field_text: dict[str, str | None] = {
        "narrative_q": assessment.narrative_q,
        "narrative_on_prem": assessment.narrative_on_prem,
        "narrative_cloud": assessment.narrative_cloud,
        "narrative_class": None,  # enum field — no text to offset into
    }

    for citation in tp0.citations:
        field_name = citation.get("narrative_field")
        if field_name not in narrative_field_text:
            continue
        claim_text = citation.get("claim") or ""
        source_quote = citation.get("source_quote") or ""
        evidence_id = citation.get("evidence_id")
        if not claim_text or not source_quote or evidence_id is None:
            continue
        shown_id = evidence_to_shown_id.get(int(evidence_id))
        if shown_id is None:
            # Model cited an evidence_id that wasn't in the bundle (hallucination
            # or post-truncation drop). Trace + raw_response_json still record
            # the failed cite; we just don't write an orphaned citation row.
            continue
        narrative_text = narrative_field_text.get(field_name)
        # find() returns -1 when not present — translate to None so the
        # nullable offset columns mean "couldn't anchor" (paraphrased) vs.
        # 0 which is a valid prefix match. Best-effort: paraphrased claims
        # still get a row, just with null offsets.
        claim_start = (
            narrative_text.find(claim_text) if narrative_text else -1
        )
        claim_end = (
            claim_start + len(claim_text) if claim_start >= 0 else -1
        )
        chunk_text = evidence_to_chunk_text.get(int(evidence_id), "")
        source_start = chunk_text.find(source_quote) if chunk_text else -1
        source_end = (
            source_start + len(source_quote) if source_start >= 0 else -1
        )
        session.add(
            AssessmentCitation(
                assessment_id=assessment_id,
                narrative_field=field_name,
                claim_text=claim_text,
                claim_start_char=claim_start if claim_start >= 0 else None,
                claim_end_char=claim_end if claim_end >= 0 else None,
                evidence_shown_id=shown_id,
                source_quote=source_quote,
                source_start_char=source_start if source_start >= 0 else None,
                source_end_char=source_end if source_end >= 0 else None,
                extraction_method="llm_self_cite",
            )
        )


def _sync_poams_for_objective(
    workbook_id: int,
    objective_id: int,
    new_status: ComplianceStatus,
    s: Session,
) -> int:
    """Drop POAM links for an objective that's no longer Non-Compliant.

    POAMs only make sense for NC findings — a Compliant or NA objective has
    nothing to remediate. When an assessment flips away from NC, we:
      1. Delete every PoamObjective row that points to this objective in any
         POAM under this workbook.
      2. For each affected POAM, if no objectives remain, delete the POAM
         (and its milestones + evidence links). Auto-generated POAMs can be
         re-created by re-running /generate; we don't preserve empty shells.

    No-op when the new status is NON_COMPLIANT — the POAM/link stays valid.
    Returns the number of POAMs deleted (caller does not need to commit).
    """
    if new_status == ComplianceStatus.NON_COMPLIANT:
        return 0

    affected_poam_ids = [
        po.poam_id
        for po in s.exec(
            select(PoamObjective)
            .join(Poam, Poam.id == PoamObjective.poam_id)
            .where(PoamObjective.objective_id == objective_id)
            .where(Poam.workbook_id == workbook_id)
        ).all()
    ]
    if not affected_poam_ids:
        return 0

    # Drop the stale links first.
    s.exec(
        delete(PoamObjective)
        .where(PoamObjective.objective_id == objective_id)
        .where(PoamObjective.poam_id.in_(affected_poam_ids))  # type: ignore[attr-defined]
    )

    deleted = 0
    for pid in set(affected_poam_ids):
        remaining = s.exec(
            select(PoamObjective).where(PoamObjective.poam_id == pid)
        ).first()
        if remaining is not None:
            continue
        # Empty POAM — clear children, then the row itself.
        s.exec(delete(PoamMilestone).where(PoamMilestone.poam_id == pid))
        s.exec(delete(PoamEvidence).where(PoamEvidence.poam_id == pid))
        p = s.get(Poam, pid)
        if p is not None:
            s.delete(p)
            deleted += 1
    return deleted

# Coverage-sensitive control families — the auto-derived asset coverage
# report (ACAS ∪ STIG checklists ∪ declared inventory) is only injected
# for CCIs whose narrative quality turns on boundary-completeness or
# scan-coverage signal. Each family maps to a distinct gap class the
# report surfaces:
#
#   CM-8 / CA-3 / PM-5 — inventory completeness (declared_not_observed,
#                        observed_not_declared)
#   RA-5               — scanned_not_checklisted (config scan missing)
#   CA-7               — checklisted_not_scanned (no continuous monitoring)
#   CM-6               — no_stig_applied / checklisted_but_stig_unknown
#
# The coverage block is non-trivial in size (per-source host counts plus
# per-gap host lists); injecting it into the prompt for every AC-2/AU-3/
# SI-4 row would burn the prompt-cache benefit and dilute signal. Family-
# gating keeps the cache prefix stable for the ~90% of CCIs that don't
# care about asset coverage.
#
# The pattern matches the base control plus any enhancement (e.g.
# "CM-8", "CM-8(1)", "CM-8 (3)"); the word-boundary anchor prevents
# accidental matches against future families like CM-80.
# _is_coverage_control and _build_evidence_block now live in
# engine/inputs.py so the eval CLI can call them without crossing the
# route layer. Imports above re-export them under their original
# underscore names; behavior is byte-identical.


router = APIRouter(prefix="/api/controls", tags=["controls"])

# Module logger — sidecar wires a FileHandler in server.py so detached
# runs leave a traceback on disk at ~/.cybersecurity-assessor/sidecar.log.
_log = logging.getLogger(__name__)


class AssessmentUpsert(BaseModel):
    workbook_id: int
    objective_id: int
    # excel_row is derived from BaselineObjective.source_row when omitted —
    # the workbook scope materialization already records which row each CCI
    # lives on, so the UI shouldn't have to re-enter it. Override is allowed
    # for the rare case where a workbook has been edited out-of-band.
    excel_row: int | None = None
    status: ComplianceStatus
    tester: str
    narrative_q: str
    # Dual-narrative inputs — optional so the manual-upsert path can update
    # column-Q only when the assessor edits in-place without retouching the
    # per-side breakdown. See Assessment.narrative_on_prem in models.py for
    # the responsibility-to-population matrix.
    narrative_on_prem: str | None = None
    narrative_cloud: str | None = None
    narrative_class: NarrativeClass
    inheritance_rule: str | None = None  # "8a", "8b", or None
    date_tested: datetime | None = None  # defaults to now


def _resolve_excel_row(
    *, workbook_id: int, objective_id: int, s: Session
) -> int:
    """Look up the canonical Excel row for an (objective, workbook) pair.

    Source of truth is ``BaselineObjective.source_row``, captured when the
    workbook was opened and the in-scope CCI set was materialized from
    column A. Raises HTTPException(422) if the lookup fails so the caller
    surfaces a clear error instead of writing a NULL row.
    """
    wb = s.get(Workbook, workbook_id)
    if wb is None:
        raise HTTPException(status_code=404, detail="Workbook not found")
    if wb.baseline_id is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "Workbook has no Baseline — reopen it with a Framework selected "
                "so the app can materialize the in-scope CCI rows from column A, "
                "or pass excel_row explicitly."
            ),
        )
    # Cross-framework backstop: each Framework owns its own Control + Objective
    # rows even for the same control_id/CCI string (catalog isolation). The UI
    # filters the workbook picker by Control.framework_id, but server-side we
    # still verify so a stale client can't silently save a Rev-5 Objective PK
    # against a Rev-4 baseline (which then 422s on the missing BO row with a
    # cryptic message). See memory/project_odp_architecture.md.
    obj = s.get(Objective, objective_id)
    if obj is not None:
        ctrl = s.get(Control, obj.control_id_fk)
        if ctrl is not None and wb.framework_id is not None and ctrl.framework_id != wb.framework_id:
            obj_fw = s.get(Framework, ctrl.framework_id)
            wb_fw = s.get(Framework, wb.framework_id)
            obj_fw_name = obj_fw.name if obj_fw else f"framework {ctrl.framework_id}"
            wb_fw_name = wb_fw.name if wb_fw else f"framework {wb.framework_id}"
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Cross-framework save blocked: objective_id={objective_id} "
                    f"belongs to {obj_fw_name} but workbook {workbook_id} targets "
                    f"{wb_fw_name}. Open or rebind a workbook to {obj_fw_name}, "
                    f"or pick a control from {wb_fw_name}."
                ),
            )
    bo = s.exec(
        select(BaselineObjective).where(
            BaselineObjective.baseline_id == wb.baseline_id,
            BaselineObjective.objective_id == objective_id,
        )
    ).first()
    if bo is None or bo.source_row is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"No BaselineObjective row for objective_id={objective_id} in "
                f"baseline {wb.baseline_id}. Reopen the workbook to refresh "
                "scope, or pass excel_row explicitly."
            ),
        )
    return int(bo.source_row)


@router.get("/{control_id}")
def get_control(
    control_id: int,
    workbook_id: int | None = None,
    s: Session = Depends(get_session),
) -> dict:
    c = s.get(Control, control_id)
    if not c:
        raise HTTPException(status_code=404, detail="Control not found")
    objs = s.exec(select(Objective).where(Objective.control_id_fk == control_id)).all()

    # Scope objectives to the active workbook when one is given. The catalog
    # carries every CCI for a control across revisions; a Rev-4 workbook
    # should only see the CCIs its baseline actually surfaced, not legacy
    # Rev-3-only catalog stubs (those are real Objective rows but were never
    # in any BaselineObjective for this workbook). Without this filter, the
    # ControlDetail count inflates — e.g. AC-2 shows 32/32 instead of 25/25.
    # Mirrors the in_workbook logic in catalog.list_objectives. When no
    # workbook is given (CSV export, raw drill-down) we keep every objective.
    if workbook_id is not None:
        wb = s.get(Workbook, workbook_id)
        if wb is not None and wb.baseline_id is not None:
            objective_ids = [o.id for o in objs if o.id is not None]
            if objective_ids:
                in_workbook_ids = set(
                    s.exec(
                        select(BaselineObjective.objective_id).where(
                            BaselineObjective.baseline_id == wb.baseline_id,
                            BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
                            BaselineObjective.objective_id.in_(objective_ids),  # type: ignore[attr-defined]
                        )
                    ).all()
                )
                objs = [o for o in objs if o.id in in_workbook_ids]
            else:
                objs = []
    # Resolve ODP placeholders ({$37$}, ac-02_odp.03, etc.) against the
    # framework-scoped odp_assignment table at render time. Templates
    # never carry program-specific values in the catalog — see
    # memory/project_odp_architecture.md.
    rendered_statement = c.statement
    unresolved: list[str] = []
    if c.statement:
        fw = s.get(Framework, c.framework_id) if c.framework_id else None
        if fw is not None:
            # bold_format="markdown" — substituted ODP values arrive as
            # ``**value**``. ControlDetail.tsx parses that into <strong> so
            # the assessor can see at a glance which words came from their
            # workbook vs. the catalog template.
            rendered_statement, unresolved = resolve_odps(
                s,
                fw.framework_id,
                c.control_id,
                c.statement,
                bold_format="markdown",
            )
    return {
        "id": c.id,
        "control_id": c.control_id,
        "title": c.title,
        "family": c.family,
        # framework_id surfaced so the UI can constrain the workbook picker
        # to workbooks from the same framework — prevents the cross-framework
        # save bug where ControlDetail auto-picked workbooks.data[0] and
        # sent a Rev-5 Objective PK against a Rev-4 baseline.
        "framework_id": c.framework_id,
        "statement": rendered_statement,
        "unresolved_odps": unresolved,
        "objectives": [
            {"id": o.id, "objective_id": o.objective_id, "source": o.source, "text": o.text}
            for o in objs
        ],
    }


@router.get("/{control_id}/program-controls")
def list_program_controls_for_control(
    control_id: int,
    framework_id: int | None = None,
    s: Session = Depends(get_session),
) -> list[dict]:
    """Group RequirementMap rows for a control by overlay source.

    Joins RequirementMap → Objective (filtered on ``control_id_fk``) →
    RequirementSource. Optional ``framework_id`` filter scopes to overlays
    attached to a specific framework — the UI passes the active workbook's
    framework so a multi-framework DB doesn't bleed (e.g. an r4 SDA overlay
    onto an r5 control).

    Returns one entry per RequirementSource, each carrying the per-objective
    PSC rows. Empty list if no overlays crosswalk to this control.
    """
    q = (
        select(RequirementMap, RequirementSource, Objective)
        .join(
            RequirementSource,
            RequirementSource.id == RequirementMap.requirement_source_id,
        )
        .join(Objective, Objective.id == RequirementMap.objective_id)
        .where(Objective.control_id_fk == control_id)
    )
    if framework_id is not None:
        q = q.where(RequirementSource.framework_id == framework_id)
    rows = s.exec(q).all()

    # Group by source.id. Stash the source itself the first time we see it so
    # we don't have to re-query for name/framework_id.
    by_source: dict[int, dict] = {}
    for rm, src, obj in rows:
        bucket = by_source.setdefault(
            src.id,
            {
                "source": {
                    "id": src.id,
                    "name": src.name,
                    "framework_id": src.framework_id,
                },
                "rows": [],
            },
        )
        bucket["rows"].append(
            {
                "id": rm.id,
                "requirement_number": rm.requirement_number,
                "requirement_text": rm.requirement_text,
                "objective_id": obj.id,
                "objective_code": obj.objective_id,
            }
        )

    # Stable sort: sources by name; rows within each source by requirement_number
    # (lexicographic — PSC numbers are stringly-typed and a natural sort isn't
    # worth the complexity until a real overlay needs it).
    out = sorted(by_source.values(), key=lambda g: g["source"]["name"])
    for g in out:
        g["rows"].sort(key=lambda r: r["requirement_number"])
    return out


@router.get("/{control_id}/odp-history")
def get_odp_history(control_id: int, s: Session = Depends(get_session)) -> list[dict]:
    """All :class:`OdpAuditLog` rows for this control, grouped per ODP.

    Empty list when no audit rows exist (typical for first-ingest
    workbooks and overlays that haven't yet been overwritten). The UI
    hides the section and the SAR omits its appendix on empty -- no
    "(none)" placeholders.

    Schema note: the path ``control_id`` is the int PK on :class:`Control`,
    but :class:`OdpAuditLog.control_id` is the OSCAL string form
    (e.g. ``"AC-2"``). We resolve the Control first to translate the PK
    into the OSCAL id + framework_id pair the audit log indexes on --
    same dance as :func:`get_control` lines above. Shortcutting by
    querying the audit log directly with the int would return zero rows
    silently.
    """
    c = s.get(Control, control_id)
    if not c:
        raise HTTPException(status_code=404, detail="Control not found")
    fw = s.get(Framework, c.framework_id) if c.framework_id else None
    if fw is None:
        return []
    return fetch_odp_history(s, fw.framework_id, c.control_id)


@router.get("/{control_id}/assessments")
def list_assessments(
    control_id: int, workbook_id: int | None = None, s: Session = Depends(get_session)
) -> list[dict]:
    obj_ids = s.exec(select(Objective.id).where(Objective.control_id_fk == control_id)).all()
    if not obj_ids:
        return []
    stmt = select(Assessment).where(Assessment.objective_id.in_(obj_ids))
    if workbook_id is not None:
        stmt = stmt.where(Assessment.workbook_id == workbook_id)
    rows = s.exec(stmt).all()

    # v0.2 multi-implementation: load the per-scope AssessmentImplementation
    # rows for every assessment in ONE query (not N), keyed by assessment_id.
    # ControlDetail's N-impl editor activates ONLY when this list is non-empty
    # (isMultiImpl = implementations.length > 0); the per-scope CRM chips and
    # the rolled-up read-only Status pill both render off it. Omitting it here
    # left currentAssessment.implementations undefined -> [] for every row, so
    # the editor silently stayed in legacy single-narrative mode and NO
    # per-scope (or N/A) chips ever rendered even though the impl rows exist
    # in the DB. Serialize them.
    impls_by_assessment: dict[int, list[dict]] = {}
    assessment_ids = [a.id for a in rows if a.id is not None]
    if assessment_ids:
        impl_rows = s.exec(
            select(AssessmentImplementation).where(
                AssessmentImplementation.assessment_id.in_(assessment_ids)
            )
        ).all()
        for im in impl_rows:
            impls_by_assessment.setdefault(im.assessment_id, []).append(
                {
                    "id": im.id,
                    "scope_label": im.scope_label,
                    "source_baseline_id": im.source_baseline_id,
                    "responsibility": im.responsibility,
                    "status": im.status,
                    "narrative": im.narrative,
                    "evidence_refs": im.evidence_refs,
                }
            )

    return [
        {
            "id": a.id,
            "objective_id": a.objective_id,
            "workbook_id": a.workbook_id,
            "excel_row": a.excel_row,
            "status": a.status,
            "tester": a.tester,
            "date_tested": iso_utc(a.date_tested),
            "narrative_q": a.narrative_q,
            "narrative_on_prem": a.narrative_on_prem,
            "narrative_cloud": a.narrative_cloud,
            "narrative_class": a.narrative_class,
            "inheritance_rule": a.inheritance_rule,
            "written_to_workbook_at": iso_utc(a.written_to_workbook_at),
            # v0.2 precision-over-recall fields — ControlDetail's per-CCI
            # Status pill and review_reason callout read these. Omitting
            # them here silently disabled the amber Review pill in the
            # detail view (the v0.2 Assessment TS type expects them).
            "needs_review": a.needs_review,
            "review_reason": a.review_reason,
            "confidence": a.confidence,
            "rewrite_requested": a.rewrite_requested,
            "rewrite_requested_refs": a.rewrite_requested_refs,
            # v0.2 multi-implementation per-scope rows (cloud platforms +
            # synthesized On-Premises). Empty list for legacy single-narrative
            # assessments; ControlDetail falls back to the single-narrative
            # editor in that case.
            "implementations": impls_by_assessment.get(a.id, []),
        }
        for a in rows
    ]


@router.post("/assessments")
def upsert_assessment(
    body: AssessmentUpsert,
    force: bool = False,
    s: Session = Depends(get_session),
) -> dict:
    """Validate (rule #11) then upsert. Pass ``?force=true`` to bypass."""
    result = v.validate(
        proposed_status=body.status,
        proposed_narrative=body.narrative_q,
    )
    if not result.ok and not force:
        raise HTTPException(
            status_code=422,
            detail={
                "ok": False,
                "classified_as": result.classified_as.value,
                "rejections": [
                    {"reason": r.value, "message": msg} for r, msg in result.rejections
                ],
                "notes": result.notes,
                "hint": "Re-submit with ?force=true to override (logged).",
            },
        )

    # Resolve excel_row from BaselineObjective when the client didn't pass
    # one — keeps the UI form trivial and avoids the assessor having to
    # eyeball Excel for the row number.
    excel_row = body.excel_row
    if excel_row is None:
        excel_row = _resolve_excel_row(
            workbook_id=body.workbook_id,
            objective_id=body.objective_id,
            s=s,
        )

    existing = s.exec(
        select(Assessment).where(
            Assessment.workbook_id == body.workbook_id,
            Assessment.objective_id == body.objective_id,
        )
    ).first()
    when = body.date_tested or datetime.now(timezone.utc)
    if existing:
        existing.status = body.status
        existing.tester = body.tester
        existing.narrative_q = body.narrative_q
        # Only overwrite dual-narrative fields when the request explicitly
        # supplies them — manual edits to column Q alone should leave the
        # per-side breakdown untouched.
        if body.narrative_on_prem is not None:
            existing.narrative_on_prem = body.narrative_on_prem
        if body.narrative_cloud is not None:
            existing.narrative_cloud = body.narrative_cloud
        existing.narrative_class = body.narrative_class
        existing.inheritance_rule = body.inheritance_rule
        existing.excel_row = excel_row
        existing.date_tested = when
        # v0.2: a manual upsert is the user explicitly trusting this
        # verdict. Clear the abstain triage signal so the row stops
        # being filtered out of exports and stops showing the amber
        # Review pill. confidence stays as-is (None on user edits).
        existing.needs_review = False
        existing.review_reason = None
        s.add(existing)
        a = existing
    else:
        a = Assessment(
            workbook_id=body.workbook_id,
            objective_id=body.objective_id,
            excel_row=excel_row,
            status=body.status,
            tester=body.tester,
            narrative_q=body.narrative_q,
            narrative_on_prem=body.narrative_on_prem,
            narrative_cloud=body.narrative_cloud,
            narrative_class=body.narrative_class,
            inheritance_rule=body.inheritance_rule,
            date_tested=when,
            # New manual rows are user-trusted by definition.
            needs_review=False,
        )
        s.add(a)
    # fix #7 -- a manual upsert is the user overriding the engine's verdict.
    # The decision cache is content-addressed, so without this the next
    # /assess on unchanged content replays the stale pre-override Decision
    # and silently clobbers the human's edit. Bump the per-objective epoch
    # so that re-run misses the cache and re-assesses fresh. Caller owns the
    # transaction; this stages the INSERT/UPDATE and the commit below lands it.
    bump_override_epoch(s, body.workbook_id, body.objective_id)
    # Keep POAMs honest: a Compliant or NA assessment has nothing to remediate,
    # so prune any POAM links pointing at this objective. Empty POAMs are
    # deleted (re-runnable via /api/poams/generate).
    _sync_poams_for_objective(body.workbook_id, body.objective_id, body.status, s)
    s.commit()
    s.refresh(a)
    return {
        "id": a.id,
        "status": a.status,
        "validation": {
            "ok": result.ok,
            "classified_as": result.classified_as.value,
            "forced": (not result.ok) and force,
            "notes": result.notes,
        },
    }


class AssessRequest(BaseModel):
    """Run the patent kernel for one CCI and return the proposed Decision.

    With ``persist=True`` (the default), accepted decisions are written to
    the Assessment table as ``needs_review=True`` rows with
    ``review_reason="pending-human-review"`` — that's what keeps the
    proposal alive after the user navigates away from the detail page.
    Apply-to-workbook still requires the human to clear ``needs_review``
    (the Save action on the detail page does this), matching the batch
    flow where abstained rows are skipped by apply-batch.

    ``persist=False`` keeps the historical read-only behavior — useful for
    a hypothetical "preview without commitment" UI we don't currently ship.
    """

    workbook_id: int
    objective_id: int
    persist: bool = True
    tester: str | None = None


@router.post("/assess")
def assess_objective(body: AssessRequest, s: Session = Depends(get_session)) -> dict:
    """Run rules+LLM+supersession+validator for one CCI and return the decision.

    The pipeline (see ``engine.assessor.Assessor``):
      1. Rule #8 — if it fires deterministically, no LLM call is made.
      2. Else Anthropic call with cached system prompt.
      3. Supersession rewrite of the narrative.
      4. Rule #11 validation; up to 2 corrective retries.
      5. Returns ``accepted=False`` if all retries are exhausted —
         the UI must surface this to the assessor; never silently write.
    """
    wb = s.get(Workbook, body.workbook_id)
    if wb is None:
        raise HTTPException(status_code=404, detail="Workbook not found")
    obj = s.get(Objective, body.objective_id)
    if obj is None:
        raise HTTPException(status_code=404, detail="Objective not found")

    wb_path = Path(wb.path)
    if not wb_path.exists():
        raise HTTPException(
            status_code=410,
            detail=f"Workbook file no longer exists at {wb.path}",
        )

    # Load CCIS rows from the workbook and look up by CCI id (Objective.objective_id
    # is the canonical "CCI-NNNNNN" string for 800-53r5 — see catalogs/oscal_loader).
    try:
        index = read_workbook_index(wb_path)
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    row = index.by_cci().get(obj.objective_id)
    row_inserted = False
    if row is None:
        # Workbook completeness gap — the catalog (DB) knows this CCI
        # belongs to the control but the workbook is missing the row.
        # Auto-insert a populated row (rather than 422-ing into a dead
        # end), refresh the index, and proceed with the normal assess
        # pipeline. See plan: .claude/plans/lucky-sleeping-parasol.md
        ctrl = s.get(Control, obj.control_id_fk)
        if ctrl is None:
            raise HTTPException(
                status_code=500,
                detail=f"Objective {obj.objective_id} has no parent Control row in DB.",
            )
        try:
            new_excel_row = ccis_writer.insert_cci_row(
                wb_path,
                control_id=ctrl.control_id,
                cci_id=obj.objective_id,
                ap_acronym=None,
                definition=obj.text,
                guidance=obj.implementation_guidance,
                procedures=obj.assessment_procedures,
                required=True,
            )
        except ccis_writer.WorkbookWriteVerificationError as e:
            raise HTTPException(status_code=500, detail=str(e)) from e
        except FileNotFoundError as e:
            raise HTTPException(status_code=410, detail=str(e)) from e
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e
        except RuntimeError as e:
            # xlwings / Excel unavailable. 503 so the UI knows the
            # workbook itself is fine but the host can't write.
            raise HTTPException(status_code=503, detail=str(e)) from e

        # Re-read the workbook. The parser cache is keyed by
        # (path, mtime_ns, size) and book.save() bumped mtime, so this
        # bypasses the cache and surfaces the newly inserted row.
        index = read_workbook_index(wb_path)
        row = index.by_cci().get(obj.objective_id)
        row_inserted = True
        if row is None:
            raise HTTPException(
                status_code=500,
                detail=(
                    f"Inserted row for {obj.objective_id} at excel_row "
                    f"{new_excel_row} but workbook re-read does not show it."
                ),
            )

    # Build the LLM client. MissingApiKeyError → 412 so the UI can prompt the
    # user to set the key in Settings without surfacing a generic 500.
    cfg = load_config()
    try:
        client = make_client(cfg)
    except MissingApiKeyError as e:
        # Hint message points at the active provider so the UI prompts the
        # user to fix the right key, not the wrong one.
        provider_label = "OpenAI" if cfg.llm_provider == "openai" else "Anthropic"
        raise HTTPException(
            status_code=412,
            detail={
                "error": "missing_api_key",
                "message": str(e),
                "hint": f"Set the {provider_label} API key in Settings "
                "(stored in Windows Credential Manager).",
            },
        ) from e
    except RuntimeError as e:  # SDK install failure
        raise HTTPException(status_code=503, detail=str(e)) from e

    # Wrap the assess() call with a RunRecorder so per-CCI token totals,
    # validator rejections, and supersession hits land on an AssessmentRun
    # row. Cost is computed AFTER the call from the recorder's accumulated
    # token totals and passed to finish() — that way the run row carries
    # both the operational telemetry (tokens, cost) and the patent-cited
    # accuracy measurements in a single transaction.
    # Build the user-message evidence block (the LLM otherwise sees only
    # the CCIS row). The kernel itself is session-free so this DB join
    # lives here, at the route handler — the resulting string passes
    # through Assessor opaquely. For inventory-family CCIs the helper
    # also appends the asset-list cross-check; for everything else it's
    # just the per-objective tagged-evidence bundle. Returns None when
    # there's nothing useful to inject so the prompt cache prefix stays
    # stable for un-tagged CCIs (the common case in early-stage workbooks).
    evidence_block = _build_evidence_block(
        objective_pk=obj.id,
        control_id=row.control_id,
        workbook_id=body.workbook_id,
        s=s,
    )

    # CRM overlay snapshot — built here (route is the integration boundary,
    # kernel stays session-free). Empty when no CRM overlays are attached,
    # in which case the kernel behaves exactly as before.
    crm_context = build_crm_context(body.workbook_id, s)

    # Deterministic system-boundary brief — built at the route (the
    # integration boundary) and threaded into the kernel so EVERY narrative
    # is situated in the authorization boundary and the LLM reasons about
    # the CSP/customer responsibility seam. scope_labels come from the
    # already-built CRM context so the demarcation names concrete cloud
    # platforms; None when there's no boundary signal (prompt omits the
    # block, kernel assesses as fully customer-owned).
    boundary_brief = build_boundary_brief(
        body.workbook_id, s, scope_labels=crm_context.scope_labels()
    )

    # fix #7 -- per-objective manual-override epoch. Forwarded into the
    # decision-cache fingerprint so that if a reviewer previously overrode
    # this CCI's verdict, this re-run misses the content-addressed cache and
    # re-assesses fresh instead of replaying the superseded Decision. 0 (the
    # common, never-overridden case) yields the legacy fingerprint.
    override_epoch = get_override_epoch(s, body.workbook_id, obj.id)

    rec = RunRecorder.start(
        s, workbook_id=body.workbook_id, model_id=active_model_id(cfg)
    )
    # v0.2 decision-cache opt-in: route owns the session, so we hand
    # it to the kernel here. Tests instantiate ``Assessor(llm=...)``
    # without a cache_session and stay session-free / cache-free.
    # fix #2 -- hoisted out of the inline call so the ``finally`` can
    # drain the one per-thread cache session this single-shot assess
    # creates (the kernel now uses a private Session(engine) for
    # decision_cache ops on whatever thread runs assess()).
    single_assessor = Assessor(llm=client, cache_session=s)
    try:
        # Pass BOTH evidence_block (structural signal for Step 1.65) AND
        # tagged_evidence=block.text (the rendered string the prompt
        # template still consumes). Two fields, one source of truth.
        decision = single_assessor.assess(
            row,
            recorder=rec,
            tagged_evidence=evidence_block.text,
            evidence_block=evidence_block,
            crm_context=crm_context,
            workbook_id=body.workbook_id,
            boundary_brief=boundary_brief,
            override_epoch=override_epoch,
        )
    finally:
        single_assessor.close_worker_sessions()
        total_in = sum(o.input_tokens for o in rec._outcomes)
        total_out = sum(o.output_tokens for o in rec._outcomes)
        total_cache_read = sum(o.cache_read_tokens for o in rec._outcomes)
        cost = compute_cost(
            active_model_id(cfg),
            input_tokens=total_in,
            output_tokens=total_out,
            cache_read_tokens=total_cache_read,
        )
        rec.finish(cost_usd=cost)

    # Persist as a pending-human-review row so navigating away doesn't
    # discard the proposal (the prior failure mode that produced "Save
    # button disappeared after I left the screen"). Apply-to-workbook
    # is still human-gated: needs_review=True keeps the row out of
    # apply-batch, and the detail page's Save action is what clears the
    # flag. If the kernel itself flagged needs_review for a model-side
    # reason (dual-pass disagreement, unverified-cites, etc.) we keep
    # that reason — it's strictly more specific than "pending-human-review".
    persisted_id: int | None = None
    # Gate widened (feedback_abstain_status_none_drops.md): a kernel
    # ``_abstain_decision`` can return ``accepted=True`` with status=None
    # AND narrative=None (the hard-abstain path, e.g. validator-exhausted
    # or LLM-parse-error). The previous gate dropped those rows on the
    # floor because the schema's NOT NULL columns wouldn't accept them —
    # but the kernel's contract is that the route writes the row with
    # needs_review=True so the reviewer queue surfaces it. Coercion
    # happens in ``_coerce_abstain_persistence_fields``; soft abstains
    # (kernel emitted a proposal but flagged review) pass through with
    # their proposed values intact.
    if body.persist and decision.accepted:
        status_to_persist, narrative_to_persist = (
            _coerce_abstain_persistence_fields(decision)
        )
        tester = body.tester or cfg.default_tester
        when = datetime.now(timezone.utc)
        rw_refs = (
            json.dumps([[lg, cu] for (lg, cu) in decision.rewrite_requested_refs])
            if decision.rewrite_requested_refs
            else None
        )
        existing = s.exec(
            select(Assessment).where(
                Assessment.workbook_id == body.workbook_id,
                Assessment.objective_id == obj.id,
            )
        ).first()
        # Single-control endpoint intentionally pins needs_review=True on
        # every persisted row — this is the review-then-apply contract
        # documented in the comment above (lines 770-777). The user has to
        # confirm via the detail page's Save action before the row flows
        # into apply-batch, regardless of how confident the kernel was.
        # That's why we don't honor ``decision.needs_review`` here the way
        # the bulk-assess site does. If the kernel itself flagged a
        # specific reason (dual-pass mismatch, unverified-cites, …) keep
        # it — it's strictly more useful than "pending-human-review".
        needs_review = True
        review_reason = decision.review_reason or "pending-human-review"
        # v0.2 patent-supporting provenance tag — derived from the kernel's
        # Decision so the persisted row carries a single filterable
        # verdict-origin signal alongside the legacy inheritance_rule /
        # needs_review / confidence trio. See _decision_to_verdict_source.
        verdict_src = _decision_to_verdict_source(decision)
        # v0.2 dual-narrative advisory mirror. The kernel populates
        # ``Decision.dual_narrative_flags`` on the LLM-accept path (empty
        # for short-circuit and clean rows). Both columns always written
        # so post-migration rows are non-null; legacy rows pre-migration
        # stay NULL and read-sites must treat NULL as "not flagged".
        dual_flags = list(getattr(decision, "dual_narrative_flags", []) or [])
        dual_flagged_bool = bool(dual_flags)
        dual_flags_json = json.dumps(dual_flags) if dual_flagged_bool else None
        # CRM short-circuit audit trail (Gap A): write a CrmShortCircuitEvent
        # for every outcome the kernel decided via provider/inherited/NA
        # short-circuit. Single-CCI run, so rec.outcomes carries exactly one
        # entry; helper skips it cleanly if no short-circuit fired.
        _persist_crm_short_circuits(
            s, workbook_id=body.workbook_id, outcomes=rec.outcomes
        )
        if existing:
            existing.status = status_to_persist
            existing.tester = tester
            existing.narrative_q = narrative_to_persist
            existing.narrative_on_prem = decision.narrative_on_prem
            existing.narrative_cloud = decision.narrative_cloud
            existing.narrative_class = decision.narrative_class
            existing.inheritance_rule = decision.rule
            existing.excel_row = decision.excel_row
            existing.date_tested = when
            existing.needs_review = needs_review
            existing.review_reason = review_reason
            existing.confidence = decision.confidence
            existing.rewrite_requested = decision.rewrite_requested
            existing.rewrite_requested_refs = rw_refs
            existing.verdict_source = verdict_src
            existing.dual_narrative_flagged = dual_flagged_bool
            existing.dual_narrative_flag_reasons = dual_flags_json
            # Audit v1: stamp the active AssessmentRun.id so an auditor can
            # replay a whole run as a batch (the assess_objective single-CCI
            # path still runs under a RunRecorder, so rec.run_id is the
            # one-row "run" that just executed).
            existing.run_id = rec.run_id
            # v0.2 multi-implementation write path: route the parent
            # Assessment write through the shared helper so a control
            # covered by N CRMs (+ synthesized On-Premises slice) persists
            # N AssessmentImplementation children and a rolled-up parent
            # status/narrative. The helper flushes (not commits) and
            # replaces prior impl rows on update — we keep the route's
            # explicit commit boundary below. Abstain rows keep their
            # coerced parent fields (helper skips rollup when status is
            # None). control_id is the OSCAL canonical id, not the CCI.
            persisted_id = persist_assessment_with_impls(
                s,
                assessment=existing,
                decision=decision,
                crm_context=crm_context,
                control_id=row.control_id,
                is_new=False,
            )
            s.commit()
            # Audit v1: persist trace + evidence-shown rows AFTER the flush
            # inside the helper so ``persisted_id`` is materialized for the
            # FK. Same transaction boundary as the Assessment write — a
            # follow-up commit keeps the row + its audit trail atomic.
            _persist_audit_trail(s, assessment_id=persisted_id, decision=decision)
            s.commit()
        else:
            new_row = Assessment(
                workbook_id=body.workbook_id,
                objective_id=obj.id,
                excel_row=decision.excel_row,
                status=status_to_persist,
                tester=tester,
                narrative_q=narrative_to_persist,
                narrative_on_prem=decision.narrative_on_prem,
                narrative_cloud=decision.narrative_cloud,
                narrative_class=decision.narrative_class,
                inheritance_rule=decision.rule,
                date_tested=when,
                needs_review=needs_review,
                review_reason=review_reason,
                confidence=decision.confidence,
                rewrite_requested=decision.rewrite_requested,
                rewrite_requested_refs=rw_refs,
                verdict_source=verdict_src,
                dual_narrative_flagged=dual_flagged_bool,
                dual_narrative_flag_reasons=dual_flags_json,
                # Audit v1: see existing-row branch above for rationale.
                run_id=rec.run_id,
            )
            # v0.2 multi-implementation write path — see the existing-row
            # branch above for rationale. INSERT skips the prior-impl
            # delete (is_new=True).
            persisted_id = persist_assessment_with_impls(
                s,
                assessment=new_row,
                decision=decision,
                crm_context=crm_context,
                control_id=row.control_id,
                is_new=True,
            )
            s.commit()
            _persist_audit_trail(s, assessment_id=persisted_id, decision=decision)
            s.commit()

    return {
        "accepted": decision.accepted,
        "status": decision.status.value if decision.status else None,
        "narrative": decision.narrative,
        # Visual multi-boundary form of column Q (labeled per-scope block) —
        # None for single-boundary rows. The GUI prefers this for display; the
        # plain ``narrative`` stays the validated single text for any consumer
        # that classifies it. Mirrors what the save path persists to narrative_q.
        "narrative_stitched": stitch_scope_narrative(decision.narratives_by_scope),
        "narrative_on_prem": decision.narrative_on_prem,
        "narrative_cloud": decision.narrative_cloud,
        "narrative_class": decision.narrative_class.value,
        "source": decision.source,
        "rule": decision.rule,
        "retries": decision.retries,
        "excel_row": decision.excel_row,
        "rejections": [
            {
                "reason": r.rejection_class,
                "context": r.corrective_context,
                "original_output": r.original_output,
            }
            for r in decision.rejection_log
        ],
        "supersession_hits": [
            {"stale": h.stale_ref, "current": h.current_ref, "source": h.source}
            for h in decision.supersession_log
        ],
        "notes": decision.notes,
        "decided_at": iso_utc(decision.decided_at),
        "run_id": rec.run_id,
        "cost_usd": cost,
        "tokens": {
            "input": total_in,
            "output": total_out,
            "cache_read": total_cache_read,
        },
        "workbook_row_inserted": row_inserted,
        # Surface the persisted Assessment id (when persist=True succeeded)
        # so the UI can immediately treat the proposal as a server-side row
        # — no more local-state proposals that vanish on unmount.
        "assessment_id": persisted_id,
        "needs_review": decision.needs_review or persisted_id is not None,
        "review_reason": (
            decision.review_reason
            if decision.review_reason
            else ("pending-human-review" if persisted_id is not None else None)
        ),
        "confidence": decision.confidence,
        "rewrite_requested": decision.rewrite_requested,
        "rewrite_requested_refs": (
            [list(p) for p in decision.rewrite_requested_refs]
            if decision.rewrite_requested_refs
            else None
        ),
    }


class AssessBatchRequest(BaseModel):
    """Auto-assess every in-scope CCI in the workbook in a single run.

    This is the canonical auto-mode entry point. The per-CCI ``/assess``
    route remains for preview/single-shot use, but the day-to-day flow is
    "open workbook → run batch → review decisions in the grid". The whole
    batch shares ONE ``AnthropicClient`` (so the cached system-prompt key
    stays stable across every call) and ONE ``RunRecorder`` (so cost +
    validator rejections + supersession hits aggregate onto a single
    ``AssessmentRun`` row — the patent-cited accuracy/$ denominator).
    """

    workbook_id: int
    family: str | None = None
    """Optional control-family filter (e.g. ``"AC"``) for incremental runs."""
    control_ids: list[int] | None = None
    """Optional explicit control PK list — when provided, the batch assesses
    every in-scope CCI under exactly these controls and SKIPS the
    ``BaselineControl.in_scope`` server-side filter. Lets the UI honor its
    own composed filter state (in-scope toggle + overlay-covered toggle +
    status filter) by sending the currently-visible row IDs. When ``None``,
    falls back to the legacy behavior: every CCI under every
    ``BaselineControl.in_scope=True`` control in the workbook's baseline."""
    limit: int | None = None
    """Optional cap on number of CCIs assessed — useful for smoke tests."""
    skip_existing: bool = True
    """If True, skip CCIs that already have a saved Assessment row."""
    persist: bool = True
    """If True, write accepted decisions as Assessment rows (review-then-apply)."""
    tester: str | None = None
    """Override ``cfg.default_tester`` for the persisted Assessment rows."""


@router.post("/assess-batch")
def assess_objectives_batch(
    body: AssessBatchRequest, s: Session = Depends(get_session)
) -> dict:
    """Run the assessor kernel across every in-scope CCI in one transaction.

    Pipeline per CCI is identical to ``/assess``: rule #8 → cached LLM →
    supersession → rule #11 validator with up to 2 corrective retries.
    Accepted decisions are persisted as ``Assessment`` rows (status N,
    narrative Q) so the UI's grid shows them populated; the assessor can
    still review-then-apply through the existing
    ``POST /assessments/apply`` route. Unaccepted decisions (validator
    rejected all retries) are returned with ``accepted=false`` so the UI
    can flag them for manual handling — never silently persisted.
    """
    wb = s.get(Workbook, body.workbook_id)
    if wb is None:
        raise HTTPException(status_code=404, detail="Workbook not found")
    if wb.baseline_id is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "Workbook has no Baseline. Reopen the workbook with a Framework "
                "selected so the app can materialize the in-scope CCI set from "
                "column A."
            ),
        )
    baseline = s.get(Baseline, wb.baseline_id)
    if baseline is None:
        raise HTTPException(
            status_code=422,
            detail=f"Workbook references missing Baseline {wb.baseline_id}.",
        )

    wb_path = Path(wb.path)
    if not wb_path.exists():
        raise HTTPException(
            status_code=410,
            detail=f"Workbook file no longer exists at {wb.path}",
        )

    # Read the workbook index ONCE — every CCI lookup hits this dict.
    try:
        index = read_workbook_index(wb_path)
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    cci_to_row = index.by_cci()

    # Resolve the in-scope objective list. Scope now lives on
    # BaselineControl (Control/Enhancement level) — a CCI is in-scope iff
    # its parent Control is. Always join through Control + BaselineControl
    # so the in_scope filter is authoritative; family filter is a cheap
    # add-on the same join already supports.
    #
    # When the caller passes ``control_ids`` (the UI does this for the
    # "Assess visible" button so all active grid filters compose into the
    # batch), use it as the authoritative scope and skip the
    # ``in_scope`` filter — the UI already filtered to what the user wants.
    # Without an explicit list, fall back to "every in-scope CCI in the
    # baseline" so the legacy single-button behavior still works.
    stmt = (
        select(BaselineObjective, Objective)
        .join(Control, Control.id == Objective.control_id_fk)
        .join(BaselineControl, BaselineControl.control_id == Control.id)
        .where(
            BaselineObjective.baseline_id == baseline.id,
            # Exclude soft-deleted CCIs — they exist only so save-path
            # can resolve source_row for historical Assessments. We
            # don't want to spend LLM cycles on rows the workbook has
            # since dropped. See models.py BaselineObjective.is_deprecated.
            BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
            BaselineObjective.objective_id == Objective.id,
            BaselineControl.baseline_id == baseline.id,
        )
    )
    if body.control_ids:
        stmt = stmt.where(Control.id.in_(body.control_ids))  # type: ignore[union-attr]
    else:
        stmt = stmt.where(BaselineControl.in_scope.is_(True))  # type: ignore[union-attr]
    if body.family:
        stmt = stmt.where(Control.family == body.family.upper())
    pairs: list[tuple[BaselineObjective, Objective]] = list(s.exec(stmt).all())

    # Stable order so reruns and resumed batches process CCIs predictably.
    pairs.sort(key=lambda po: po[1].objective_id)

    # Skip already-assessed CCIs. The lookup is one query, not N — pull
    # the objective_ids of every existing Assessment for this workbook.
    if body.skip_existing:
        existing_obj_ids = set(
            s.exec(
                select(Assessment.objective_id).where(
                    Assessment.workbook_id == body.workbook_id
                )
            ).all()
        )
        pairs = [(bo, o) for (bo, o) in pairs if o.id not in existing_obj_ids]

    if body.limit is not None and body.limit > 0:
        pairs = pairs[: body.limit]

    # Build the LLM client ONCE for the whole batch — same as /assess for
    # error mapping (412 / 503), but the shared instance means the prompt
    # cache key stays stable across every call in the batch (huge cost win).
    cfg = load_config()
    try:
        client = make_client(cfg)
    except MissingApiKeyError as e:
        provider_label = "OpenAI" if cfg.llm_provider == "openai" else "Anthropic"
        raise HTTPException(
            status_code=412,
            detail={
                "error": "missing_api_key",
                "message": str(e),
                "hint": f"Set the {provider_label} API key in Settings "
                "(stored in Windows Credential Manager).",
            },
        ) from e
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e

    tester = body.tester or cfg.default_tester
    # v0.2 decision-cache opt-in. Worker threads in Phase 2 share this
    # Assessor instance. fix #2 (2026-06-10): cache lookups/stores no
    # longer serialize through the Assessor's ``_cache_lock`` — each worker
    # now uses its own ``Session(engine)`` for decision_cache ops (see
    # Assessor._worker_cache_session). ``s`` is still passed as the cache
    # gate flag and backs the priming read + the rare session-bound
    # rewrite branch + RunRecorder commits (the latter two still share
    # ``_cache_lock``). The per-worker sessions are drained in the
    # ``finally`` after the executor below. Skipping cache_session on
    # tests keeps the legacy test contract intact.
    assessor = Assessor(llm=client, cache_session=s)
    # CRM snapshot built ONCE per batch (not per CCI). Each lookup is a
    # dict hit, so a 300-CCI batch costs one DB join instead of 300.
    crm_context = build_crm_context(body.workbook_id, s)
    # System-boundary brief built ONCE per batch (same rationale as the
    # CRM snapshot): a workbook-scoped constant threaded into every CCI's
    # assess call so each narrative is situated in the authorization
    # boundary and the LLM reasons about the CSP/customer responsibility
    # seam. scope_labels come from the CRM snapshot above.
    boundary_brief = build_boundary_brief(
        body.workbook_id, s, scope_labels=crm_context.scope_labels()
    )
    # Supersession candidate index built ONCE per batch (not per CCI).
    # The kernel funnels four finalize paths through
    # ``_locked_rewrite_evidence_chain``; priming here turns the indexed
    # fast path on so each worker walks a pre-compiled, frozen candidate
    # tuple instead of running a full-table scan + N+1 head lookup on
    # the shared session under ``_cache_lock``. Same "build once per
    # batch" pattern as ``crm_context`` directly above.
    assessor.prime_evidence_chain_index(body.workbook_id)
    # Share the assessor's session lock with the recorder so BOTH owners
    # serialize through one lock when worker threads in the parallel
    # fan-out below touch the same SQLModel session ``s``. Without this,
    # Assessor's ``_cache_lock`` and RunRecorder's internal lock are
    # independent — a worker mid-``decision_cache.lookup`` races a worker
    # mid-``rec._commit_outcome`` and SQLAlchemy raises
    # ``InvalidRequestError: This session is in 'prepared' state`` on
    # the next autoflush. See assessor.py ``session_lock`` property and
    # measurement.py ``RunRecorder.__init__`` for the full rationale.
    rec = RunRecorder.start(
        s,
        workbook_id=body.workbook_id,
        model_id=active_model_id(cfg),
        session_lock=assessor.session_lock,
    )

    decisions: list[dict] = []
    skipped: list[dict] = []
    accepted_count = 0
    unresolved_count = 0
    persisted_count = 0
    # v0.2: counts rows written with ``needs_review=True``. Subset of
    # ``persisted_count`` — UI shows this so the operator knows how many
    # rows landed in the review queue versus the trusted-verdict pile.
    abstained_count = 0
    # Bug #3: set non-None when the single batched commit in ``finally``
    # raises. We rollback, zero the persisted/abstained counters (nothing
    # actually landed), and surface this string in the payload instead of
    # letting a 500 wipe the grid. See the finally block for rationale.
    persist_error: str | None = None

    try:
        # ---- Phase 1: serial evidence build (main thread, uses ``s``) ----
        # SQLModel sessions aren't thread-safe, so the DB-bound prep work
        # (per-objective tagged_evidence join) runs serially on the main
        # thread before the parallel fan-out. Each lookup is sub-ms after
        # the catalog warm-up, so this loop is cheap relative to the LLM
        # round-trip phase below.
        work_items: list[tuple] = []  # (bo, obj, row, evidence_block, override_epoch)
        for bo, obj in pairs:
            row = cci_to_row.get(obj.objective_id)
            if row is None:
                # Baseline references a CCI that's no longer in the
                # workbook (manual edit of col A, framework swap, etc.).
                # Surface it instead of silently dropping it.
                skipped.append(
                    {
                        "objective_id": obj.objective_id,
                        "reason": "not_in_workbook",
                    }
                )
                continue
            try:
                # Per-objective evidence block. Built here (not in the
                # kernel) so Assessor stays session-free. Returns an
                # ``EvidenceBlock`` envelope: ``text`` is what the prompt
                # template consumes (None when nothing useful to inject),
                # and the structural booleans tell Assessor's Step 1.65
                # whether the bundle has per-objective artifacts or only
                # workbook-wide context wrappers (coverage report / CRM
                # hybrid prepend). Coverage-sensitive CCIs (CM-8 / CM-6 /
                # CA-3 / CA-7 / PM-5 / RA-5) additionally get the auto-
                # derived asset coverage report appended.
                #
                # Bug 11: individual source failures are caught inside
                # _build_evidence_block (per-source graceful degrade).
                # This outer catch is the last-resort for catastrophic
                # errors (session corruption, etc.). Instead of dropping
                # the CCI from the batch, substitute an empty evidence
                # block so it still enters work_items and gets counted in
                # total / assessed / properly needs_review'd by the kernel.
                evidence_block = _build_evidence_block(
                    objective_pk=obj.id,
                    control_id=row.control_id,
                    workbook_id=body.workbook_id,
                    s=s,
                )
            except Exception as exc:  # noqa: BLE001 — keep batch alive
                _log.exception(
                    "assess-batch: evidence build for CCI %s raised %s "
                    "(substituting empty evidence block — CCI stays in batch)",
                    obj.objective_id,
                    type(exc).__name__,
                )
                # Substitute a degraded empty evidence block so this CCI
                # still enters work_items — it will be assessed with no
                # evidence and the kernel's Step 1.65 / needs_review path
                # will handle it correctly. The source_warnings tuple
                # records what failed so it surfaces in the decision dict.
                evidence_block = EvidenceBlock(
                    text=None,
                    has_artifacts=False,
                    has_coverage=False,
                    has_findings=False,
                    has_hosts=False,
                    has_nonscan_artifact=False,
                    evidence_shown=(),
                    source_warnings=(
                        f"evidence_build_fatal: {type(exc).__name__}: {exc}",
                    ),
                )
            # fix #7 -- per-objective manual-override epoch, looked up HERE in
            # Phase 1 (main thread, owns ``s``). The Phase-2 workers run on
            # pool threads with their own private cache sessions and must not
            # touch ``s``, so the epoch is resolved now and carried as a plain
            # int in the work item. 0 (never overridden) yields the legacy
            # fingerprint and preserves cross-workbook cache sharing.
            override_epoch = get_override_epoch(s, body.workbook_id, obj.id)
            work_items.append((bo, obj, row, evidence_block, override_epoch))

        # ---- Phase 2: parallel LLM fan-out (8 workers) ------------------
        # ``Assessor.assess`` is stateless; the only shared mutable state
        # is the RunRecorder, which has an internal lock around its
        # session commit (see measurement.py). The LLM call dominates
        # wall-clock at 5-30s per CCI vs. ms-scale telemetry flush, so
        # eight workers cut a 25-minute serial batch to ~3-4 minutes
        # without hitting Anthropic's concurrent-request ceiling.
        # The main thread blocks on ``executor.map`` and does NOT touch
        # ``s`` during this phase — workers only mutate the recorder
        # (locked) and the LLM proposal kept in memory.
        def _assess_one(item):
            _bo, _obj, _row, _ev, _epoch = item
            try:
                # Pass BOTH the EvidenceBlock (structural signal for the
                # Step 1.65 no-evidence short-circuit) AND its rendered
                # text (what the prompt template consumes). The kernel
                # uses _ev.is_only_context to fire the rule on coverage-
                # only or hybrid-only bundles; the string is what the LLM
                # actually sees on rows that don't short-circuit.
                d = assessor.assess(
                    _row,
                    recorder=rec,
                    tagged_evidence=_ev.text,
                    evidence_block=_ev,
                    crm_context=crm_context,
                    workbook_id=body.workbook_id,
                    boundary_brief=boundary_brief,
                    override_epoch=_epoch,
                )
                _batch_progress.record_done(
                    body.workbook_id, _obj.objective_id, errored=False
                )
                return (item, d, None)
            except Exception as exc:  # noqa: BLE001 — keep batch alive
                _log.exception(
                    "assess-batch: CCI %s raised %s",
                    _obj.objective_id,
                    type(exc).__name__,
                )
                _batch_progress.record_done(
                    body.workbook_id, _obj.objective_id, errored=True
                )
                return (item, None, exc)

        results: list[tuple] = []
        if work_items:
            # Register the batch with the in-memory progress tracker so the
            # UI's poll endpoint can surface completed/total/last_objective
            # while the POST is in flight. ``total`` is the post-Phase-1
            # work_items length — Phase-1 skips (not-in-workbook, evidence
            # build raised) never enter the parallel fan-out and so don't
            # count toward the progress denominator.
            _batch_progress.start(body.workbook_id, len(work_items))
            try:
                with ThreadPoolExecutor(max_workers=8) as ex:
                    # ``map`` preserves order; we want stable decisions[] so the
                    # UI's row ordering matches workbook excel_row order. Memory
                    # cost is bounded — each result is one Decision dataclass.
                    for r in ex.map(_assess_one, work_items):
                        results.append(r)
            finally:
                # fix #2 -- release the per-worker decision-cache sessions.
                # The pool reused up to 8 threads, each holding one lazily-
                # created ``Session(engine)``; drain them deterministically
                # rather than waiting for GC to reclaim the SQLite handles.
                assessor.close_worker_sessions()

        # ---- Phase 3: serial persistence (main thread, uses ``s``) ------
        # All DB writes for accepted decisions land here, in workbook
        # order. The error path mirrors the original per-CCI try/except —
        # exceptions caught inside the worker surface as an unresolved
        # decision with ``error`` set so the UI can flag it for manual
        # triage.
        for item, decision, exc in results:
            bo, obj, row, _ev, _epoch = item
            if exc is not None or decision is None:
                # Worker raised (infra failure: LLM timeout, network, parse
                # crash) or returned no Decision. This is deliberately NOT
                # persisted: an exception is not an assessment verdict, and
                # leaving no Assessment row means a re-run with
                # ``skip_existing=true`` retries it instead of treating the
                # transient failure as a permanent NON_COMPLIANT. The CCI is
                # not silently dropped — the entry below carries ``error`` so
                # the UI's "Worker errored — re-run these" section surfaces it.
                # (The genuine silent-drop bug,
                # feedback_abstain_status_none_drops.md, is the hard-abstain
                # path — a real Decision with status=None — which is coerced +
                # persisted in the ``decision.accepted`` branch below, not
                # here.)
                unresolved_count += 1
                decisions.append(
                    {
                        "objective_id": obj.objective_id,
                        "excel_row": row.excel_row,
                        "accepted": False,
                        "status": None,
                        "narrative": None,
                        "narrative_on_prem": None,
                        "narrative_cloud": None,
                        "narrative_class": NarrativeClass.AMBIGUOUS.value,
                        "source": None,
                        "rule": None,
                        "retries": 0,
                        "rejections": [],
                        "supersession_hits": [],
                        "needs_review": False,
                        "review_reason": None,
                        "confidence": None,
                        "rewrite_requested": False,
                        "rewrite_requested_refs": None,
                        "error": f"{type(exc).__name__}: {exc}" if exc else "no_decision",
                        "source_warnings": list(_ev.source_warnings),
                    }
                )
                continue
            if decision.accepted:
                accepted_count += 1
                # Gate widened (feedback_abstain_status_none_drops.md): see
                # the single-control site above for the full rationale. Hard
                # abstains (status=None, narrative=None) are coerced via
                # ``_coerce_abstain_persistence_fields`` so they land as
                # NON_COMPLIANT + placeholder with needs_review=True,
                # surfacing them in the reviewer queue instead of being
                # silently dropped. Soft abstains pass through untouched.
                if body.persist:
                    status_to_persist, narrative_to_persist = (
                        _coerce_abstain_persistence_fields(decision)
                    )
                    existing = s.exec(
                        select(Assessment).where(
                            Assessment.workbook_id == body.workbook_id,
                            Assessment.objective_id == obj.id,
                        )
                    ).first()
                    when = datetime.now(timezone.utc)
                    nc = decision.narrative_class
                    # v0.2 citation-hygiene: rewrite_requested rides as a
                    # workflow note, NOT a verdict block. Stored as JSON
                    # array of [legacy, current] pairs (TEXT column).
                    # See Assessment.rewrite_requested in models.py and
                    # the demote logic in engine/assessor.py for context.
                    rw_refs = (
                        json.dumps(
                            [[lg, cu] for (lg, cu) in decision.rewrite_requested_refs]
                        )
                        if decision.rewrite_requested_refs
                        else None
                    )
                    # v0.2 patent-supporting provenance tag — see
                    # _decision_to_verdict_source for the single source-of-truth
                    # mapping that both Assessment-write sites share.
                    verdict_src = _decision_to_verdict_source(decision)
                    # v0.2 dual-narrative advisory mirror (batch site —
                    # same contract as the single-control site above).
                    dual_flags = list(
                        getattr(decision, "dual_narrative_flags", []) or []
                    )
                    dual_flagged_bool = bool(dual_flags)
                    dual_flags_json = (
                        json.dumps(dual_flags) if dual_flagged_bool else None
                    )
                    if existing:
                        existing.status = status_to_persist
                        existing.tester = tester
                        existing.narrative_q = narrative_to_persist
                        existing.narrative_on_prem = decision.narrative_on_prem
                        existing.narrative_cloud = decision.narrative_cloud
                        existing.narrative_class = nc
                        existing.inheritance_rule = decision.rule
                        existing.excel_row = decision.excel_row
                        existing.date_tested = when
                        # v0.2 precision-over-recall: carry the abstain
                        # triage signal onto the row so export gates can
                        # refuse it and the UI can render the Review pill.
                        existing.needs_review = decision.needs_review
                        existing.review_reason = decision.review_reason
                        existing.confidence = decision.confidence
                        existing.rewrite_requested = decision.rewrite_requested
                        existing.rewrite_requested_refs = rw_refs
                        existing.verdict_source = verdict_src
                        existing.dual_narrative_flagged = dual_flagged_bool
                        existing.dual_narrative_flag_reasons = dual_flags_json
                        # Audit v1: stamp run_id so an auditor can replay
                        # the whole batch as a unit.
                        existing.run_id = rec.run_id
                        # v0.2 multi-implementation write path — same helper
                        # the single-control site and crm_backfill use, so a
                        # control covered by N CRMs (+ synthesized On-Premises
                        # slice) persists N AssessmentImplementation children
                        # and a rolled-up parent. The helper flushes (assigns
                        # the PK) but never commits — the single batched
                        # ``s.commit()`` in the finally block stays the
                        # transaction boundary, matching the prior s.flush()
                        # behavior. Abstain rows keep their coerced parent
                        # fields. control_id is the OSCAL canonical id.
                        persisted_pk = persist_assessment_with_impls(
                            s,
                            assessment=existing,
                            decision=decision,
                            crm_context=crm_context,
                            control_id=row.control_id,
                            is_new=False,
                        )
                        _persist_audit_trail(
                            s, assessment_id=persisted_pk, decision=decision
                        )
                    else:
                        new_row = Assessment(
                            workbook_id=body.workbook_id,
                            objective_id=obj.id,
                            excel_row=decision.excel_row,
                            status=status_to_persist,
                            tester=tester,
                            narrative_q=narrative_to_persist,
                            narrative_on_prem=decision.narrative_on_prem,
                            narrative_cloud=decision.narrative_cloud,
                            narrative_class=nc,
                            inheritance_rule=decision.rule,
                            date_tested=when,
                            needs_review=decision.needs_review,
                            review_reason=decision.review_reason,
                            confidence=decision.confidence,
                            rewrite_requested=decision.rewrite_requested,
                            rewrite_requested_refs=rw_refs,
                            verdict_source=verdict_src,
                            dual_narrative_flagged=dual_flagged_bool,
                            dual_narrative_flag_reasons=dual_flags_json,
                            # Audit v1: see existing branch above.
                            run_id=rec.run_id,
                        )
                        # v0.2 multi-implementation write path — see the
                        # existing-row branch above. INSERT skips the
                        # prior-impl delete (is_new=True). Commit stays
                        # batched in finally.
                        persisted_pk = persist_assessment_with_impls(
                            s,
                            assessment=new_row,
                            decision=decision,
                            crm_context=crm_context,
                            control_id=row.control_id,
                            is_new=True,
                        )
                        _persist_audit_trail(
                            s, assessment_id=persisted_pk, decision=decision
                        )
                    persisted_count += 1
                    if decision.needs_review:
                        abstained_count += 1
            else:
                unresolved_count += 1

            decisions.append(
                {
                    "objective_id": obj.objective_id,
                    "excel_row": decision.excel_row,
                    "accepted": decision.accepted,
                    "status": decision.status.value if decision.status else None,
                    "narrative": decision.narrative,
                    # Visual multi-boundary form of column Q (labeled per-scope
                    # block); None for single-boundary rows. Mirrors persisted
                    # narrative_q. See single-control handler for rationale.
                    "narrative_stitched": stitch_scope_narrative(
                        decision.narratives_by_scope
                    ),
                    "narrative_on_prem": decision.narrative_on_prem,
                    "narrative_cloud": decision.narrative_cloud,
                    "narrative_class": decision.narrative_class.value,
                    "source": decision.source,
                    "rule": decision.rule,
                    "retries": decision.retries,
                    "rejections": [
                        {
                            "reason": r.rejection_class,
                            "context": r.corrective_context,
                        }
                        for r in decision.rejection_log
                    ],
                    "supersession_hits": [
                        {"stale": h.stale_ref, "current": h.current_ref}
                        for h in decision.supersession_log
                    ],
                    # v0.2 precision-over-recall surface: UI uses these to
                    # render the Review pill and review_reason callout
                    # without an extra GET round-trip.
                    "needs_review": decision.needs_review,
                    "review_reason": decision.review_reason,
                    "confidence": decision.confidence,
                    # v0.2 citation-hygiene surface (not an abstain). Lets the
                    # UI render an info badge + the (legacy → current) pair
                    # list without re-querying the row.
                    "rewrite_requested": decision.rewrite_requested,
                    "rewrite_requested_refs": (
                        [list(p) for p in decision.rewrite_requested_refs]
                        if decision.rewrite_requested_refs
                        else None
                    ),
                    # Bug 11: per-source degrade warnings. Non-empty when
                    # one evidence source failed but the CCI was still
                    # assessed with whatever survived. Empty list = clean.
                    "source_warnings": list(_ev.source_warnings),
                }
            )
    finally:
        # Aggregate cost ONCE on the whole batch's accumulated tokens.
        # Cache reads stay split so pricing applies the ~10% cache rate
        # instead of full input price (~10x cost inflation otherwise).
        total_in = sum(o.input_tokens for o in rec._outcomes)
        total_out = sum(o.output_tokens for o in rec._outcomes)
        total_cache_read = sum(o.cache_read_tokens for o in rec._outcomes)
        cost = compute_cost(
            active_model_id(cfg),
            input_tokens=total_in,
            output_tokens=total_out,
            cache_read_tokens=total_cache_read,
        )
        rec.finish(cost_usd=cost)
        if body.persist:
            # CRM short-circuit audit trail (Gap A): persist one
            # CrmShortCircuitEvent per outcome whose kernel decision was
            # short-circuited by the CRM (provider/inherited/NA). Helper
            # iterates rec.outcomes and skips entries with no short-circuit.
            #
            # Bug #3: every Phase-3 row write was flushed but not committed
            # — the whole batch commits exactly once here. A failure at this
            # single point (e.g. a late IntegrityError, disk/lock error)
            # previously propagated out of the route as a 500: the UI got an
            # error, the grid rendered empty, and ZERO of the (possibly 300)
            # assessed rows persisted. We now contain the failure: rollback,
            # zero the persisted/abstained counters (the rollback undid every
            # flushed row, so reporting them would lie), and report
            # ``persist_error`` in the 200 payload so the grid still renders
            # the in-memory decisions and the operator can retry the save.
            try:
                _persist_crm_short_circuits(
                    s, workbook_id=body.workbook_id, outcomes=rec.outcomes
                )
                s.commit()
            except Exception as commit_exc:  # noqa: BLE001 - reported, not swallowed
                s.rollback()
                persist_error = str(commit_exc)
                persisted_count = 0
                abstained_count = 0
                _log.error(
                    "assess-batch commit failed for workbook %s: %s",
                    body.workbook_id,
                    persist_error,
                )
        # Clear the progress slot regardless of how the batch exited. A
        # mid-batch raise would otherwise leave a stale row that the next
        # UI poll interprets as "still running" until the next batch
        # registers and overwrites it.
        _batch_progress.finish(body.workbook_id)

    return {
        "run_id": rec.run_id,
        "workbook_id": body.workbook_id,
        "baseline_id": baseline.id,
        "assessed": len(decisions),
        "accepted": accepted_count,
        "unresolved": unresolved_count,
        "persisted": persisted_count,
        "abstained": abstained_count,
        "skipped": skipped,
        "cost_usd": cost,
        "tokens": {
            "input": total_in,
            "output": total_out,
            "cache_read": total_cache_read,
        },
        # Bug #3: None on the happy path; a string when the batched commit
        # failed and was rolled back. The UI renders the in-memory grid plus
        # a "results not saved — retry" banner instead of an empty error.
        "persist_error": persist_error,
        "decisions": decisions,
    }


@router.get("/assess-batch/progress")
def get_assess_batch_progress(workbook_id: int) -> dict:
    """Snapshot of the in-flight ``/assess-batch`` for ``workbook_id``.

    Returns ``{"active": false}`` when no batch is running, or
    ``{"active": true, ...counters}`` when one is. The UI polls this on a
    short interval (see ``useAssessBatchProgress`` in queries.ts) while
    the assess-batch mutation is pending so the progress bar can move
    instead of showing only the indeterminate spinner.

    Read-only, no session needed — the tracker lives in process memory.
    """
    snap = _batch_progress.snapshot(workbook_id)
    if snap is None:
        return {"active": False}
    return {"active": True, **snap}


@router.get("/assessments/{assessment_id}/audit")
def get_assessment_audit(
    assessment_id: int, s: Session = Depends(get_session)
) -> dict:
    """Verdict→evidence audit trail for a single Assessment (Audit v1).

    Returns the literal prompt the LLM saw, the literal evidence chunks it
    received, model + version + temperature + raw_response_json for replay,
    and any per-claim citations (empty unless ``audit_citations_enabled``
    was on at decision time).

    Short-circuit verdicts (rule_8a/8b/8c, CRM, deterministic abstain)
    legitimately return empty ``trace`` and ``evidence_shown`` — no LLM
    call was made and no per-objective evidence was rendered. The route
    layer returns 200 with empty arrays in that case so the UI can render
    a "no LLM trace — deterministic verdict" banner instead of erroring.

    Read-only — sidecar binds 127.0.0.1 so no auth changes needed.
    """
    assessment = s.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    traces = s.exec(
        select(AssessmentTrace)
        .where(AssessmentTrace.assessment_id == assessment_id)
        .order_by(AssessmentTrace.pass_index)
    ).all()

    # Dedup system prompts by sha — single-pass has 1 sha, dual-pass also
    # has 1 (both passes use the same system prompt). Hash-keyed dict keeps
    # the response shape stable if a future variant uses different prompts
    # per pass.
    system_prompts: dict[str, dict] = {}
    for tr in traces:
        if tr.system_prompt_sha in system_prompts:
            continue
        snap = s.get(PromptSnapshot, tr.system_prompt_sha)
        if snap is not None:
            system_prompts[snap.sha256] = {
                "sha256": snap.sha256,
                "text": snap.text,
                "prompt_kind": snap.prompt_kind,
            }

    # Join Evidence for title + canonical path so the UI Audit trail card can
    # render "{evidence title} • sha={short} • order #N • relevance" per the
    # Audit v1 plan. Left join — an Evidence row may be hard-deleted later
    # but its trace snapshot must still display (auditors care about what the
    # model saw, not whether the file still exists).
    evidence_rows = s.exec(
        select(AssessmentEvidenceShown, Evidence.title, Evidence.path)
        .join(
            Evidence,
            Evidence.id == AssessmentEvidenceShown.evidence_id,
            isouter=True,
        )
        .where(AssessmentEvidenceShown.assessment_id == assessment_id)
        .order_by(AssessmentEvidenceShown.order_index)
    ).all()

    citations = s.exec(
        select(AssessmentCitation)
        .where(AssessmentCitation.assessment_id == assessment_id)
        .order_by(AssessmentCitation.id)
    ).all()

    return {
        "assessment_id": assessment_id,
        "run_id": assessment.run_id,
        "trace": [
            {
                "id": tr.id,
                "pass_index": tr.pass_index,
                "system_prompt_sha": tr.system_prompt_sha,
                "user_message": tr.user_message,
                "model": tr.model,
                "anthropic_model_version": tr.anthropic_model_version,
                "temperature": tr.temperature,
                "max_tokens": tr.max_tokens,
                "request_id": tr.request_id,
                "raw_response_json": tr.raw_response_json,
                "input_tokens": tr.input_tokens,
                "output_tokens": tr.output_tokens,
                "cache_read_tokens": tr.cache_read_tokens,
                "created_at": iso_utc(tr.created_at),
            }
            for tr in traces
        ],
        "system_prompts": list(system_prompts.values()),
        "evidence_shown": [
            {
                "id": e.id,
                "evidence_id": e.evidence_id,
                "evidence_title": ev_title,
                "evidence_path": ev_path,
                "chunk_sha": e.chunk_sha,
                "chunk_text": e.chunk_text,
                "order_index": e.order_index,
                "relevance": e.relevance,
                "tag_source": e.tag_source,
            }
            for (e, ev_title, ev_path) in evidence_rows
        ],
        "citations": [
            {
                "id": c.id,
                "narrative_field": c.narrative_field,
                "claim_text": c.claim_text,
                "claim_start_char": c.claim_start_char,
                "claim_end_char": c.claim_end_char,
                "evidence_shown_id": c.evidence_shown_id,
                "source_quote": c.source_quote,
                "source_start_char": c.source_start_char,
                "source_end_char": c.source_end_char,
                "extraction_method": c.extraction_method,
            }
            for c in citations
        ],
    }


class ApplyToWorkbookBody(BaseModel):
    assessment_id: int
    close: bool = False  # leave workbook open by default so user can review


@router.post("/assessments/apply")
def apply_assessment_to_workbook(
    body: ApplyToWorkbookBody, s: Session = Depends(get_session)
) -> dict:
    """Write the persisted assessment back into the CCIS workbook (cols N/O/P/Q).

    Uses xlwings so comments, named ranges, merged cells, data validation,
    and conditional formatting are preserved. The workbook is left open in
    Excel by default; pass ``close=true`` to close after saving.
    """
    a = s.get(Assessment, body.assessment_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    # v0.2 precision-over-recall hard gate. UI's Apply-to-workbook button
    # is disabled on needs_review rows; this 409 catches stale clients and
    # direct curl. An abstained verdict must not silently land in the
    # workbook — that would defeat the entire abstain mechanism.
    if a.needs_review:
        raise HTTPException(
            status_code=409,
            detail=(
                "Assessment is flagged needs_review and cannot be applied to the "
                "workbook. Resolve the review (manually edit the status/narrative "
                "to clear the abstain) before applying."
            ),
        )

    wb = s.get(Workbook, a.workbook_id)
    if wb is None:
        raise HTTPException(status_code=404, detail="Workbook not found")

    # Direct writes to the user's original .xlsx are deliberately impossible
    # here -- we redirect to a "<stem>_edited<ext>" working copy under the
    # program's working_copies/<wb_id>/ directory so a mistaken Apply can
    # never corrupt the customer-supplied workbook (typically still sitting
    # in Downloads or a OneDrive evidence drop). See excel/working_copy.py
    # for the lazy-create / re-anchor rules.
    try:
        wb_path = get_or_create_working_copy(wb, s)
    except FileNotFoundError as e:
        raise HTTPException(status_code=410, detail=str(e)) from e

    try:
        summary = ccis_writer.write_single(
            wb_path,
            excel_row=a.excel_row,
            status=a.status,
            date_tested=a.date_tested,
            tester=a.tester,
            results=a.narrative_q,
            rewrite_requested=getattr(a, "rewrite_requested", False),
            rewrite_requested_refs=getattr(a, "rewrite_requested_refs", None),
            save=True,
            close=body.close,
        )
    except PermissionError as e:
        # Working copy is open in Excel — the atomic move at the end of
        # xlsx_surgery can't replace a file the OS has handed an exclusive
        # lock to. Surface this as 423 Locked with a user-actionable
        # message so the UI toast can say "close Excel and try again"
        # instead of a generic 500. Logged so the sidecar log still has the
        # trace if the user reports it.
        _log.warning("apply-single: workbook locked: %s", e)
        raise HTTPException(
            status_code=423,
            detail=(
                f"Workbook working copy is locked (likely open in Excel): "
                f"{wb_path.name}. Close the file and try again."
            ),
        ) from e
    except RuntimeError as e:
        # xlwings/Excel unavailable
        raise HTTPException(status_code=503, detail=str(e)) from e
    except FileNotFoundError as e:
        raise HTTPException(status_code=410, detail=str(e)) from e
    except ValueError as e:
        # No WORKING SHEET found, etc.
        raise HTTPException(status_code=422, detail=str(e)) from e

    a.written_to_workbook_at = _utcnow()
    s.add(a)
    s.commit()
    s.refresh(a)

    return {
        "ok": True,
        "assessment_id": a.id,
        "written_to_workbook_at": iso_utc(a.written_to_workbook_at),
        "summary": summary,
    }


class ApplyBatchBody(BaseModel):
    """Bulk-apply request body.

    ``workbook_id`` is required; ``family`` and ``assessment_ids`` are optional
    narrowing filters that mirror the Controls grid filter state so the user's
    "Apply N to workbook" click writes exactly the rows they're looking at.

    ``skip_written`` defaults True so re-clicking the button after a partial
    apply is idempotent — already-stamped rows are silently skipped.
    """

    workbook_id: int
    family: str | None = None
    assessment_ids: list[int] | None = None
    skip_written: bool = True
    close: bool = False


@router.post("/assessments/apply-batch")
def apply_assessments_batch_to_workbook(
    body: ApplyBatchBody, s: Session = Depends(get_session)
) -> dict:
    """Bulk-write all writable assessments for a workbook in ONE xlwings session.

    Backend payoff for the "Apply N to workbook" button: opens the workbook
    once, walks every selected Assessment row, dispatches a single
    ``ccis_writer.write_assessment`` call with the full ``CcisWrite`` iterable,
    saves once, and stamps ``written_to_workbook_at`` on every row that landed.
    Compared to N round-trips of the single-row endpoint this is one Excel
    open/save/close cycle instead of N — orders of magnitude faster on a
    50-CCI family rollup.

    Precision-over-recall posture matches single-row apply but with bulk
    semantics: ``needs_review`` rows are SILENTLY SKIPPED (not 409'd) because
    "apply 47 of 52" is the expected outcome of a bulk operation; the
    abstained-five just stay unwritten and surface in the returned
    ``skipped_needs_review`` count. The UI already disables Apply on
    needs_review rows in the per-control view, so the user has already seen
    that gate before reaching here.
    """
    wb = s.get(Workbook, body.workbook_id)
    if wb is None:
        raise HTTPException(status_code=404, detail="Workbook not found")

    # Build the candidate set — workbook scope is mandatory, family /
    # assessment_ids are optional narrowing filters that mirror the
    # Controls grid filter state in the UI.
    stmt = select(Assessment).where(Assessment.workbook_id == body.workbook_id)
    if body.assessment_ids:
        stmt = stmt.where(Assessment.id.in_(body.assessment_ids))  # type: ignore[attr-defined]
    if body.family:
        # Family lives on Control, two joins away through Objective.
        stmt = (
            stmt.join(Objective, Objective.id == Assessment.objective_id)
            .join(Control, Control.id == Objective.control_id_fk)
            .where(Control.family == body.family.upper())
        )

    candidates: list[Assessment] = list(s.exec(stmt))

    # Partition into write / skip buckets so the response can explain
    # exactly why each row was or wasn't applied. The UI toast surfaces
    # these counters so the user knows "47 written, 3 abstained, 2 already
    # applied" without opening Excel.
    to_write: list[Assessment] = []
    skipped_needs_review = 0
    skipped_already_written = 0
    skipped_no_excel_row = 0
    for a in candidates:
        if a.needs_review:
            skipped_needs_review += 1
            continue
        if body.skip_written and a.written_to_workbook_at is not None:
            skipped_already_written += 1
            continue
        if a.excel_row is None:
            # Assessment was written against an Objective that never resolved
            # to a CCIS row (e.g. SOC 1 / non-CCIS framework). Bulk-apply is
            # CCIS-only — surface the skip rather than crashing the writer.
            skipped_no_excel_row += 1
            continue
        to_write.append(a)

    if not to_write:
        # Nothing to do — return the diagnostics so the UI toast can say
        # "0 written (3 abstained, 2 already applied)" instead of a generic
        # success state that hides the no-op.
        return {
            "ok": True,
            "workbook_id": body.workbook_id,
            "applied": 0,
            "skipped_needs_review": skipped_needs_review,
            "skipped_already_written": skipped_already_written,
            "skipped_no_excel_row": skipped_no_excel_row,
            "summary": None,
        }

    # Same working-copy redirect as the single-row endpoint — bulk writes
    # MUST NOT touch the customer-supplied original. See
    # excel/working_copy.py for the lazy-create / re-anchor rules.
    try:
        wb_path = get_or_create_working_copy(wb, s)
    except FileNotFoundError as e:
        raise HTTPException(status_code=410, detail=str(e)) from e

    writes = [
        ccis_writer.CcisWrite(
            excel_row=a.excel_row,  # type: ignore[arg-type]  -- partitioned above
            status=a.status,
            date_tested=a.date_tested,
            tester=a.tester,
            results=a.narrative_q,
            rewrite_requested=getattr(a, "rewrite_requested", False),
            rewrite_requested_refs=getattr(a, "rewrite_requested_refs", None),
        )
        for a in to_write
    ]

    try:
        summary = ccis_writer.write_assessment(
            wb_path,
            writes,
            save=True,
            close=body.close,
        )
    except PermissionError as e:
        # Working copy is open in Excel — same root cause as the single-row
        # endpoint. Map to 423 Locked with the same actionable message
        # rather than letting it bubble to a CORS-stripping raw 500.
        _log.warning("apply-batch: workbook locked: %s", e)
        raise HTTPException(
            status_code=423,
            detail=(
                f"Workbook working copy is locked (likely open in Excel): "
                f"{wb_path.name}. Close the file and try again."
            ),
        ) from e
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except FileNotFoundError as e:
        raise HTTPException(status_code=410, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    # Stamp every assessment we handed to the writer. The writer's own
    # ``skipped_needs_review`` defensive counter SHOULD be zero here because
    # we already filtered, but if it isn't, only stamp the ones that
    # actually wrote rows — we know that from ``summary["rows_written"]``
    # matching ``len(to_write)`` minus the writer's defensive skips.
    writer_skipped = int(summary.get("skipped_needs_review", 0))  # type: ignore[arg-type]
    now = _utcnow()
    applied = 0
    if writer_skipped == 0:
        # Common path — every queued row landed in the workbook.
        for a in to_write:
            a.written_to_workbook_at = now
            s.add(a)
            applied += 1
    else:
        # Defensive path — writer dropped some rows after we partitioned.
        # We don't know which specific rows it dropped (the writer reports
        # a count, not ids), so leave timestamps alone for safety. The
        # cells_changed surface still tells the user how much actually
        # made it in.
        applied = max(0, len(to_write) - writer_skipped)

    s.commit()

    return {
        "ok": True,
        "workbook_id": body.workbook_id,
        "applied": applied,
        "skipped_needs_review": skipped_needs_review + writer_skipped,
        "skipped_already_written": skipped_already_written,
        "skipped_no_excel_row": skipped_no_excel_row,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Controls export — eMASS-strict and working-view
# ---------------------------------------------------------------------------
#
# Two POST endpoints, both writing xlsx. The eMASS-strict path copies a
# user-supplied template (POAM-style: operator picks the path), preserves the
# 29 sibling tabs, and writes one row per in-scope control with the multi-line
# status rollup. The working-view path emits a fresh openpyxl xlsx with one
# row per OBJECTIVE so the assessor can review needs_review / abstain rows
# alongside the trusted ones — never an eMASS deliverable.
#
# Both return the same ControlExportResultDto so the UI modal can render
# "N rows written, M with PSC mappings, 0 skipped" identically.


from ..controls.exporter import (  # noqa: E402  -- avoid circular import at top
    ControlsFilterState,
    export_controls_to_emass,
    export_controls_working_view,
)


class ControlExportResultDto(BaseModel):
    """Wire-format mirror of ``controls.exporter.ControlExportResult``.

    ``skipped`` is a list of ``[control_acronym, reason]`` pairs (Pydantic
    rejects raw tuples in JSON output, so we widen to ``list[list[str]]``).
    """

    output_path: str
    rows_written: int
    controls_with_psc: int
    skipped: list[list[str]]
    template_warnings: list[str]


class _ControlsExportEmassBody(BaseModel):
    workbook_id: int
    template_path: str
    output_path: str


class _ControlsExportWorkingBody(BaseModel):
    workbook_id: int
    output_path: str
    # Filter state mirrors the Controls list page. Nulls mean "no filter"
    # — matches the UI's "All" rows in each dropdown.
    family: str | None = None
    status: str | None = None
    search: str | None = None


@router.post("/export/emass", response_model=ControlExportResultDto)
def export_controls_emass(
    body: _ControlsExportEmassBody,
    s: Session = Depends(get_session),
) -> ControlExportResultDto:
    """Write in-scope controls into a copy of the user's eMASS template.

    Copies ``template_path`` → ``output_path``, inserts a Program-Specific
    Controls column right after Control Acronym (idempotent — re-export
    onto the same file detects the existing header and skips the insert),
    and writes one row per in-scope control with the multi-line status
    rollup. Stamps ``Workbook.exported_at`` on success so the Controls
    list header can render the "Exported <timestamp>" badge.

    Maps exporter exceptions:
      - ``Workbook`` lookup miss → 404
      - missing template / unreachable output dir → 410
      - workbook has no Baseline → 422
      - xlwings/Excel unavailable → 503
    """
    try:
        result = export_controls_to_emass(
            session=s,
            workbook_id=body.workbook_id,
            template_path=body.template_path,
            output_path=body.output_path,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=410, detail=str(e)) from e
    except ValueError as e:
        # Surfaces "Workbook {id} not found", "has no Baseline", or
        # "Template missing a Control Acronym column" — all 422-shaped
        # operator-fixable conditions.
        detail = str(e)
        status = 404 if "not found" in detail.lower() else 422
        raise HTTPException(status_code=status, detail=detail) from e
    except RuntimeError as e:
        # xlwings raises RuntimeError when Excel isn't installed/reachable.
        raise HTTPException(status_code=503, detail=str(e)) from e

    return ControlExportResultDto(
        output_path=result.output_path,
        rows_written=result.rows_written,
        controls_with_psc=result.controls_with_psc,
        skipped=[[a, r] for (a, r) in result.skipped],
        template_warnings=result.template_warnings,
    )


from ..excel.narrative_importer import (  # noqa: E402  -- avoid circular import
    import_narratives,
)


class NarrativeImportResultDto(BaseModel):
    """Wire-format mirror of ``excel.narrative_importer.NarrativeImportResult``.

    The three skip buckets are lists of CCI ids so the operator can
    reconcile the import file against the workbook's in-scope set.
    """

    output_path: str
    total_rows: int
    imported: int
    updated: int
    unmatched: list[str]
    skipped_no_status: list[str]
    skipped_no_narrative: list[str]


class _ControlsImportNarrativesBody(BaseModel):
    workbook_id: int
    file_path: str


@router.post("/import/narratives", response_model=NarrativeImportResultDto)
def import_controls_narratives(
    body: _ControlsImportNarrativesBody,
    s: Session = Depends(get_session),
) -> NarrativeImportResultDto:
    """Upsert Assessments from an operator-filled eMASS Test Result template.

    "Import only" — reads column N (status) / P (tester) / O (date) / Q
    (narrative) per CCI, matches each to an in-scope Objective, and writes
    the verdict as an ``IMPORTED`` Assessment with ``needs_review=False`` so
    Non-Compliant rows flow straight into the existing Generate POAMs step.
    No LLM, no kernel, no POAM generation here.

    Maps importer exceptions:
      - ``Workbook`` lookup miss / missing Baseline / unparseable file → 404/422
      - import file or workbook file gone → 410
    """
    try:
        result = import_narratives(
            session=s,
            workbook_id=body.workbook_id,
            file_path=body.file_path,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=410, detail=str(e)) from e
    except ValueError as e:
        detail = str(e)
        status = 404 if "not found" in detail.lower() else 422
        raise HTTPException(status_code=status, detail=detail) from e

    return NarrativeImportResultDto(
        output_path=result.output_path,
        total_rows=result.total_rows,
        imported=result.imported,
        updated=result.updated,
        unmatched=result.unmatched,
        skipped_no_status=result.skipped_no_status,
        skipped_no_narrative=result.skipped_no_narrative,
    )


@router.post("/export/working", response_model=ControlExportResultDto)
def export_controls_working(
    body: _ControlsExportWorkingBody,
    s: Session = Depends(get_session),
) -> ControlExportResultDto:
    """Emit a fresh xlsx mirroring the current Controls list view.

    One row per objective (not per control) so needs_review / abstain rows
    are visible. Honors the same filter state the UI page uses. Never
    stamps ``Workbook.exported_at`` — this is a working artifact, not an
    eMASS deliverable.
    """
    filter_state = ControlsFilterState(
        family=body.family,
        status=body.status,
        search=body.search,
    )
    try:
        result = export_controls_working_view(
            session=s,
            workbook_id=body.workbook_id,
            output_path=body.output_path,
            filter_state=filter_state,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=410, detail=str(e)) from e
    except ValueError as e:
        detail = str(e)
        status = 404 if "not found" in detail.lower() else 422
        raise HTTPException(status_code=status, detail=detail) from e

    return ControlExportResultDto(
        output_path=result.output_path,
        rows_written=result.rows_written,
        controls_with_psc=result.controls_with_psc,
        skipped=[[a, r] for (a, r) in result.skipped],
        template_warnings=result.template_warnings,
    )
