"""CCIS workbook endpoints.

Opening a workbook is now a two-step thing under the hood:

  1. Record the workbook (path + filename) so the UI can list it.
  2. If a framework is bound, run the :class:`CcisWorkbookBaselineSource`
     adapter to (a) enrich Objective rows with CCI text from the
     workbook, and (b) materialize a Baseline that says which CCIs are
     in scope for this system.

We deliberately do NOT auto-pick a framework when multiple are loaded —
rev4 vs rev5 catalogs both register as Frameworks and the workbook may
target either. The caller must supply ``framework_id`` (the UI prompts
when ambiguous; future work: detect from workbook metadata).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, func, update
from sqlmodel import Session, select

from ..baselines import CcisWorkbookBaselineSource
from ..db import chunked, get_session
from ..engine.crm_backfill import backfill_workbook_crm, backfill_workbook_rules
from ..excel.ccis_reader import read_workbook_summary
from ..models import (
    Assessment,
    AssessmentCitation,
    AssessmentEvidenceShown,
    AssessmentRun,
    AssessmentTrace,
    Asset,
    AutomationSchedule,
    Baseline,
    BaselineControl,
    BaselineSourceType,
    BoundarySegment,
    ComplianceStatus,
    Component,
    Control,
    CrmCorpusFeatures,
    CrmShortCircuitEvent,
    CrmSuspicionLog,
    Evidence,
    EvidenceAsset,
    EvidenceBoundary,
    EvidenceRetentionEvent,
    Framework,
    Objective,
    OverrideEpoch,
    Poam,
    PoamEvidence,
    PoamMilestone,
    PoamObjective,
    RequirementMap,
    RequirementSource,
    StigFinding,
    SweepDecision,
    SweepRun,
    SystemContext,
    Workbook,
    WorkbookOverlay,
    WorkbookSyncEvent,
    iso_utc,
)
from .baselines import compute_and_persist_crm_suspicion
from .evidence import _serialize as _serialize_evidence
from .system_context import promote_pending_to_workbook

router = APIRouter(prefix="/api/workbooks", tags=["workbooks"])

_log = logging.getLogger(__name__)


class WorkbookCreate(BaseModel):
    path: str
    framework_id: int | None = None  # explicit — see module docstring


@router.get("")
def list_workbooks(s: Session = Depends(get_session)) -> list[dict]:
    rows = s.exec(select(Workbook).order_by(Workbook.last_opened.desc())).all()
    # One pass to pull every attached overlay so the response stays N+1-free.
    overlay_rows = s.exec(
        select(WorkbookOverlay.workbook_id, WorkbookOverlay.baseline_id)
    ).all()
    overlays_by_wb: dict[int, list[int]] = {}
    for wb_id, bl_id in overlay_rows:
        overlays_by_wb.setdefault(wb_id, []).append(bl_id)
    return [
        {
            "id": w.id,
            "path": w.path,
            "filename": w.filename,
            "framework_id": w.framework_id,
            "baseline_id": w.baseline_id,
            "overlay_baseline_ids": overlays_by_wb.get(w.id, []),
            "last_opened": iso_utc(w.last_opened),
            "last_emass_import_at": iso_utc(w.last_emass_import_at),
            # None until the first Apply lazily clones the original into
            # "working_copies/<wb_id>/<stem>_edited<ext>" inside the program
            # dir. UI uses this to render the "Assessments → …_edited.xlsx"
            # hint under each row.
            "working_path": w.working_path,
            # v0.2 sweep-cap counter. UI banner reads this to render
            # "Sweep attempts: N of 2" and surface the Reset button at 2/2.
            "sweep_attempts": w.sweep_attempts or 0,
        }
        for w in rows
    ]


@router.post("")
def open_workbook(body: WorkbookCreate, s: Session = Depends(get_session)) -> dict:
    p = Path(body.path)
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"Workbook not found: {p}")

    existing = s.exec(select(Workbook).where(Workbook.path == str(p))).first()
    if existing:
        existing.last_opened = datetime.now(timezone.utc)
        wb = existing
    else:
        wb = Workbook(path=str(p), filename=p.name)
        s.add(wb)
        s.commit()
        s.refresh(wb)

    # Resolve framework: explicit body param wins, then the workbook's
    # last-bound framework. If neither is set we skip baseline-apply
    # rather than guess — the UI shows a "pick framework" prompt.
    framework_id = body.framework_id if body.framework_id is not None else wb.framework_id

    baseline_summary: dict | None = None
    if framework_id is not None:
        if not s.get(Framework, framework_id):
            raise HTTPException(
                status_code=400, detail=f"Framework id={framework_id} not loaded"
            )
        source = CcisWorkbookBaselineSource(
            workbook_path=p, name=p.stem, system_id=wb.system_id
        )
        result = source.apply(s, framework_id=framework_id)
        wb.framework_id = framework_id
        wb.baseline_id = result.baseline.id
        baseline_summary = {
            "id": result.baseline.id,
            "name": result.baseline.name,
            "source_type": result.baseline.source_type.value,
            "controls_in_scope": result.controls_in_scope,
            "controls_out_of_scope": result.controls_out_of_scope,
            "controls_unknown": result.controls_unknown,
            "objectives_seen": result.objectives_seen,
            "objectives_unknown": result.objectives_unknown,
            "notes": result.notes,
        }

    s.add(wb)
    s.commit()

    # No overlay auto-attach. Opening a workbook is side-effect-free at the
    # overlay layer: program-controls overlays attach ONLY when the user
    # explicitly attaches them via the Manage Overlays dialog. The previous
    # first-open auto-attach pulled in EVERY PROGRAM_CONTROLS baseline that
    # merely shared the framework (including unrelated demo overlays like
    # "Example Program …"), which surprised users and over-applied program
    # scope. This now mirrors program_controls_loader, which also no longer
    # auto-attaches on load.

    # Auto-promote pending pre-workbook SystemContext + boundary docs.
    # The assessor may have dropped SSP/diagram/ATO PDFs on the Sweep
    # Context page BEFORE picking a workbook — promote them now so the
    # docs land on this workbook automatically. Tolerant by design:
    # `no_pending` is the common case and we silently skip; `conflict`
    # means this workbook already has its own SystemContext, in which
    # case the pending row stays put for the user to promote elsewhere.
    # Frontend still calls /pending/promote explicitly as belt-and-
    # suspenders for the mid-session "open another workbook" path.
    pending_promotion: dict | None = None
    if wb.id is not None:
        promote_result = promote_pending_to_workbook(s, wb.id)
        if promote_result["status"] != "no_pending":
            pending_promotion = promote_result

    # Front-load deterministic RULE verdicts (rules.classify_row) so
    # workbook-intrinsic Compliant/Not-Applicable controls surface in the
    # Controls grid the moment the workbook is opened — without waiting for the
    # user to click Assess. The motivating case: a control marked Not
    # Applicable in workbook col N (e.g. AC-18 wireless scope-exclusion) had no
    # auto-writer and showed a blank chip. Idempotent + non-stomping: skips any
    # objective that already has an Assessment. Only runs once a baseline is
    # bound (need the in-scope objective set).
    rule_backfill: dict | None = None
    if wb.id is not None and wb.baseline_id is not None:
        rb = backfill_workbook_rules(wb.id, s)
        if rb.applied > 0:
            s.commit()
        rule_backfill = rb.as_dict()

    summary = read_workbook_summary(p)
    # NOTE: SQLModel's session.exec(select(Single.column)).all() returns
    # a list of bare scalars, not 1-tuples — destructuring with `(bl_id,)`
    # raises TypeError.
    overlay_ids = [
        bl_id
        for bl_id in s.exec(
            select(WorkbookOverlay.baseline_id).where(
                WorkbookOverlay.workbook_id == wb.id
            )
        ).all()
    ]
    return {
        "id": wb.id,
        "path": wb.path,
        "filename": wb.filename,
        "framework_id": wb.framework_id,
        "baseline_id": wb.baseline_id,
        "overlay_baseline_ids": overlay_ids,
        "last_opened": iso_utc(wb.last_opened),
        "last_emass_import_at": iso_utc(wb.last_emass_import_at),
        # Same field as list_workbooks — without it here, reopening a
        # workbook that already has an _edited.xlsx working copy would not
        # show the "Assessments → …" hint until the next full list refresh.
        "working_path": wb.working_path,
        # v0.2 sweep-cap counter — same field as list_workbooks. Without it
        # here, the first response after open_workbook would lack the counter
        # and the UI banner would flash "0 of 2" until the next list refresh.
        "sweep_attempts": wb.sweep_attempts or 0,
        "summary": summary,
        "baseline": baseline_summary,
        # Auto-promote outcome — None when nothing pending. UI uses this to
        # render a "boundary scope promoted onto this workbook" toast and
        # to invalidate the system-context + boundary-docs caches without
        # waiting for the explicit /pending/promote round-trip.
        "pending_promotion": pending_promotion,
        # Deterministic-rule backfill counts (None when no baseline bound).
        "rule_backfill": rule_backfill,
    }


class OverlayAttach(BaseModel):
    baseline_id: int
    note: str | None = None


@router.get("/{workbook_id}/overlays")
def list_workbook_overlays(
    workbook_id: int, s: Session = Depends(get_session)
) -> list[dict]:
    """Reference baselines attached to this workbook (read-only annotation).

    The workbook's *primary* baseline (``Workbook.baseline_id``) is the
    assessment scope — owned by assess_batch. Overlays returned here are
    FedRAMP / Li-SaaS / etc. profiles attached for gap-display only.
    """
    if not s.get(Workbook, workbook_id):
        raise HTTPException(status_code=404, detail="Workbook not found")

    rows = s.exec(
        select(WorkbookOverlay, Baseline)
        .join(Baseline, Baseline.id == WorkbookOverlay.baseline_id)
        .where(WorkbookOverlay.workbook_id == workbook_id)
        .order_by(WorkbookOverlay.attached_at)
    ).all()
    return [
        {
            "workbook_id": ov.workbook_id,
            "baseline_id": ov.baseline_id,
            "attached_at": iso_utc(ov.attached_at),
            "note": ov.note,
            "baseline": {
                "id": bl.id,
                "name": bl.name,
                "framework_id": bl.framework_id,
                "source_type": bl.source_type.value,
            },
        }
        for ov, bl in rows
    ]


@router.post("/{workbook_id}/overlays")
def attach_workbook_overlay(
    workbook_id: int, body: OverlayAttach, s: Session = Depends(get_session)
) -> dict:
    wb = s.get(Workbook, workbook_id)
    if not wb:
        raise HTTPException(status_code=404, detail="Workbook not found")
    bl = s.get(Baseline, body.baseline_id)
    if not bl:
        raise HTTPException(
            status_code=404, detail=f"Baseline id={body.baseline_id} not found"
        )
    # Don't let the assessment-write target double as a reference overlay —
    # it would just confuse the Controls grid and SAR appendix.
    if wb.baseline_id == body.baseline_id:
        raise HTTPException(
            status_code=409,
            detail="Baseline is already this workbook's primary scope",
        )
    existing = s.exec(
        select(WorkbookOverlay).where(
            WorkbookOverlay.workbook_id == workbook_id,
            WorkbookOverlay.baseline_id == body.baseline_id,
        )
    ).first()
    if existing:
        raise HTTPException(
            status_code=409, detail="Overlay already attached to this workbook"
        )
    ov = WorkbookOverlay(
        workbook_id=workbook_id, baseline_id=body.baseline_id, note=body.note
    )
    s.add(ov)
    s.commit()
    s.refresh(ov)

    # When the overlay is a CRM, immediately translate its deterministic
    # responsibilities (provider / inherited / not_applicable) into
    # Assessment rows so the Controls grid reflects the CRM verdict
    # without waiting for the user to click Assess. Hybrid + customer
    # rows are intentionally deferred to the LLM at assess time.
    backfill: dict[str, int] | None = None
    if bl.source_type == BaselineSourceType.CRM:
        result = backfill_workbook_crm(workbook_id, s)
        if result.applied > 0:
            s.commit()
        backfill = result.as_dict()
        # Auto-trigger adversarial-CRM scoring on attach (Gap B). Without
        # this, the suspicion banner never fires in the default path —
        # the UI only does a cache lookup on the latest log. Server-side
        # so headless attach paths (future SDK / CLI) also produce the
        # banner. Wrapped per ``engine/CRM_SANITY_DESIGN.md`` "don't crash
        # the report on ML failure": a TF-IDF / IsolationForest unpickle
        # failure must NOT 500 the attach response. Log and continue —
        # the user can retry compute via the manual endpoint.
        try:
            compute_and_persist_crm_suspicion(
                s, workbook_id=workbook_id, crm_baseline_id=bl.id
            )
        except Exception:
            _log.exception(
                "CRM suspicion auto-compute failed on attach "
                "(workbook_id=%s, crm_baseline_id=%s); attach succeeds, "
                "user can retry via GET /api/baselines/%s/crm-suspicion",
                workbook_id,
                bl.id,
                workbook_id,
            )
    elif bl.source_type == BaselineSourceType.OTHER:
        # OTHER overlays are intentionally inert: they register in the
        # attach UI (so the user can see the file is in play) but no
        # resolver runs against them during assessment. The CRM-backfill
        # / PSC-CCI-resolver paths simply don't fire because their
        # selects filter on source_type. Log once at INFO so operators
        # can see *why* nothing happened post-attach — easier than
        # debugging a silent no-op when someone reports "I attached the
        # overlay and nothing changed."
        _log.info(
            "overlay attached as OTHER kind; no resolver registered "
            "(workbook_id=%s, baseline_id=%s, name=%r); assessment will "
            "ignore this overlay",
            workbook_id,
            bl.id,
            bl.name,
        )

    return {
        "workbook_id": ov.workbook_id,
        "baseline_id": ov.baseline_id,
        "attached_at": iso_utc(ov.attached_at),
        "note": ov.note,
        "baseline": {
            "id": bl.id,
            "name": bl.name,
            "framework_id": bl.framework_id,
            "source_type": bl.source_type.value,
        },
        "backfill": backfill,
    }


@router.delete("/{workbook_id}/overlays/{baseline_id}")
def detach_workbook_overlay(
    workbook_id: int, baseline_id: int, s: Session = Depends(get_session)
) -> dict:
    ov = s.exec(
        select(WorkbookOverlay).where(
            WorkbookOverlay.workbook_id == workbook_id,
            WorkbookOverlay.baseline_id == baseline_id,
        )
    ).first()
    if not ov:
        raise HTTPException(status_code=404, detail="Overlay not attached")
    s.delete(ov)
    s.commit()
    return {"detached": True, "workbook_id": workbook_id, "baseline_id": baseline_id}


@router.delete("/{workbook_id}")
def delete_workbook(workbook_id: int, s: Session = Depends(get_session)) -> dict:
    """Delete a workbook and every workbook-owned row that hangs off it.

    SQLite has no ``ON DELETE CASCADE`` wired in our schema, so we hand-walk
    the fan-out. The split between *delete* and *NULL* is deliberate:

    **Hard-deleted** (workbook is the sole owner — these rows are meaningless
    without it):

      * ``Assessment`` and its children (``AssessmentTrace``,
        ``AssessmentEvidenceShown``, ``AssessmentCitation``). ``PromptSnapshot``
        is deliberately NOT in this list — it is a content-addressed dedup
        store keyed by sha256 and shared cross-workbook; deleting it would
        orphan traces in other workbooks.
      * ``AssessmentRun`` (run-level metadata, scoped to the workbook).
      * ``Poam`` and its children (``PoamObjective``, ``PoamEvidence``,
        ``PoamMilestone``).
      * ``SweepDecision`` / ``SweepRun`` (sweep state is per-workbook).
      * ``CrmSuspicionLog`` / ``CrmShortCircuitEvent`` / ``CrmCorpusFeatures``
        (CRM telemetry is workbook-scoped).
      * ``StigFinding``, ``Asset`` (with ``EvidenceAsset`` link rows),
        ``BoundarySegment`` (with ``EvidenceBoundary`` link rows).
      * ``WorkbookOverlay``, ``WorkbookSyncEvent``.

    **NULL'd, not deleted** (shared artifacts the user uploaded — must
    survive workbook removal so they remain available to other workbooks):

      * ``Evidence`` — the artifact pool is global. ``workbook_id`` is nulled,
        ``EvidenceTag`` rows stay intact and continue to surface in any other
        workbook with overlapping CCIs.
      * ``SystemContext`` — boundary description is reusable.

    Not touched: the workbook's auto-created ``Baseline`` (if any) and the
    on-disk working copy under ``working_copies/<wb_id>/``. The user clears
    those via the baseline delete endpoint and manually, respectively —
    silently deleting either is the kind of blast radius we want to confirm.

    Returns the per-table counts so the UI can render a confirmation toast.
    """
    wb = s.get(Workbook, workbook_id)
    if not wb:
        raise HTTPException(status_code=404, detail="Workbook not found")

    filename = wb.filename

    # Snapshot child PKs we need before deleting parents (so we can cascade
    # Trace / EvidenceShown / Citation off Assessment, and
    # PoamObjective / PoamEvidence / PoamMilestone off Poam, and the
    # EvidenceAsset / EvidenceBoundary link rows off Asset / BoundarySegment).
    assessment_ids = [
        row for row in s.exec(
            select(Assessment.id).where(Assessment.workbook_id == workbook_id)
        ).all()
    ]
    poam_ids = [
        row for row in s.exec(
            select(Poam.id).where(Poam.workbook_id == workbook_id)
        ).all()
    ]
    asset_ids = [
        row for row in s.exec(
            select(Asset.id).where(Asset.workbook_id == workbook_id)
        ).all()
    ]
    boundary_ids = [
        row for row in s.exec(
            select(BoundarySegment.id).where(BoundarySegment.workbook_id == workbook_id)
        ).all()
    ]
    # StigFinding has no workbook_id column — it hangs off Evidence. Snapshot
    # the Evidence ids attached to this workbook now so the StigFinding delete
    # below can filter by evidence_id. Evidence itself is NULL'd (not deleted)
    # further down, so this snapshot is the only chance to identify "the STIG
    # rows that belonged to this workbook's files".
    evidence_ids = [
        row for row in s.exec(
            select(Evidence.id).where(Evidence.workbook_id == workbook_id)
        ).all()
    ]

    counts: dict[str, int] = {}

    # --- Assessment + children -------------------------------------------------
    # NOTE: PromptSnapshot is intentionally NOT deleted here. It is a
    # deduplicated, content-addressed (sha256-PK) store of system-prompt text
    # shared across thousands of assessments and across workbooks — see
    # models.PromptSnapshot. Deleting by workbook would cascade-orphan traces
    # in *other* workbooks that referenced the same prompt sha. Orphan
    # PromptSnapshot rows after a workbook delete are harmless (the next
    # ingest re-uses them) and a future maintenance pass can sweep any rows
    # with zero AssessmentTrace references.
    if assessment_ids:
        # Chunk every IN-clause through ``chunked`` so a workbook with more
        # than SQLITE_MAX_VARIABLES (32766) assessments/objectives — possible
        # once several frameworks/overlays multiply the CCI count on a large
        # enterprise — doesn't crash the delete with "too many SQL variables".
        traces = shown = cites = 0
        for batch in chunked(assessment_ids):
            r = s.exec(
                delete(AssessmentTrace).where(
                    AssessmentTrace.assessment_id.in_(batch)
                )
            )
            traces += getattr(r, "rowcount", 0) or 0
            r = s.exec(
                delete(AssessmentEvidenceShown).where(
                    AssessmentEvidenceShown.assessment_id.in_(batch)
                )
            )
            shown += getattr(r, "rowcount", 0) or 0
            r = s.exec(
                delete(AssessmentCitation).where(
                    AssessmentCitation.assessment_id.in_(batch)
                )
            )
            cites += getattr(r, "rowcount", 0) or 0
        counts["assessment_traces"] = traces
        counts["assessment_evidence_shown"] = shown
        counts["assessment_citations"] = cites
    r = s.exec(delete(Assessment).where(Assessment.workbook_id == workbook_id))
    counts["assessments"] = getattr(r, "rowcount", 0) or 0

    # AssessmentRun is nullable-FK'd to workbook but we treat it as
    # workbook-owned — the run captures one ingest of this workbook.
    r = s.exec(delete(AssessmentRun).where(AssessmentRun.workbook_id == workbook_id))
    counts["assessment_runs"] = getattr(r, "rowcount", 0) or 0

    # --- POAM + children -------------------------------------------------------
    if poam_ids:
        r = s.exec(delete(PoamObjective).where(PoamObjective.poam_id.in_(poam_ids)))
        counts["poam_objectives"] = getattr(r, "rowcount", 0) or 0
        r = s.exec(delete(PoamEvidence).where(PoamEvidence.poam_id.in_(poam_ids)))
        counts["poam_evidence_links"] = getattr(r, "rowcount", 0) or 0
        r = s.exec(delete(PoamMilestone).where(PoamMilestone.poam_id.in_(poam_ids)))
        counts["poam_milestones"] = getattr(r, "rowcount", 0) or 0
    r = s.exec(delete(Poam).where(Poam.workbook_id == workbook_id))
    counts["poams"] = getattr(r, "rowcount", 0) or 0

    # --- Sweep state -----------------------------------------------------------
    r = s.exec(delete(SweepDecision).where(SweepDecision.workbook_id == workbook_id))
    counts["sweep_decisions"] = getattr(r, "rowcount", 0) or 0
    r = s.exec(delete(SweepRun).where(SweepRun.workbook_id == workbook_id))
    counts["sweep_runs"] = getattr(r, "rowcount", 0) or 0

    # --- CRM telemetry ---------------------------------------------------------
    r = s.exec(delete(CrmSuspicionLog).where(CrmSuspicionLog.workbook_id == workbook_id))
    counts["crm_suspicion_logs"] = getattr(r, "rowcount", 0) or 0
    r = s.exec(
        delete(CrmShortCircuitEvent).where(CrmShortCircuitEvent.workbook_id == workbook_id)
    )
    counts["crm_short_circuit_events"] = getattr(r, "rowcount", 0) or 0
    r = s.exec(delete(CrmCorpusFeatures).where(CrmCorpusFeatures.workbook_id == workbook_id))
    counts["crm_corpus_features"] = getattr(r, "rowcount", 0) or 0

    # --- Boundary + assets (with their link tables) ---------------------------
    if asset_ids:
        asset_links = 0
        for batch in chunked(asset_ids):
            r = s.exec(delete(EvidenceAsset).where(EvidenceAsset.asset_id.in_(batch)))
            asset_links += getattr(r, "rowcount", 0) or 0
        counts["evidence_asset_links"] = asset_links
    r = s.exec(delete(Asset).where(Asset.workbook_id == workbook_id))
    counts["assets"] = getattr(r, "rowcount", 0) or 0

    if boundary_ids:
        r = s.exec(
            delete(EvidenceBoundary).where(
                EvidenceBoundary.boundary_segment_id.in_(boundary_ids)
            )
        )
        counts["evidence_boundary_links"] = getattr(r, "rowcount", 0) or 0
    r = s.exec(delete(BoundarySegment).where(BoundarySegment.workbook_id == workbook_id))
    counts["boundary_segments"] = getattr(r, "rowcount", 0) or 0

    # --- STIG findings ---------------------------------------------------------
    # Filtered by evidence_id (not workbook_id — StigFinding doesn't carry
    # workbook_id; it's keyed off Evidence). Uses the evidence_ids snapshot
    # taken before any deletes ran.
    if evidence_ids:
        # evidence_ids can reach the per-workbook retention cap (30_000),
        # well past SQLITE_MAX_VARIABLES — must chunk.
        stig = 0
        for batch in chunked(evidence_ids):
            r = s.exec(delete(StigFinding).where(StigFinding.evidence_id.in_(batch)))
            stig += getattr(r, "rowcount", 0) or 0
        counts["stig_findings"] = stig
    else:
        counts["stig_findings"] = 0

    # --- Overlay attachments + sync events ------------------------------------
    r = s.exec(delete(WorkbookOverlay).where(WorkbookOverlay.workbook_id == workbook_id))
    counts["overlay_attachments"] = getattr(r, "rowcount", 0) or 0
    r = s.exec(delete(WorkbookSyncEvent).where(WorkbookSyncEvent.workbook_id == workbook_id))
    counts["sync_events"] = getattr(r, "rowcount", 0) or 0

    # --- Remaining workbook-owned tables with NOT-NULL workbook FKs ------------
    # These four carry a NOT-NULL ``workbook_id`` FK and were previously omitted
    # from the cascade. With ``PRAGMA foreign_keys=ON`` (db.py), a workbook that
    # had ANY of these rows raised a FOREIGN KEY constraint failure on
    # ``s.delete(wb)`` below → HTTP 500 → the UI delete silently failed and the
    # workbook stayed. All are per-workbook state meaningless without it:
    #   * Component        — parsed system components (routes/scope.py)
    #   * OverrideEpoch    — per-(workbook,objective) override generation counter
    #   * EvidenceRetentionEvent — per-workbook evidence-eviction ledger
    #   * AutomationSchedule     — per-workbook sync schedules
    r = s.exec(delete(Component).where(Component.workbook_id == workbook_id))
    counts["components"] = getattr(r, "rowcount", 0) or 0
    r = s.exec(delete(OverrideEpoch).where(OverrideEpoch.workbook_id == workbook_id))
    counts["override_epochs"] = getattr(r, "rowcount", 0) or 0
    r = s.exec(
        delete(EvidenceRetentionEvent).where(
            EvidenceRetentionEvent.workbook_id == workbook_id
        )
    )
    counts["evidence_retention_events"] = getattr(r, "rowcount", 0) or 0
    r = s.exec(
        delete(AutomationSchedule).where(AutomationSchedule.workbook_id == workbook_id)
    )
    counts["automation_schedules"] = getattr(r, "rowcount", 0) or 0

    # --- Shared artifacts: NULL workbook_id (do NOT delete) -------------------
    # Evidence is a global artifact pool — other workbooks may reference these
    # same files. Same logic for SystemContext (boundary description is reusable).
    r = s.exec(
        update(Evidence)
        .where(Evidence.workbook_id == workbook_id)
        .values(workbook_id=None)
    )
    counts["evidence_unlinked"] = getattr(r, "rowcount", 0) or 0
    r = s.exec(
        update(SystemContext)
        .where(SystemContext.workbook_id == workbook_id)
        .values(workbook_id=None)
    )
    counts["system_contexts_unlinked"] = getattr(r, "rowcount", 0) or 0

    # --- Finally, the workbook row itself --------------------------------------
    orphan_baseline_id = wb.baseline_id
    s.delete(wb)
    s.commit()

    # --- Orphaned primary baseline cleanup ------------------------------------
    # The workbook's auto-created primary Baseline (Workbook.baseline_id) used
    # to be left behind on delete. That orphan kept showing up in the header
    # ComplianceTargetPicker, which lists *baselines* — so a deleted workbook
    # still appeared as a selectable "workbook" entry even though it was gone
    # from the Indexed table. If no OTHER workbook still points at this baseline
    # as its primary scope, cascade-delete it via the canonical baseline deleter
    # (reuses the BaselineControl/BaselineObjective/WorkbookOverlay fan-out).
    # Shared baselines (another workbook still references this one) are left
    # intact. Overlay baselines (CRM/FedRAMP) are catalog-level and reusable —
    # they're only *detached* above (WorkbookOverlay rows), never deleted here.
    baseline_removed = 0
    if orphan_baseline_id is not None:
        still_referenced = s.exec(
            select(Workbook.id).where(Workbook.baseline_id == orphan_baseline_id)
        ).first()
        if not still_referenced:
            # Local import breaks the workbooks<->baselines import cycle.
            from .baselines import delete_baseline

            try:
                delete_baseline(baseline_id=orphan_baseline_id, force=False, s=s)
                baseline_removed = orphan_baseline_id
            except HTTPException:
                # Baseline already gone, or unexpectedly still in use — leave it
                # rather than fail the (already-committed) workbook delete.
                pass
    counts["baseline_removed"] = baseline_removed

    _log.info(
        "deleted workbook id=%s filename=%s cascade=%s",
        workbook_id, filename, counts,
    )
    return {
        "ok": True,
        "workbook_id": workbook_id,
        "filename": filename,
        "cascade": counts,
    }


@router.get("/{workbook_id}/overlay-membership")
def workbook_overlay_membership(
    workbook_id: int, s: Session = Depends(get_session)
) -> dict:
    """Per-control membership across every reference overlay attached.

    Returns a shape the Controls grid can merge in O(1):

      ``overlays``: list of attached overlay baselines (id + name + source_type).
      ``by_control``: ``{control_id: {baseline_id: "in"|"out"}}``. Controls not
      mentioned in an overlay are simply absent from that overlay's inner dict
      — the UI renders that as no badge.
      ``by_control_requirements``: ``{control_id: {baseline_id: ["SDA-127",
      ...]}}``. Populated only for ``PROGRAM_CONTROLS``-type overlays — the
      Controls grid shows the actual program-requirement numbers (e.g. SDA-XXX)
      mapped to each control instead of a generic "in scope" badge. CRM /
      FedRAMP overlays have no entry here and continue to render as in/out.

    Single GROUP-BY-style query per overlay; total cost is one extra round-trip
    instead of N (one per overlay, one per control).
    """
    if not s.get(Workbook, workbook_id):
        raise HTTPException(status_code=404, detail="Workbook not found")

    overlay_rows = s.exec(
        select(Baseline)
        .join(WorkbookOverlay, WorkbookOverlay.baseline_id == Baseline.id)
        .where(WorkbookOverlay.workbook_id == workbook_id)
        .order_by(WorkbookOverlay.attached_at)
    ).all()
    overlays_payload = [
        {
            "baseline_id": b.id,
            "name": b.name,
            "framework_id": b.framework_id,
            "source_type": b.source_type.value,
            # scope_label distinguishes sibling CRM overlays (e.g. one per
            # cloud) so the Controls grid can render one column per CRM. May
            # be None for CRMs imported before the scope-label picker was
            # restored — the UI falls back to a cleaned overlay name then.
            "scope_label": b.scope_label,
        }
        for b in overlay_rows
    ]

    by_control: dict[int, dict[int, str]] = {}
    by_control_requirements: dict[int, dict[int, list[str]]] = {}
    if overlay_rows:
        bc_rows = s.exec(
            select(
                BaselineControl.baseline_id,
                BaselineControl.control_id,
                BaselineControl.in_scope,
            ).where(
                BaselineControl.baseline_id.in_(  # type: ignore[attr-defined]
                    [b.id for b in overlay_rows]
                )
            )
        ).all()
        for bl_id, ctrl_id, in_scope in bc_rows:
            by_control.setdefault(ctrl_id, {})[bl_id] = "in" if in_scope else "out"

        # For PROGRAM_CONTROLS overlays, pull the actual requirement numbers
        # (e.g. "SDA-127") mapped to each control. The synthetic Baseline and
        # the RequirementSource share `framework_id` + the source file path
        # — Baseline.source_ref and RequirementSource.path both carry the
        # absolute workbook path (see catalogs/program_controls_loader.py).
        # Keying on path (not name) keeps two distinct files with the same
        # human label cleanly separated.
        pc_baselines = [
            b for b in overlay_rows
            if b.source_type == BaselineSourceType.PROGRAM_CONTROLS
        ]
        for pc in pc_baselines:
            req_rows = s.exec(
                select(
                    Objective.control_id_fk,
                    RequirementMap.requirement_number,
                )
                .join(RequirementMap, RequirementMap.objective_id == Objective.id)
                .join(
                    RequirementSource,
                    RequirementSource.id == RequirementMap.requirement_source_id,
                )
                .where(
                    RequirementSource.framework_id == pc.framework_id,
                    RequirementSource.path == pc.source_ref,
                )
            ).all()
            # Dedupe per (control, baseline) — one control can map to multiple
            # objectives that each carry the same SDA-XXX, and we don't want
            # the cell repeating "SDA-127, SDA-127, SDA-127".
            seen: dict[int, set[str]] = {}
            for ctrl_id, req_num in req_rows:
                seen.setdefault(ctrl_id, set()).add(req_num)
            for ctrl_id, nums in seen.items():
                # Natural sort would need parsing; lex sort is fine for
                # SDA-001..SDA-999 since the loader zero-pads. If a program
                # ships unpadded numbers later, revisit.
                by_control_requirements.setdefault(ctrl_id, {})[pc.id] = sorted(nums)

    return {
        "overlays": overlays_payload,
        "by_control": by_control,
        "by_control_requirements": by_control_requirements,
    }


@router.get("/{workbook_id}/catalog")
def workbook_catalog(
    workbook_id: int, s: Session = Depends(get_session)
) -> dict:
    """Catalog data scoped to a single workbook — drives the per-workbook
    catalog detail panel on the Workbooks page (replaces the global Settings
    → Catalogs tab).

    Returns:
      ``framework``: the workbook's bound framework with control/objective
        counts. ``None`` if the workbook has no framework bound yet.
      ``attached_baselines``: every Baseline currently attached via
        :class:`WorkbookOverlay` (FedRAMP, CRM, PROGRAM_CONTROLS), each
        enriched with its source :class:`RequirementSource` and map count
        when one exists. PROGRAM_CONTROLS overlays look up their
        RequirementSource by ``(framework_id, path)`` — the post-Stage-2
        upsert key — so two distinct files sharing a human label render
        as two distinct entries.

    One round-trip per resource (framework, counts, overlays, sources).
    No N+1 over the per-overlay enrichments.
    """
    wb = s.get(Workbook, workbook_id)
    if not wb:
        raise HTTPException(status_code=404, detail="Workbook not found")

    framework_payload: dict | None = None
    if wb.framework_id is not None:
        framework = s.get(Framework, wb.framework_id)
        if framework is not None:
            control_count = s.exec(
                select(func.count(Control.id)).where(
                    Control.framework_id == wb.framework_id
                )
            ).one()
            objective_count = s.exec(
                select(func.count(Objective.id))
                .join(Control, Objective.control_id_fk == Control.id)
                .where(Control.framework_id == wb.framework_id)
            ).one()
            framework_payload = {
                "id": framework.id,
                "name": framework.name,
                "version": framework.version,
                "control_count": int(control_count or 0),
                "objective_count": int(objective_count or 0),
            }

    overlay_baselines = s.exec(
        select(Baseline)
        .join(WorkbookOverlay, WorkbookOverlay.baseline_id == Baseline.id)
        .where(WorkbookOverlay.workbook_id == workbook_id)
        .order_by(WorkbookOverlay.attached_at)
    ).all()

    # Pre-fetch the RequirementSource rows that back the PROGRAM_CONTROLS
    # overlays, plus per-source RequirementMap counts. Single query per
    # resource — no N+1 across overlays.
    pc_paths = [
        b.source_ref
        for b in overlay_baselines
        if b.source_type == BaselineSourceType.PROGRAM_CONTROLS and b.source_ref
    ]
    sources_by_path: dict[tuple[int, str], RequirementSource] = {}
    map_counts_by_source_id: dict[int, int] = {}
    if pc_paths and wb.framework_id is not None:
        src_rows = s.exec(
            select(RequirementSource).where(
                RequirementSource.framework_id == wb.framework_id,
                RequirementSource.path.in_(pc_paths),  # type: ignore[attr-defined]
            )
        ).all()
        for src in src_rows:
            sources_by_path[(src.framework_id, src.path)] = src
        if src_rows:
            mc_rows = s.exec(
                select(
                    RequirementMap.requirement_source_id,
                    func.count(RequirementMap.id),
                )
                .where(
                    RequirementMap.requirement_source_id.in_(  # type: ignore[attr-defined]
                        [src.id for src in src_rows]
                    )
                )
                .group_by(RequirementMap.requirement_source_id)
            ).all()
            for src_id, n in mc_rows:
                map_counts_by_source_id[src_id] = int(n)

    attached_payload: list[dict] = []
    for bl in overlay_baselines:
        src_payload: dict | None = None
        if (
            bl.source_type == BaselineSourceType.PROGRAM_CONTROLS
            and wb.framework_id is not None
            and bl.source_ref
        ):
            src = sources_by_path.get((wb.framework_id, bl.source_ref))
            if src is not None:
                src_payload = {
                    "id": src.id,
                    "name": src.name,
                    "path": src.path,
                    "map_count": map_counts_by_source_id.get(src.id, 0),
                }
        attached_payload.append(
            {
                "baseline_id": bl.id,
                "name": bl.name,
                "source_type": bl.source_type.value,
                "source_ref": bl.source_ref,
                "requirement_source": src_payload,
            }
        )

    return {
        "framework": framework_payload,
        "attached_baselines": attached_payload,
    }


@router.get("/{workbook_id}/summary")
def workbook_summary(workbook_id: int, s: Session = Depends(get_session)) -> dict:
    wb = s.get(Workbook, workbook_id)
    if not wb:
        raise HTTPException(status_code=404, detail="Workbook not found")
    return read_workbook_summary(Path(wb.path))


@router.get("/{workbook_id}/boundary-docs")
def workbook_boundary_docs(
    workbook_id: int, s: Session = Depends(get_session)
) -> list[dict]:
    """List Evidence rows flagged as boundary docs for this workbook.

    Drives the Sweep Context page's "attached boundary documents"
    table. Returns the same shape as ``GET /api/evidence`` — reuses the
    evidence serializer so the UI can render with one component.
    Ordered oldest-first so the assessor sees the upload order they
    actually performed; the panel itself isn't long enough for newer-
    first paging to matter.
    """
    if not s.get(Workbook, workbook_id):
        raise HTTPException(status_code=404, detail="Workbook not found")
    rows = s.exec(
        select(Evidence)
        .where(
            Evidence.workbook_id == workbook_id,
            Evidence.is_boundary_doc.is_(True),  # type: ignore[union-attr]
        )
        .order_by(Evidence.ingested_at)
    ).all()
    return [_serialize_evidence(e) for e in rows]


@router.get("/{workbook_id}/control-status")
def workbook_control_status(
    workbook_id: int, s: Session = Depends(get_session)
) -> list[dict]:
    """Per-control assessment rollup for a workbook — drives the Controls grid.

    Returns one row per control that has at least one persisted Assessment
    in this workbook. Controls with no assessments yet are simply absent;
    the UI renders them as "—". A control rolls up to:

    * ``Compliant`` — every assessed objective is Compliant
    * ``Non-Compliant`` — at least one objective is Non-Compliant
      (Non-Compliant wins — one failing CCI fails the control)
    * ``Not Applicable`` — every assessed objective is Not Applicable
    * ``Mixed`` — assessed objectives include both Compliant and N/A,
      but no Non-Compliant
    * ``Needs Review`` — at least one objective is needs_review and there
      are no trusted Non-Compliant verdicts on the control. Surfaced so
      the operator can find pending-triage controls in the grid without
      a verdict masking them. Non-Compliant still wins over Needs Review
      (a confirmed gap is a stronger signal than an open question).

    Rows with ``needs_review=True`` are EXCLUDED from the
    compliant / non_compliant / na buckets — their verdicts aren't
    trusted yet. They roll up into the separate ``needs_review`` count
    so the UI can render the amber-tinted control row.
    """
    if not s.get(Workbook, workbook_id):
        raise HTTPException(status_code=404, detail="Workbook not found")

    # Count per (control_id, status, needs_review, rewrite_requested) in a
    # single GROUP BY -- N+1-free. needs_review is the precision-over-recall
    # gate: only trusted (needs_review=False) rows contribute to the verdict
    # rollup. rewrite_requested is the orthogonal citation-hygiene flag --
    # rows with rewrite_requested=True are TRUSTED verdicts that flow into
    # the compliant/non_compliant/na buckets normally; the count is exposed
    # alongside so the UI can render a "Cite refresh" pill without flipping
    # the verdict.
    rows = s.exec(
        select(
            Control.id,
            Assessment.status,
            Assessment.needs_review,
            Assessment.rewrite_requested,
            func.count(Assessment.id),
        )
        .join(Objective, Objective.control_id_fk == Control.id)
        .join(Assessment, Assessment.objective_id == Objective.id)
        .where(Assessment.workbook_id == workbook_id)
        .group_by(
            Control.id,
            Assessment.status,
            Assessment.needs_review,
            Assessment.rewrite_requested,
        )
    ).all()

    by_control: dict[int, dict[str, int]] = {}
    for ctrl_id, status, needs_review, rewrite_requested, n in rows:
        d = by_control.setdefault(
            ctrl_id,
            {
                "compliant": 0,
                "non_compliant": 0,
                "na": 0,
                "needs_review": 0,
                "rewrites_requested": 0,
            },
        )
        # rewrite_requested is orthogonal -- it tags TRUSTED verdicts that
        # need a cite swap on the next narrative pass. Count it in its own
        # bucket regardless of status / needs_review so the UI can flag the
        # row even when the verdict rolls up clean.
        if rewrite_requested:
            d["rewrites_requested"] += int(n)
        # All abstained rows funnel into needs_review regardless of the
        # status the LLM proposed -- exports filter on the flag, the
        # rollup must too.
        if needs_review:
            d["needs_review"] += int(n)
            continue
        if status == ComplianceStatus.COMPLIANT:
            d["compliant"] += int(n)
        elif status == ComplianceStatus.NON_COMPLIANT:
            d["non_compliant"] += int(n)
        elif status == ComplianceStatus.NOT_APPLICABLE:
            d["na"] += int(n)

    out: list[dict] = []
    for ctrl_id, counts in by_control.items():
        total = (
            counts["compliant"]
            + counts["non_compliant"]
            + counts["na"]
            + counts["needs_review"]
        )
        if counts["non_compliant"] > 0:
            rollup = "Non-Compliant"
        elif counts["needs_review"] > 0 and (
            counts["compliant"] + counts["na"] == 0
        ):
            # Only needs_review rows exist for this control yet.
            rollup = "Needs Review"
        elif counts["needs_review"] > 0:
            # Mix of trusted + needs_review — surface as Needs Review so
            # the operator knows triage is outstanding before claiming
            # the whole control is Compliant or NA.
            rollup = "Needs Review"
        elif counts["compliant"] > 0 and counts["na"] == 0:
            rollup = "Compliant"
        elif counts["na"] > 0 and counts["compliant"] == 0:
            rollup = "Not Applicable"
        else:
            rollup = "Mixed"
        out.append(
            {
                "control_id": ctrl_id,
                "status": rollup,
                "compliant": counts["compliant"],
                "non_compliant": counts["non_compliant"],
                "na": counts["na"],
                "needs_review": counts["needs_review"],
                "rewrites_requested": counts["rewrites_requested"],
                "total_assessed": total,
            }
        )
    return out


@router.get("/{workbook_id}/col-l-status")
def workbook_col_l_status(
    workbook_id: int, s: Session = Depends(get_session)
) -> list[dict]:
    """Per-control Column-L (flex/on-prem inheritance) rollup for the grid.

    Column L (CcisRow.inherited) is the eMASS workbook's per-CCI inheritance
    attestation and the authority for the flex (On-Premises/workbook) slice's
    status (pie-slice model). The grid renders one row per CONTROL, while col L
    is per-CCI, so we re-read the workbook and aggregate each control's CCIs
    worst-of: ASSESS (must assess) > ESCALATE (bare "Yes", unnamed source) >
    INHERITED (named source → Compliant). A control whose CCIs are all
    INHERITED rolls up INHERITED; any ASSESS CCI makes the whole control ASSESS.

    Returns one entry per control that ACTUALLY HAS a synthesized flex slice
    (i.e. the control is covered by CRM cloud slices — the pie-slice model only
    synthesizes a flex slice for those). Controls with no CRM (e.g. a wholly
    column-N Not Applicable control like AC-18) have NO flex slice and get NO
    entry here, so the grid omits the chip for them — the flex chip describes a
    slice that doesn't exist otherwise.

    Each entry:
      ``control_id``  — OSCAL canonical id (matches the grid's Control.control_id)
      ``outcome``     — "inherited" | "assess" | "escalate"
      ``value``       — a representative raw col-L cell (the one that drove the
                        rollup), for the chip tooltip/label.
    Empty list when the workbook can't be read (chip simply omitted).
    """
    from ..baselines.scope_labels import ON_PREM_LABEL
    from ..engine import rules
    from ..engine.crm_context import build_crm_context
    from ..excel.ccis_reader import (
        _ccis_to_oscal_control_id,
        _normalize_control,
        read_workbook_index,
    )

    wb = s.get(Workbook, workbook_id)
    if not wb:
        raise HTTPException(status_code=404, detail="Workbook not found")
    if not wb.path:
        return []
    try:
        index = read_workbook_index(Path(wb.path))
    except (ValueError, FileNotFoundError, OSError):
        return []

    # A control gets a flex chip when EITHER:
    #   (1) it has a synthesized flex slice — build_crm_context synthesizes the
    #       ON_PREM flex slice for CRM-covered controls; OR
    #   (2) it is wholly Column-N Not Applicable (rule 8b) — even with NO CRM,
    #       a fully-N/A control (e.g. AC-18, no CRM, col N="Not Applicable")
    #       should show an "N/A" flex chip, not a blank "—". (Owner: AC-18 must
    #       read N/A.)
    crm_context = build_crm_context(workbook_id, s)
    flex_control_ids = {
        oscal
        for oscal, sls in crm_context.by_control_impls.items()
        if any(sl.scope_label == ON_PREM_LABEL for sl in sls)
    }

    # Worst-of precedence: higher number wins when aggregating a control's CCIs.
    _RANK = {
        rules.ColLFlexOutcome.INHERITED: 1,
        rules.ColLFlexOutcome.ESCALATE: 2,
        rules.ColLFlexOutcome.ASSESS: 3,
    }
    # control_id -> (rank, outcome_value, representative_raw_value). outcome_value
    # is a plain string so we can emit the synthetic "na" outcome (not a
    # ColLFlexOutcome member) when the workbook's Column N already marks the
    # control Not Applicable.
    agg: dict[str, tuple[int, str, str]] = {}
    # Track whether EVERY CCI of a control is column-N Not Applicable: a wholly
    # N/A control (rule 8b) has no real flex assessment to do, so the chip
    # should read "N/A". One non-NA CCI voids the N/A (mirrors
    # compute_rollup_status's "N/A only if ALL are N/A"). This is ALSO the
    # signal that earns a no-CRM control a chip at all (case 2 above).
    col_n_na_all: dict[str, bool] = {}
    for cci_row in index.by_cci().values():
        if not cci_row.control_id:
            continue
        oscal = _ccis_to_oscal_control_id(_normalize_control(cci_row.control_id))
        is_na = (cci_row.status or "").strip().lower() in (
            "not applicable", "n/a", "na",
        )
        col_n_na_all[oscal] = is_na if oscal not in col_n_na_all else (
            col_n_na_all[oscal] and is_na
        )
        outcome = rules.resolve_col_l_flex_status(
            cci_row.inherited, cci_row.remote_inheritance
        )
        rank = _RANK[outcome]
        prev = agg.get(oscal)
        if prev is None or rank > prev[0]:
            agg[oscal] = (rank, outcome.value, (cci_row.inherited or "").strip())

    out: list[dict] = []
    for oscal, (_rank, outcome_value, value) in agg.items():
        wholly_na = col_n_na_all.get(oscal, False)
        # Emit a chip only when the control has a flex slice OR is wholly N/A.
        if oscal not in flex_control_ids and not wholly_na:
            continue
        # Column-N Not Applicable wins: the control is wholly N/A (rule 8b),
        # so the flex slice has nothing to assess — show "na" not "assess".
        if wholly_na:
            out.append({"control_id": oscal, "outcome": "na", "value": value})
        else:
            out.append(
                {"control_id": oscal, "outcome": outcome_value, "value": value}
            )
    return out


@router.get("/{workbook_id}/review-queue")
def workbook_review_queue(
    workbook_id: int, s: Session = Depends(get_session)
) -> list[dict]:
    """List every v0.2 needs_review assessment for a workbook.

    The Controls page already filters its grid to `Needs Review` via the
    status dropdown, but that view is at the control-rollup level — one
    row per control regardless of how many CCIs underneath are abstained.
    This endpoint returns the underlying per-CCI rows joined to their
    control / objective metadata so the dedicated Review Queue route can
    group by `review_reason` category and link straight to ControlDetail.

    Returns one row per abstained Assessment, sorted by review_reason
    prefix (so all `dual-pass-disagreement:` rows cluster, all
    `unverified-cites:` cluster, etc.) then by control_id for stable
    in-group ordering.
    """
    if not s.get(Workbook, workbook_id):
        raise HTTPException(status_code=404, detail="Workbook not found")

    # Single GROUP-BY-free join — abstained rows are a small subset, so a
    # flat select is cheaper than rollups + per-control follow-ups.
    rows = s.exec(
        select(
            Assessment.id,
            Assessment.objective_id,
            Assessment.workbook_id,
            Assessment.status,
            Assessment.narrative_q,
            Assessment.narrative_on_prem,
            Assessment.narrative_cloud,
            Assessment.review_reason,
            Assessment.confidence,
            Assessment.inheritance_rule,
            Assessment.date_tested,
            Objective.objective_id,
            Objective.text,
            Control.id,
            Control.control_id,
            Control.title,
            Control.family,
        )
        .join(Objective, Objective.id == Assessment.objective_id)
        .join(Control, Control.id == Objective.control_id_fk)
        .where(
            Assessment.workbook_id == workbook_id,
            Assessment.needs_review.is_(True),  # type: ignore[union-attr]
        )
    ).all()

    out: list[dict] = []
    for (
        a_id,
        obj_id,
        wb_id,
        status,
        narrative,
        narrative_on_prem,
        narrative_cloud,
        reason,
        confidence,
        inheritance_rule,
        date_tested,
        cci_id,
        obj_text,
        ctrl_id,
        control_id,
        control_title,
        family,
    ) in rows:
        out.append(
            {
                "assessment_id": a_id,
                "objective_id": obj_id,
                "workbook_id": wb_id,
                "proposed_status": status,
                "narrative_q": narrative,
                "narrative_on_prem": narrative_on_prem,
                "narrative_cloud": narrative_cloud,
                "review_reason": reason,
                "confidence": confidence,
                "inheritance_rule": inheritance_rule,
                "date_tested": iso_utc(date_tested),
                "cci_id": cci_id,
                "objective_text": obj_text,
                "control_id": ctrl_id,
                "control_label": control_id,
                "control_title": control_title,
                "family": family,
            }
        )

    # Sort: review_reason prefix (the colon-delimited tag) then control_id.
    # Empty / null reasons sort last under a "(uncategorized)" bucket so
    # they're visible but don't disrupt the grouping.
    def _reason_prefix(r: str | None) -> str:
        if not r:
            return "~uncategorized"  # tilde sorts after letters
        head = r.split(":", 1)[0].strip()
        return head or "~uncategorized"

    out.sort(key=lambda r: (_reason_prefix(r["review_reason"]), r["control_label"]))
    return out


@router.post("/{workbook_id}/sweep-attempts/reset")
def reset_sweep_attempts(
    workbook_id: int, s: Session = Depends(get_session)
) -> dict:
    """Clear the sweep cap counter for this workbook.

    The legitimate use case is "I just dropped new artifacts into SharePoint
    and want a fresh sweep budget against the updated library." Not a UI
    affordance the user reaches for casually — the SystemContext page only
    surfaces the Reset button once the counter hits 2/2, so the user has to
    have actually exhausted their attempts before this endpoint becomes
    visible. Returns the cleared counter so the UI doesn't need a refetch.
    """
    wb = s.get(Workbook, workbook_id)
    if not wb:
        raise HTTPException(status_code=404, detail="workbook not found")
    wb.sweep_attempts = 0
    s.add(wb)
    s.commit()
    return {"sweep_attempts": 0}
