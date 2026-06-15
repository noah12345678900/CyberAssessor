"""Baseline endpoints.

Read-side surface for the catalog-vs-baseline view. ``Baseline`` rows
are created by source adapters (CCIS workbook open, OSCAL SSP import,
manual UI), so there is no POST to create them directly — refresh re-
runs the adapter for the stored ``source_type`` + ``source_ref``.

**Scope model.** Tailoring decisions live on Controls/Enhancements via
:class:`BaselineControl`. :class:`BaselineObjective` rows carry CCI-level
metadata only (notably ``source_row`` for write-back). To list "in-scope
CCIs" we therefore join Objective → Control → BaselineControl rather
than looking at any flag on BaselineObjective itself.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlmodel import Session, delete, select, update

from ..baselines import (
    CrmXlsxBaselineSource,
    get_source_for_type,
)
from ..baselines.scope_labels import (
    CANONICAL_SCOPE_LABELS,
    ON_PREM_LABEL,
    OTHER_LABEL,
)
from ..db import get_session
from ..engine.crm_context import build_crm_context
from ..engine.crm_ml import CURRENT_FEATURE_SCHEMA_VERSION
from ..engine.crm_sanity import CrmSuspicionReport, score_crm_suspicion
from ..engine.narrative_embeddings import resolve_provider
from ..evidence.sources.sweep import build_boundary_fingerprint
from ..models import (
    AssessmentImplementation,
    Baseline,
    BaselineControl,
    BaselineObjective,
    BaselineSourceType,
    Control,
    CrmAnomalyModel,
    CrmCorpusFeatures,
    CrmSuspicionLog,
    Evidence,
    EvidenceTag,
    Framework,
    Objective,
    Workbook,
    WorkbookOverlay,
    iso_utc,
)

router = APIRouter(prefix="/api/baselines", tags=["baselines"])


@router.get("")
def list_baselines(s: Session = Depends(get_session)) -> list[dict]:
    rows = s.exec(select(Baseline).order_by(Baseline.refreshed_at.desc())).all()
    return [
        {
            "id": b.id,
            "name": b.name,
            "framework_id": b.framework_id,
            "system_id": b.system_id,
            "source_type": b.source_type.value,
            "source_ref": b.source_ref,
            "scope_label": b.scope_label,
            "created_at": iso_utc(b.created_at),
            "refreshed_at": iso_utc(b.refreshed_at),
        }
        for b in rows
    ]


@router.get("/scope-labels")
def list_scope_labels() -> dict:
    """Return the canonical scope-label vocabulary for CRM uploads.

    The UI consumes this to populate the implementation-slice picker on
    the CRM upload modal. ``canonical`` is the ordered list the UI should
    render as selectable options; ``on_prem`` is the reserved label that
    the server rejects on CRM upload (it's synthesized at assess-time);
    ``other`` is the sentinel string the UI uses to switch to a
    free-text input.

    Backed by ``baselines.scope_labels`` so adding or renaming a label is
    a one-file change with no UI redeploy required (the query has
    ``staleTime: Infinity`` client-side so it loads once per session, but
    invalidates on app reload).
    """
    return {
        "canonical": list(CANONICAL_SCOPE_LABELS),
        "on_prem": ON_PREM_LABEL,
        "other": OTHER_LABEL,
    }


@router.get("/{baseline_id}")
def get_baseline(baseline_id: int, s: Session = Depends(get_session)) -> dict:
    b = s.get(Baseline, baseline_id)
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")

    # Scope counts come from BaselineControl (Control/Enhancement level).
    ctl_in = len(
        s.exec(
            select(BaselineControl).where(
                BaselineControl.baseline_id == baseline_id,
                BaselineControl.in_scope.is_(True),  # type: ignore[union-attr]
            )
        ).all()
    )
    ctl_out = len(
        s.exec(
            select(BaselineControl).where(
                BaselineControl.baseline_id == baseline_id,
                BaselineControl.in_scope.is_(False),  # type: ignore[union-attr]
            )
        ).all()
    )

    # CCI-level rollup: a CCI is "in scope" iff its parent Control is in
    # scope. Same join used by /objectives below.
    #
    # Soft-deleted (is_deprecated=True) BaselineObjective rows are
    # excluded from both counts so the UI rollup reflects the current
    # workbook roster, not the historical superset the row preserves for
    # save-time lookups. See models.py BaselineObjective.is_deprecated.
    cci_in = len(
        s.exec(
            select(BaselineObjective)
            .join(Objective, Objective.id == BaselineObjective.objective_id)
            .join(Control, Control.id == Objective.control_id_fk)
            .join(BaselineControl, BaselineControl.control_id == Control.id)
            .where(
                BaselineObjective.baseline_id == baseline_id,
                BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
                BaselineControl.baseline_id == baseline_id,
                BaselineControl.in_scope.is_(True),  # type: ignore[union-attr]
            )
        ).all()
    )
    cci_total = len(
        s.exec(
            select(BaselineObjective).where(
                BaselineObjective.baseline_id == baseline_id,
                BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
            )
        ).all()
    )

    # Workbooks that have this baseline attached as an overlay. Only
    # populated for CRM-source baselines today — the suspicion banner
    # uses this to render a workbook picker. For non-CRM baselines this
    # is informational (and almost always empty).
    # NOTE: SQLModel's session.exec(select(Single.column)).all() returns
    # a list of bare scalars, not 1-tuples — destructuring with `(wid,)`
    # raises TypeError.
    attached_workbook_ids = [
        int(wid)
        for wid in s.exec(
            select(WorkbookOverlay.workbook_id)
            .where(WorkbookOverlay.baseline_id == baseline_id)
            .order_by(WorkbookOverlay.attached_at.desc())
        ).all()
    ]

    return {
        "id": b.id,
        "name": b.name,
        "framework_id": b.framework_id,
        "source_type": b.source_type.value,
        "source_ref": b.source_ref,
        "created_at": iso_utc(b.created_at),
        "refreshed_at": iso_utc(b.refreshed_at),
        "counts": {
            "in_scope": ctl_in,  # legacy alias: control-level in scope
            "out_of_scope": ctl_out,  # legacy alias: control-level out
            "controls_in_scope": ctl_in,
            "controls_out_of_scope": ctl_out,
            "objectives_in_scope": cci_in,
            "objectives_total": cci_total,
        },
        "attached_workbook_ids": attached_workbook_ids,
    }


@router.get("/{baseline_id}/controls")
def list_baseline_controls(
    baseline_id: int,
    in_scope_only: bool = False,
    s: Session = Depends(get_session),
) -> list[dict]:
    """List Controls/Enhancements covered by this baseline.

    This is the authoritative scoping surface — tailoring decisions live
    here. Joins :class:`Control` for the human-readable id/title/family.
    """
    b = s.get(Baseline, baseline_id)
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")
    stmt = (
        select(BaselineControl, Control)
        .where(
            BaselineControl.baseline_id == baseline_id,
            BaselineControl.control_id == Control.id,
        )
        .order_by(Control.control_id)
    )
    if in_scope_only:
        stmt = stmt.where(BaselineControl.in_scope.is_(True))  # type: ignore[union-attr]
    rows = s.exec(stmt).all()
    return [
        {
            "baseline_control_id": bc.id,
            "control_id": c.id,
            "control_code": c.control_id,
            "title": c.title,
            "family": c.family,
            "in_scope": bc.in_scope,
            "tailoring_reason": bc.tailoring_reason,
            "parameter_overrides_json": bc.parameter_overrides_json,
            # CRM overlay fields per scope. Cloud-scope values come from
            # the original single-column CRM templates; on-prem-scope
            # values come from dual-column CRMs for mixed cloud+on-prem
            # systems. Both are null when no CRM overlay supplied them —
            # the UI hides the CRM panel entirely in that case.
            "responsibility": bc.responsibility,
            "responsibility_narrative": bc.responsibility_narrative,
            "responsibility_onprem": bc.responsibility_onprem,
            "responsibility_onprem_narrative": bc.responsibility_onprem_narrative,
        }
        for (bc, c) in rows
    ]


@router.get("/{baseline_id}/objectives")
def list_baseline_objectives(
    baseline_id: int,
    in_scope_only: bool = False,
    s: Session = Depends(get_session),
) -> list[dict]:
    """List CCIs in this baseline, with the parent control's in-scope flag.

    in-scope/out-of-scope filtering uses the **parent control's** decision —
    individual CCIs are never tailored on their own. Joins to
    :class:`Objective`, :class:`Control`, and :class:`BaselineControl`
    so the UI can render objective_id + text + scope without a second
    round-trip.
    """
    b = s.get(Baseline, baseline_id)
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")
    stmt = (
        select(BaselineObjective, Objective, Control, BaselineControl)
        .where(
            BaselineObjective.baseline_id == baseline_id,
            # Hide soft-deleted rows from the UI — they exist only so
            # _resolve_excel_row in routes/controls.py can still find
            # source_row when the user re-saves a status for a CCI that
            # the workbook has since dropped. See models.py.
            BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
            BaselineObjective.objective_id == Objective.id,
            Objective.control_id_fk == Control.id,
            BaselineControl.control_id == Control.id,
            BaselineControl.baseline_id == baseline_id,
        )
    )
    if in_scope_only:
        stmt = stmt.where(BaselineControl.in_scope.is_(True))  # type: ignore[union-attr]
    rows = s.exec(stmt).all()
    return [
        {
            "baseline_objective_id": bo.id,
            "objective_id": o.id,
            "objective_code": o.objective_id,
            "source": o.source,
            "control_id": c.id,
            "control_code": c.control_id,
            "in_scope": bc.in_scope,  # inherited from parent Control
            "tailoring_reason": bo.tailoring_reason or bc.tailoring_reason,
            "source_row": bo.source_row,
            "text": o.text,
        }
        for (bo, o, c, bc) in rows
    ]


class CrmLoadRequest(BaseModel):
    framework_id: int  # NIST 800-53 rev5 Framework id
    path: str  # local filesystem path to the CRM xlsx
    system_id: int | None = None
    name: str | None = None


@router.post("/crm/load", deprecated=True)
def load_crm(req: CrmLoadRequest, s: Session = Depends(get_session)) -> dict:
    """Create or refresh a CRM (Customer Responsibility Matrix) baseline.

    DEPRECATED — prefer ``POST /api/catalog/overlays/import`` which
    auto-classifies the file and dispatches to the CRM loader without
    forcing the user to pick a button. Kept so any caller that already
    knows the file is a CRM keeps working until the UI fully migrates.

    The CRM is an overlay, not a primary scope source — callers should
    attach the returned ``baseline_id`` to a workbook via
    ``POST /api/workbooks/{id}/overlays``. The kernel reads
    ``responsibility`` per control to short-circuit Provider/Inherited/NA
    rows and to inject a ``## responsibility_split`` block for Hybrid
    controls.

    Idempotent: re-loading the same xlsx upserts on
    ``(source_type, source_ref)`` so the user can re-upload a corrected
    CRM without orphaning the overlay attachment.
    """
    if not s.get(Framework, req.framework_id):
        raise HTTPException(
            status_code=400, detail=f"Framework id={req.framework_id} not loaded"
        )
    src = CrmXlsxBaselineSource(
        workbook_path=req.path,
        name=req.name,
        system_id=req.system_id,
    )
    try:
        result = src.apply(s, framework_id=req.framework_id)
    except (FileNotFoundError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    # Promote the two failure-mode counters out of the loose ``notes`` dict
    # so the UI toast can name them separately. ``controls_unknown`` (catalog
    # misses — CRM references AC-99 but no AC-99 in the loaded framework)
    # and ``unknown_responsibility_rows`` (typo'd/unrecognized responsibility
    # strings like "Customr") are independent diagnostics; conflating them
    # under one count made the upload toast literally mislabel one as the
    # other. ``unknown_control_ids`` carries the actual IDs so the user can
    # fix their CRM rather than guessing which controls were dropped.
    notes = result.notes or {}
    unknown_control_ids = notes.get("unknown_control_ids", []) or []
    unknown_responsibility_rows = int(
        notes.get("unknown_responsibility_rows", 0) or 0
    )
    return {
        "baseline_id": result.baseline.id,
        "name": result.baseline.name,
        "source_type": result.baseline.source_type.value,
        "controls_in_scope": result.controls_in_scope,
        "controls_unknown": result.controls_unknown,
        "unknown_control_ids": unknown_control_ids,
        "unknown_responsibility_rows": unknown_responsibility_rows,
        "notes": result.notes,
    }


@router.post("/{baseline_id}/refresh")
def refresh_baseline(baseline_id: int, s: Session = Depends(get_session)) -> dict:
    """Re-run the adapter for this baseline's source.

    Useful when the underlying workbook / SSP file changed on disk.
    Manual baselines reject — there is no external source to re-read.
    """
    b = s.get(Baseline, baseline_id)
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")
    try:
        adapter = get_source_for_type(b.source_type, source_ref=b.source_ref)
    except (NotImplementedError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    result = adapter.apply(s, framework_id=b.framework_id)
    return {
        "baseline_id": result.baseline.id,
        "refreshed_at": iso_utc(result.baseline.refreshed_at),
        "controls_in_scope": result.controls_in_scope,
        "controls_out_of_scope": result.controls_out_of_scope,
        "controls_unknown": result.controls_unknown,
        "objectives_seen": result.objectives_seen,
        "objectives_unknown": result.objectives_unknown,
        "notes": result.notes,
    }


@router.delete("/{baseline_id}")
def delete_baseline(
    baseline_id: int,
    force: bool = False,
    s: Session = Depends(get_session),
) -> dict:
    """Delete a baseline and its scoping rows.

    Hard-fails (409) when a workbook still points at this baseline as its
    primary scope — deleting under that would orphan the assessment surface
    and silently break status writes. The user has to clear or swap the
    workbook's framework/baseline first.

    Pass ``force=true`` to override the guard: every dependent workbook is
    fully cascade-deleted first (assessments, POAMs, sweep state, etc. — the
    same fan-out as ``DELETE /api/workbooks/{id}``), then the baseline is
    removed. This is the fully-destructive "unblock re-testing" path the UI
    offers behind a second confirmation.

    Reference-overlay attachments (``WorkbookOverlay``) are detached
    automatically — overlays are annotation-only and don't own any state.

    Removes:
      * dependent ``Workbook`` rows + their cascade (force only)
      * ``BaselineControl`` rows (tailoring decisions)
      * ``BaselineObjective`` rows (CCI back-references)
      * ``WorkbookOverlay`` rows for this baseline
      * the ``Baseline`` row itself

    Returns the counts so the UI can show a confirmation toast.
    """
    b = s.get(Baseline, baseline_id)
    if not b:
        raise HTTPException(status_code=404, detail="Baseline not found")

    # Capture name + scoping-row counts UP FRONT. The force path below deletes
    # dependent workbooks, and ``delete_workbook`` now cascades away an orphaned
    # primary baseline itself (so the header picker doesn't keep stale entries).
    # That means by the time we get past the loop, *this* baseline and its
    # scoping rows may already be gone — so we snapshot what we're removing
    # while it's all still present.
    baseline_name = b.name
    control_count = len(s.exec(
        select(BaselineControl.baseline_id).where(BaselineControl.baseline_id == baseline_id)
    ).all())
    objective_count = len(s.exec(
        select(BaselineObjective.baseline_id).where(BaselineObjective.baseline_id == baseline_id)
    ).all())
    overlay_count = len(s.exec(
        select(WorkbookOverlay.baseline_id).where(WorkbookOverlay.baseline_id == baseline_id)
    ).all())

    # Block if any workbook still treats this as its primary baseline —
    # destroying it would leave Assessments pointed at a workbook whose
    # scope has vanished. Surface 409 with the dependent filenames so the
    # UI can tell the assessor exactly which workbooks to fix.
    in_use = s.exec(
        select(Workbook).where(Workbook.baseline_id == baseline_id)
    ).all()
    workbooks_removed: list[str] = []
    if in_use:
        if not force:
            names = [w.filename for w in in_use]
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Baseline is still the primary scope for {len(in_use)} "
                    f"workbook{'' if len(in_use) == 1 else 's'}: "
                    f"{', '.join(names)}. Change or clear the workbook's "
                    "framework/baseline before deleting, or force-delete to "
                    "remove the dependent workbook(s) too."
                ),
            )
        # Force path: cascade-delete each dependent workbook (assessments,
        # POAMs, sweep state, the lot) via the canonical workbook deleter so
        # we don't re-derive the fan-out here. Local import breaks the
        # workbooks<->baselines import cycle.
        from .workbooks import delete_workbook

        for wb in in_use:
            workbooks_removed.append(wb.filename)
            delete_workbook(workbook_id=wb.id, s=s)  # type: ignore[arg-type]

    # Re-fetch: the last workbook delete above may have already cascaded this
    # baseline away (orphan-baseline cleanup in delete_workbook). Only delete
    # the scoping rows + baseline row if they're still here, so we don't fire
    # ``s.delete`` on a detached/stale instance.
    b = s.get(Baseline, baseline_id)
    if b is not None:
        s.exec(delete(BaselineControl).where(BaselineControl.baseline_id == baseline_id))
        s.exec(delete(BaselineObjective).where(BaselineObjective.baseline_id == baseline_id))
        s.exec(delete(WorkbookOverlay).where(WorkbookOverlay.baseline_id == baseline_id))
        s.exec(delete(CrmSuspicionLog).where(CrmSuspicionLog.crm_baseline_id == baseline_id))
        s.exec(delete(CrmCorpusFeatures).where(CrmCorpusFeatures.crm_baseline_id == baseline_id))
        s.exec(
            update(AssessmentImplementation)
            .where(AssessmentImplementation.source_baseline_id == baseline_id)
            .values(source_baseline_id=None)
        )
        s.delete(b)
        s.commit()

    return {
        "ok": True,
        "baseline_id": baseline_id,
        "name": baseline_name,
        "controls_removed": control_count,
        "objectives_removed": objective_count,
        "overlay_attachments_removed": overlay_count,
        "workbooks_removed": workbooks_removed,
    }


# ---------------------------------------------------------------------------
# CRM suspicion (three-tier hybrid scoring)
# ---------------------------------------------------------------------------


def compute_and_persist_crm_suspicion(
    session: Session,
    *,
    workbook_id: int,
    crm_baseline_id: int,
) -> tuple[CrmSuspicionLog, CrmSuspicionReport]:
    """Build inputs, score, persist a ``CrmSuspicionLog`` for the workbook+CRM.

    Pure helper — no FastAPI Request/Response surface. Used by both the
    ``GET /api/baselines/{workbook_id}/crm-suspicion`` endpoint (manual
    trigger) and the workbook attach-overlay handler (auto-trigger on
    CRM upload). Same inputs, same persistence, no behavior drift.

    Returns ``(log, report)``: the endpoint uses ``report.to_json_safe()``
    to preserve the canonical JSON shape (including derived ``severity``
    bucket); the attach-overlay handler only needs the log identity to
    confirm persistence succeeded.

    Side effects:
      * Persists a ``CrmSuspicionLog`` row.
      * Persists a ``CrmCorpusFeatures`` row when the feature extractor
        returned a vector (grows the IsolationForest training corpus).
      * Commits the session and refreshes the log row.

    Per ``engine/CRM_SANITY_DESIGN.md`` — provider auto-resolves silently
    (OpenAI if API key present, TF-IDF fallback otherwise); cold-start
    paths (n_corpus < MIN_CORPUS_SIZE) skip IsolationForest entirely.
    """
    crm_context = build_crm_context(workbook_id, session)
    fingerprint = build_boundary_fingerprint(
        workbook_id=workbook_id, session=session
    )
    in_scope_control_ids = sorted(fingerprint.in_scope_control_ids)

    # Tagged-evidence-by-family — Evidence → EvidenceTag → Objective →
    # Control GROUP BY family. Count distinct evidence rows per family so
    # multiple tags on the same artifact aren't double-counted (a single
    # ACAS scan can tag dozens of CCIs across one family).
    family_rows = session.exec(
        select(Control.family, func.count(func.distinct(Evidence.id)))
        .join(EvidenceTag, EvidenceTag.evidence_id == Evidence.id)
        .join(Objective, Objective.id == EvidenceTag.objective_id)
        .join(Control, Control.id == Objective.control_id_fk)
        .group_by(Control.family)
    ).all()
    tagged_evidence_by_family: dict[str, int] = {
        (fam or "").lower(): int(count) for (fam, count) in family_rows if fam
    }

    # Tier 3 inputs — current schema version only. Stale-version corpus
    # rows are preserved on disk for diagnostics but never feed the live
    # score.
    n_corpus = int(
        session.exec(
            select(func.count(CrmCorpusFeatures.id)).where(
                CrmCorpusFeatures.feature_schema_version
                == CURRENT_FEATURE_SCHEMA_VERSION
            )
        ).one()
        or 0
    )
    anomaly_model_blob: bytes | None = session.exec(
        select(CrmAnomalyModel.model_blob).where(
            CrmAnomalyModel.is_active.is_(True),  # type: ignore[union-attr]
            CrmAnomalyModel.feature_schema_version
            == CURRENT_FEATURE_SCHEMA_VERSION,
        )
    ).first()

    # Tier 2b — provider auto-resolves silently (OpenAI if API key
    # present, TF-IDF fallback otherwise). The narrative-quality scorer
    # gracefully returns None when its provider returns empty results.
    embeddings_provider = resolve_provider()

    report = score_crm_suspicion(
        workbook_id=workbook_id,
        crm_baseline_id=crm_baseline_id,
        crm_context=crm_context,
        in_scope_control_ids=in_scope_control_ids,
        tagged_evidence_by_family=tagged_evidence_by_family,
        n_corpus=n_corpus,
        anomaly_model_blob=anomaly_model_blob,
        embeddings_provider=embeddings_provider,
    )

    # Persist the log row — flags + per_family JSON-stringified for the
    # SQLite text columns.
    log = CrmSuspicionLog(
        workbook_id=workbook_id,
        crm_baseline_id=crm_baseline_id,
        computed_at=report.computed_at,
        heuristic_score=report.heuristic_score,
        ml_anomaly_score=report.ml_anomaly_score,
        narrative_quality_score=report.narrative_quality_score,
        overall_suspicion=report.overall_suspicion,
        flags_json=json.dumps([asdict(f) for f in report.flags]),
        per_family_json=json.dumps(report.per_family),
        n_corpus=report.n_corpus,
    )
    session.add(log)

    # Grow the corpus for future IsolationForest refits. Only persist
    # when the feature extractor actually returned a vector (it always
    # does today; defensive against future cold-start paths).
    if report.feature_vector is not None:
        session.add(
            CrmCorpusFeatures(
                crm_baseline_id=crm_baseline_id,
                workbook_id=workbook_id,
                feature_schema_version=report.feature_vector.schema_version,
                features_json=report.feature_vector.to_json(),
                extracted_at=datetime.now(timezone.utc),
            )
        )

    session.commit()
    session.refresh(log)
    return log, report


def _latest_crm_baseline_id(
    session: Session, *, workbook_id: int
) -> int | None:
    """Pick the most-recently-attached CRM overlay's baseline_id, if any.

    ``build_crm_context`` itself merges across all attached CRMs
    latest-wins per control, but the ``CrmSuspicionLog`` row needs to
    point at *one* baseline_id for the UI's "mark false positive" action
    to know which overlay the operator's verdict applies to. The latest
    attached one matches the one whose entries dominate the merged view.
    """
    return session.exec(
        select(WorkbookOverlay.baseline_id)
        .join(Baseline, Baseline.id == WorkbookOverlay.baseline_id)
        .where(
            WorkbookOverlay.workbook_id == workbook_id,
            Baseline.source_type == BaselineSourceType.CRM,
        )
        .order_by(WorkbookOverlay.attached_at.desc())
    ).first()


@router.get("/{workbook_id}/crm-suspicion")
def compute_crm_suspicion(
    workbook_id: int, s: Session = Depends(get_session)
) -> dict:
    """Compute (and persist) a three-tier suspicion score for a workbook's CRM.

    Tier 1: heuristics (always emitted) — floor that works on the very
    first CRM ever uploaded.
    Tier 2a: TF-IDF intra-CRM similarity (always emitted) — boilerplate
    narrative detection.
    Tier 2b: embedding-based narrative quality (emitted when an embedder
    resolves; falls back silently to TF-IDF pseudo-embeddings).
    Tier 3: IsolationForest cross-CRM anomaly (emitted once corpus
    ≥ ``MIN_CORPUS_SIZE`` at current feature schema version).

    Side effects (intentional — the suspicion compute is the natural place
    to grow the corpus):
      * Persists a ``CrmSuspicionLog`` row with the full breakdown.
      * Persists a ``CrmCorpusFeatures`` row from the extracted feature
        vector so the next refit of the IsolationForest has one more
        sample. Idempotency is intentionally loose — the operator can
        recompute as often as they like; duplicate corpus rows naturally
        weight a frequently-recomputed CRM higher, which matches "this
        CRM is being actively scrutinized."

    Returns the JSON-safe report shape (see
    :meth:`CrmSuspicionReport.to_json_safe`) plus ``suspicion_log_id``
    so the UI can wire the "mark as false positive" action.

    Raises 404 if the workbook isn't found or has no CRM overlay
    attached. The UI hides the suspicion banner entirely for workbooks
    in either state, so a 404 here is the expected silent path, not an
    error toast.

    Thin wrapper around :func:`compute_and_persist_crm_suspicion` so the
    same compute path is reachable from the attach-overlay handler
    without an HTTP round-trip.
    """
    wb = s.get(Workbook, workbook_id)
    if not wb:
        raise HTTPException(status_code=404, detail="Workbook not found")

    crm_baseline_id = _latest_crm_baseline_id(s, workbook_id=workbook_id)
    if crm_baseline_id is None:
        raise HTTPException(
            status_code=404,
            detail="No CRM overlay attached to this workbook",
        )

    log, report = compute_and_persist_crm_suspicion(
        s, workbook_id=workbook_id, crm_baseline_id=crm_baseline_id
    )
    payload = report.to_json_safe()
    payload["suspicion_log_id"] = log.id
    return payload


@router.get("/{workbook_id}/crm-suspicion/latest")
def get_latest_crm_suspicion(
    workbook_id: int, s: Session = Depends(get_session)
) -> dict:
    """Return the most recently persisted ``CrmSuspicionLog`` for a workbook.

    Distinct from ``GET /{workbook_id}/crm-suspicion`` (which *computes*
    and writes a new log + corpus row on every hit). This endpoint is
    pure read — no embedder calls, no IsolationForest scoring, no corpus
    growth. The intended caller is post-attach UI feedback that wants to
    re-warn the user when a previously-computed suspicion verdict still
    stands, without paying the compute cost on every CRM re-upload.

    Returns the cached score breakdown + the assessor's verdict
    (``assessor_marked_false_positive``) so the toast can suppress the
    warning when the user has already cleared it. Decodes ``flags_json``
    into a list of dicts to match the live-compute endpoint's response
    shape so the UI can share a renderer.

    Returns 404 when no log exists for this workbook. The UI keys off the
    404 to omit the suspicion clause entirely — same silent-skip pattern
    as the live-compute endpoint uses for "no CRM attached."
    """
    wb = s.get(Workbook, workbook_id)
    if not wb:
        raise HTTPException(status_code=404, detail="Workbook not found")

    log = s.exec(
        select(CrmSuspicionLog)
        .where(CrmSuspicionLog.workbook_id == workbook_id)
        .order_by(CrmSuspicionLog.computed_at.desc())
    ).first()
    if log is None:
        raise HTTPException(
            status_code=404,
            detail="No suspicion log for this workbook",
        )

    # flags_json is the canonical persisted form (one row per dataclass).
    # Decode here so the wire shape matches the live-compute endpoint —
    # the UI shares the renderer between cached and fresh paths.
    try:
        flags = json.loads(log.flags_json) if log.flags_json else []
    except json.JSONDecodeError:
        # Corrupt log row shouldn't break the toast — degrade to empty
        # flags. The user can still recompute to repair.
        flags = []

    return {
        "suspicion_log_id": log.id,
        "workbook_id": log.workbook_id,
        "crm_baseline_id": log.crm_baseline_id,
        "computed_at": iso_utc(log.computed_at),
        "heuristic_score": log.heuristic_score,
        "ml_anomaly_score": log.ml_anomaly_score,
        "narrative_quality_score": log.narrative_quality_score,
        "overall_suspicion": log.overall_suspicion,
        "flags": flags,
        "n_corpus": log.n_corpus,
        "assessor_marked_false_positive": log.assessor_marked_false_positive,
    }


class MarkSuspicionFalsePositiveBody(BaseModel):
    """PATCH body for marking a CrmSuspicionLog as a false positive.

    ``notes`` is optional but strongly recommended — the v0.3+ supervised
    "CRM lied" classifier reads these labels and the free-text rationale
    is what makes a false-positive marking auditable later.
    """

    notes: str | None = None


@router.patch("/crm-suspicion/{log_id}/mark")
def mark_suspicion_false_positive(
    log_id: int,
    body: MarkSuspicionFalsePositiveBody,
    s: Session = Depends(get_session),
) -> dict:
    """Flip ``assessor_marked_false_positive`` on a CrmSuspicionLog.

    The mark is a *label* for the v0.3+ supervised classifier, not a
    veto on the heuristics — the current banner still surfaces the
    score so the operator can revisit. The route is intentionally
    permissive (no transition check) because the operator may flip the
    flag back and forth as they investigate.
    """
    log = s.get(CrmSuspicionLog, log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Suspicion log not found")
    log.assessor_marked_false_positive = True
    if body.notes is not None:
        log.assessor_review_notes = body.notes
    s.add(log)
    s.commit()
    s.refresh(log)
    return {
        "ok": True,
        "suspicion_log_id": log.id,
        "marked_at": iso_utc(datetime.now(timezone.utc)),
    }
