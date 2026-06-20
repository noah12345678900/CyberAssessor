"""SystemContext CRUD + extract endpoint.

Routes (per-workbook):

* ``GET  /api/system-context/{workbook_id}``                — SystemContext or 404
* ``POST /api/system-context/{workbook_id}``                — upsert from freeform
                                                              inputs; runs LLM
                                                              extraction
* ``POST /api/system-context/{workbook_id}/reset``          — deletes the row
* ``POST /api/system-context/{workbook_id}/bump-confidence`` — +0.05 per accepted
                                                               triage artifact

Routes (pending singleton, workbook_id IS NULL):

* ``GET  /api/system-context/pending``                 — pending context + its
                                                         pending boundary docs
* ``POST /api/system-context/pending``                 — upsert the pending row
* ``POST /api/system-context/pending/reset``           — deletes pending row +
                                                         pending boundary docs
* ``POST /api/system-context/pending/bump-confidence`` — +0.05 per accepted
                                                         triage artifact
* ``POST /api/system-context/pending/promote``         — reparent pending context
                                                         + pending boundary docs
                                                         onto a workbook

The SystemContext row biases boundary-aware sweep scoring (see
``evidence/sources/sweep.py``). It does NOT change which CCIs are in
scope — per ``feedback_scoping_out_of_assessor``, scope lives in the
workbook, not the assessor app.

The "pending" routes let an assessor drop boundary docs (SSP / network
diagram / ATO letter) BEFORE picking a workbook — the natural reflex,
since those docs exist independent of any particular assessment. The
partial unique index ``ix_systemcontext_pending_singleton`` enforces
at-most-one pending row at the schema level, so this layer doesn't need
an app-level lock. ``promote`` is an explicit user-click action exposed
via the Sweep Context page banner; it refuses (409) if the target
workbook already has a SystemContext so the assessor's prior boundary
work can't be silently clobbered.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..config import load_config
from ..db import get_session
from ..llm.client import MissingApiKeyError, make_client
from ..models import Evidence, SystemContext, SystemContextSourceType, Workbook, iso_utc
from ..system_context.base import get_source_for_type
from ..system_context.freeform import FreeformContextSource
from .evidence import _serialize as _serialize_evidence
from .evidence import delete_one_evidence

router = APIRouter(prefix="/api/system-context", tags=["system-context"])


class FreeformInput(BaseModel):
    """Upsert body — superset of the legacy four-blob shape.

    ``source_type`` picks which adapter runs:
      * ``"freeform_markdown"`` (default for back-compat) — uses the four
        markdown fields below; legacy prose-driven extraction.
      * ``"docx_narrative"`` — boundary-doc adapter; pulls Evidence rows
        flagged with ``is_boundary_doc=True`` for this workbook. The four
        markdown fields are ignored.

    Kept as one body shape (rather than a discriminated union) so the
    existing UI clients on the freeform path keep working unchanged
    while the new Sweep Context page just sets ``source_type``.
    """

    source_type: str | None = None
    boundary: str | None = None
    stakeholders: str | None = None
    tech_inventory: str | None = None
    requirement_hints: str | None = None


class BumpConfidenceInput(BaseModel):
    """How many artifacts the user just accepted through the triage flow."""

    accepted_count: int = 1


def _serialize(ctx: SystemContext) -> dict:
    """SystemContext.model_dump() with datetimes coerced to UTC-marked ISO strings."""
    data = ctx.model_dump()
    for k in ("created_at", "updated_at"):
        v = data.get(k)
        if hasattr(v, "isoformat"):
            data[k] = iso_utc(v)
    return data


def _make_extractor_or_412():
    """Build the LLM extractor or raise the standard 412 with the settings hint."""
    cfg = load_config()
    try:
        return make_client(cfg)
    except MissingApiKeyError as e:
        provider_label = "OpenAI" if cfg.llm_provider == "openai" else "Anthropic"
        raise HTTPException(
            status_code=412,
            detail={
                "error": "missing_api_key",
                "message": str(e),
                "hint": (
                    f"Set the {provider_label} API key in Settings "
                    "(stored in Windows Credential Manager)."
                ),
            },
        ) from e


def _dispatch_upsert(
    s: Session,
    workbook_id: int | None,
    body: FreeformInput,
) -> dict:
    """Shared body for the per-workbook AND pending POSTs.

    workbook_id=None means "pending singleton" — the adapters branch on
    `.is_(None)` so the same code path serves both cases without an extra
    code fork at the route level.
    """
    extractor = _make_extractor_or_412()

    # Dispatch on source_type. Default = freeform for back-compat with the
    # legacy prose UI; the new Sweep Context page passes "docx_narrative"
    # and the boundary-doc adapter pulls from Evidence, ignoring the four
    # markdown fields entirely.
    src_type_raw = (body.source_type or "freeform_markdown").lower()
    try:
        src_type = SystemContextSourceType(src_type_raw)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown source_type: {body.source_type!r}",
        ) from exc

    if src_type == SystemContextSourceType.FREEFORM_MARKDOWN:
        src = FreeformContextSource()
        result = src.apply(
            s,
            workbook_id=workbook_id,
            extractor=extractor,
            boundary=body.boundary,
            stakeholders=body.stakeholders,
            tech_inventory=body.tech_inventory,
            requirement_hints=body.requirement_hints,
        )
    else:
        # Boundary-docs adapter (and future file-based adapters) take no
        # body payload — they read from Evidence / a referenced file.
        adapter = get_source_for_type(src_type)
        result = adapter.apply(s, workbook_id=workbook_id, extractor=extractor)
    return {
        "context": _serialize(result.context),
        "tokens_extracted": result.tokens_extracted,
        "confidence": result.confidence,
        "notes": result.notes,
    }


# ---------------------------------------------------------------------------
# Pending (pre-workbook) endpoints
#
# FastAPI matches routes in REGISTRATION ORDER and a path-param type mismatch
# returns 422 rather than falling through. So ALL literal `/pending*` routes
# MUST be registered ABOVE the parametric `/{workbook_id}` handlers further
# down — otherwise `POST /pending` would match `POST /{workbook_id}` first,
# try to coerce "pending" → int, and 422.
# ---------------------------------------------------------------------------


def _get_pending_context(s: Session) -> SystemContext | None:
    return s.exec(
        select(SystemContext).where(SystemContext.workbook_id.is_(None))
    ).first()


def _get_pending_boundary_docs(s: Session) -> list[Evidence]:
    return list(
        s.exec(
            select(Evidence)
            .where(
                Evidence.workbook_id.is_(None),  # type: ignore[union-attr]
                Evidence.is_boundary_doc.is_(True),  # type: ignore[union-attr]
            )
            .order_by(Evidence.ingested_at)
        ).all()
    )


@router.get("/pending")
def get_pending_context(s: Session = Depends(get_session)) -> dict:
    """Return the pending SystemContext singleton + its attached boundary docs.

    Always 200 — empty state returns ``{"context": None, "boundary_docs": []}``.
    The route used to 404 when both were absent, but that turned the polled
    "is there pending scope?" check into DevTools console noise on every
    fresh app load. The frontend already treats the empty payload as "no
    pending scope yet", so 200 is the honest contract.
    """
    ctx = _get_pending_context(s)
    docs = _get_pending_boundary_docs(s)
    return {
        "context": _serialize(ctx) if ctx is not None else None,
        "boundary_docs": [_serialize_evidence(d) for d in docs],
    }


@router.post("/pending")
def upsert_pending_context(
    body: FreeformInput,
    s: Session = Depends(get_session),
) -> dict:
    """Upsert the pending SystemContext row.

    No workbook validation — that's the whole point of the pending mode.
    The partial unique index ``ix_systemcontext_pending_singleton`` keeps
    us honest at the schema level; the adapters' ``.is_(None)`` lookup
    keeps a second POST from colliding.
    """
    return _dispatch_upsert(s, None, body)


@router.post("/pending/reset")
def reset_pending_context(s: Session = Depends(get_session)) -> dict:
    """Delete the pending SystemContext singleton + its boundary docs.

    Mirrors the per-workbook reset. The boundary-doc Evidence rows are
    deleted explicitly here — there's no FK cascade between Evidence and
    SystemContext (Evidence pre-dates the pending-singleton concept), so
    leaving them orphaned would mean a stale "you have pending boundary
    docs" badge persists after the user explicitly cleared scope.
    """
    ctx = _get_pending_context(s)
    docs = _get_pending_boundary_docs(s)
    # Delete each boundary-doc Evidence via the shared evidence-delete helper,
    # NOT a bare s.delete(d). Evidence has nine FK children (EvidenceTag,
    # StigFinding, EvidenceComponent/Asset/Boundary, BoundaryTokenSource,
    # AssessmentEvidenceShown/Citation, the superseded_by self-FK) with no DB
    # ondelete; a bare delete under PRAGMA foreign_keys=ON raises a FK
    # constraint failure → 500 (boundary docs auto-tag EvidenceTag + carry
    # EvidenceBoundary/BoundaryTokenSource on ingest, so this fired in practice).
    # delete_one_evidence clears all children first and commits per doc.
    for d in docs:
        if d.id is not None:
            delete_one_evidence(d.id, purge_text=True, s=s)
    if ctx is not None:
        s.delete(ctx)
    s.commit()
    return {
        "reset": True,
        "context_removed": ctx is not None,
        "boundary_docs_removed": len(docs),
    }


@router.post("/pending/bump-confidence")
def bump_pending_confidence(
    body: BumpConfidenceInput,
    s: Session = Depends(get_session),
) -> dict:
    """Outcome-tied confidence bump for the pending singleton — mirrors the
    per-workbook bump, called from SweepTriageDialog when the assessor
    accepts artifacts during a pre-workbook sweep.

    No-op if no pending row exists; the bump is purely additive telemetry,
    not state we want to silently create.
    """
    if body.accepted_count <= 0:
        return {"bumped": False, "reason": "accepted_count <= 0"}
    ctx = _get_pending_context(s)
    if ctx is None:
        return {"bumped": False, "reason": "no pending SystemContext"}
    ctx.confidence = min(1.0, ctx.confidence + 0.05 * body.accepted_count)
    s.add(ctx)
    s.commit()
    return {"bumped": True, "confidence": ctx.confidence}


def promote_pending_to_workbook(s: Session, workbook_id: int) -> dict:
    """Reparent the pending SystemContext + boundary docs onto a workbook.

    Library helper shared by the explicit ``/pending/promote`` route AND the
    auto-promote hook inside ``open_workbook`` (``routes/workbooks.py``). Does
    NOT raise — callers translate the result into HTTP shape as needed. The
    helper commits on success so the caller doesn't have to wrap it in its
    own transaction.

    Returns one of three shapes (always includes ``status``):

    * ``{"status": "no_pending"}`` — nothing pending; caller should treat
      as a clean no-op.
    * ``{"status": "conflict", "reason": str}`` — target workbook already
      has its own SystemContext. We do NOT silently clobber: the pending
      row + docs stay put so the assessor can decide (today the UI keeps
      them around until the user picks a workbook that doesn't have one).
    * ``{"status": "promoted", "workbook_id": int, "context": dict | None,
      "boundary_doc_count": int}`` — pending rows are now bound to the
      workbook. ``context`` is None when only docs were promoted (an
      edge case: docs uploaded but extraction never ran).

    The caller is responsible for verifying ``workbook_id`` references a
    real Workbook before calling this — we don't repeat the lookup.
    """
    pending_ctx = _get_pending_context(s)
    pending_docs = _get_pending_boundary_docs(s)
    if pending_ctx is None and not pending_docs:
        return {"status": "no_pending"}

    existing = s.exec(
        select(SystemContext).where(SystemContext.workbook_id == workbook_id)
    ).first()
    if existing is not None and pending_ctx is not None:
        return {
            "status": "conflict",
            "reason": (
                f"workbook {workbook_id} already has a SystemContext; "
                "promotion would overwrite it"
            ),
        }

    if pending_ctx is not None:
        pending_ctx.workbook_id = workbook_id
        pending_ctx.updated_at = datetime.now(timezone.utc)
        s.add(pending_ctx)
    for d in pending_docs:
        d.workbook_id = workbook_id
        s.add(d)
    s.commit()
    if pending_ctx is not None:
        s.refresh(pending_ctx)

    return {
        "status": "promoted",
        "workbook_id": workbook_id,
        "context": _serialize(pending_ctx) if pending_ctx is not None else None,
        "boundary_doc_count": len(pending_docs),
    }


@router.post("/pending/promote")
def promote_pending_context(
    workbook_id: int,
    s: Session = Depends(get_session),
) -> dict:
    """Attach the pending SystemContext + boundary docs to ``workbook_id``.

    Explicit user-click action exposed via the Sweep Context page banner —
    the assessor opens a workbook, sees "you have pending boundary scope,
    promote onto {wb.name}?", and clicks. Tolerant on the empty side: if
    nothing is pending, returns ``{promoted: False}`` so callers don't
    have to special-case the empty case.

    Refuses (409) if the target workbook already has a SystemContext —
    promoting on top of an existing row would either silently overwrite
    the assessor's prior boundary work or trip the per-workbook UNIQUE
    index. The partial UNIQUE on workbook_id IS NOT NULL is the safety
    net but we surface the conflict here so the UI can tell the user
    *why* promotion was skipped.

    Thin wrapper over :func:`promote_pending_to_workbook` — same logic
    fires on auto-promote inside ``open_workbook``; this route just maps
    the helper's status field to HTTP semantics.
    """
    wb = s.get(Workbook, workbook_id)
    if wb is None:
        raise HTTPException(
            status_code=404, detail=f"workbook {workbook_id} not found"
        )

    result = promote_pending_to_workbook(s, workbook_id)
    if result["status"] == "no_pending":
        return {
            "promoted": False,
            "reason": "no pending context",
            "workbook_id": workbook_id,
        }
    if result["status"] == "conflict":
        raise HTTPException(status_code=409, detail=result["reason"])

    return {
        "promoted": True,
        "workbook_id": result["workbook_id"],
        "context": result["context"],
        "boundary_doc_count": result["boundary_doc_count"],
    }


@router.get("/{workbook_id}")
def get_context(
    workbook_id: int, s: Session = Depends(get_session)
) -> dict | None:
    """Per-workbook SystemContext lookup.

    Registered AFTER the literal `/pending` routes because FastAPI matches in
    registration order — putting this parametric handler first would shadow
    `GET /pending` (the router would parse "pending" as workbook_id and 422).

    Returns ``null`` (200) when the workbook has no SystemContext yet, rather
    than 404 — the page polls this on every render and a 404 was logged as a
    red error in DevTools on every fresh workbook open. ``None`` matches the
    frontend ``useSystemContext`` typing (``SystemContext | null``).
    """
    ctx = s.exec(
        select(SystemContext).where(SystemContext.workbook_id == workbook_id)
    ).first()
    if not ctx:
        return None
    return _serialize(ctx)


@router.post("/{workbook_id}")
def upsert_context(
    workbook_id: int,
    body: FreeformInput,
    s: Session = Depends(get_session),
) -> dict:
    """Upsert + run LLM extraction on the freeform inputs.

    Returns the SystemContext row plus extraction telemetry
    (``tokens_extracted``, ``confidence``, ``notes``). On LLM failure the
    row is still saved with confidence=0.2 and ``notes.extraction_error``
    populated — the UI surfaces this as a toast.

    Registered AFTER `POST /pending` for the same routing-order reason as
    `GET /{workbook_id}` above — otherwise "pending" would be coerced to int
    and 422 the pending POST.
    """
    wb = s.get(Workbook, workbook_id)
    if wb is None:
        raise HTTPException(status_code=404, detail=f"workbook {workbook_id} not found")
    return _dispatch_upsert(s, workbook_id, body)


@router.post("/{workbook_id}/reset")
def reset_context(workbook_id: int, s: Session = Depends(get_session)) -> dict:
    ctx = s.exec(
        select(SystemContext).where(SystemContext.workbook_id == workbook_id)
    ).first()
    if ctx:
        s.delete(ctx)
        s.commit()
    return {"reset": True, "workbook_id": workbook_id}


@router.post("/{workbook_id}/bump-confidence")
def bump_confidence(
    workbook_id: int,
    body: BumpConfidenceInput,
    s: Session = Depends(get_session),
) -> dict:
    """Outcome-tied confidence bump — called from SweepTriageDialog after a
    successful ingest start.

    +0.05 per accepted artifact (clamped at 1.0). The plan called for the
    bump to fire inside /api/sharepoint/ingest, but real ingest is
    /api/evidence/ingest and runs on a background thread with no
    workbook_id awareness — plumbing one through would require touching the
    job registry, IngestSummary, and the sweep-source loader. The triage
    dialog already knows both the workbook_id and the user's selection
    size, so the cleanest hook is here: confidence tracks user-intent
    (the assessor accepted N) rather than commit-completion (N landed in
    Evidence). Close enough; failed ingests would only inflate confidence
    by 0.05 per attempt, which the next sweep's relevance will discount
    naturally.

    No-op if the workbook has no SystemContext row — sweep usage doesn't
    require one, and we don't want to silently create a placeholder here.
    """
    if body.accepted_count <= 0:
        return {"bumped": False, "reason": "accepted_count <= 0"}
    ctx = s.exec(
        select(SystemContext).where(SystemContext.workbook_id == workbook_id)
    ).first()
    if not ctx:
        return {"bumped": False, "reason": "no SystemContext for workbook"}
    ctx.confidence = min(1.0, ctx.confidence + 0.05 * body.accepted_count)
    s.add(ctx)
    s.commit()
    return {"bumped": True, "confidence": ctx.confidence}
