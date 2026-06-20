"""POAM (Plan of Action & Milestones) endpoints.

Thin route layer over :mod:`cybersecurity_assessor.poam`. The heavy lifting
lives in ``poam/generator.py`` (cluster NC assessments into draft POAMs),
``poam/exporter.py`` (write to eMASS template via xlwings), and
``poam/importer.py`` (round-trip eMASS workbook back into the DB). This
module's job is just to expose those + CRUD on the rows for the UI.

Surface:
  GET    /api/poams                       list (filter by workbook_id, status)
  POST   /api/poams/generate              cluster NC assessments → draft POAMs
  POST   /api/poams/export                write workbook POAMs to eMASS template
  POST   /api/poams/import                read eMASS workbook → merge
  GET    /api/poams/{id}                  detail with milestones + objectives
  POST   /api/poams                       create one POAM manually
  PATCH  /api/poams/{id}                  update editable fields
  DELETE /api/poams/{id}                  delete POAM (cascades milestones + links)
  POST   /api/poams/{id}/milestones       add milestone
  PATCH  /api/poams/{id}/milestones/{mid} update milestone
  DELETE /api/poams/{id}/milestones/{mid} delete milestone
  POST   /api/poams/{id}/evidence         link an evidence artifact
  DELETE /api/poams/{id}/evidence/{eid}   unlink an evidence artifact

Risk fields use the NIST SP 800-30r1 5-level scale; computed raw_severity is
re-derived from likelihood × impact on every PATCH that touches either —
keeps the matrix lookup as the single source of truth (poam/risk.py).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, delete, select

from ..config import load_config
from ..db import get_session
from ..llm.client import MissingApiKeyError, make_client
from ..models import (
    Control,
    Evidence,
    Objective,
    Poam,
    PoamEvidence,
    PoamMilestone,
    PoamObjective,
    PoamRiskHistory,
    PoamStatus,
    RiskLevel,
    Workbook,
    iso_utc,
)
from ..poam.exporter import export_poams as run_export
from ..poam.generator import generate_for_workbook
from ..poam.importer import import_poams as run_import
from ..poam.residual_advisor import suggest_residual
from ..poam.risk import (
    LEVEL_DESCRIPTIONS,
    RISK_HISTORY_FIELDS,
    SCORES,
    compute_risk,
    record_risk_change,
)

router = APIRouter(prefix="/api/poams", tags=["poams"])

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _milestone_dict(m: PoamMilestone) -> dict:
    return {
        "id": m.id,
        "poam_id": m.poam_id,
        "description": m.description,
        "scheduled_date": iso_utc(m.scheduled_date),
        "completion_date": iso_utc(m.completion_date),
        "changes_history": m.changes_history,
        "created_at": iso_utc(m.created_at),
    }


def _poam_summary(
    p: Poam,
    milestone_count: int,
    objective_count: int,
    evidence_count: int,
) -> dict:
    """List-view shape: enough to render a row without N+1 reads."""
    return {
        "id": p.id,
        "workbook_id": p.workbook_id,
        "control_cluster": p.control_cluster,
        "vulnerability_description": p.vulnerability_description,
        "security_control_number": p.security_control_number,
        "emass_poam_id": p.emass_poam_id,
        "status": p.status.value,
        "scheduled_completion_date": iso_utc(p.scheduled_completion_date),
        "actual_completion_date": iso_utc(p.actual_completion_date),
        "likelihood": p.likelihood.value if p.likelihood else None,
        "impact": p.impact.value if p.impact else None,
        "raw_severity": p.raw_severity.value if p.raw_severity else None,
        "residual_risk": p.residual_risk.value if p.residual_risk else None,
        # Risk provenance — drive the UI source badges and tooltip prose so
        # the assessor (and a future 3PAO) can distinguish auto-seeded
        # values from manual judgments without diving into the audit table.
        # See alembic 0008 / poam/risk.py for the source taxonomy.
        "likelihood_source": p.likelihood_source,
        "likelihood_rationale": p.likelihood_rationale,
        "impact_source": p.impact_source,
        "impact_rationale": p.impact_rationale,
        "residual_risk_source": p.residual_risk_source,
        "residual_risk_rationale": p.residual_risk_rationale,
        # Numeric score helps the UI sort highest-risk-first without
        # re-shipping the enum→int mapping.
        "raw_severity_score": SCORES[p.raw_severity] if p.raw_severity else None,
        "milestone_count": milestone_count,
        "objective_count": objective_count,
        "evidence_count": evidence_count,
        "created_at": iso_utc(p.created_at),
        "updated_at": iso_utc(p.updated_at),
        "exported_at": iso_utc(p.exported_at),
        # True once the assessor has edited vulnerability_description via the
        # UI (or created the POAM manually). The generator's regenerate pass
        # skips locked rows; UI can show a lock indicator if it wants to.
        "narrative_locked": p.narrative_locked,
    }


def _poam_detail(p: Poam, s: Session) -> dict:
    """Full detail: summary + milestones + linked objectives + linked evidence."""
    milestones = s.exec(
        select(PoamMilestone)
        .where(PoamMilestone.poam_id == p.id)
        .order_by(PoamMilestone.scheduled_date, PoamMilestone.id)
    ).all()

    # Join PoamObjective → Objective → Control so the UI can show
    # "AC-2.1 — Develop and document account management policy"
    # without a second round-trip.
    obj_rows = s.exec(
        select(PoamObjective, Objective, Control)
        .join(Objective, Objective.id == PoamObjective.objective_id)
        .join(Control, Control.id == Objective.control_id_fk)
        .where(PoamObjective.poam_id == p.id)
    ).all()

    # Same one-shot join for evidence — fetch the artifact metadata in the
    # same trip as the link row so the UI doesn't have to follow N pointers
    # back to /api/evidence/{id} just to render the name + kind.
    ev_rows = s.exec(
        select(PoamEvidence, Evidence)
        .join(Evidence, Evidence.id == PoamEvidence.evidence_id)
        .where(PoamEvidence.poam_id == p.id)
        .order_by(PoamEvidence.created_at)
    ).all()

    base = _poam_summary(p, len(milestones), len(obj_rows), len(ev_rows))
    base.update(
        {
            "source_identifying_control_vulnerability": (
                p.source_identifying_control_vulnerability
            ),
            "office_org": p.office_org,
            "relevance_of_threat": (
                p.relevance_of_threat.value if p.relevance_of_threat else None
            ),
            "resources_required": p.resources_required,
            "mitigations": p.mitigations,
            "comments": p.comments,
            "milestones": [_milestone_dict(m) for m in milestones],
            "objectives": [
                {
                    "objective_id": o.id,
                    "objective_code": o.objective_id,
                    "objective_text": o.text,
                    "control_id": c.control_id,
                    "control_title": c.title,
                    "status_at_creation": (
                        po.status_at_creation.value if po.status_at_creation else None
                    ),
                }
                for po, o, c in obj_rows
            ],
            "evidence": [
                {
                    "evidence_id": e.id,
                    "title": e.title,
                    "path": e.path,
                    "kind": e.kind.value,
                    "doc_number": e.doc_number,
                    "note": pe.note,
                    "linked_at": iso_utc(pe.created_at),
                }
                for pe, e in ev_rows
            ],
            "evidence_count": len(ev_rows),
        }
    )
    return base


# ---------------------------------------------------------------------------
# List + reference data
# ---------------------------------------------------------------------------


@router.get("")
def list_poams(
    workbook_id: int | None = None,
    status: PoamStatus | None = None,
    s: Session = Depends(get_session),
) -> list[dict]:
    """List POAMs, newest first. Optional workbook_id / status filter.

    Sorted by raw_severity desc (highest-risk first) then created_at desc so
    the highest-impact open work is always at the top of the list.
    """
    stmt = select(Poam)
    if workbook_id is not None:
        stmt = stmt.where(Poam.workbook_id == workbook_id)
    if status is not None:
        stmt = stmt.where(Poam.status == status)
    rows = s.exec(stmt).all()

    # Build counts in one round-trip each to avoid N+1.
    poam_ids = [p.id for p in rows]
    milestone_counts: dict[int, int] = {pid: 0 for pid in poam_ids}
    objective_counts: dict[int, int] = {pid: 0 for pid in poam_ids}
    evidence_counts: dict[int, int] = {pid: 0 for pid in poam_ids}
    if poam_ids:
        # NOTE: SQLModel's session.exec(select(Single.column)).all() returns
        # a list of bare scalars, not 1-tuples — destructuring with `(pid,)`
        # raises TypeError.
        for pid in s.exec(
            select(PoamMilestone.poam_id).where(PoamMilestone.poam_id.in_(poam_ids))  # type: ignore[attr-defined]
        ).all():
            milestone_counts[pid] = milestone_counts.get(pid, 0) + 1
        for pid in s.exec(
            select(PoamObjective.poam_id).where(PoamObjective.poam_id.in_(poam_ids))  # type: ignore[attr-defined]
        ).all():
            objective_counts[pid] = objective_counts.get(pid, 0) + 1
        for pid in s.exec(
            select(PoamEvidence.poam_id).where(PoamEvidence.poam_id.in_(poam_ids))  # type: ignore[attr-defined]
        ).all():
            evidence_counts[pid] = evidence_counts.get(pid, 0) + 1

    def _sort_key(p: Poam):
        # Highest risk first → negate score (None → 0).
        score = SCORES[p.raw_severity] if p.raw_severity else 0
        return (-score, -(p.created_at.timestamp()))

    rows.sort(key=_sort_key)
    return [
        _poam_summary(
            p,
            milestone_counts.get(p.id, 0),
            objective_counts.get(p.id, 0),
            evidence_counts.get(p.id, 0),
        )
        for p in rows
    ]


@router.get("/risk-levels")
def list_risk_levels() -> list[dict]:
    """Surface the 800-30r1 5-level scale + descriptions for UI dropdowns.

    The UI shouldn't hard-code the enum values or the description text — both
    live in poam/risk.py so the SP 800-30 source-of-truth principle holds.
    """
    return [
        {
            "value": lvl.value,
            "score": SCORES[lvl],
            "description": LEVEL_DESCRIPTIONS[lvl],
        }
        for lvl in RiskLevel
    ]


# ---------------------------------------------------------------------------
# Generation / import / export — wrappers over poam/*
# ---------------------------------------------------------------------------


class GenerateRequest(BaseModel):
    workbook_id: int


@router.post("/generate")
def generate(body: GenerateRequest, s: Session = Depends(get_session)) -> dict:
    """Cluster NC assessments in a workbook into draft POAMs.

    Idempotent + self-healing:
      - New NC clusters become new draft POAMs.
      - Existing DRAFT POAMs whose enriched description is stale get
        rewritten in place, picking up new scan findings / host inventory /
        narrative edits since the prior generate run.
      - Existing DRAFT POAMs the assessor has touched (``narrative_locked``)
        are preserved verbatim.
      - Non-DRAFT POAMs (ONGOING/COMPLETED/RISK_ACCEPTED) are preserved to
        keep the workflow audit trail intact.

    Response shape exposes all five buckets so the UI can show a meaningful
    flash (e.g. "rewrote 55, preserved 1 locked edit, no new"), instead of
    the prior count-of-created-only that made non-creating runs look broken.
    ``created`` / ``poam_ids`` are kept for backward compatibility with any
    external callers wired to the v0.1 shape.
    """
    res = generate_for_workbook(body.workbook_id, s)
    s.commit()
    return {
        "workbook_id": body.workbook_id,
        # Backward-compat fields — older UI builds and external callers
        # read these. New UI consumes the counts/ids dicts below.
        "created": len(res.created),
        "poam_ids": [p.id for p in res.created],
        # New, partitioned shape.
        "counts": {
            "created": len(res.created),
            "rewritten": len(res.rewritten),
            "unchanged": len(res.unchanged),
            "locked_skipped": len(res.locked_skipped),
            "non_draft_skipped": len(res.non_draft_skipped),
        },
        "ids": {
            "created": [p.id for p in res.created],
            "rewritten": [p.id for p in res.rewritten],
            "unchanged": [p.id for p in res.unchanged],
            "locked_skipped": [p.id for p in res.locked_skipped],
            "non_draft_skipped": [p.id for p in res.non_draft_skipped],
        },
    }


class ExportRequest(BaseModel):
    workbook_id: int
    output_path: str
    system_name: str | None = None


@router.post("/export")
def export(body: ExportRequest, s: Session = Depends(get_session)) -> dict:
    """Write a workbook's POAMs into a copy of the eMASS RMF POAM template.

    Uses the bundled scrubbed RMF_POAM template — callers don't have to
    locate one. The exporter still accepts a custom template path for
    program-specific overrides, but the route does not surface it because
    100% of UI callers want the bundled default.

    Maps exporter exceptions (mirrors controls export pattern):
      - missing template → 410
      - unwritable / unreachable output path (bad dir, permission, file
        locked open in Excel) → 410 with the OS error text
      - invalid data shape (bad enum, missing column) → 422
      - any other failure → 500 with the actual error message + log entry

    Note: the exporter is pure-Python zip surgery (no xlwings/COM), so an
    OSError here is a filesystem problem with the destination — NOT the
    sidecar or Excel being down. Surfacing it as 410 keeps the UI from
    showing the misleading "is the sidecar running?" copy.
    """
    try:
        report = run_export(
            body.workbook_id,
            body.output_path,
            s,
            system_name=body.system_name,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=410, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    except OSError as e:
        # Destination path problem: directory missing, no write permission,
        # or the target .xlsx is open in Excel and locked. Actionable for the
        # user, so surface the real OS error text.
        _log.warning("POAM export failed (output path): %s", e)
        raise HTTPException(
            status_code=410,
            detail=f"Could not write the export file: {e}",
        ) from e
    except Exception as e:  # noqa: BLE001 — surface the real failure
        _log.exception("POAM export failed unexpectedly: %s", e)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}") from e

    # Stamp exported_at on every POAM that was written, so the UI can show
    # "last exported 5m ago" without forcing the user to re-export to refresh.
    now = datetime.now(timezone.utc)
    for p in s.exec(
        select(Poam).where(Poam.workbook_id == body.workbook_id)
    ).all():
        p.exported_at = now
        s.add(p)
    s.commit()
    return report


class ImportRequest(BaseModel):
    workbook_id: int
    poam_file_path: str


@router.post("/import")
def import_(body: ImportRequest, s: Session = Depends(get_session)) -> dict:
    """Read an eMASS POAM workbook and merge its rows into the DB."""
    try:
        report = run_import(body.workbook_id, body.poam_file_path, s)
    except FileNotFoundError as e:
        raise HTTPException(status_code=410, detail=str(e)) from e
    except ValueError as e:
        # importer raises ValueError on a missing sheet or malformed row
        raise HTTPException(status_code=422, detail=str(e)) from e
    except Exception as e:  # noqa: BLE001 — surface the real failure
        _log.exception("POAM import failed unexpectedly: %s", e)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}") from e

    # Stamp the workbook with "we've reconciled against eMASS as of now". The
    # UI uses this to drop the "you haven't imported the eMASS list yet"
    # warning on Generate / Export — once you've imported once, the Draft
    # rows the generator produces are guaranteed not to collide with eMASS
    # rows we've already learned about (the importer matches on emass_poam_id).
    wb = s.get(Workbook, body.workbook_id)
    if wb is not None:
        wb.last_emass_import_at = datetime.now(timezone.utc)
        s.add(wb)
    s.commit()
    return report


# ---------------------------------------------------------------------------
# Detail / create / update / delete
# ---------------------------------------------------------------------------


@router.get("/{poam_id}")
def get_poam(poam_id: int, s: Session = Depends(get_session)) -> dict:
    p = s.get(Poam, poam_id)
    if not p:
        raise HTTPException(status_code=404, detail="POAM not found")
    return _poam_detail(p, s)


class CreateRequest(BaseModel):
    """Manually create one POAM (UI add-button flow).

    Most POAMs are born from /generate, but the assessor occasionally needs
    to capture a finding that isn't tied to a Non-Compliant assessment row
    (e.g. an externally reported vulnerability).
    """

    workbook_id: int
    control_cluster: str
    vulnerability_description: str
    security_control_number: str | None = None
    status: PoamStatus = PoamStatus.DRAFT
    likelihood: RiskLevel | None = None
    impact: RiskLevel | None = None
    relevance_of_threat: RiskLevel | None = None
    scheduled_completion_date: datetime | None = None
    resources_required: str | None = None
    mitigations: str | None = None
    comments: str | None = None
    office_org: str | None = None
    # Rationale text accompanying the risk levels. *_source is NOT in the
    # API surface — the server derives it ("manual" for anything the
    # assessor sets via this route, per alembic 0008).
    likelihood_rationale: str | None = None
    impact_rationale: str | None = None
    residual_risk_rationale: str | None = None
    objective_ids: list[int] = []  # CCIs this POAM covers


@router.post("")
def create_poam(body: CreateRequest, s: Session = Depends(get_session)) -> dict:
    raw = (
        compute_risk(body.likelihood, body.impact)
        if body.likelihood and body.impact
        else None
    )
    # Any risk field the assessor sends through this endpoint is by definition
    # a manual judgment — auto-flip *_source so the UI badge tells the truth.
    # Mirrors the auto-flip in update_poam below.
    likelihood_source = "manual" if body.likelihood is not None else None
    impact_source = "manual" if body.impact is not None else None
    residual_source = "manual" if raw is not None else None
    p = Poam(
        workbook_id=body.workbook_id,
        control_cluster=body.control_cluster,
        vulnerability_description=body.vulnerability_description,
        security_control_number=body.security_control_number,
        status=body.status,
        likelihood=body.likelihood,
        impact=body.impact,
        relevance_of_threat=body.relevance_of_threat,
        raw_severity=raw,
        residual_risk=raw,
        likelihood_source=likelihood_source,
        likelihood_rationale=body.likelihood_rationale,
        impact_source=impact_source,
        impact_rationale=body.impact_rationale,
        residual_risk_source=residual_source,
        residual_risk_rationale=body.residual_risk_rationale,
        scheduled_completion_date=body.scheduled_completion_date,
        resources_required=body.resources_required,
        mitigations=body.mitigations,
        comments=body.comments,
        office_org=body.office_org,
        # Author-supplied descriptions are owned by the assessor — lock so the
        # generator's regenerate pass leaves manually-created POAMs alone.
        narrative_locked=True,
    )
    s.add(p)
    s.flush()  # populate id for the M2M rows + history rows below

    # Seed the audit trail with one row per non-NULL risk field. Mirrors
    # the generator's seeding pattern (poam/generator.py) so the history
    # table reflects the same "born with these values" story regardless of
    # which code path created the POAM.
    actor = "assessor:manual-create"
    if body.likelihood is not None:
        record_risk_change(
            s,
            poam_id=p.id,
            field="likelihood",
            prev_value=None,
            new_value=body.likelihood,
            actor=actor,
            new_rationale=body.likelihood_rationale,
            new_source=likelihood_source,
        )
    if body.impact is not None:
        record_risk_change(
            s,
            poam_id=p.id,
            field="impact",
            prev_value=None,
            new_value=body.impact,
            actor=actor,
            new_rationale=body.impact_rationale,
            new_source=impact_source,
        )
    if raw is not None:
        record_risk_change(
            s,
            poam_id=p.id,
            field="raw_severity",
            prev_value=None,
            new_value=raw,
            actor=actor,
        )
        record_risk_change(
            s,
            poam_id=p.id,
            field="residual_risk",
            prev_value=None,
            new_value=raw,
            actor=actor,
            new_rationale=body.residual_risk_rationale,
            new_source=residual_source,
        )

    for oid in body.objective_ids:
        s.add(PoamObjective(poam_id=p.id, objective_id=oid))
    s.commit()
    return _poam_detail(p, s)


class UpdateRequest(BaseModel):
    """All-optional patch body. Only-fields-supplied semantics.

    We use a sentinel-free shape (None means "don't change") for everything
    except text/date fields that legitimately accept empty strings — those
    pass through as the actual value. Clients that want to *clear* a date
    can send an explicit null because Pydantic treats absence and null
    differently when we check ``field in body.__fields_set__``.
    """

    vulnerability_description: str | None = None
    security_control_number: str | None = None
    emass_poam_id: str | None = None
    source_identifying_control_vulnerability: str | None = None
    office_org: str | None = None
    status: PoamStatus | None = None
    scheduled_completion_date: datetime | None = None
    actual_completion_date: datetime | None = None
    likelihood: RiskLevel | None = None
    impact: RiskLevel | None = None
    relevance_of_threat: RiskLevel | None = None
    residual_risk: RiskLevel | None = None
    # Free-text justification for the corresponding risk level. *_source is
    # NOT settable through this route — the server flips it to "manual"
    # whenever the assessor touches the level or rationale, per
    # alembic 0008's provenance contract.
    likelihood_rationale: str | None = None
    impact_rationale: str | None = None
    residual_risk_rationale: str | None = None
    resources_required: str | None = None
    mitigations: str | None = None
    comments: str | None = None


@router.patch("/{poam_id}")
def update_poam(
    poam_id: int, body: UpdateRequest, s: Session = Depends(get_session)
) -> dict:
    p = s.get(Poam, poam_id)
    if not p:
        raise HTTPException(status_code=404, detail="POAM not found")

    changed = body.model_dump(exclude_unset=True)

    # Snapshot the risk-relevant state BEFORE any setattr so we can compare
    # for history rows. Capturing per-field tuples (value, rationale,
    # source) lets record_risk_change detect rationale-only edits (same
    # MODERATE but sharper wording) and emit a row for them too.
    risk_prev: dict[str, tuple[RiskLevel | None, str | None, str | None]] = {
        "likelihood": (p.likelihood, p.likelihood_rationale, p.likelihood_source),
        "impact": (p.impact, p.impact_rationale, p.impact_source),
        "residual_risk": (
            p.residual_risk,
            p.residual_risk_rationale,
            p.residual_risk_source,
        ),
    }
    prev_raw_severity = p.raw_severity

    # Apply the scalar field updates. *_source is deliberately NOT in the
    # patch body (server-derived); rationales come through as plain fields.
    for k, v in changed.items():
        setattr(p, k, v)

    # Auto-flip *_source to "manual" whenever the assessor touches a risk
    # level OR its rationale via this route. The contract: any write through
    # the assessor-facing PATCH endpoint is by definition a manual judgment.
    # The dedicated POST /apply-residual-suggestion route bypasses this so
    # it can stamp "llm_suggested" instead.
    if "likelihood" in changed or "likelihood_rationale" in changed:
        p.likelihood_source = "manual" if p.likelihood is not None else None
    if "impact" in changed or "impact_rationale" in changed:
        p.impact_source = "manual" if p.impact is not None else None
    if "residual_risk" in changed or "residual_risk_rationale" in changed:
        p.residual_risk_source = "manual" if p.residual_risk is not None else None

    # Re-derive raw_severity whenever likelihood or impact change. The
    # canonical matrix lives in poam/risk.py — never compute it inline.
    if "likelihood" in changed or "impact" in changed:
        if p.likelihood and p.impact:
            p.raw_severity = compute_risk(p.likelihood, p.impact)
        else:
            p.raw_severity = None

    # Lock the narrative as soon as the assessor edits it through the UI so a
    # later generator re-run doesn't clobber the manual wording. We honor any
    # appearance of the key in the payload (including an explicit empty string)
    # — the assessor's intent to control the text is what we're capturing,
    # independent of the value chosen.
    if "vulnerability_description" in changed:
        p.narrative_locked = True

    p.updated_at = datetime.now(timezone.utc)
    s.add(p)

    # Audit-trail writes happen AFTER the mutations are staged but BEFORE
    # commit so prev/new comparison sees the assessor's intent, not a
    # partial state. record_risk_change is a no-op when value+rationale+
    # source are all unchanged so we can fire it unconditionally per field.
    actor = "assessor:update"
    for field in ("likelihood", "impact", "residual_risk"):
        prev_value, prev_rationale, prev_source = risk_prev[field]
        new_value = getattr(p, field)
        new_rationale = getattr(p, f"{field}_rationale")
        new_source = getattr(p, f"{field}_source")
        record_risk_change(
            s,
            poam_id=p.id,
            field=field,
            prev_value=prev_value,
            new_value=new_value,
            actor=actor,
            prev_rationale=prev_rationale,
            new_rationale=new_rationale,
            prev_source=prev_source,
            new_source=new_source,
        )

    # raw_severity has no rationale/source of its own — it's derived. Record
    # its transition independently so an assessor reading the audit trail
    # can see "I set MODERATE × HIGH and the matrix gave me HIGH" without
    # cross-referencing risk.py.
    if prev_raw_severity != p.raw_severity:
        record_risk_change(
            s,
            poam_id=p.id,
            field="raw_severity",
            prev_value=prev_raw_severity,
            new_value=p.raw_severity,
            actor=actor,
        )

    s.commit()
    return _poam_detail(p, s)


# ---------------------------------------------------------------------------
# Risk history
#
# Registered BEFORE the parametric GET /{poam_id} (would be a collision-free
# subpath in FastAPI anyway, but we keep it adjacent to the related routes
# so the file reads top-to-bottom).
# ---------------------------------------------------------------------------


@router.get("/{poam_id}/risk-history")
def get_poam_risk_history(
    poam_id: int, s: Session = Depends(get_session)
) -> list[dict]:
    """Append-only audit trail for one POAM's risk-field transitions.

    Ordered newest-first to match how the UI RiskHistoryCard renders. The
    history table is populated by record_risk_change on the generator path
    (system:generator), manual create (assessor:manual-create), PATCH
    (assessor:update), and apply-suggestion (system:residual-advisor).
    """
    if not s.get(Poam, poam_id):
        raise HTTPException(status_code=404, detail="POAM not found")
    rows = s.exec(
        select(PoamRiskHistory)
        .where(PoamRiskHistory.poam_id == poam_id)
        .order_by(PoamRiskHistory.created_at.desc(), PoamRiskHistory.id.desc())
    ).all()
    return [
        {
            "id": r.id,
            "poam_id": r.poam_id,
            "field": r.field,
            "prev_value": r.prev_value,
            "new_value": r.new_value,
            "prev_rationale": r.prev_rationale,
            "new_rationale": r.new_rationale,
            "prev_source": r.prev_source,
            "new_source": r.new_source,
            "actor": r.actor,
            "created_at": iso_utc(r.created_at),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Residual-risk advisor (LLM-powered)
#
# Two surfaces:
#   GET  /{id}/residual-suggestion          — lazy; UI calls when card mounts
#   POST /{id}/apply-residual-suggestion    — sole codepath that stamps
#                                             residual_risk_source="llm_suggested"
#
# PATCH /{id} always stamps residual_risk_source="manual". Splitting the apply
# action into its own POST keeps the source-of-truth single-write: a manual
# edit is unambiguous, an LLM-accepted suggestion is unambiguous, and the
# audit row in poam_risk_history records the actor either way.
# ---------------------------------------------------------------------------


@router.get("/{poam_id}/residual-suggestion")
def get_residual_suggestion(
    poam_id: int,
    force_refresh: bool = False,
    s: Session = Depends(get_session),
) -> dict:
    """Render — or cache-hit — one residual-risk suggestion for a POAM.

    Lazy: only the UI advisor card calls this, and only on mount / explicit
    refresh. ``force_refresh=true`` bypasses the decision cache and
    overwrites any prior entry.

    Never returns 500 from the model side — ``suggest_residual`` always
    yields a ``ResidualSuggestion`` (low-confidence abstain on parse /
    validation failure). The only error surfaces here are 404 (no POAM)
    and 412 (no LLM API key configured).
    """
    if not s.get(Poam, poam_id):
        raise HTTPException(status_code=404, detail="POAM not found")

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
                "hint": (
                    f"Set the {provider_label} API key in Settings "
                    "(stored in Windows Credential Manager)."
                ),
            },
        ) from e
    except RuntimeError as e:  # SDK install failure
        raise HTTPException(status_code=503, detail=str(e)) from e

    suggestion = suggest_residual(
        poam_id=poam_id,
        session=s,
        llm=client,
        force_refresh=force_refresh,
    )
    s.commit()  # persist any cache writes / hit-count bumps

    suggested = suggestion.suggested_residual
    return {
        "suggested": suggested.value if suggested is not None else None,
        "rationale": suggestion.rationale,
        "confidence": suggestion.confidence,
        "key_factors": list(suggestion.key_factors),
        "decided_at": iso_utc(suggestion.decided_at),
        "cache_source": suggestion.cache_source,
    }


class ApplyResidualRequest(BaseModel):
    """Body for accepting an LLM-suggested residual risk verdict.

    Sent by the UI's "Apply suggestion" button. The assessor has already
    seen the suggestion + rationale + key factors; this endpoint just
    records that decision and stamps the provenance source so the audit
    trail distinguishes it from a manual override.
    """

    residual_risk: RiskLevel
    residual_risk_rationale: str


@router.post("/{poam_id}/apply-residual-suggestion")
def apply_residual_suggestion(
    poam_id: int,
    body: ApplyResidualRequest,
    s: Session = Depends(get_session),
) -> dict:
    """Apply an LLM-suggested residual risk to a POAM.

    Stamps ``residual_risk_source = "llm_suggested"`` (the only codepath
    that does — PATCH /{id} always stamps ``"manual"``) and records the
    transition in poam_risk_history with ``actor="system:residual-advisor"``
    so the audit row makes the lineage obvious.

    Rationale text is whatever the UI sent — typically a copy of the LLM
    rationale, possibly trimmed or annotated by the assessor before
    clicking Apply. The advisor doesn't see this back; the audit trail
    does.
    """
    p = s.get(Poam, poam_id)
    if not p:
        raise HTTPException(status_code=404, detail="POAM not found")

    prev_value = p.residual_risk
    prev_rationale = p.residual_risk_rationale
    prev_source = p.residual_risk_source

    p.residual_risk = body.residual_risk
    p.residual_risk_rationale = body.residual_risk_rationale
    p.residual_risk_source = "llm_suggested"
    p.updated_at = datetime.now(timezone.utc)

    record_risk_change(
        s,
        poam_id=poam_id,
        field="residual_risk",
        prev_value=prev_value,
        new_value=body.residual_risk,
        actor="system:residual-advisor",
        prev_rationale=prev_rationale,
        new_rationale=body.residual_risk_rationale,
        prev_source=prev_source,
        new_source="llm_suggested",
    )

    s.add(p)
    s.commit()
    s.refresh(p)
    return _poam_detail(p, s)


@router.delete("")
def delete_all_poams(
    workbook_id: int | None = None,
    status: PoamStatus | None = None,
    s: Session = Depends(get_session),
) -> dict:
    """Bulk-delete POAMs matching the same filters as GET /api/poams.

    Scoped to *exactly* what the list view currently shows — pass the same
    ``workbook_id`` / ``status`` query params the list endpoint uses so
    "delete all" removes only the rows the user sees, nothing more.

    Child rows (PoamMilestone, PoamObjective, PoamEvidence, PoamRiskHistory)
    are deleted first to honour FK ordering (SQLite doesn't cascade).

    Returns the count of deleted POAM rows.
    """
    stmt = select(Poam.id)
    if workbook_id is not None:
        stmt = stmt.where(Poam.workbook_id == workbook_id)
    if status is not None:
        stmt = stmt.where(Poam.status == status)
    poam_ids = s.exec(stmt).all()

    if not poam_ids:
        return {"ok": True, "deleted": 0}

    s.exec(delete(PoamRiskHistory).where(PoamRiskHistory.poam_id.in_(poam_ids)))  # type: ignore[attr-defined]
    s.exec(delete(PoamMilestone).where(PoamMilestone.poam_id.in_(poam_ids)))  # type: ignore[attr-defined]
    s.exec(delete(PoamObjective).where(PoamObjective.poam_id.in_(poam_ids)))  # type: ignore[attr-defined]
    s.exec(delete(PoamEvidence).where(PoamEvidence.poam_id.in_(poam_ids)))  # type: ignore[attr-defined]
    s.exec(delete(Poam).where(Poam.id.in_(poam_ids)))  # type: ignore[attr-defined]
    s.commit()
    return {"ok": True, "deleted": len(poam_ids)}


@router.delete("/{poam_id}")
def delete_poam(poam_id: int, s: Session = Depends(get_session)) -> dict:
    """Delete a POAM + its milestones + objective links.

    SQLite FKs aren't declared ON DELETE CASCADE on these tables, so we do
    the housekeeping by hand in the right order (children first).
    """
    p = s.get(Poam, poam_id)
    if not p:
        raise HTTPException(status_code=404, detail="POAM not found")
    # PoamRiskHistory FKs to poam.id (NOT NULL, no DB cascade). Under
    # PRAGMA foreign_keys=ON, deleting a POAM that has any risk-history row
    # raises a FK constraint failure → 500. Delete it first, matching the bulk
    # delete_all_poams path. (Was missing here — single-POAM delete 500'd on any
    # POAM whose risk level was ever changed.)
    s.exec(delete(PoamRiskHistory).where(PoamRiskHistory.poam_id == poam_id))
    s.exec(delete(PoamMilestone).where(PoamMilestone.poam_id == poam_id))
    s.exec(delete(PoamObjective).where(PoamObjective.poam_id == poam_id))
    s.exec(delete(PoamEvidence).where(PoamEvidence.poam_id == poam_id))
    s.delete(p)
    s.commit()
    return {"ok": True, "id": poam_id}


# ---------------------------------------------------------------------------
# Objective links
# ---------------------------------------------------------------------------


class LinkObjectiveRequest(BaseModel):
    objective_id: int


@router.post("/{poam_id}/objectives")
def link_objective(
    poam_id: int,
    body: LinkObjectiveRequest,
    s: Session = Depends(get_session),
) -> dict:
    """Attach a CCI to this POAM. No-op if already linked."""
    if not s.get(Poam, poam_id):
        raise HTTPException(status_code=404, detail="POAM not found")
    if not s.get(Objective, body.objective_id):
        raise HTTPException(status_code=404, detail="Objective not found")
    existing = s.get(PoamObjective, (poam_id, body.objective_id))
    if existing:
        return {"ok": True, "added": False}
    s.add(PoamObjective(poam_id=poam_id, objective_id=body.objective_id))
    s.commit()
    return {"ok": True, "added": True}


@router.delete("/{poam_id}/objectives/{objective_id}")
def unlink_objective(
    poam_id: int, objective_id: int, s: Session = Depends(get_session)
) -> dict:
    link = s.get(PoamObjective, (poam_id, objective_id))
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    s.delete(link)
    s.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Evidence links
# ---------------------------------------------------------------------------


class LinkEvidenceRequest(BaseModel):
    """Attach an evidence artifact to a POAM.

    `note` is an optional free-text justification — e.g. "ACAS scan
    2026-05-12, host exsys-app-01" or "vendor advisory CVE-2026-1234, ETA Q3".
    On re-link of an already-linked artifact we update the note instead of
    rejecting, so the user can correct typos via the same Plus button.
    """

    evidence_id: int
    note: str | None = None


@router.post("/{poam_id}/evidence")
def link_evidence(
    poam_id: int,
    body: LinkEvidenceRequest,
    s: Session = Depends(get_session),
) -> dict:
    if not s.get(Poam, poam_id):
        raise HTTPException(status_code=404, detail="POAM not found")
    if not s.get(Evidence, body.evidence_id):
        raise HTTPException(status_code=404, detail="Evidence not found")
    existing = s.get(PoamEvidence, (poam_id, body.evidence_id))
    if existing:
        # Treat re-link as note-edit. The UI Plus button doubles as a
        # "save my new note" affordance, which avoids needing a separate
        # PATCH endpoint just to tweak one string.
        if body.note is not None and body.note != existing.note:
            existing.note = body.note
            s.add(existing)
            s.commit()
            return {"ok": True, "added": False, "note_updated": True}
        return {"ok": True, "added": False, "note_updated": False}
    s.add(
        PoamEvidence(
            poam_id=poam_id,
            evidence_id=body.evidence_id,
            note=body.note,
        )
    )
    s.commit()
    return {"ok": True, "added": True}


@router.delete("/{poam_id}/evidence/{evidence_id}")
def unlink_evidence(
    poam_id: int, evidence_id: int, s: Session = Depends(get_session)
) -> dict:
    link = s.get(PoamEvidence, (poam_id, evidence_id))
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    s.delete(link)
    s.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Milestones
# ---------------------------------------------------------------------------


class MilestoneCreateRequest(BaseModel):
    description: str
    scheduled_date: datetime | None = None
    completion_date: datetime | None = None
    changes_history: str | None = None


@router.post("/{poam_id}/milestones")
def create_milestone(
    poam_id: int,
    body: MilestoneCreateRequest,
    s: Session = Depends(get_session),
) -> dict:
    if not s.get(Poam, poam_id):
        raise HTTPException(status_code=404, detail="POAM not found")
    m = PoamMilestone(
        poam_id=poam_id,
        description=body.description,
        scheduled_date=body.scheduled_date,
        completion_date=body.completion_date,
        changes_history=body.changes_history,
    )
    s.add(m)
    s.commit()
    s.refresh(m)
    return _milestone_dict(m)


class MilestoneUpdateRequest(BaseModel):
    description: str | None = None
    scheduled_date: datetime | None = None
    completion_date: datetime | None = None
    changes_history: str | None = None


@router.patch("/{poam_id}/milestones/{milestone_id}")
def update_milestone(
    poam_id: int,
    milestone_id: int,
    body: MilestoneUpdateRequest,
    s: Session = Depends(get_session),
) -> dict:
    m = s.get(PoamMilestone, milestone_id)
    if not m or m.poam_id != poam_id:
        raise HTTPException(status_code=404, detail="Milestone not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(m, k, v)
    s.add(m)
    s.commit()
    s.refresh(m)
    return _milestone_dict(m)


@router.delete("/{poam_id}/milestones/{milestone_id}")
def delete_milestone(
    poam_id: int, milestone_id: int, s: Session = Depends(get_session)
) -> dict:
    m = s.get(PoamMilestone, milestone_id)
    if not m or m.poam_id != poam_id:
        raise HTTPException(status_code=404, detail="Milestone not found")
    s.delete(m)
    s.commit()
    return {"ok": True, "id": milestone_id}
