"""Automation schedule CRUD endpoints.

Per-workbook autostart queue — each :class:`~cybersecurity_assessor.models.AutomationSchedule`
row describes when to pull evidence from a connector and whether to chain a
re-assessment.  The scheduler tick in ``evidence.scheduler`` does the actual
work; these routes only manage the schedule rows and expose a manual
"run now" trigger.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models import AutomationSchedule, Workbook, _utcnow, iso_utc

router = APIRouter(prefix="/api/automation", tags=["automation"])


# ---------------------------------------------------------------------------
# Serialisation helper
# ---------------------------------------------------------------------------


def _serialize(row: AutomationSchedule) -> dict:
    return {
        "id": row.id,
        "workbook_id": row.workbook_id,
        "name": row.name,
        "source_type": row.source_type,
        "source_ref": row.source_ref,
        "interval_minutes": row.interval_minutes,
        "run_assessment": row.run_assessment,
        "enabled": row.enabled,
        "last_run_at": iso_utc(row.last_run_at),
        "last_status": row.last_status,
        "last_detail": row.last_detail,
        "next_run_at": iso_utc(row.next_run_at),
        "created_at": iso_utc(row.created_at),
        "updated_at": iso_utc(row.updated_at),
    }


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


class ScheduleCreate(BaseModel):
    workbook_id: int
    source_type: str
    name: str | None = None
    source_ref: str | None = None
    interval_minutes: int = 1440
    run_assessment: bool = False
    enabled: bool = True


class SchedulePatch(BaseModel):
    name: str | None = None
    source_type: str | None = None
    source_ref: str | None = None
    interval_minutes: int | None = None
    run_assessment: bool | None = None
    enabled: bool | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("")
def list_schedules(
    workbook_id: int | None = None,
    s: Session = Depends(get_session),
) -> list[dict]:
    """List all automation schedules, optionally filtered by workbook."""
    stmt = select(AutomationSchedule)
    if workbook_id is not None:
        stmt = stmt.where(AutomationSchedule.workbook_id == workbook_id)
    stmt = stmt.order_by(AutomationSchedule.id)
    rows = s.exec(stmt).all()
    return [_serialize(r) for r in rows]


@router.get("/{schedule_id}")
def get_schedule(
    schedule_id: int,
    s: Session = Depends(get_session),
) -> dict:
    row = s.get(AutomationSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _serialize(row)


@router.post("")
def create_schedule(
    body: ScheduleCreate,
    s: Session = Depends(get_session),
) -> dict:
    """Create a new schedule.

    ``next_run_at`` is set to *now* so an enabled schedule fires on the
    very next scheduler tick (no waiting one full interval after creation).
    """
    wb = s.get(Workbook, body.workbook_id)
    if wb is None:
        raise HTTPException(status_code=404, detail="Workbook not found")

    now = _utcnow()
    row = AutomationSchedule(
        workbook_id=body.workbook_id,
        name=body.name,
        source_type=body.source_type,
        source_ref=body.source_ref,
        interval_minutes=body.interval_minutes,
        run_assessment=body.run_assessment,
        enabled=body.enabled,
        # Fire on the next tick if enabled; defer by one interval if not,
        # so disabling at creation doesn't produce a noise fire.
        next_run_at=now if body.enabled else now + timedelta(minutes=body.interval_minutes),
        created_at=now,
        updated_at=now,
    )
    s.add(row)
    s.commit()
    s.refresh(row)
    return _serialize(row)


@router.patch("/{schedule_id}")
def update_schedule(
    schedule_id: int,
    body: SchedulePatch,
    s: Session = Depends(get_session),
) -> dict:
    """Update mutable schedule fields.

    When ``interval_minutes`` or ``enabled`` changes, ``next_run_at`` is
    recomputed sensibly:
    - Enabling a disabled schedule → fire promptly (next_run_at = now).
    - Changing interval on an already-enabled schedule → advance next_run_at
      relative to last_run_at if known, else now + new interval.
    - Disabling → push next_run_at far out so the tick doesn't pick it up.
    """
    row = s.get(AutomationSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")

    now = _utcnow()
    was_enabled = row.enabled

    if body.name is not None:
        row.name = body.name
    if body.source_type is not None:
        row.source_type = body.source_type
    if body.source_ref is not None:
        row.source_ref = body.source_ref
    if body.run_assessment is not None:
        row.run_assessment = body.run_assessment

    interval_changed = body.interval_minutes is not None and body.interval_minutes != row.interval_minutes
    enabled_changed = body.enabled is not None and body.enabled != row.enabled

    if body.interval_minutes is not None:
        row.interval_minutes = body.interval_minutes
    if body.enabled is not None:
        row.enabled = body.enabled

    # Recompute next_run_at when relevant fields change.
    if enabled_changed or interval_changed:
        if not row.enabled:
            # Push far out; the tick skips disabled rows anyway (belt + braces).
            row.next_run_at = now + timedelta(days=365)
        elif enabled_changed and not was_enabled:
            # Just enabled → run promptly.
            row.next_run_at = now
        else:
            # Interval changed while still enabled → recalculate from last run.
            base = row.last_run_at or now
            if base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
            row.next_run_at = base + timedelta(minutes=row.interval_minutes)

    row.updated_at = now
    s.add(row)
    s.commit()
    s.refresh(row)
    return _serialize(row)


@router.delete("/{schedule_id}")
def delete_schedule(
    schedule_id: int,
    s: Session = Depends(get_session),
) -> dict:
    row = s.get(AutomationSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    s.delete(row)
    s.commit()
    return {"ok": True, "deleted_id": schedule_id}


@router.post("/{schedule_id}/run-now")
def run_now(
    schedule_id: int,
    s: Session = Depends(get_session),
) -> dict:
    """Force ``next_run_at = now`` so the schedule fires on the next tick.

    Useful for testing a schedule without waiting for the interval to elapse.
    The schedule does not need to be enabled for this to work — the tick
    driver checks ``next_run_at <= now`` only for enabled rows, but setting
    the time here is still useful: once you enable the row the next tick
    will pick it up immediately.
    """
    row = s.get(AutomationSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")

    now = _utcnow()
    row.next_run_at = now
    row.updated_at = now
    s.add(row)
    s.commit()
    s.refresh(row)
    return {"ok": True, "next_run_at": iso_utc(row.next_run_at)}
