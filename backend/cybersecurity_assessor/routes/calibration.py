"""Calibration endpoints — reviewer accept/reject signal + report.

Two surfaces, one table (:class:`CalibrationEntry`):

* ``POST /api/calibration/review/{entry_id}`` — reviewer writes their
  accept/reject signal (and optionally a corrected status) onto an
  existing entry. Wired into the Electron review queue's existing
  accept/reject button so no new UI surface is needed.
* ``GET /api/calibration/report`` — aggregates Brier + ECE + per-bin
  breakdown across all reviewed entries. Optional ``run_id`` scopes the
  report to a single AssessmentRun for per-run drill-down.

Cross-references :mod:`engine.calibration` for the scoring contract.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..engine import calibration as calibration_engine
from ..models import CalibrationEntry

router = APIRouter(prefix="/api/calibration", tags=["calibration"])


class ReviewBody(BaseModel):
    """Reviewer's decision on a single calibration entry.

    ``human_accepted`` is the binary signal the calibration math grades
    confidence against. ``human_status`` is optional — populated when the
    reviewer corrected the verdict to a different ComplianceStatus value
    (so an analyst can audit which controls the LLM systematically
    over/under-classifies, not just whether they got the binary right).
    """

    human_accepted: bool
    human_status: str | None = None


@router.post("/review/{entry_id}")
def review_entry(
    entry_id: int,
    body: ReviewBody,
    s: Session = Depends(get_session),
) -> dict[str, Any]:
    """Stamp the reviewer's accept/reject onto an existing entry.

    Idempotent: re-posting overwrites prior review fields (so a reviewer
    flipping their decision lands cleanly without duplicate rows). The
    ``reviewed_at`` timestamp is refreshed on every write.
    """
    entry = s.get(CalibrationEntry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="CalibrationEntry not found")
    entry.human_accepted = body.human_accepted
    entry.human_status = body.human_status
    entry.reviewed_at = datetime.now(timezone.utc)
    s.add(entry)
    s.commit()
    s.refresh(entry)
    return {
        "id": entry.id,
        "human_accepted": entry.human_accepted,
        "human_status": entry.human_status,
        "reviewed_at": entry.reviewed_at.isoformat() if entry.reviewed_at else None,
    }


@router.get("/report")
def report(
    run_id: int | None = None,
    bins: int = 10,
    s: Session = Depends(get_session),
) -> dict[str, Any]:
    """Brier + ECE + per-bucket breakdown.

    ``run_id`` scopes to one assessment; omit for global history.
    ``bins`` defaults to 10 (deciles); the UI is free to ask for fewer
    bins on small samples where decile-level noise dominates the signal.
    """
    return calibration_engine.calibration_report(s, run_id=run_id, bins=bins)


@router.get("/entries")
def list_entries(
    run_id: int | None = None,
    reviewed: bool | None = None,
    limit: int = 200,
    s: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    """Raw entry list for the review queue UI.

    ``reviewed=False`` returns only entries still awaiting a signal —
    that's the working set for the reviewer panel. ``reviewed=True``
    returns the audit trail of past reviews. ``None`` returns both.
    """
    stmt = select(CalibrationEntry)
    if run_id is not None:
        stmt = stmt.where(CalibrationEntry.run_id == run_id)
    if reviewed is True:
        stmt = stmt.where(CalibrationEntry.human_accepted.is_not(None))  # type: ignore[union-attr]
    elif reviewed is False:
        stmt = stmt.where(CalibrationEntry.human_accepted.is_(None))  # type: ignore[union-attr]
    stmt = stmt.order_by(CalibrationEntry.recorded_at.desc()).limit(limit)
    rows = s.exec(stmt).all()
    return [
        {
            "id": e.id,
            "run_id": e.run_id,
            "cci_id": e.cci_id,
            "fingerprint": e.fingerprint,
            "stated_confidence": e.stated_confidence,
            "proposed_status": e.proposed_status,
            "final_status": e.final_status,
            "abstained": e.abstained,
            "rewrite_requested": e.rewrite_requested,
            "human_accepted": e.human_accepted,
            "human_status": e.human_status,
            "recorded_at": e.recorded_at.isoformat() if e.recorded_at else None,
            "reviewed_at": e.reviewed_at.isoformat() if e.reviewed_at else None,
        }
        for e in rows
    ]
