"""Assessment run telemetry endpoints.

Accuracy fields (retry_count, validator_rejections, supersession_hits,
ccis_accepted, crm_short_circuit_count) back the patent claim. Token /
cost fields are operational telemetry only.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ..db import get_session
from ..models import AssessmentRun, iso_utc

router = APIRouter(prefix="/api/runs", tags=["runs"])


def _serialize(r: AssessmentRun) -> dict:
    return {
        "id": r.id,
        "workbook_id": r.workbook_id,
        "command": r.command,
        "started_at": iso_utc(r.started_at),
        "finished_at": iso_utc(r.finished_at),
        # Derived — lets the UI render a spinner / "Running" badge instead
        # of conflating in-flight runs with truly stopped ones. The
        # underlying ``finished_at is None`` check is the same; surfacing
        # it as a typed field keeps the UI from drifting on the convention.
        "status": "in_progress" if r.finished_at is None else "complete",
        # Operational
        "llm_calls": r.llm_calls,
        "llm_input_tokens": r.llm_input_tokens,
        "llm_output_tokens": r.llm_output_tokens,
        "llm_cache_read_tokens": r.llm_cache_read_tokens,
        "cost_usd": r.cost_usd,
        # Accuracy (patent-supporting)
        "ccis_accepted": r.ccis_accepted,
        "retry_count": r.retry_count,
        "validator_rejections": r.validator_rejections,
        "supersession_hits": r.supersession_hits,
        "crm_short_circuit_count": r.crm_short_circuit_count,
        "notes": r.notes,
    }


@router.get("")
def list_runs(limit: int = 50, s: Session = Depends(get_session)) -> list[dict]:
    rows = s.exec(
        select(AssessmentRun).order_by(AssessmentRun.started_at.desc()).limit(limit)
    ).all()
    return [_serialize(r) for r in rows]


@router.get("/{run_id}")
def get_run(run_id: int, s: Session = Depends(get_session)) -> dict:
    r = s.get(AssessmentRun, run_id)
    if not r:
        raise HTTPException(status_code=404, detail="Run not found")
    return _serialize(r)
