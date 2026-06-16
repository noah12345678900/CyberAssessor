"""Read-only view of auto-detected document supersessions, per workbook.

Supersession is data-driven: the ingest-time tracker links an older
artifact to a newer one (same ``doc_number``, Rev A → Rev B) by setting
``Evidence.superseded_by_id``, and the assessor rewrites narratives that
cite the older doc to the current one. This endpoint surfaces those
detected chains so the Metrics page can show, for a given workbook, every
legacy → current rewrite the engine would apply — the same candidates the
assessor uses, via :func:`engine.supersession.build_evidence_chain_index`.

Scoped per workbook (the index filters on ``Evidence.workbook_id`` OR
workbook-agnostic null rows). Entries carry program doc numbers/titles, so
this lives only on the in-app API — never the Nuon-safe ``/public`` metrics
payload.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlmodel import Session

from ..db import get_session
from ..engine.supersession import build_evidence_chain_index

router = APIRouter(prefix="/api/supersession", tags=["supersession"])


@router.get("/chains")
def list_supersession_chains(
    workbook_id: int, s: Session = Depends(get_session)
) -> list[dict[str, Any]]:
    """Auto-detected legacy → current document chains for one workbook.

    Returns one row per distinct rewrite candidate, de-duplicated and
    sorted longest-legacy-first (same order the rewriter applies them).
    Empty list when the workbook has no superseded evidence yet.
    """
    index = build_evidence_chain_index(s, workbook_id=workbook_id)
    return [
        {
            "legacy": legacy_ref,
            "current": current_ref,
            "kind": kind,
            "stale_evidence_id": stale_id,
            "current_evidence_id": current_id,
        }
        for (legacy_ref, current_ref, stale_id, current_id, kind, _pattern) in index.candidates
    ]
