"""STIG / SCAP / Nessus finding endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..evidence.extractors import ExtractorError, extract_path
from ..models import StigFinding

router = APIRouter(prefix="/api/stig", tags=["stig"])

_STIG_SUFFIXES = {".ckl", ".cklb", ".xml", ".nessus"}


class ParseRequest(BaseModel):
    path: str


@router.post("/parse")
def parse_stig_file(body: ParseRequest, s: Session = Depends(get_session)) -> dict:
    """Detect .ckl / .cklb / XCCDF / .nessus and parse into normalized StigFindings.

    This is a read-only preview — it does NOT persist findings to the
    DB. Use ``POST /api/evidence/ingest`` on the parent folder to
    persist (the ingest orchestrator routes through the same parsers).
    """
    p = Path(body.path)
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {p}")
    if p.suffix.lower() not in _STIG_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported STIG/SCAP suffix: {p.suffix}",
        )
    try:
        doc = extract_path(p)
    except ExtractorError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    findings = doc.metadata.get("_stig_findings") or []
    return {
        "path": str(p),
        "kind": doc.kind,
        "title": doc.title,
        "host": doc.metadata.get("host"),
        "finding_count": len(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_version": f.rule_version,
                "cci_refs": f.cci_refs,
                "severity": f.severity,
                "status": f.status,
                "finding_details": f.finding_details,
                "comments": f.comments,
            }
            for f in findings
        ],
    }


@router.get("/findings")
def list_findings(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 500,
    s: Session = Depends(get_session),
) -> list[dict]:
    stmt = select(StigFinding)
    if status:
        stmt = stmt.where(StigFinding.status == status)
    if severity:
        stmt = stmt.where(StigFinding.severity == severity)
    stmt = stmt.limit(limit)
    rows = s.exec(stmt).all()
    return [
        {
            "id": f.id,
            "evidence_id": f.evidence_id,
            "rule_id": f.rule_id,
            "rule_version": f.rule_version,
            "cci_refs": f.cci_refs,
            "severity": f.severity,
            "status": f.status,
            "finding_details": f.finding_details,
            "comments": f.comments,
        }
        for f in rows
    ]
