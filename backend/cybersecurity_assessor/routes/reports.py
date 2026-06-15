"""PDF / report-export endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.exc import OperationalError
from sqlmodel import Session

from ..db import get_session
from ..models import Workbook
from ..reports import build_evidence_disposition_csv, build_sar_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/workbook/{workbook_id}/sar.pdf")
def workbook_sar_pdf(workbook_id: int, s: Session = Depends(get_session)) -> Response:
    """Render a NIST SP 800-53A Security Assessment Report PDF and stream it back."""
    wb = s.get(Workbook, workbook_id)
    if wb is None:
        raise HTTPException(status_code=404, detail="Workbook not found")

    try:
        pdf = build_sar_report(s, workbook_id)
    except ValueError as e:  # missing workbook / bad join
        raise HTTPException(status_code=422, detail=str(e)) from e
    except ImportError as e:  # reportlab not installed
        raise HTTPException(
            status_code=503,
            detail=f"PDF dependency not installed: {e}. Run `pip install reportlab`.",
        ) from e
    except OperationalError as e:  # stale DB missing odp_assignment / odp_audit_log
        raise HTTPException(
            status_code=503,
            detail=(
                f"Database schema is out of date: {e.orig}. "
                "Restart the sidecar to apply additive migrations."
            ),
        ) from e

    stem = wb.filename.rsplit(".", 1)[0] if "." in wb.filename else wb.filename
    download_name = f"sar-{stem}.pdf"

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{download_name}"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/workbook/{workbook_id}/evidence-disposition.csv")
def workbook_evidence_disposition_csv(
    workbook_id: int, s: Session = Depends(get_session)
) -> Response:
    """Stream the exhaustive evidence-disposition audit trail as CSV.

    One row per artifact the assessor was handed — examined AND deferred — so a
    reviewer can prove the token-budget ranker dropped nothing. Companion to
    SAR Appendix I (which is only the per-CCI summary).
    """
    wb = s.get(Workbook, workbook_id)
    if wb is None:
        raise HTTPException(status_code=404, detail="Workbook not found")

    try:
        csv_text = build_evidence_disposition_csv(s, workbook_id)
    except ValueError as e:  # missing workbook / bad join
        raise HTTPException(status_code=422, detail=str(e)) from e
    except OperationalError as e:  # stale DB missing disposition columns
        raise HTTPException(
            status_code=503,
            detail=(
                f"Database schema is out of date: {e.orig}. "
                "Restart the sidecar to apply additive migrations."
            ),
        ) from e

    stem = wb.filename.rsplit(".", 1)[0] if "." in wb.filename else wb.filename
    download_name = f"evidence-disposition-{stem}.csv"

    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{download_name}"',
            "Cache-Control": "no-store",
        },
    )
