"""Import operator-supplied narratives from an eMASS Test Result template.

This is the read-side companion to ``controls/exporter.py``. The user
exports the in-scope controls to an eMASS Test Result Import Template,
fills column N (Compliance Status) / column P (Tester) / column O (Date
Tested) / column Q (Test Results narrative) by hand (or via eMASS), then
feeds that file back in here. Each row is matched by CCI to an in-scope
:class:`Objective` and upserted as an :class:`Assessment`.

"Import only" — no LLM, no kernel, no POAM generation. The imported NC
rows land with ``needs_review=False`` so they flow straight into the
existing ``POST /api/poams/generate`` clustering step the user runs next.

The parse is already solved: :func:`read_workbook_index` understands the
WORKING SHEET layout (the eMASS template and the program workbook share
it), so this module is DB-wiring on top of that reader.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from zipfile import BadZipFile

from openpyxl.utils.exceptions import InvalidFileException
from sqlmodel import Session, delete, select

from ..config import load_config
from ..engine import rules
from ..models import (
    Assessment,
    AssessmentCitation,
    AssessmentEvidenceShown,
    AssessmentImplementation,
    AssessmentTrace,
    Baseline,
    BaselineControl,
    BaselineObjective,
    ComplianceStatus,
    Control,
    NarrativeClass,
    Objective,
    VerdictSource,
    Workbook,
)
from .ccis_reader import read_workbook_index

_log = logging.getLogger(__name__)


# Column N is free text in practice; normalize before matching the enum so
# "compliant"/"COMPLIANT"/"Compliant " all resolve.
_STATUS_MAP: dict[str, ComplianceStatus] = {
    "compliant": ComplianceStatus.COMPLIANT,
    "non-compliant": ComplianceStatus.NON_COMPLIANT,
    "noncompliant": ComplianceStatus.NON_COMPLIANT,
    "not compliant": ComplianceStatus.NON_COMPLIANT,
    "not applicable": ComplianceStatus.NOT_APPLICABLE,
    "not-applicable": ComplianceStatus.NOT_APPLICABLE,
    "n/a": ComplianceStatus.NOT_APPLICABLE,
    "na": ComplianceStatus.NOT_APPLICABLE,
}

# Imported rows carry no LLM classification. Derive a narrative class from
# the human verdict so the NOT-NULL field stays meaningful and downstream
# validators/exporters see a coherent class.
_CLASS_FOR_STATUS: dict[ComplianceStatus, NarrativeClass] = {
    ComplianceStatus.COMPLIANT: NarrativeClass.COMPLIANCE_AFFIRMING,
    ComplianceStatus.NON_COMPLIANT: NarrativeClass.GAP_DESCRIBING,
    ComplianceStatus.NOT_APPLICABLE: NarrativeClass.NA_JUSTIFYING,
}


@dataclass
class NarrativeImportResult:
    """Outcome of a narrative import run.

    ``imported`` / ``updated`` count Assessment rows written; the three
    list buckets explain every input row that did NOT produce a write so
    the operator can reconcile the file against the workbook scope.
    """

    output_path: str
    total_rows: int
    imported: int = 0
    updated: int = 0
    # CCIs present in the file but not in the workbook's in-scope baseline.
    unmatched: list[str] = field(default_factory=list)
    # In-scope CCIs whose column N value didn't map to a known status.
    skipped_no_status: list[str] = field(default_factory=list)
    # In-scope CCIs with a status but an empty column Q narrative — a row
    # with no narrative can't seed a POAM, so we skip rather than write "".
    skipped_no_narrative: list[str] = field(default_factory=list)
    overridden_by_column_d: int = 0


def _normalize_status(raw: str | None) -> ComplianceStatus | None:
    if raw is None:
        return None
    return _STATUS_MAP.get(raw.strip().lower())


def import_narratives(
    session: Session,
    workbook_id: int,
    file_path: str | Path,
) -> NarrativeImportResult:
    """Upsert Assessments from an eMASS Test Result template.

    Raises:
        ValueError: workbook missing / has no baseline / file unparseable
            (the route maps these to 404/422).
        FileNotFoundError: import file or workbook file is gone (route → 410).
    """
    wb = session.get(Workbook, workbook_id)
    if wb is None:
        raise ValueError(f"Workbook {workbook_id} not found")
    if wb.baseline_id is None:
        raise ValueError(
            "Workbook has no Baseline. Reopen the workbook with a Framework "
            "selected so the in-scope CCI set exists before importing."
        )
    baseline = session.get(Baseline, wb.baseline_id)
    if baseline is None:
        raise ValueError(f"Workbook references missing Baseline {wb.baseline_id}.")

    import_path = Path(file_path)
    if not import_path.exists():
        raise FileNotFoundError(f"Import file not found at {import_path}")

    # Parse the operator's file (status / narrative / tester / date source).
    import_index = read_workbook_index(import_path)
    import_by_cci = import_index.by_cci()

    # Parse the program workbook so the upserted Assessment's ``excel_row``
    # points at the program workbook's own row (what eMASS export writes
    # back to), not the import file's row. Best-effort: a missing workbook
    # file just leaves excel_row null.
    wb_rows_by_cci = {}
    wb_path = Path(wb.path)
    if not wb_path.exists():
        raise FileNotFoundError(f"Source workbook not found at {wb_path}")
    try:
        wb_index = read_workbook_index(wb_path)
        wb_rows_by_cci = wb_index.by_cci()
    except (BadZipFile, InvalidFileException, OSError, ValueError) as exc:
        raise ValueError(f"Source workbook could not be read: {wb_path}") from exc

    # In-scope objective set: a CCI is in-scope iff its parent Control is.
    # Mirrors the authoritative join in routes/controls.py assess batch.
    stmt = (
        select(Objective)
        .join(Control, Control.id == Objective.control_id_fk)
        .join(BaselineControl, BaselineControl.control_id == Control.id)
        .join(BaselineObjective, BaselineObjective.objective_id == Objective.id)
        .where(
            BaselineObjective.baseline_id == baseline.id,
            BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
            BaselineControl.baseline_id == baseline.id,
            BaselineControl.in_scope.is_(True),  # type: ignore[union-attr]
        )
    )
    objective_by_cci: dict[str, Objective] = {
        o.objective_id: o for o in session.exec(stmt).all()
    }

    # Existing assessments for this workbook, keyed by objective FK, so the
    # upsert is one query not N.
    existing_by_obj: dict[int, Assessment] = {
        a.objective_id: a
        for a in session.exec(
            select(Assessment).where(Assessment.workbook_id == workbook_id)
        ).all()
    }

    result = NarrativeImportResult(
        output_path=str(import_path),
        total_rows=len(import_by_cci),
    )
    now = datetime.now(timezone.utc)
    cfg = load_config()
    authoritative_objective_ids: set[int] = set()

    for cci, row in import_by_cci.items():
        obj = objective_by_cci.get(cci)
        if obj is None:
            result.unmatched.append(cci)
            continue

        program_row = wb_rows_by_cci.get(cci)
        if program_row is None:
            raise ValueError(
                f"Source workbook row not found for in-scope objective {cci}."
            )
        status = _normalize_status(row.status)
        column_d_na = bool(
            program_row is not None
            and rules.is_column_d_not_applicable(program_row)
        )
        if column_d_na:
            if status != ComplianceStatus.NOT_APPLICABLE:
                result.overridden_by_column_d += 1
            status = ComplianceStatus.NOT_APPLICABLE
            authoritative_objective_ids.add(obj.id)
        elif status == ComplianceStatus.NOT_APPLICABLE:
            raise ValueError(
                f"Imported N/A conflicts with source workbook Column D for {cci}."
            )
        if status is None:
            result.skipped_no_status.append(cci)
            continue

        if column_d_na:
            narrative = (rules.classify_row(program_row).narrative or "").strip()
        else:
            # Preserve pre-v2.1.8 behavior for every non-N/A import: an import
            # row without its own narrative is skipped rather than borrowing
            # possibly contradictory text from the program workbook.
            narrative = (row.results or "").strip()
        if not narrative:
            result.skipped_no_narrative.append(cci)
            continue

        tester = (row.tester or cfg.default_tester or "Unknown").strip() or "Unknown"
        date_tested = row.date_tested or now
        excel_row = program_row.excel_row if program_row is not None else row.excel_row
        narrative_class = _CLASS_FOR_STATUS[status]
        inheritance_rule = "8b" if column_d_na else None
        verdict_source = VerdictSource.RULE_8B if column_d_na else VerdictSource.IMPORTED

        existing = existing_by_obj.get(obj.id)
        if existing is not None:
            # Overwrite the parent verdict with the imported one. Drop any
            # prior per-implementation children so the single-boundary
            # imported status is authoritative (POAM gen reads impls when
            # present — mirrors persist_assessment_with_impls' replace).
            session.exec(
                delete(AssessmentImplementation).where(
                    AssessmentImplementation.assessment_id == existing.id
                )
            )
            session.exec(
                delete(AssessmentCitation).where(
                    AssessmentCitation.assessment_id == existing.id
                )
            )
            session.exec(
                delete(AssessmentTrace).where(
                    AssessmentTrace.assessment_id == existing.id
                )
            )
            session.exec(
                delete(AssessmentEvidenceShown).where(
                    AssessmentEvidenceShown.assessment_id == existing.id
                )
            )
            existing.status = status
            existing.tester = tester
            existing.date_tested = date_tested
            existing.narrative_q = narrative
            existing.narrative_on_prem = None
            existing.narrative_cloud = None
            existing.narrative_class = narrative_class
            existing.inheritance_rule = inheritance_rule
            existing.needs_review = False
            existing.review_reason = None
            existing.confidence = None
            existing.rewrite_requested = False
            existing.rewrite_requested_refs = None
            existing.verdict_source = verdict_source
            existing.dual_narrative_flagged = False
            existing.dual_narrative_flag_reasons = None
            existing.run_id = None
            existing.excel_row = excel_row
            session.add(existing)
            result.updated += 1
        else:
            session.add(
                Assessment(
                    workbook_id=workbook_id,
                    objective_id=obj.id,
                    excel_row=excel_row,
                    status=status,
                    tester=tester,
                    date_tested=date_tested,
                    narrative_q=narrative,
                    narrative_class=narrative_class,
                    needs_review=False,
                    inheritance_rule=inheritance_rule,
                    verdict_source=verdict_source,
                )
            )
            result.imported += 1

    if authoritative_objective_ids:
        from ..poam.generator import prune_poam_links_for_objectives
        prune_poam_links_for_objectives(
            workbook_id,
            authoritative_objective_ids,
            session,
        )
    session.commit()
    _log.info(
        "Narrative import wb=%s: %d new, %d updated, %d unmatched, "
        "%d no-status, %d no-narrative (of %d file rows)",
        workbook_id,
        result.imported,
        result.updated,
        len(result.unmatched),
        len(result.skipped_no_status),
        len(result.skipped_no_narrative),
        result.total_rows,
    )
    return result
