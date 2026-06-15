"""Controls export — eMASS-strict and working-view xlsx writers.

Two public entry points:

- :func:`export_controls_to_emass` copies a user-supplied ``enterprise
  services controls.xlsx`` template, inserts a Program-Specific Controls
  column right after ``Control Acronym``, and writes one row per
  in-scope control with a status rollup that surfaces CRM-inherited /
  hybrid splits explicitly per the user's requested format::

      Compliant: CCI-000196, CCI-000197 (inherited from AWS GovCloud)
      Non-Compliant: CCI-000198 (no documented sanctions procedure)

  Uses xlwings (Excel COM) for the same reason ``poam/exporter.py`` does:
  the template carries data validation, conditional formatting, and 29
  sibling tabs that openpyxl's write path strips. xlwings goes through
  the live app and preserves all of it.

- :func:`export_controls_working_view` emits a fresh xlsx (openpyxl, no
  template) that mirrors the Controls UI: one row per **objective**, all
  needs_review and abstain rows included, plus the same PSC column.
  Owned by the assessor for working/review, never an eMASS deliverable.

The eMASS export is **idempotent**. Re-running onto the same output
file detects the existing "Program-Specific Controls" column header and
re-writes in place instead of stacking a second PSC column.

Precision-over-recall gate: rows with ``Assessment.needs_review=True``
are excluded from the eMASS export (per ``feedback_precision_over_recall``)
but included in the working view with a Needs Review column so the
assessor can triage them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sqlmodel import Session, select

from ..models import (
    Assessment,
    Baseline,
    BaselineControl,
    BaselineObjective,
    ComplianceStatus,
    Control,
    Objective,
    RequirementMap,
    RequirementSource,
    Workbook,
    _utcnow,
)

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


# Excel cell hard-cap. Each PSC line is also capped (see _PSC_LINE_MAX) so a
# single huge requirement_text can't blow the whole cell budget on row 1.
_EXCEL_CELL_MAX = 32_767
_PSC_LINE_MAX = 500

# Header text we look for to locate the Control Acronym column. eMASS
# template variants spell this differently across program copies; the
# matcher is case-insensitive and matches any of the candidates.
_CONTROL_ACRONYM_HEADERS: tuple[str, ...] = (
    "control acronym",
    "control number",
    "control id",
    "controls / aps",
)
_PSC_HEADER = "Program-Specific Controls"

# eMASS Controls tab — also matches the working-view templates we've seen.
_DEFAULT_SHEET_NAME = "Controls"

# Bucket display order for _rollup_status. Compliant first so the eMASS
# reviewer sees the positive case at the top; Needs Review last because
# (a) those rows are excluded from the eMASS export anyway and (b) when
# a working-view export DOES surface them, they're the most actionable
# triage item and should sit closest to the row's other context.
_BUCKET_ORDER: tuple[str, ...] = (
    "Compliant",
    "Non-Compliant",
    "Not Applicable",
    "Needs Review",
)


@dataclass(frozen=True)
class ProgramControlRow:
    """One RequirementMap row, denormalized for the PSC column formatter.

    Mirrors the shape ``routes/controls.py::list_program_controls_for_control``
    returns under ``rows[]``, but we keep it as a dataclass so the bulk
    fetch helper can hand it to the formatter without dict-juggling.
    """

    source_name: str
    requirement_number: str
    requirement_text: str
    objective_id: int


@dataclass(frozen=True)
class ObjectiveAssessment:
    """The (objective, assessment) pair the rollup helper bucket-sorts on."""

    objective_id: int
    objective_code: str  # e.g. "CCI-000196"
    status: ComplianceStatus
    narrative_q: str | None
    needs_review: bool
    inheritance_rule: str | None
    # CRM cloud-scope verdict + narrative (matches CSP-issued CRM templates
    # like AWS GovCloud / Azure / GCP). ``crm_responsibility_onprem`` carries
    # the separately-tracked on-prem verdict for mixed cloud + on-prem
    # systems; both may be set independently per the dual-scope CRM schema.
    crm_responsibility: str | None  # "customer" / "customer_configured" / "provider" / "hybrid" / "inherited" / "not_applicable" / None
    crm_narrative: str | None
    crm_responsibility_onprem: str | None = None
    crm_narrative_onprem: str | None = None
    # Dual-narrative fields written into the eMASS export's per-scope
    # columns alongside ``narrative_q`` (the canonical CCIS col-Q text).
    # Default None so existing test fixtures and callers that don't
    # populate them keep working — the working-copy exporter passes
    # explicit values when an Assessment row carries them.
    narrative_on_prem: str | None = None
    narrative_cloud: str | None = None


@dataclass(frozen=True)
class ControlExportResult:
    """Summary of one export run. Returned to the UI so the modal can show
    "42 rows written, 6 with PSC mappings, 0 skipped" and surface any
    template-shape warnings inline.
    """

    output_path: str
    rows_written: int
    controls_with_psc: int
    skipped: list[tuple[str, str]] = field(default_factory=list)
    template_warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Status rollup
# ---------------------------------------------------------------------------


def _rollup_status(objectives: list[ObjectiveAssessment]) -> str:
    """Return the multi-line Status cell text per user-specified format.

    Bucketing rules:
      - Objectives where ``crm_responsibility`` is ``inherited`` or
        ``provider`` are short-circuited into the ``Compliant`` bucket
        regardless of any stored Assessment status. Their reason carries
        "inherited from <source>" so the eMASS reviewer knows the verdict
        is overlay-driven, not investigation-driven.
      - ``crm_responsibility == "not_applicable"`` → Not Applicable
        bucket with "marked NA by CRM overlay".
      - ``needs_review=True`` rows go to the Needs Review bucket no
        matter what status the LLM proposed (precision-over-recall).
      - Everything else uses ``Assessment.status``.

    Output shape:
      - Empty input → "" (caller decides what to write into the cell).
      - Single bucket → just the status token (e.g. "Compliant") so the
        cell stays compatible with eMASS's single-value expectations
        when there's no ambiguity to surface.
      - Multiple buckets → one line per bucket in ``_BUCKET_ORDER``::

            Compliant: CCI-000196, CCI-000197 (inherited from AWS GovCloud)
            Non-Compliant: CCI-000198 (no documented sanctions procedure)
    """
    if not objectives:
        return ""

    # bucket_name -> list[(objective_code, reason)]
    buckets: dict[str, list[tuple[str, str]]] = {b: [] for b in _BUCKET_ORDER}

    for oa in objectives:
        bucket, reason = _classify(oa)
        buckets[bucket].append((oa.objective_code, reason))

    nonempty = [(b, items) for b, items in buckets.items() if items]
    if not nonempty:
        return ""

    if len(nonempty) == 1:
        # Single-bucket control → emit just the status token. eMASS's
        # status field is single-valued by design; no ambiguity to surface.
        return nonempty[0][0]

    lines: list[str] = []
    for bucket, items in nonempty:
        # Group by reason within a bucket so we collapse
        # "CCI-1, CCI-2, CCI-3 (inherited from AWS)" into one line per
        # distinct reason rather than three identical trailing parens.
        by_reason: dict[str, list[str]] = {}
        for code, reason in items:
            by_reason.setdefault(reason, []).append(code)
        for reason, codes in by_reason.items():
            cci_list = ", ".join(codes)
            if reason:
                lines.append(f"{bucket}: {cci_list} ({reason})")
            else:
                lines.append(f"{bucket}: {cci_list}")
    return "\n".join(lines)


def _classify(oa: ObjectiveAssessment) -> tuple[str, str]:
    """Return (bucket_name, reason) for one objective.

    CRM short-circuit takes precedence over Assessment status — the
    overlay decision is the ground truth for inherited / provider /
    not_applicable, per ``feedback_overlay_default_local``.

    Dual-scope semantics (cloud + on-prem): short-circuit only when EVERY
    specified scope is inheritable. A control that's ``inherited`` in the
    cloud but ``customer`` on-prem still requires real assessment —
    falling through to the Assessment status path keeps the on-prem
    verdict from being hidden behind the cloud short-circuit. Mirrors
    the gate in ``engine/assessor.py``.
    """
    crm = (oa.crm_responsibility or "").lower() or None
    crm_op = (oa.crm_responsibility_onprem or "").lower() or None

    short_circuit_set = {"inherited", "provider", "not_applicable"}
    specified = [r for r in (crm, crm_op) if r]
    all_short_circuit = bool(specified) and all(
        r in short_circuit_set for r in specified
    )

    if all_short_circuit:
        # When both scopes agree, use the single combined reason. When
        # scopes disagree (e.g. cloud=inherited, on-prem=provider) we
        # join the per-scope reasons so the eMASS reviewer sees both.
        cloud_reason = _scope_short_circuit_reason(crm, oa.crm_narrative, "cloud")
        onprem_reason = _scope_short_circuit_reason(
            crm_op, oa.crm_narrative_onprem, "on-prem"
        )
        scope_reasons = [r for r in (cloud_reason, onprem_reason) if r]
        # Bucket priority: any "inherited" → Compliant; else any
        # "provider" → Compliant; else all "not_applicable" → NA.
        if crm == "inherited" or crm_op == "inherited":
            return "Compliant", " | ".join(scope_reasons)
        if crm == "provider" or crm_op == "provider":
            return "Compliant", " | ".join(scope_reasons)
        return "Not Applicable", " | ".join(scope_reasons) or "marked NA by CRM overlay"

    if oa.needs_review:
        return "Needs Review", _short_reason(oa.narrative_q) or "needs reviewer check"

    if oa.inheritance_rule == "8a":
        return "Compliant", "Rule 8a auto-compliant"

    if oa.status == ComplianceStatus.COMPLIANT:
        return "Compliant", _short_reason(oa.narrative_q)
    if oa.status == ComplianceStatus.NON_COMPLIANT:
        return "Non-Compliant", _short_reason(oa.narrative_q) or "gap identified"
    if oa.status == ComplianceStatus.NOT_APPLICABLE:
        return "Not Applicable", _short_reason(oa.narrative_q)

    return "Needs Review", "unknown status"


def _scope_short_circuit_reason(
    resp: str | None,
    narrative: str | None,
    scope_label: str,
) -> str:
    """Format a per-scope short-circuit reason for the rollup cell.

    Examples (with scope_label="cloud"):
      - inherited + "AWS GovCloud — ..." → "cloud: inherited from AWS GovCloud"
      - provider  + None                 → "cloud: implemented by provider"
      - not_applicable                   → "cloud: marked NA by CRM overlay"

    Empty string when resp is None — caller filters those out so a
    single-scope CRM doesn't produce orphan " | " separators.
    """
    if not resp:
        return ""
    src = _crm_source_phrase(narrative)
    if resp == "inherited":
        return f"{scope_label}: inherited from {src}" if src else f"{scope_label}: inherited"
    if resp == "provider":
        return (
            f"{scope_label}: implemented by {src}" if src
            else f"{scope_label}: implemented by provider"
        )
    if resp == "not_applicable":
        return f"{scope_label}: marked NA by CRM overlay"
    return ""


def _crm_source_phrase(crm_narrative: str | None) -> str:
    """Extract a short source phrase from the CRM narrative (e.g. "AWS
    GovCloud") for the Status cell. We don't try to NLP-parse — just take
    the first ~50 chars of the first sentence, which is overwhelmingly how
    CRM narratives are written ("AWS GovCloud — inherited control...").
    """
    if not crm_narrative:
        return ""
    first = crm_narrative.split(".")[0].strip()
    if len(first) <= 50:
        return first
    return first[:47].rstrip() + "..."


def _short_reason(narrative_q: str | None) -> str:
    """First sentence of the narrative, truncated to ~80 chars."""
    if not narrative_q:
        return ""
    first = narrative_q.strip().split(".")[0].strip()
    if len(first) <= 80:
        return first
    return first[:77].rstrip() + "..."


# ---------------------------------------------------------------------------
# PSC column formatter
# ---------------------------------------------------------------------------


def _format_psc_column(rows: list[ProgramControlRow]) -> str:
    """Render the PSC cell text for one control.

    Already-grouped input (by source.name + requirement_number) — the
    bulk fetcher sorts. Output is one line per PSC row::

        SDA-127: <text>
        SDA-128: <text>
        T1TL-031: <text>

    Per-line cap of 500 chars; whole-cell cap of Excel's 32,767-char
    hard limit with a trailing ``...[N more truncated]`` marker so the
    operator knows something was dropped instead of silently losing data.
    """
    if not rows:
        return ""

    lines: list[str] = []
    used = 0
    truncated_count = 0
    for r in rows:
        text = r.requirement_text or ""
        if len(text) > _PSC_LINE_MAX:
            text = text[: _PSC_LINE_MAX - 3].rstrip() + "..."
        line = f"{r.requirement_number}: {text}"
        # +1 for the newline separator we'll add between lines.
        projected = used + len(line) + (1 if lines else 0)
        # Reserve ~32 chars for the trailing truncation marker.
        if projected > _EXCEL_CELL_MAX - 32:
            truncated_count = len(rows) - len(lines)
            break
        lines.append(line)
        used = projected

    if truncated_count > 0:
        lines.append(f"...[{truncated_count} more truncated]")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Bulk PSC fetch — avoids N+1 during export
# ---------------------------------------------------------------------------


def fetch_psc_rows_bulk(
    session: Session,
    framework_id: int | None,
    control_ids: list[int],
) -> dict[int, list[ProgramControlRow]]:
    """One query → ``{control_id: [ProgramControlRow, ...]}`` map.

    Single join across RequirementMap → RequirementSource → Objective,
    then bucketed in Python by ``Objective.control_id_fk``. Empty list
    for any control with no overlay rows so the caller can index without
    a ``get(..., [])`` defensive read.

    Sort order matches ``list_program_controls_for_control``: source name
    ascending, then requirement_number lexicographic. Stable across
    re-exports.
    """
    if not control_ids:
        return {}

    q = (
        select(RequirementMap, RequirementSource, Objective)
        .join(
            RequirementSource,
            RequirementSource.id == RequirementMap.requirement_source_id,
        )
        .join(Objective, Objective.id == RequirementMap.objective_id)
        .where(Objective.control_id_fk.in_(control_ids))  # type: ignore[attr-defined]
    )
    if framework_id is not None:
        q = q.where(RequirementSource.framework_id == framework_id)

    out: dict[int, list[ProgramControlRow]] = {cid: [] for cid in control_ids}
    for rm, src, obj in session.exec(q).all():
        out[obj.control_id_fk].append(
            ProgramControlRow(
                source_name=src.name,
                requirement_number=rm.requirement_number,
                requirement_text=rm.requirement_text,
                objective_id=obj.id,
            )
        )
    for cid in out:
        out[cid].sort(key=lambda r: (r.source_name, r.requirement_number))
    return out


# ---------------------------------------------------------------------------
# Internal data loaders
# ---------------------------------------------------------------------------


def _load_in_scope_controls(
    session: Session,
    baseline: Baseline,
    family_filter: str | None = None,
) -> list[tuple[Control, BaselineControl]]:
    """Return every in-scope ``(Control, BaselineControl)`` pair for the
    baseline. Mirrors the join shape in ``routes/controls.py`` so the
    in_scope semantics stay authoritative.
    """
    stmt = (
        select(Control, BaselineControl)
        .join(BaselineControl, BaselineControl.control_id == Control.id)
        .where(
            BaselineControl.baseline_id == baseline.id,
            BaselineControl.in_scope.is_(True),  # type: ignore[union-attr]
        )
    )
    if family_filter:
        stmt = stmt.where(Control.family == family_filter.upper())
    rows = list(session.exec(stmt).all())
    rows.sort(key=lambda pc: pc[0].control_id)
    return rows


def _load_objectives_for_control(
    session: Session,
    workbook_id: int,
    baseline: Baseline,
    control: Control,
    bc: BaselineControl,
) -> list[ObjectiveAssessment]:
    """Pull every objective for the control along with its latest
    Assessment for this workbook. Objectives without an assessment are
    still returned (status defaults to the CRM short-circuit or None)
    so the rollup helper doesn't silently drop them.
    """
    # Exclude soft-deleted CCIs from the per-control rollup so the
    # exporter reports the current workbook roster — not the historical
    # superset preserved for save-path source_row lookups.
    obj_rows = list(
        session.exec(
            select(Objective, BaselineObjective)
            .join(BaselineObjective, BaselineObjective.objective_id == Objective.id)
            .where(
                Objective.control_id_fk == control.id,
                BaselineObjective.baseline_id == baseline.id,
                BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
            )
        ).all()
    )

    if not obj_rows:
        return []

    obj_ids = [o.id for o, _ in obj_rows]
    assessments_by_obj: dict[int, Assessment] = {}
    for a in session.exec(
        select(Assessment).where(
            Assessment.workbook_id == workbook_id,
            Assessment.objective_id.in_(obj_ids),  # type: ignore[attr-defined]
        )
    ).all():
        # Keep the most recent assessment per objective. Created_at sort
        # in Python — N is small (controls have ~5-20 CCIs).
        prior = assessments_by_obj.get(a.objective_id)
        if prior is None or (a.created_at or datetime.min) > (
            prior.created_at or datetime.min
        ):
            assessments_by_obj[a.objective_id] = a

    out: list[ObjectiveAssessment] = []
    for obj, _bo in obj_rows:
        a = assessments_by_obj.get(obj.id)
        out.append(
            ObjectiveAssessment(
                objective_id=obj.id,
                objective_code=obj.objective_id,
                status=a.status if a else ComplianceStatus.NOT_APPLICABLE,
                narrative_q=a.narrative_q if a else None,
                narrative_on_prem=a.narrative_on_prem if a else None,
                narrative_cloud=a.narrative_cloud if a else None,
                needs_review=bool(a.needs_review) if a else False,
                inheritance_rule=a.inheritance_rule if a else None,
                crm_responsibility=bc.responsibility,
                crm_narrative=bc.responsibility_narrative,
                crm_responsibility_onprem=bc.responsibility_onprem,
                crm_narrative_onprem=bc.responsibility_onprem_narrative,
            )
        )
    # Stable order — eMASS reviewers expect CCI ids ascending.
    out.sort(key=lambda oa: oa.objective_code)
    return out


# ---------------------------------------------------------------------------
# eMASS export (xlwings, template-preserving)
# ---------------------------------------------------------------------------


def export_controls_to_emass(
    *,
    session: Session,
    workbook_id: int,
    template_path: str | Path,
    output_path: str | Path,
    sheet_name: str = _DEFAULT_SHEET_NAME,
) -> ControlExportResult:
    """Copy ``template_path`` → ``output_path``, fill the Controls tab.

    1. Loads in-scope controls + objectives + CRM responsibility from
       the workbook's primary baseline.
    2. Computes the multi-line Status cell per ``_rollup_status``.
    3. Inserts a "Program-Specific Controls" column right after the
       Control Acronym column (idempotent — re-export onto the same file
       reuses the existing column).
    4. Writes one row per in-scope control. Stamps ``Workbook.exported_at``
       (via ``poam`` precedent: tracked on the workbook so the UI can
       show "last exported" alongside last-opened).

    Raises:
        HTTPException-style errors are the caller's job to map; we raise
        plain ``ValueError`` / ``FileNotFoundError`` / ``RuntimeError``
        and let ``routes/controls.py`` translate.
    """
    import shutil

    # The eMASS controls-export path still needs COM for the idempotent
    # column-insert (xlsx_surgery exposes row-insert but not column-insert
    # yet — column-insert has to bump every <c r="L<N>">, mergeCell, named
    # range, defined name, and conditional-format sqref across every sheet,
    # which we haven't built out). xlwings is now an optional dep; users
    # who want this export path must `pip install -e .[excel]` and have
    # Excel installed. CCIS writes and POAM export both went headless and
    # do NOT trigger this import.
    try:
        import xlwings as xw
    except ImportError as exc:  # pragma: no cover — env-dependent
        raise RuntimeError(
            "The eMASS controls export uses xlwings + Excel COM (for the "
            "Program-Specific Controls column-insert). Install the `excel` "
            "extra (`pip install -e .[excel]`) and ensure Excel is "
            "installed locally. CCIS assessments and POAM export work "
            "without Excel; only this controls-template path needs it."
        ) from exc

    wb = session.get(Workbook, workbook_id)
    if wb is None:
        raise ValueError(f"Workbook {workbook_id} not found")
    if wb.baseline_id is None:
        raise ValueError(
            "Workbook has no Baseline. Reopen with a Framework selected so the "
            "app can materialize the in-scope control set."
        )
    baseline = session.get(Baseline, wb.baseline_id)
    if baseline is None:
        raise ValueError(f"Workbook references missing Baseline {wb.baseline_id}")

    src = Path(template_path)
    dst = Path(output_path)
    if not src.exists():
        raise FileNotFoundError(f"Controls template not found: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    # Idempotent re-export: operator points template_path at the previous
    # output to refresh status rollups in place. shutil.copyfile() raises
    # SameFileError on identical paths, so skip the copy when src == dst —
    # the file is already at its destination and the open-modify-save pass
    # below handles the rewrite.
    if not (dst.exists() and src.resolve() == dst.resolve()):
        shutil.copyfile(src, dst)

    pairs = _load_in_scope_controls(session, baseline)
    control_ids = [c.id for c, _ in pairs]
    psc_map = fetch_psc_rows_bulk(session, baseline.framework_id, control_ids)

    # Only inject a Program-Specific Controls column when an overlay is
    # actually loaded for this framework — otherwise we silently mutate
    # the user's template by inserting an empty column and shifting any
    # columns they added rightward. Users who don't run a PSC overlay
    # were complaining that the export "inserts Program-Specific Controls"
    # and blocks them from adding their own columns; gating on real
    # content keeps the exporter a no-op on column shape for those flows.
    # The map is keyed by control_id; if *any* control has at least one
    # PSC row, we still need the column so the values land somewhere.
    has_psc_overlay = any(rows for rows in psc_map.values())

    rows_written = 0
    controls_with_psc = 0
    skipped: list[tuple[str, str]] = []
    warnings: list[str] = []

    app = xw.App(visible=False, add_book=False)
    try:
        book = app.books.open(str(dst))
        try:
            try:
                sh = book.sheets[sheet_name]
            except Exception as e:  # noqa: BLE001 — xlwings raises generic Exception
                raise ValueError(
                    f"Template missing required sheet '{sheet_name}': {e}"
                ) from e

            # Locate header row + Control Acronym column. Templates we've
            # seen put the header on row 1; we still scan rows 1-5 to be
            # forgiving of banner-decorated copies.
            header_row, acronym_col = _find_control_acronym_column(sh, warnings)
            # PSC column is inserted only when (a) we have overlay rows to
            # write, OR (b) the template already declares a
            # "Program-Specific Controls" column from a prior export — in
            # which case _ensure_psc_column finds it and returns its index
            # without inserting. Templates without an existing PSC column
            # and no overlay data get psc_col=None and we skip the write.
            psc_col: int | None = None
            if has_psc_overlay:
                psc_col = _ensure_psc_column(
                    sh, header_row=header_row, after_col=acronym_col
                )
            else:
                psc_col = _find_existing_psc_column(sh, header_row)

            # Data starts the row after the header.
            data_row = header_row + 1
            for control, bc in pairs:
                objectives = _load_objectives_for_control(
                    session, workbook_id, baseline, control, bc
                )

                # Precision-over-recall gate: any objective whose row
                # would land in the Needs Review bucket disqualifies the
                # whole control from the eMASS export.
                if _has_untrusted_verdict(objectives):
                    skipped.append(
                        (
                            control.control_id,
                            "needs_review verdict — clear in UI before re-exporting",
                        )
                    )
                    continue

                status_text = _rollup_status(objectives)
                psc_rows = psc_map.get(control.id, [])
                psc_text = _format_psc_column(psc_rows)
                if psc_text:
                    controls_with_psc += 1

                # Acronym is the only guaranteed column. PSC is written
                # only when we located/inserted a PSC column above —
                # templates without a PSC column (and no overlay loaded)
                # skip the write entirely so the export stays
                # column-shape-preserving. Status / narrative columns are
                # looked up by header text; missing column logs a
                # one-time warning and the export continues without
                # writing that field.
                sh.cells(data_row, acronym_col).value = control.control_id
                if psc_col is not None:
                    sh.cells(data_row, psc_col).value = psc_text

                status_col = _find_header_col(
                    sh, header_row, ("status", "compliance status"), warnings
                )
                if status_col:
                    sh.cells(data_row, status_col).value = status_text

                narrative_col = _find_header_col(
                    sh,
                    header_row,
                    ("narrative", "implementation narrative", "control narrative"),
                    warnings,
                )
                if narrative_col:
                    sh.cells(data_row, narrative_col).value = (
                        _rollup_narrative(objectives)
                    )

                data_row += 1
                rows_written += 1

            book.save()
        finally:
            book.close()
    finally:
        app.quit()

    wb.exported_at = _utcnow()
    session.add(wb)
    session.commit()

    return ControlExportResult(
        output_path=str(dst),
        rows_written=rows_written,
        controls_with_psc=controls_with_psc,
        skipped=skipped,
        template_warnings=warnings,
    )


def _has_untrusted_verdict(objectives: list[ObjectiveAssessment]) -> bool:
    """Any needs_review row keeps the control out of the eMASS export."""
    return any(o.needs_review for o in objectives)


def _rollup_narrative(objectives: list[ObjectiveAssessment]) -> str:
    """Concatenate per-objective narratives for the Narrative column.

    Single-objective controls emit just the narrative; multi-objective
    controls prefix each non-empty narrative with its objective code so
    the eMASS reviewer can trace verdicts back to CCIs.
    """
    if not objectives:
        return ""
    if len(objectives) == 1:
        return (objectives[0].narrative_q or "").strip()
    parts: list[str] = []
    for oa in objectives:
        n = (oa.narrative_q or "").strip()
        if not n:
            continue
        parts.append(f"{oa.objective_code}: {n}")
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# eMASS template helpers (column discovery + idempotent PSC insert)
# ---------------------------------------------------------------------------


def _find_control_acronym_column(sh, warnings: list[str]) -> tuple[int, int]:
    """Scan rows 1-5 for the header row containing a Control Acronym
    column. Returns ``(header_row, col_1based)``.

    Raises ``ValueError`` if no recognizable header is found — the
    template is too far off-spec to write into safely.
    """
    for header_row in range(1, 6):
        col = _find_header_col(sh, header_row, _CONTROL_ACRONYM_HEADERS, warnings=None)
        if col:
            if header_row != 1:
                warnings.append(
                    f"Header row detected at row {header_row} (not row 1); "
                    "data will be written starting at the next row."
                )
            return header_row, col
    raise ValueError(
        "Template missing a Control Acronym / Control Number / Controls / APs "
        "column in the first 5 rows. Cannot determine where to write controls."
    )


def _find_header_col(
    sh,
    header_row: int,
    candidates: tuple[str, ...],
    warnings: list[str] | None,
) -> int | None:
    """Case-insensitive header lookup across the candidate phrases.

    Header cells in real-world templates often contain embedded whitespace
    (e.g. ``'Control \\nAcronym'`` in the enterprise services template, or
    ``'COMMON  CONTROL'`` with a double space). ``_norm`` collapses all
    interior whitespace runs to a single space before comparing so cosmetic
    line-wrap formatting in the header doesn't break header discovery.

    Scans up to 100 columns. None if no header matches — logs a one-time
    warning (when ``warnings`` is not None) so the export modal can show
    "Status column not found, status rollup not written."
    """
    candidates_norm = {_norm_header(c) for c in candidates}
    for col in range(1, 101):
        v = sh.cells(header_row, col).value
        if not v:
            continue
        if _norm_header(str(v)) in candidates_norm:
            return col
    if warnings is not None:
        warnings.append(
            f"Header column for '{candidates[0]}' not found; skipping that field."
        )
    return None


def _norm_header(s: str) -> str:
    """Collapse whitespace + lowercase for tolerant header matching.

    ``'Control \\nAcronym'`` and ``'COMMON  CONTROL'`` (double space) both
    appear in real templates; ``str.split() + ' '.join()`` collapses any
    run of whitespace — including embedded newlines — to a single space.
    """
    return " ".join(str(s).split()).lower()


def _find_existing_psc_column(sh, header_row: int) -> int | None:
    """Return the 1-based column index of an existing PSC header, or None.

    Read-only twin of ``_ensure_psc_column``: looks for a column whose
    header already reads "Program-Specific Controls" but never inserts.
    Used by the eMASS export to detect "user has a PSC column from a
    prior export — keep writing into it" without forcing the column on
    templates that don't carry one.
    """
    existing_norm = _norm_header(_PSC_HEADER)
    for col in range(1, 101):
        v = sh.cells(header_row, col).value
        if v and _norm_header(str(v)) == existing_norm:
            return col
    return None


def _ensure_psc_column(sh, header_row: int, after_col: int) -> int:
    """Return the 1-based column index of the PSC column.

    Idempotent:
      - If a column header already reads "Program-Specific Controls"
        (case-insensitive), return its index without inserting.
      - Otherwise insert a new column at ``after_col + 1``, write the
        header, and return that index.

    Insert is via Excel COM (``EntireColumn.Insert``) because xlwings
    has no native insert-column API. Existing data validation and
    column widths shift right with the insert — that's Excel's default
    behavior and the desired one here.

    Only call this when there is real PSC content to write — for the
    "no PSC overlay loaded" path use ``_find_existing_psc_column``
    instead so we don't silently mutate the user's template.
    """
    existing = _find_existing_psc_column(sh, header_row)
    if existing is not None:
        return existing

    insert_at = after_col + 1
    # xlwings exposes the COM Range object via .api; Insert shifts the
    # existing column at insert_at to the right.
    sh.range((1, insert_at)).api.EntireColumn.Insert()
    sh.cells(header_row, insert_at).value = _PSC_HEADER
    return insert_at


# ---------------------------------------------------------------------------
# Working-view export (openpyxl, no template)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ControlsFilterState:
    """Mirrors the Controls list page filter state. None = no filter."""

    family: str | None = None
    status: str | None = None  # "Compliant" / "Non-Compliant" / ...
    search: str | None = None  # case-insensitive substring on control_id/title


def export_controls_working_view(
    *,
    session: Session,
    workbook_id: int,
    output_path: str | Path,
    filter_state: ControlsFilterState | None = None,
) -> ControlExportResult:
    """Emit a fresh xlsx mirroring the Controls UI: one row per OBJECTIVE.

    Includes needs_review rows (with the flag surfaced as a column) so the
    assessor can review everything they see on the page in one workbook.
    """
    from openpyxl import Workbook as PyXlWorkbook

    wb = session.get(Workbook, workbook_id)
    if wb is None:
        raise ValueError(f"Workbook {workbook_id} not found")
    if wb.baseline_id is None:
        raise ValueError("Workbook has no Baseline.")
    baseline = session.get(Baseline, wb.baseline_id)
    if baseline is None:
        raise ValueError(f"Missing Baseline {wb.baseline_id}")

    dst = Path(output_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    fs = filter_state or ControlsFilterState()
    pairs = _load_in_scope_controls(session, baseline, family_filter=fs.family)

    if fs.search:
        needle = fs.search.lower()
        pairs = [
            (c, bc) for c, bc in pairs
            if needle in (c.control_id or "").lower()
            or needle in (c.title or "").lower()
        ]

    control_ids = [c.id for c, _ in pairs]
    psc_map = fetch_psc_rows_bulk(session, baseline.framework_id, control_ids)

    py_wb = PyXlWorkbook()
    ws = py_wb.active
    ws.title = "Controls (Working View)"
    headers = [
        "Control",
        "Title",
        "Family",
        "Program-Specific Controls",
        "CCI",
        "Status",
        "Needs Review",
        "Narrative",
        "Narrative (On-Prem)",
        "Narrative (Cloud)",
        "Inheritance Rule",
        "Confidence",
        "CRM Responsibility (Cloud)",
        "CRM Responsibility (On-Prem)",
    ]
    ws.append(headers)

    rows_written = 0
    controls_with_psc = 0
    skipped: list[tuple[str, str]] = []

    for control, bc in pairs:
        objectives = _load_objectives_for_control(
            session, workbook_id, baseline, control, bc
        )
        psc_rows = psc_map.get(control.id, [])
        psc_text = _format_psc_column(psc_rows)
        if psc_text:
            controls_with_psc += 1

        # Per-objective row (working view shows the full breakdown). If
        # the optional status filter is set, drop rows that don't match.
        for oa in objectives:
            row_status = oa.status.value if oa.status else ""
            if fs.status and row_status != fs.status:
                continue
            ws.append([
                control.control_id,
                control.title,
                control.family,
                psc_text,
                oa.objective_code,
                row_status,
                "Yes" if oa.needs_review else "",
                oa.narrative_q or "",
                oa.narrative_on_prem or "",
                oa.narrative_cloud or "",
                oa.inheritance_rule or "",
                "",  # confidence — not loaded in this slice
                bc.responsibility or "",
                bc.responsibility_onprem or "",
            ])
            rows_written += 1

    py_wb.save(str(dst))

    return ControlExportResult(
        output_path=str(dst),
        rows_written=rows_written,
        controls_with_psc=controls_with_psc,
        skipped=skipped,
        template_warnings=[],
    )
