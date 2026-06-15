"""Security Assessment Report (SAR) generator — NIST SP 800-53A § 3.6.

The formal Security Assessment Report for the AO / ISSM / eMASS package
reviewer. Risk-rated findings + recommendations + NIST-style
scope/methodology/appendices.

Findings are NOT re-clustered here. The POAM generator
(``poam/generator.py``) is the canonical clusterer; this report consumes
whatever ``Poam`` rows already exist for the workbook.
"""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO, StringIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlmodel import Session, select

from ..controls.odp_render import resolve_odps
from ..db import chunked
from ..excel.ccis_reader import _ccis_to_oscal_control_id, read_workbook_index
from ..engine.crm_sanity import OVERALL_INFO_MAX, OVERALL_WARN_MAX
from ..engine.evidence_ranker import DISPOSITION_DEFERRED, DISPOSITION_EXAMINED
from ..engine.finding_corroboration import format_finding_citation
from ..models import (
    Assessment,
    AssessmentEvidenceShown,
    AssessmentImplementation,
    Baseline,
    BaselineControl,
    BaselineObjective,
    BaselineSourceType,
    ComplianceStatus,
    Control,
    CrmShortCircuitEvent,
    CrmSuspicionLog,
    Evidence,
    EvidenceTag,
    Framework,
    Objective,
    OdpAuditLog,
    Poam,
    PoamMilestone,
    PoamObjective,
    RiskLevel,
    StigFinding,
    System,
    Workbook,
    WorkbookOverlay,
)


# ---------------------------------------------------------------------------
# Local helpers (formerly shared with the now-deleted pdf.py)
# ---------------------------------------------------------------------------


def _coerce_status(raw: str | None) -> ComplianceStatus | None:
    """Map a workbook col-N string to a ComplianceStatus enum, or None if unassessed."""
    if not raw:
        return None
    s = str(raw).strip().lower()
    if not s:
        return None
    if s.startswith("compliant"):
        return ComplianceStatus.COMPLIANT
    if s.startswith("non"):
        return ComplianceStatus.NON_COMPLIANT
    if s.startswith("not appl") or s == "n/a" or s == "na":
        return ComplianceStatus.NOT_APPLICABLE
    return None


def _family_from_control_id(control_id: str) -> str:
    """'AC-2(1)' -> 'AC'. Used when DB has no Control row for this id."""
    head = control_id.split("-", 1)[0]
    return head.upper() if head else "??"


# Status → cell fill color (light tints; print-safe)
_STATUS_FILL = {
    ComplianceStatus.COMPLIANT: colors.HexColor("#dcfce7"),
    ComplianceStatus.NON_COMPLIANT: colors.HexColor("#fee2e2"),
    ComplianceStatus.NOT_APPLICABLE: colors.HexColor("#e0e7ff"),
}


def _xml(text: str | None) -> str:
    """Escape free-form text for reportlab Paragraph (parsed as mini-XML).

    reportlab feeds Paragraph content through its paraparser, so a stray
    ``&``/``<``/``>`` in user- or LLM-authored text aborts the whole PDF with
    ``paraparser: syntax error: parse ended with N unclosed tags``. Any dynamic
    string interpolated into a Paragraph must pass through here. Table cells that
    are raw strings (see ``_kv_table``) are NOT XML-parsed and must NOT be escaped.
    """
    if not text:
        return ""
    return escape(text)


def _truncate(text: str | None, limit: int = 280) -> str:
    if not text:
        return ""
    t = " ".join(text.split())
    out = t if len(t) <= limit else t[: limit - 1].rstrip() + "…"
    return escape(out)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontSize=22, leading=26, spaceAfter=12,
        ),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"], fontSize=15, leading=18,
            spaceBefore=14, spaceAfter=8, textColor=colors.HexColor("#0f172a"),
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontSize=12, leading=15,
            spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#334155"),
        ),
        "body": ParagraphStyle(
            "body", parent=base["BodyText"], fontSize=9.5, leading=12,
        ),
        "small": ParagraphStyle(
            "small", parent=base["BodyText"], fontSize=8, leading=10,
            textColor=colors.HexColor("#475569"),
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["BodyText"], fontName="Courier",
            fontSize=8, leading=10,
        ),
    }

# ---------------------------------------------------------------------------
# Risk-tier color palette (POAM findings) — matches UI risk badges
# ---------------------------------------------------------------------------

_RISK_FILL: dict[RiskLevel, colors.Color] = {
    RiskLevel.VERY_LOW: colors.HexColor("#e0f2fe"),   # sky-100
    RiskLevel.LOW: colors.HexColor("#dcfce7"),        # green-100
    RiskLevel.MODERATE: colors.HexColor("#fef3c7"),   # amber-100
    RiskLevel.HIGH: colors.HexColor("#fed7aa"),       # orange-200
    RiskLevel.VERY_HIGH: colors.HexColor("#fecaca"),  # red-200
}

# Risk levels SAR §2 calls out as "high-risk findings". Per NIST SP 800-30r1
# Table I-3, High = severe/catastrophic, Very High = multiple severe/catastrophic.
_HIGH_RISK_LEVELS = {RiskLevel.HIGH, RiskLevel.VERY_HIGH}


# Ordered risk levels — desc, so AO sees the worst first in §7 Recommendations.
_RISK_ORDER_DESC = [
    RiskLevel.VERY_HIGH,
    RiskLevel.HIGH,
    RiskLevel.MODERATE,
    RiskLevel.LOW,
    RiskLevel.VERY_LOW,
]


# ---------------------------------------------------------------------------
# Section data container — built once up front, consumed by each _build_*
# ---------------------------------------------------------------------------


@dataclass
class _ImplSummary:
    """One AssessmentImplementation row attached to an Assessment.

    Carries the per-scope verdict that §5's Appendix-D sub-table renders so
    a 3PAO can read AWS-GovCloud vs Azure-Government vs On-Premises rows
    side-by-side without diffing exports. Empty list on the parent summary
    means the assessment is pre-v0.2 single-scope; the section composer
    falls back to the rolled-up ``narrative_q`` paragraph in that case.
    """

    scope_label: str
    responsibility: str | None
    status: ComplianceStatus
    narrative: str
    source_baseline_id: int | None
    evidence_refs: str | None


@dataclass
class _EvidenceDisposition:
    """One ``AssessmentEvidenceShown`` audit row, flattened for the SAR.

    The token-budget audit unit. Each row is one evidence chunk the ranker
    either showed the model (``disposition="examined"``) or recorded but held
    back over the budget (``disposition="deferred"``). Carrying the chunk SHA
    and rank score makes "anything not examined must be traceable" verifiable:
    a 3PAO/JAB reviewer can enumerate every chunk that exceeded the budget for
    a control and confirm the deferred tail was low-signal corroboration (or,
    if it was decisive, that the verdict was withheld to needs_review).

    ``control_id`` / ``cci_id`` are resolved from the workbook index by the
    assessment's ``excel_row`` — NOT from the needs_review-filtered row set,
    because the overflow-escalation path produces needs_review=True rows whose
    deferred artifacts are exactly what this audit must surface.
    """

    control_id: str
    cci_id: str
    evidence_title: str
    doc_number: str
    chunk_sha: str
    order_index: int
    disposition: str
    rank_score: float | None
    deferred_reason: str | None


@dataclass
class _AssessmentSummary:
    """One assessed row in the workbook (DB Assessment overlay or col-N status)."""

    control_id: str        # workbook col B, e.g. "AC-2(1)"
    cci_id: str            # CCI-NNNNNN or AP acronym fallback
    status: ComplianceStatus
    tester: str
    date_tested: datetime | None
    narrative: str         # narrative_q if DB else col Q
    inheritance: str | None
    objective_pk: int | None
    has_db_row: bool       # True if there's an Assessment row (vs col-N only)
    implementations: list[_ImplSummary] = field(default_factory=list)


@dataclass
class _SarData:
    """Everything ``build_sar_report`` needs to render — assembled in one pass."""

    workbook: Workbook
    framework: Framework | None
    baseline: Baseline | None
    system: System | None
    assessor: str
    period_start: datetime | None
    period_end: datetime | None
    generated_at: datetime

    rows: list[_AssessmentSummary] = field(default_factory=list)
    status_totals: Counter = field(default_factory=Counter)
    by_control: dict[str, list[_AssessmentSummary]] = field(default_factory=lambda: defaultdict(list))
    inheritance_totals: Counter = field(default_factory=Counter)

    # Baseline scope (CCI counts come from BaselineObjective; Control scope
    # from BaselineControl). May be empty for legacy workbooks with no
    # baseline_id.
    baseline_ccis_total: int = 0
    baseline_controls_in_scope: int = 0
    baseline_controls_out_of_scope: int = 0
    tailored_out_controls: list[tuple[str, str]] = field(default_factory=list)  # (control_id, reason)

    # POAMs (the canonical finding unit — DO NOT re-cluster)
    poams: list[Poam] = field(default_factory=list)
    poam_milestones: dict[int, list[PoamMilestone]] = field(default_factory=dict)
    poam_objective_ids: dict[int, list[int]] = field(default_factory=dict)
    poam_finding_ref: dict[int, str] = field(default_factory=dict)  # poam.id -> "F-001"
    # objective_pk -> finding ref label, so §5 per-objective tables can link
    objective_finding_ref: dict[int, str] = field(default_factory=dict)

    # Evidence inventory
    evidence_rows: list[tuple[Evidence, set[str]]] = field(default_factory=list)
    # STIG findings (joined via Evidence -> StigFinding for evidence tagged to
    # any in-scope objective)
    stig_findings: list[StigFinding] = field(default_factory=list)

    # Token-budget evidence disposition audit (Appendix I + transparency CSV).
    # One entry per AssessmentEvidenceShown row — examined AND deferred — so the
    # full partition the ranker produced is traceable. Gathered UNFILTERED on
    # needs_review (unlike db_by_excel_row) because the overflow-escalation
    # path produces needs_review=True rows whose deferred artifacts are exactly
    # what this audit must surface. Empty for pre-ranker workbooks.
    evidence_dispositions: list[_EvidenceDisposition] = field(default_factory=list)

    # Method-codes per objective_pk — "E" (examine), "I" (interview), "T" (test)
    methods_by_objective: dict[int, str] = field(default_factory=dict)
    evidence_count_by_objective: dict[int, int] = field(default_factory=dict)

    # Control metadata lookup: control_id (string) -> (title, family, statement)
    control_meta: dict[str, tuple[str, str, str | None]] = field(default_factory=dict)

    # Reference overlays attached to this workbook (FedRAMP, Li-SaaS, etc.) —
    # never assessed against, just rendered as a gap-analysis appendix. Keys
    # below are control_id strings ("AC-2", "AC-2(1)") not PKs, so the SAR
    # renders friendly IDs without an extra reverse-lookup map.
    overlays: list[Baseline] = field(default_factory=list)
    # control_id -> in_scope on the primary baseline (for gap math)
    primary_membership: dict[str, bool] = field(default_factory=dict)
    # overlay baseline.id -> {control_id -> in_scope}. Controls missing from
    # an overlay's inner dict are "unmentioned" by that overlay.
    overlay_membership: dict[int, dict[str, bool]] = field(default_factory=dict)

    # CRM responsibility assignments from attached CRM-source overlays.
    # Bucket name -> list of (control_id, narrative_or_None, source_baseline_name).
    # Buckets are the responsibility values: "provider", "inherited",
    # "not_applicable", "hybrid", "customer". Latest overlay wins on duplicate
    # control_id (per build_crm_context pattern). Empty when no CRM overlays
    # are attached, in which case the appendix renders as no-op.
    crm_by_responsibility: dict[str, list[tuple[str, str | None, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    # Runtime ledger of CCIs the assessment loop actually short-circuited
    # because an attached CRM declared the control provider / inherited /
    # not_applicable. Populated from ``CrmShortCircuitEvent`` rows; the
    # severity / score columns are LEFT-JOINed from the
    # ``CrmSuspicionLog`` that was latest at decision time (None when no
    # log existed yet). Distinct from ``crm_by_responsibility``, which is
    # the CRM's *declared* scope at attach time — a control declared
    # inherited but never assessed (no CCI evaluated) appears in
    # ``crm_by_responsibility`` but NOT here.
    # (control_id_str, responsibility, severity_bucket|None,
    #  overall_suspicion|None, created_at)
    crm_short_circuit_events: list[
        tuple[str, str, str | None, float | None, datetime]
    ] = field(default_factory=list)

    # Append-only OdpAuditLog rows for this workbook's framework — every
    # ODP value overwrite recorded during re-ingest. Drives Appendix H.
    # Scoped at gather time by Framework.framework_id (the OSCAL short
    # identifier that pairs with OdpAuditLog.framework_version), so a
    # workbook for one framework never spills rows from another. Empty
    # list when no audit rows exist or the workbook has no framework —
    # the appendix skips entirely in that case.
    # (control_id_str, odp_id, assigned_from, prev_value, new_value, who, when)
    odp_audit_events: list[
        tuple[str, str, str, str, str, str, datetime]
    ] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Data gathering
# ---------------------------------------------------------------------------


def _evidence_methods(sources: list[str]) -> str:
    """Map ``EvidenceTag.source`` values to NIST 800-53A method codes.

    NIST recognizes Examine / Interview / Test. ``EvidenceTag.source`` is a
    loose string (``auto``, ``manual``, ``llm``, plus user-typed values). We
    detect ``interview`` and ``test`` substrings; everything else collapses to
    Examine — that's the default mode for document review, which is what the
    rest of the pipeline produces.
    """
    methods: list[str] = []
    has_interview = any("interview" in (s or "").lower() for s in sources)
    has_test = any("test" in (s or "").lower() for s in sources)
    methods.append("E")  # examine is always implied — we're reading evidence
    if has_interview:
        methods.append("I")
    if has_test:
        methods.append("T")
    return ", ".join(methods)


def _gather(session: Session, workbook_id: int) -> _SarData:
    """Single-pass query bundle. All DB reads happen here so render is pure."""
    wb = session.get(Workbook, workbook_id)
    if wb is None:
        raise ValueError(f"Workbook {workbook_id} not found")

    framework = (
        session.get(Framework, wb.framework_id) if wb.framework_id is not None else None
    )
    baseline = (
        session.get(Baseline, wb.baseline_id) if wb.baseline_id is not None else None
    )
    system = session.get(System, wb.system_id) if wb.system_id is not None else None

    # Workbook is authoritative for col-N status; DB Assessments overlay where
    # written through the app.
    #
    # Precision-over-recall gate: rows flagged needs_review=True are excluded
    # from the SAR for the same reason controls/exporter.py:28-30 excludes them
    # from the eMASS CCIS export and poam/generator.py:713 excludes them from
    # the POAM -- an abstain-coerced row carries a placeholder narrative
    # ("(abstain -- pending human review)") and a status forced to
    # NON_COMPLIANT by routes.controls._coerce_abstain_persistence_fields, not
    # an assessor finding. Bleeding it into status_totals / verdict promotion
    # / Appendix D would misrepresent the assessor's actual conclusions. The
    # reviewer queue (which DOES surface needs_review rows) is the right
    # consumer for these. See feedback_sar_needs_review_gate.md and
    # feedback_precision_over_recall.md.
    index = read_workbook_index(wb.path)
    # excel_row -> CcisRow, for resolving (control_id, cci_id) on rows that
    # the needs_review verdict gate excludes (used by the disposition audit).
    row_by_excel_row = {
        r.excel_row: r for r in index.rows if r.excel_row is not None
    }
    db_by_excel_row: dict[int, Assessment] = {
        a.excel_row: a
        for a in session.exec(
            select(Assessment)
            .where(Assessment.workbook_id == workbook_id)
            .where(Assessment.needs_review.is_(False))
        ).all()
        if a.excel_row is not None
    }

    # Batch-load child AssessmentImplementation rows for every parent assessment
    # we just pulled. Single .in_(...) query + defaultdict grouping keeps this
    # O(1) per CCI in the flatten loop below — N+1 would be brutal for a 500-CCI
    # workbook. Pre-v0.2 assessments have zero children and simply receive an
    # empty list on _AssessmentSummary, which the section composer falls back
    # to the rolled-up narrative_q for.
    impls_by_assessment_id: dict[int, list[_ImplSummary]] = defaultdict(list)
    assessment_ids = [a.id for a in db_by_excel_row.values() if a.id is not None]
    if assessment_ids:
        impl_rows = list(
            session.exec(
                select(AssessmentImplementation)
                .where(AssessmentImplementation.assessment_id.in_(assessment_ids))
            ).all()
        )
        impl_rows.sort(key=lambda i: (i.assessment_id or 0, i.scope_label))
        for impl in impl_rows:
            if impl.assessment_id is None:
                continue
            impls_by_assessment_id[impl.assessment_id].append(
                _ImplSummary(
                    scope_label=impl.scope_label,
                    responsibility=impl.responsibility,
                    status=impl.status,
                    narrative=impl.narrative or "",
                    source_baseline_id=impl.source_baseline_id,
                    evidence_refs=impl.evidence_refs,
                )
            )

    # Control + Objective lookups (so we can map CCI -> objective.id -> Control).
    # Statement is rendered through resolve_odps so ODP placeholders
    # ({$37$}, ac-02_odp.03) are substituted with the program's stored
    # values at SAR generation time — never baked at ingest. See
    # memory/project_odp_architecture.md.
    control_meta: dict[str, tuple[str, str, str | None]] = {}
    control_pk_to_id: dict[int, str] = {}
    if framework is not None:
        for c in session.exec(
            select(Control).where(Control.framework_id == framework.id)
        ).all():
            rendered_statement = c.statement
            # Skip ODP resolution when framework_id is None (legacy/overlay rows
            # not backfilled by the additive migration) — resolve_odps would
            # filter on NULL and return nothing, but more importantly it'd issue
            # SQL against odp_assignment which may not exist on stale dev DBs.
            if c.statement and framework.framework_id:
                try:
                    # bold_format="html" — substituted ODP values arrive as
                    # ``<b>value</b>`` so ReportLab's Paragraph renders them
                    # bold in the DOCX, visually distinguishing the program's
                    # answers from the template prose.
                    rendered_statement, _ = resolve_odps(
                        session,
                        framework.framework_id,
                        c.control_id,
                        c.statement,
                        bold_format="html",
                    )
                except Exception:
                    # Render-time substitution is best-effort; never let a
                    # missing table or malformed template break SAR export.
                    rendered_statement = c.statement
            control_meta[c.control_id] = (c.title, c.family, rendered_statement)
            if c.id is not None:
                control_pk_to_id[c.id] = c.control_id

    # cci_id -> Objective row (for method/evidence lookups via objective_pk)
    objectives_by_cci: dict[str, Objective] = {}
    if framework is not None:
        for o in session.exec(
            select(Objective)
            .join(Control, Control.id == Objective.control_id_fk)
            .where(Control.framework_id == framework.id)
        ).all():
            objectives_by_cci[o.objective_id] = o

    # Assessor: most-frequent tester among DB Assessments; fall back to default
    tester_counts = Counter(
        a.tester for a in db_by_excel_row.values() if (a.tester or "").strip()
    )
    assessor = tester_counts.most_common(1)[0][0] if tester_counts else "Noah Jaskolski"

    # Period: earliest -> latest date_tested across all assessed rows (DB or col-O)
    dates: list[datetime] = []
    for a in db_by_excel_row.values():
        if a.date_tested:
            dates.append(a.date_tested)
    for row in index.rows:
        if row.date_tested:
            dates.append(row.date_tested)
    period_start = min(dates) if dates else None
    period_end = max(dates) if dates else None

    data = _SarData(
        workbook=wb,
        framework=framework,
        baseline=baseline,
        system=system,
        assessor=assessor,
        period_start=period_start,
        period_end=period_end,
        generated_at=datetime.now(timezone.utc),
        control_meta=control_meta,
    )

    # ----- Flatten assessed rows -----
    for row in index.rows:
        db_row = db_by_excel_row.get(row.excel_row)
        status = db_row.status if db_row else _coerce_status(row.status)
        if status is None:
            continue

        cci_id = row.cci_id or row.ap_acronym or ""
        # The DB objective_pk for this row, if we can resolve it via cci_id.
        # We try CCI first, then the AP-acronym form (some objectives are
        # stored as "AC-2.1" rather than "CCI-NNNNNN").
        obj: Objective | None = None
        if row.cci_id:
            obj = objectives_by_cci.get(row.cci_id)
        if obj is None and row.ap_acronym:
            obj = objectives_by_cci.get(row.ap_acronym)
        objective_pk = obj.id if obj else (db_row.objective_id if db_row else None)

        summary = _AssessmentSummary(
            control_id=row.control_id,
            cci_id=cci_id,
            status=status,
            tester=(db_row.tester if db_row else row.tester) or "",
            date_tested=db_row.date_tested if db_row else row.date_tested,
            narrative=(db_row.narrative_q if db_row else row.results) or "",
            inheritance=db_row.inheritance_rule if db_row else row.inherited,
            objective_pk=objective_pk,
            has_db_row=db_row is not None,
            implementations=(
                impls_by_assessment_id.get(db_row.id, [])
                if db_row is not None and db_row.id is not None
                else []
            ),
        )
        data.rows.append(summary)
        data.status_totals[status] += 1
        data.by_control[row.control_id].append(summary)
        if summary.inheritance:
            data.inheritance_totals[summary.inheritance] += 1

    # Sort rows within each control for stable output
    for ctl in data.by_control:
        data.by_control[ctl].sort(key=lambda r: (r.control_id, r.cci_id))

    # ----- Baseline scope -----
    if baseline is not None and baseline.id is not None:
        # Exclude soft-deleted CCIs from the SAR baseline rollup so the
        # report reflects the current workbook roster, not the historical
        # superset the row preserves for save-path lookups. See models.py
        # BaselineObjective.is_deprecated.
        bo_rows = session.exec(
            select(BaselineObjective).where(
                BaselineObjective.baseline_id == baseline.id,
                BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
            )
        ).all()
        data.baseline_ccis_total = len(bo_rows)

        bc_rows = session.exec(
            select(BaselineControl).where(BaselineControl.baseline_id == baseline.id)
        ).all()
        for bc in bc_rows:
            ctl_id = control_pk_to_id.get(bc.control_id)
            if ctl_id:
                data.primary_membership[ctl_id] = bool(bc.in_scope)
            if bc.in_scope:
                data.baseline_controls_in_scope += 1
            else:
                data.baseline_controls_out_of_scope += 1
                if ctl_id:
                    data.tailored_out_controls.append(
                        (ctl_id, bc.tailoring_reason or "—")
                    )
        data.tailored_out_controls.sort(key=lambda t: t[0])

    # ----- Reference overlays (read-only gap-analysis annotations) -----
    overlay_baselines = list(
        session.exec(
            select(Baseline)
            .join(WorkbookOverlay, WorkbookOverlay.baseline_id == Baseline.id)
            .where(WorkbookOverlay.workbook_id == workbook_id)
            .order_by(WorkbookOverlay.attached_at)
        ).all()
    )
    data.overlays = overlay_baselines
    if overlay_baselines:
        overlay_ids = [b.id for b in overlay_baselines if b.id is not None]
        if overlay_ids:
            ov_bc_rows = session.exec(
                select(
                    BaselineControl.baseline_id,
                    BaselineControl.control_id,
                    BaselineControl.in_scope,
                ).where(
                    BaselineControl.baseline_id.in_(overlay_ids)  # type: ignore[attr-defined]
                )
            ).all()
            for bl_id, ctrl_pk, in_scope in ov_bc_rows:
                ctl_id = control_pk_to_id.get(ctrl_pk)
                if ctl_id:
                    data.overlay_membership.setdefault(bl_id, {})[ctl_id] = bool(in_scope)

    # ----- CRM responsibility assignments (from CRM-source overlays) -----
    # Same join pattern as build_crm_context but rendered for the SAR:
    # WorkbookOverlay -> Baseline(source_type=CRM) -> BaselineControl -> Control.
    # Latest overlay wins on duplicate control_id (attached_at desc + first-wins).
    crm_rows = list(
        session.exec(
            select(BaselineControl, Control, Baseline, WorkbookOverlay)
            .join(Baseline, Baseline.id == BaselineControl.baseline_id)
            .join(Control, Control.id == BaselineControl.control_id)
            .join(WorkbookOverlay, WorkbookOverlay.baseline_id == Baseline.id)
            .where(WorkbookOverlay.workbook_id == workbook_id)
            .where(Baseline.source_type == BaselineSourceType.CRM)
            .where(BaselineControl.responsibility.is_not(None))  # type: ignore[union-attr]
            .order_by(WorkbookOverlay.attached_at.desc())
        ).all()
    )
    crm_seen: set[str] = set()
    for bc, ctrl, bl, _overlay in crm_rows:
        if ctrl.control_id in crm_seen:
            continue  # latest overlay already won
        crm_seen.add(ctrl.control_id)
        bucket = bc.responsibility or "customer"
        data.crm_by_responsibility[bucket].append(
            (ctrl.control_id, bc.responsibility_narrative, bl.name)
        )
    # Sort each bucket by control_id for stable output
    for bucket in data.crm_by_responsibility:
        data.crm_by_responsibility[bucket].sort(key=lambda t: t[0])

    # ----- CRM short-circuit runtime ledger (Appendix G) -----
    # Distinct from the declared-scope block above: every row here is a CCI
    # the assessor actually skipped because the CRM said provider /
    # inherited / not_applicable at decision time. LEFT JOIN the suspicion
    # log so events written before any score lands still surface
    # (suspicion_log_id is nullable per the model). Order desc on
    # created_at so the in-memory regroup in the renderer can keep
    # most-recent-first within each control without resorting.
    sc_rows = list(
        session.exec(
            select(CrmShortCircuitEvent, CrmSuspicionLog)
            .join(
                CrmSuspicionLog,
                CrmSuspicionLog.id == CrmShortCircuitEvent.suspicion_log_id,
                isouter=True,
            )
            .where(CrmShortCircuitEvent.workbook_id == workbook_id)
            .order_by(CrmShortCircuitEvent.created_at.desc())  # type: ignore[attr-defined]
        ).all()
    )
    for ev, log in sc_rows:
        control_id_str = control_pk_to_id.get(ev.control_id_fk)
        if not control_id_str:
            # Control was deleted post-event. Skip rather than render an
            # orphan row with an empty control cell — the FK is dangling
            # in user-visible terms even if the DB row still exists.
            continue
        sev = _suspicion_bucket(log.overall_suspicion) if log else None
        score = log.overall_suspicion if log else None
        data.crm_short_circuit_events.append(
            (control_id_str, ev.responsibility, sev, score, ev.created_at)
        )

    # ----- ODP value-history ledger (Appendix H) -----
    # Every ODP value overwrite the workbook ingest path has recorded for
    # this framework. Scoped by Framework.framework_id (the OSCAL short
    # identifier) — OdpAuditLog rows from a sibling framework's workbook
    # never leak into this SAR. SQL orders by control_id asc and when
    # desc; the renderer's in-memory regroup (control -> odp_id -> events)
    # rides that ordering for the desired secondary sort for free.
    # Skipped entirely when the workbook has no framework (no point of
    # comparison) or when the audit table is empty for this framework.
    if framework is not None and framework.framework_id:
        odp_rows = list(
            session.exec(
                select(OdpAuditLog)
                .where(OdpAuditLog.framework_version == framework.framework_id)
                .order_by(
                    OdpAuditLog.control_id,
                    OdpAuditLog.when.desc(),  # type: ignore[attr-defined]
                )
            ).all()
        )
        for r in odp_rows:
            data.odp_audit_events.append((
                r.control_id,
                r.odp_id,
                r.assigned_from or "",
                r.prev_value or "",
                r.new_value or "",
                r.who or "",
                r.when,
            ))

    # ----- POAMs (and finding refs) -----
    data.poams = list(
        session.exec(
            select(Poam)
            .where(Poam.workbook_id == workbook_id)
            .order_by(Poam.control_cluster)
        ).all()
    )

    # Build the F-NNN label map and reverse-link to per-objective table cells
    for idx, p in enumerate(data.poams, start=1):
        if p.id is None:
            continue
        label = f"F-{idx:03d}"
        data.poam_finding_ref[p.id] = label

        # Milestones
        data.poam_milestones[p.id] = list(
            session.exec(
                select(PoamMilestone)
                .where(PoamMilestone.poam_id == p.id)
                .order_by(PoamMilestone.scheduled_date, PoamMilestone.id)
            ).all()
        )

        # Per-POAM objectives → reverse map for §5 "Finding ref" column
        po_links = list(
            session.exec(
                select(PoamObjective).where(PoamObjective.poam_id == p.id)
            ).all()
        )
        data.poam_objective_ids[p.id] = [po.objective_id for po in po_links]
        for po in po_links:
            data.objective_finding_ref[po.objective_id] = label

    # ----- Evidence inventory & methods per objective -----
    # Only walk objectives that actually appear in this workbook's assessments.
    objective_pks = {r.objective_pk for r in data.rows if r.objective_pk is not None}
    if objective_pks:
        # Every .in_() below is chunked through ``chunked`` — on a multi-
        # framework enterprise workbook the objective and evidence id sets can
        # exceed SQLITE_MAX_VARIABLES (32766) and an un-chunked IN clause would
        # abort the SAR build with "too many SQL variables".
        objective_pk_list = list(objective_pks)
        tags = []
        for batch in chunked(objective_pk_list):
            tags.extend(
                session.exec(
                    select(EvidenceTag).where(EvidenceTag.objective_id.in_(batch))  # type: ignore[attr-defined]
                ).all()
            )

        # Count + method codes
        sources_by_obj: dict[int, list[str]] = defaultdict(list)
        for t in tags:
            sources_by_obj[t.objective_id].append(t.source or "")
            data.evidence_count_by_objective[t.objective_id] = (
                data.evidence_count_by_objective.get(t.objective_id, 0) + 1
            )
        for obj_pk, srcs in sources_by_obj.items():
            data.methods_by_objective[obj_pk] = _evidence_methods(srcs)

        # Evidence rows + their controls-covered set
        ev_ids = {t.evidence_id for t in tags}
        if ev_ids:
            ev_id_list = list(ev_ids)
            ev_rows = []
            for batch in chunked(ev_id_list):
                ev_rows.extend(
                    session.exec(
                        select(Evidence).where(Evidence.id.in_(batch))  # type: ignore[attr-defined]
                    ).all()
                )
            # Which controls does each evidence touch (via its objectives)?
            obj_to_ctl: dict[int, str] = {}
            for batch in chunked(objective_pk_list):
                for o in session.exec(
                    select(Objective).where(Objective.id.in_(batch))  # type: ignore[attr-defined]
                ).all():
                    if o.id is not None:
                        obj_to_ctl[o.id] = control_pk_to_id.get(o.control_id_fk, "")
            ev_to_ctls: dict[int, set[str]] = defaultdict(set)
            for t in tags:
                ctl = obj_to_ctl.get(t.objective_id)
                if ctl:
                    ev_to_ctls[t.evidence_id].add(ctl)
            data.evidence_rows = sorted(
                ((e, ev_to_ctls[e.id or -1]) for e in ev_rows),
                key=lambda pair: ((pair[0].title or "").lower(), pair[0].id or 0),
            )

            # STIG findings on those evidence rows
            stig_findings: list = []
            for batch in chunked(ev_id_list):
                stig_findings.extend(
                    session.exec(
                        select(StigFinding).where(StigFinding.evidence_id.in_(batch))  # type: ignore[attr-defined]
                    ).all()
                )
            data.stig_findings = stig_findings

    # ----- Token-budget evidence disposition audit (Appendix I + CSV) -----
    # Deliberately a SEPARATE pass over ALL assessments for this workbook,
    # NOT the needs_review-filtered db_by_excel_row. The overflow-escalation
    # path (assessor Step 1.67) abstains a control to needs_review=True
    # precisely when high-relevance evidence was deferred, so the rows whose
    # deferred artifacts most need surfacing are the ones the SAR verdict gate
    # excludes. Filtering here would re-create the silent-drop blind spot this
    # whole initiative exists to close. The verdict rollups stay gated
    # (feedback_sar_needs_review_gate); only this audit trail sees everything.
    all_assessments = list(
        session.exec(
            select(Assessment).where(Assessment.workbook_id == workbook_id)
        ).all()
    )
    assessment_ctx: dict[int, tuple[str, str]] = {}
    for a in all_assessments:
        if a.id is None or a.excel_row is None:
            continue
        idx_row = row_by_excel_row.get(a.excel_row)
        if idx_row is not None:
            ctl = idx_row.control_id
            cci = idx_row.cci_id or idx_row.ap_acronym or ""
        else:
            # Assessment references a row no longer in the workbook (soft-
            # deleted / manually edited). Still surface its disposition rows so
            # nothing the model saw goes unrecorded; label with what we have.
            ctl = ""
            cci = ""
        assessment_ctx[a.id] = (ctl, cci)

    if assessment_ctx:
        # Chunk the assessment-id IN-clause: a fully-assessed 10k-host
        # workbook accumulates one Assessment per CCI across hundreds of
        # controls, which can exceed SQLITE_MAX_VARIABLES. Re-sort after the
        # union so the (assessment_id, order_index) ordering the appendix
        # relies on survives the per-batch concatenation.
        shown_rows: list[AssessmentEvidenceShown] = []
        for batch in chunked(list(assessment_ctx.keys())):
            shown_rows.extend(
                session.exec(
                    select(AssessmentEvidenceShown)
                    .where(AssessmentEvidenceShown.assessment_id.in_(batch))  # type: ignore[attr-defined]
                    .order_by(
                        AssessmentEvidenceShown.assessment_id,
                        AssessmentEvidenceShown.order_index,
                    )
                ).all()
            )
        shown_rows.sort(key=lambda r: (r.assessment_id, r.order_index))
        if shown_rows:
            shown_ev_ids = {r.evidence_id for r in shown_rows}
            ev_by_id: dict[int, Evidence] = {}
            for batch in chunked(list(shown_ev_ids)):
                for e in session.exec(
                    select(Evidence).where(Evidence.id.in_(batch))  # type: ignore[attr-defined]
                ).all():
                    if e.id is not None:
                        ev_by_id[e.id] = e
            for r in shown_rows:
                ctl, cci = assessment_ctx.get(r.assessment_id, ("", ""))
                ev = ev_by_id.get(r.evidence_id)
                title = ""
                doc_number = ""
                if ev is not None:
                    title = ev.title or (
                        ev.path.rsplit("/", 1)[-1] if ev.path else f"evidence #{ev.id}"
                    )
                    doc_number = ev.doc_number or ""
                data.evidence_dispositions.append(
                    _EvidenceDisposition(
                        control_id=ctl,
                        cci_id=cci,
                        evidence_title=title,
                        doc_number=doc_number,
                        chunk_sha=r.chunk_sha or "",
                        order_index=r.order_index,
                        disposition=r.disposition,
                        rank_score=r.rank_score,
                        deferred_reason=r.deferred_reason,
                    )
                )

    return data


# ---------------------------------------------------------------------------
# Section builders — each returns a list of Platypus flowables
# ---------------------------------------------------------------------------


def _kv_table(rows: list[list[str]], col1_width: float = 1.8) -> Table:
    """Two-column key/value table — used in cover and scope sections."""
    t = Table(rows, colWidths=[col1_width * inch, (7.0 - col1_width) * inch])
    t.setStyle(
        TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#334155")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ])
    )
    return t


def _section_cover(data: _SarData, sty: dict) -> list:
    """§1 — Cover page."""
    wb = data.workbook
    fw = (
        f"{data.framework.name} {data.framework.version}"
        if data.framework
        else "—"
    )
    bl = data.baseline.name if data.baseline else "—"
    sys_name = data.system.name if data.system else (wb.filename.rsplit(".", 1)[0])
    period = "—"
    if data.period_start and data.period_end:
        period = (
            f"{data.period_start.strftime('%Y-%m-%d')} → "
            f"{data.period_end.strftime('%Y-%m-%d')}"
        )
    elif data.period_end:
        period = data.period_end.strftime("%Y-%m-%d")

    story: list = []
    story.append(Spacer(1, 1.4 * inch))
    story.append(Paragraph("Security Assessment Report", sty["title"]))
    story.append(
        Paragraph(
            f"<font color='#475569'>{_xml(fw)}</font>",
            sty["h2"],
        )
    )
    story.append(Spacer(1, 0.3 * inch))
    story.append(
        _kv_table([
            ["System", sys_name],
            ["Workbook", wb.filename],
            ["Framework", fw],
            ["Baseline", bl],
            ["Assessment period", period],
            ["Assessor", data.assessor],
            ["Report generated", data.generated_at.strftime("%Y-%m-%d %H:%M UTC")],
        ])
    )

    # TODO(sar): pull classification from System.description / SSP metadata.
    story.append(Spacer(1, 0.6 * inch))
    story.append(
        Paragraph(
            "<b>CONTROLLED UNCLASSIFIED INFORMATION (CUI)</b>",
            sty["h2"],
        )
    )
    story.append(
        Paragraph(
            "This document contains CUI and is intended solely for authorized "
            "personnel involved in the assessment, accreditation, and ongoing "
            "authorization of the system named above.",
            sty["small"],
        )
    )
    return story


def _section_executive_summary(data: _SarData, sty: dict) -> list:
    """§2 — Executive summary."""
    story: list = [Paragraph("1. Executive Summary", sty["h1"])]

    sys_name = _xml(data.system.name if data.system else data.workbook.filename)
    fw = _xml(
        f"{data.framework.name} {data.framework.version}"
        if data.framework
        else "the controls catalog"
    )
    total = sum(data.status_totals.values())
    nc = data.status_totals.get(ComplianceStatus.NON_COMPLIANT, 0)

    high_risk = sum(
        1 for p in data.poams if p.raw_severity in _HIGH_RISK_LEVELS
    )

    headline = (
        f"This Security Assessment Report documents the results of a "
        f"control assessment of <b>{sys_name}</b> against <b>{fw}</b>. "
        f"A total of <b>{total}</b> assessment objectives were evaluated; "
        f"<b>{nc}</b> were determined Non-Compliant, resulting in "
        f"<b>{len(data.poams)}</b> Plan of Action &amp; Milestones entries — "
        f"<b>{high_risk}</b> of which carry a raw severity of High or "
        f"Very High and require AO attention."
    )
    story.append(Paragraph(headline, sty["body"]))
    story.append(Spacer(1, 0.15 * inch))

    # Status counts table — same palette as the compliance report
    pct = lambda n: f"{(n / total * 100):.1f}%" if total else "—"  # noqa: E731
    summary_data = [
        ["Status", "Count", "Share"],
        ["Compliant", str(data.status_totals.get(ComplianceStatus.COMPLIANT, 0)),
         pct(data.status_totals.get(ComplianceStatus.COMPLIANT, 0))],
        ["Non-Compliant", str(nc), pct(nc)],
        ["Not Applicable", str(data.status_totals.get(ComplianceStatus.NOT_APPLICABLE, 0)),
         pct(data.status_totals.get(ComplianceStatus.NOT_APPLICABLE, 0))],
        ["Total assessed", str(total), "100.0%" if total else "—"],
    ]
    t = Table(summary_data, colWidths=[2.0 * inch, 1.2 * inch, 1.2 * inch])
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
            ("BACKGROUND", (0, 1), (-1, 1), _STATUS_FILL[ComplianceStatus.COMPLIANT]),
            ("BACKGROUND", (0, 2), (-1, 2), _STATUS_FILL[ComplianceStatus.NON_COMPLIANT]),
            ("BACKGROUND", (0, 3), (-1, 3), _STATUS_FILL[ComplianceStatus.NOT_APPLICABLE]),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("LINEABOVE", (0, -1), (-1, -1), 0.6, colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(t)

    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Findings by severity (raw)", sty["h2"]))
    sev_counts: Counter = Counter(p.raw_severity for p in data.poams)
    sev_data = [["Severity", "Findings"]]
    any_sev = False
    for lvl in _RISK_ORDER_DESC:
        c = sev_counts.get(lvl, 0)
        if c:
            any_sev = True
        sev_data.append([lvl.value, str(c)])
    sev_data.append([
        "Unrated",
        str(sev_counts.get(None, 0)),
    ])
    sev_table = Table(sev_data, colWidths=[2.0 * inch, 1.2 * inch])
    sev_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i, lvl in enumerate(_RISK_ORDER_DESC, start=1):
        sev_style.append(("BACKGROUND", (0, i), (-1, i), _RISK_FILL[lvl]))
    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)
    if not any_sev and sev_counts.get(None, 0) == 0:
        story.append(Spacer(1, 0.1 * inch))
        story.append(
            Paragraph("No POAMs generated for this workbook.", sty["small"])
        )

    return story


def _section_scope(data: _SarData, sty: dict) -> list:
    """§3 — System description & scope."""
    story: list = [Paragraph("2. System Description &amp; Scope", sty["h1"])]

    sys_name = _xml(data.system.name if data.system else data.workbook.filename)
    sys_desc = _xml(
        (data.system.description or "").strip()
        if data.system
        else ""
    )
    story.append(
        Paragraph(
            f"The system under assessment is <b>{sys_name}</b>. "
            + (sys_desc or "No supplementary system description has been recorded in the catalog."),
            sty["body"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    # Scope summary
    bl = data.baseline
    scope_rows = [
        ["Baseline", bl.name if bl else "—"],
        ["Baseline source",
         bl.source_type.value if bl else "no baseline materialized"],
        ["Controls in scope", str(data.baseline_controls_in_scope)],
        ["Controls tailored out", str(data.baseline_controls_out_of_scope)],
        ["CCIs in baseline catalog", str(data.baseline_ccis_total)],
        ["CCIs with assessed status", str(sum(data.status_totals.values()))],
    ]
    story.append(_kv_table(scope_rows))

    # Tailored-out detail
    if data.tailored_out_controls:
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph("Tailored-out controls", sty["h2"]))
        tdata: list[list] = [["Control", "Tailoring rationale"]]
        for ctl_id, reason in data.tailored_out_controls:
            tdata.append([
                Paragraph(f"<b>{ctl_id}</b>", sty["small"]),
                Paragraph(_truncate(reason, 240), sty["small"]),
            ])
        ttbl = Table(tdata, colWidths=[1.2 * inch, 5.8 * inch], repeatRows=1)
        ttbl.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(ttbl)

    # Inheritance summary
    if data.inheritance_totals:
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph("Inheritance distribution", sty["h2"]))
        idata: list[list] = [["Inheritance", "Objectives"]]
        for inh, cnt in sorted(data.inheritance_totals.items(), key=lambda kv: -kv[1]):
            idata.append([inh, str(cnt)])
        itbl = Table(idata, colWidths=[3.5 * inch, 1.2 * inch])
        itbl.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(itbl)

    return story


def _section_methodology(data: _SarData, sty: dict) -> list:
    """§4 — Assessment methodology."""
    story: list = [Paragraph("3. Assessment Methodology", sty["h1"])]
    story.append(
        Paragraph(
            "The assessment followed the procedures described in NIST SP "
            "800-53A using the three assessment methods: <b>Examine</b> "
            "(review of specifications, mechanisms, and activities), "
            "<b>Interview</b> (discussions with individuals or groups), and "
            "<b>Test</b> (exercising assessment objects under specified "
            "conditions). For each in-scope CCI the assessor collected "
            "supporting evidence, evaluated implementation against the "
            "control's assessment objectives, and recorded a determination of "
            "Compliant, Non-Compliant, or Not Applicable.",
            sty["body"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    story.append(
        Paragraph(
            "Assessment was AI-augmented: candidate findings were generated by "
            "a Large Language Model from indexed evidence and validated by a "
            "deterministic post-validator before being surfaced for human "
            "review. Each finding remains subject to assessor judgment; the "
            "LLM accelerates evidence triage and narrative drafting but does "
            "not replace the assessor's compliance determination.",
            sty["body"],
        )
    )

    return story


def _section_results(data: _SarData, sty: dict) -> list:
    """§5 — Assessment results, grouped by control."""
    story: list = [Paragraph("4. Assessment Results", sty["h1"])]
    story.append(
        Paragraph(
            "Per-control roll-up of assessed objectives. The full per-objective "
            "narrative is provided in Appendix D; this section presents the "
            "determination summary and points to the relevant findings in §5.",
            sty["body"],
        )
    )

    if not data.by_control:
        story.append(Spacer(1, 0.1 * inch))
        story.append(
            Paragraph(
                "No assessed objectives recorded — this workbook has no status "
                "values in column N and no Assessment rows in the catalog. "
                "Sections 5 and 6 will likewise be empty.",
                sty["small"],
            )
        )
        return story

    for ctl_id in sorted(data.by_control.keys()):
        items = data.by_control[ctl_id]
        title, family, statement = data.control_meta.get(
            ctl_id, ("", _family_from_control_id(ctl_id), None)
        )
        nc = sum(1 for r in items if r.status == ComplianceStatus.NON_COMPLIANT)
        c = sum(1 for r in items if r.status == ComplianceStatus.COMPLIANT)
        na = sum(1 for r in items if r.status == ComplianceStatus.NOT_APPLICABLE)

        # Single-word control verdict — NC if any NC, else NA if any NA, else C.
        if nc > 0:
            verdict = "Non-Compliant"
        elif c > 0:
            verdict = "Compliant"
        else:
            verdict = "Not Applicable"

        block: list = []
        header_line = f"<b>{ctl_id}</b>"
        if title:
            header_line += f" — {_xml(title)}"
        block.append(Paragraph(header_line, sty["h2"]))
        block.append(
            Paragraph(
                f"Family {family} · Objectives assessed: <b>{len(items)}</b> · "
                f"Determination: <b>{verdict}</b> "
                f"({c} C / {nc} NC / {na} NA)",
                sty["small"],
            )
        )

        # Control statement per SAR_DESIGN.md §5 line 99. The ODP
        # placeholders ({$N$} / ac-XX_odp.NN) were already resolved
        # against odp_assignment at control_meta construction time
        # (see resolve_odps call earlier in this module); printing
        # `statement` here renders program-specific values inline.
        if statement:
            block.append(
                Paragraph(
                    f"<i>Control statement:</i> {_xml(statement)}",
                    sty["small"],
                )
            )

        # Per-objective table
        tdata: list[list] = [
            [
                Paragraph("<b>CCI / AP</b>", sty["small"]),
                Paragraph("<b>Status</b>", sty["small"]),
                Paragraph("<b>Methods</b>", sty["small"]),
                Paragraph("<b>Evidence</b>", sty["small"]),
                Paragraph("<b>Finding</b>", sty["small"]),
            ]
        ]
        status_row_idx: dict[int, ComplianceStatus] = {}
        for i, r in enumerate(items, start=1):
            methods = (
                data.methods_by_objective.get(r.objective_pk, "E")
                if r.objective_pk is not None
                else "E"
            )
            ev_count = (
                data.evidence_count_by_objective.get(r.objective_pk, 0)
                if r.objective_pk is not None
                else 0
            )
            finding = (
                data.objective_finding_ref.get(r.objective_pk, "—")
                if r.objective_pk is not None
                else "—"
            )
            tdata.append([
                Paragraph(
                    f"<font face='Courier' size='7'>{r.cci_id or '—'}</font>",
                    sty["small"],
                ),
                Paragraph(r.status.value, sty["small"]),
                Paragraph(methods, sty["small"]),
                Paragraph(str(ev_count), sty["small"]),
                Paragraph(_xml(finding), sty["small"]),
            ])
            status_row_idx[i] = r.status

        tbl = Table(
            tdata,
            colWidths=[1.55 * inch, 1.15 * inch, 0.95 * inch, 0.95 * inch, 1.05 * inch],
            repeatRows=1,
        )
        style_cmds: list = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for ri, st in status_row_idx.items():
            style_cmds.append(("BACKGROUND", (1, ri), (1, ri), _STATUS_FILL[st]))
        tbl.setStyle(TableStyle(style_cmds))
        block.append(tbl)
        block.append(Spacer(1, 0.12 * inch))

        # Keep the header + first ~10 rows on one page; let huge tables flow
        if len(items) <= 12:
            story.append(KeepTogether(block))
        else:
            story.extend(block)

    return story


def _section_findings(data: _SarData, sty: dict) -> list:
    """§6 — Findings summary (one row per POAM)."""
    story: list = [Paragraph("5. Findings Summary", sty["h1"])]
    if not data.poams:
        story.append(
            Paragraph(
                "No Plan of Action &amp; Milestones entries have been generated "
                "for this workbook. Either there are no Non-Compliant objectives, "
                "or the POAM generator has not been run. Use the POAMs view in "
                "the application to generate findings from current NC results.",
                sty["body"],
            )
        )
        return story

    story.append(
        Paragraph(
            "One row per POAM. Findings are clustered at the natural "
            "remediation boundary (base control + its (N) enhancements by "
            "default); the assessor may split or merge clusters in the UI "
            "before export to eMASS. Risk ratings follow NIST SP 800-30 "
            "Rev 1 Appendix I Table I-2.",
            sty["small"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    header = [
        Paragraph("<b>ID</b>", sty["small"]),
        Paragraph("<b>Controls</b>", sty["small"]),
        Paragraph("<b>Likelihood × Impact = Raw</b>", sty["small"]),
        Paragraph("<b>Residual</b>", sty["small"]),
        Paragraph("<b>Description</b>", sty["small"]),
        Paragraph("<b>Scheduled</b>", sty["small"]),
    ]
    tdata: list[list] = [header]
    severity_per_row: dict[int, RiskLevel | None] = {}
    for idx, p in enumerate(data.poams, start=1):
        label = data.poam_finding_ref.get(p.id or -1, f"F-{idx:03d}")
        controls = p.security_control_number or p.control_cluster
        like = p.likelihood.value if p.likelihood else "—"
        imp = p.impact.value if p.impact else "—"
        raw = p.raw_severity.value if p.raw_severity else "—"
        resid = p.residual_risk.value if p.residual_risk else "—"
        sched = (
            p.scheduled_completion_date.strftime("%Y-%m-%d")
            if p.scheduled_completion_date
            else "—"
        )
        tdata.append([
            Paragraph(f"<b>{_xml(label)}</b>", sty["small"]),
            Paragraph(_xml(controls), sty["small"]),
            Paragraph(f"{like} × {imp} = <b>{raw}</b>", sty["small"]),
            Paragraph(resid, sty["small"]),
            Paragraph(_truncate(p.vulnerability_description, 260), sty["small"]),
            Paragraph(sched, sty["small"]),
        ])
        severity_per_row[idx] = p.raw_severity

    t = Table(
        tdata,
        colWidths=[
            0.55 * inch,
            1.25 * inch,
            1.65 * inch,
            0.75 * inch,
            2.25 * inch,
            0.85 * inch,
        ],
        repeatRows=1,
    )
    style_cmds: list = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    # Color the Raw cell by severity tier
    for ri, lvl in severity_per_row.items():
        if lvl is not None:
            style_cmds.append(("BACKGROUND", (2, ri), (2, ri), _RISK_FILL[lvl]))
    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    return story


def _section_recommendations(data: _SarData, sty: dict) -> list:
    """§7 — Recommendations, grouped by descending raw severity."""
    story: list = [Paragraph("6. Recommendations", sty["h1"])]
    if not data.poams:
        story.append(
            Paragraph(
                "No findings — no recommendations.",
                sty["body"],
            )
        )
        return story

    by_severity: dict[RiskLevel | None, list[Poam]] = defaultdict(list)
    for p in data.poams:
        by_severity[p.raw_severity].append(p)

    any_rendered = False
    for lvl in _RISK_ORDER_DESC:
        bucket = by_severity.get(lvl, [])
        if not bucket:
            continue
        any_rendered = True
        story.append(Paragraph(f"{lvl.value} severity", sty["h2"]))
        for p in bucket:
            label = _xml(data.poam_finding_ref.get(p.id or -1, "F-???"))
            controls = _xml(p.security_control_number or p.control_cluster)
            sched = (
                p.scheduled_completion_date.strftime("%Y-%m-%d")
                if p.scheduled_completion_date
                else "TBD"
            )
            mit = (p.mitigations or "").strip()
            if not mit:
                # Pull the first milestone description as fallback recommendation
                ms = data.poam_milestones.get(p.id or -1, [])
                mit = ms[0].description if ms else "Develop remediation plan."
            story.append(
                Paragraph(
                    f"<b>{label}</b> ({controls}) — by <b>{sched}</b>: "
                    f"{_truncate(mit, 360)}",
                    sty["body"],
                )
            )
        story.append(Spacer(1, 0.08 * inch))

    # Unrated bucket
    unrated = by_severity.get(None, [])
    if unrated:
        any_rendered = True
        story.append(Paragraph("Unrated", sty["h2"]))
        for p in unrated:
            label = _xml(data.poam_finding_ref.get(p.id or -1, "F-???"))
            controls = _xml(p.security_control_number or p.control_cluster)
            story.append(
                Paragraph(
                    f"<b>{label}</b> ({controls}) — assign likelihood and "
                    f"impact, then re-run this report for an AO-actionable "
                    f"recommendation.",
                    sty["body"],
                )
            )

    if not any_rendered:
        story.append(Paragraph("No findings — no recommendations.", sty["body"]))

    return story


def _appendix_evidence(data: _SarData, sty: dict) -> list:
    """Appendix A — Evidence inventory."""
    story: list = [Paragraph("Appendix A. Evidence Inventory", sty["h1"])]
    if not data.evidence_rows:
        story.append(
            Paragraph(
                "No evidence artifacts tagged to in-scope objectives.",
                sty["small"],
            )
        )
        return story

    header = [
        Paragraph("<b>Title</b>", sty["small"]),
        Paragraph("<b>Doc #</b>", sty["small"]),
        Paragraph("<b>Kind</b>", sty["small"]),
        Paragraph("<b>SHA-256</b>", sty["small"]),
        Paragraph("<b>Superseded</b>", sty["small"]),
        Paragraph("<b>Controls</b>", sty["small"]),
    ]
    rows: list[list] = [header]
    for ev, ctls in data.evidence_rows:
        title = ev.title or (ev.path.rsplit("/", 1)[-1] if ev.path else f"evidence #{ev.id}")
        rows.append([
            Paragraph(_truncate(title, 80), sty["small"]),
            Paragraph(_xml(ev.doc_number) or "—", sty["small"]),
            Paragraph(ev.kind.value if ev.kind else "—", sty["small"]),
            Paragraph(
                f"<font face='Courier' size='7'>{(ev.sha256 or '')[:12]}</font>",
                sty["small"],
            ),
            Paragraph("yes" if ev.superseded_by_id else "no", sty["small"]),
            Paragraph(
                _truncate(", ".join(sorted(ctls)), 100) if ctls else "—",
                sty["small"],
            ),
        ])
    t = Table(
        rows,
        colWidths=[2.2 * inch, 1.0 * inch, 0.6 * inch, 0.9 * inch, 0.75 * inch, 1.55 * inch],
        repeatRows=1,
    )
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(t)
    return story


def _appendix_stig(data: _SarData, sty: dict) -> list:
    """Appendix B — STIG findings (skip entirely if none)."""
    if not data.stig_findings:
        return []
    story: list = [Paragraph("Appendix B. STIG Findings", sty["h1"])]
    header = [
        Paragraph("<b>V-ID</b>", sty["small"]),
        Paragraph("<b>Rule ID (SV-rule)</b>", sty["small"]),
        Paragraph("<b>Rule Title</b>", sty["small"]),
        Paragraph("<b>Severity</b>", sty["small"]),
        Paragraph("<b>Status</b>", sty["small"]),
        Paragraph("<b>CCI refs</b>", sty["small"]),
    ]
    rows: list[list] = [header]
    for f in sorted(data.stig_findings, key=lambda x: (x.severity or "z", x.rule_id or "")):
        # Build the V-ID + SV-rule citation using the shared helper so the
        # format is consistent with what the POAM and evidence bundle emit.
        # Pass the rule_id as the evidence_label fallback so every row has
        # a non-empty first cell even when group_id is None (Nessus).
        citation_label = f.rule_id or "—"
        vid_cell = f.group_id or "—"
        sv_cell = f.rule_id or "—"
        rows.append([
            Paragraph(
                f"<font face='Courier' size='7'>{vid_cell}</font>",
                sty["small"],
            ),
            Paragraph(
                f"<font face='Courier' size='7'>{sv_cell}</font>",
                sty["small"],
            ),
            Paragraph(_truncate(f.rule_title or "—", 80), sty["small"]),
            Paragraph(f.severity or "—", sty["small"]),
            Paragraph(f.status.value if f.status else "—", sty["small"]),
            Paragraph(_truncate(f.cci_refs or "—", 120), sty["small"]),
        ])
    t = Table(
        rows,
        colWidths=[0.8 * inch, 1.6 * inch, 1.8 * inch, 0.8 * inch, 0.9 * inch, 2.1 * inch],
        repeatRows=1,
    )
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(t)
    return story


def _appendix_plan(data: _SarData, sty: dict) -> list:
    """Appendix C — Assessment plan (the full list of in-scope CCIs)."""
    story: list = [Paragraph("Appendix C. Assessment Plan", sty["h1"])]
    if not data.rows:
        story.append(
            Paragraph(
                "No CCIs were in scope (or none had a recorded status).",
                sty["small"],
            )
        )
        return story
    story.append(
        Paragraph(
            f"The full set of {len(data.rows)} CCIs covered by this assessment, "
            "ordered by control. CCIs without a recorded status are excluded.",
            sty["small"],
        )
    )
    story.append(Spacer(1, 0.08 * inch))

    header = [
        Paragraph("<b>Control</b>", sty["small"]),
        Paragraph("<b>CCI / AP</b>", sty["small"]),
        Paragraph("<b>Status</b>", sty["small"]),
        Paragraph("<b>Tester</b>", sty["small"]),
        Paragraph("<b>Date</b>", sty["small"]),
    ]
    rows: list[list] = [header]
    status_row_idx: dict[int, ComplianceStatus] = {}
    sorted_rows = sorted(data.rows, key=lambda r: (r.control_id, r.cci_id))
    for i, r in enumerate(sorted_rows, start=1):
        rows.append([
            Paragraph(f"<b>{r.control_id}</b>", sty["small"]),
            Paragraph(
                f"<font face='Courier' size='7'>{r.cci_id or '—'}</font>",
                sty["small"],
            ),
            Paragraph(r.status.value, sty["small"]),
            Paragraph(_xml(r.tester) or "—", sty["small"]),
            Paragraph(
                r.date_tested.strftime("%Y-%m-%d") if r.date_tested else "—",
                sty["small"],
            ),
        ])
        status_row_idx[i] = r.status

    t = Table(
        rows,
        colWidths=[1.1 * inch, 1.6 * inch, 1.2 * inch, 1.7 * inch, 0.95 * inch],
        repeatRows=1,
    )
    style_cmds: list = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for ri, st in status_row_idx.items():
        style_cmds.append(("BACKGROUND", (2, ri), (2, ri), _STATUS_FILL[st]))
    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    return story


def _appendix_overlays(data: _SarData, sty: dict) -> list:
    """Appendix — Reference overlay membership (FedRAMP / Li-SaaS / etc.).

    For each attached overlay we render:

    * counts: in primary AND overlay (covered) / primary-only (overlay-gap) /
      overlay-only (out-of-scope but required elsewhere) / overlay-unmentioned
    * a per-control gap detail table for the first two non-trivial categories

    This is the "everywhere" the user asked for in the SAR — the Controls
    page handles live UI; this gives the AO a paper trail.
    """
    if not data.overlays:
        return []

    story: list = [
        Paragraph("Appendix E. Reference Overlay Membership", sty["h1"]),
        Paragraph(
            f"This system is assessed against the primary baseline above. "
            f"The {len(data.overlays)} reference overlay"
            f"{'s' if len(data.overlays) != 1 else ''} below "
            "annotate the same controls — they identify where the primary "
            "scope overlaps with, exceeds, or falls short of another "
            "compliance regime (e.g., FedRAMP Moderate). Overlays are "
            "informational; they do not drive Compliant / Non-Compliant "
            "rollups in §6.",
            sty["small"],
        ),
        Spacer(1, 0.1 * inch),
    ]

    primary_in = {pk for pk, in_scope in data.primary_membership.items() if in_scope}
    primary_known = set(data.primary_membership.keys())

    for ov in data.overlays:
        if ov.id is None:
            continue
        mem = data.overlay_membership.get(ov.id, {})
        overlay_in = {pk for pk, in_scope in mem.items() if in_scope}
        overlay_out = {pk for pk, in_scope in mem.items() if not in_scope}

        covered = primary_in & overlay_in
        primary_only = primary_in - overlay_in - overlay_out  # unmentioned by overlay
        primary_in_overlay_out = primary_in & overlay_out
        overlay_only = overlay_in - primary_in

        story.append(
            Paragraph(
                f"{_xml(ov.name)} "
                f"<font color='#64748b' size='9'>({ov.source_type.value})</font>",
                sty["h2"],
            )
        )

        counts_rows = [
            ["Both in primary scope AND required by overlay", str(len(covered))],
            ["In primary scope, overlay does not list",       str(len(primary_only))],
            ["In primary scope, overlay tailors OUT",          str(len(primary_in_overlay_out))],
            ["Required by overlay, NOT in primary scope",      str(len(overlay_only))],
        ]
        t = Table(counts_rows, colWidths=[4.6 * inch, 0.8 * inch])
        t.setStyle(
            TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("FONTNAME", (1, 0), (1, -1), "Courier"),
                # Highlight overlay-only (the gap the AO most likely cares about)
                ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#fef3c7")
                    if overlay_only else colors.white),
            ])
        )
        story.append(t)

        # Gap callout — controls required by overlay but not in primary scope.
        if overlay_only:
            sample = sorted(overlay_only)[:20]
            sample_labels = ", ".join(sample)
            more = (
                f" (+{len(overlay_only) - len(sample)} more)"
                if len(overlay_only) > len(sample)
                else ""
            )
            story.append(Spacer(1, 0.05 * inch))
            story.append(
                Paragraph(
                    f"<b>Overlay-only controls (gap):</b> "
                    f"<font face='Courier' size='8'>{sample_labels}</font>"
                    f"{more}",
                    sty["small"],
                )
            )

        # Unknown — overlay references a control the primary baseline has no
        # row for. Worth flagging because it usually means the workbook was
        # opened against a framework that doesn't fully cover the overlay.
        unknown_to_primary = (overlay_in | overlay_out) - primary_known
        if unknown_to_primary:
            story.append(
                Paragraph(
                    f"<i>Note:</i> {len(unknown_to_primary)} control"
                    f"{'s' if len(unknown_to_primary) != 1 else ''} listed by "
                    "this overlay are not present in the primary baseline — "
                    "verify the workbook framework matches the overlay's "
                    "framework.",
                    sty["small"],
                )
            )

        story.append(Spacer(1, 0.18 * inch))

    return story


# Severity palette for the Appendix G short-circuit table — mirrors the
# React banner colors so an AO who's seen the UI immediately recognizes
# the bucket. info / warn / alert match CrmSuspicionReport.severity at
# engine/crm_sanity.py:154-161.
_SUSPICION_BUCKET_COLOR: dict[str, str] = {
    "info": "#16a34a",
    "warn": "#ca8a04",
    "alert": "#dc2626",
}


def _suspicion_bucket(overall: float) -> str:
    """Map ``CrmSuspicionLog.overall_suspicion`` to its severity bucket.

    Bucket boundaries are sourced from ``engine.crm_sanity`` so the SAR
    matches the CrmSuspicionReport.severity property exactly — no second
    threshold table to drift.
    """
    if overall < OVERALL_INFO_MAX:
        return "info"
    if overall < OVERALL_WARN_MAX:
        return "warn"
    return "alert"


# Display labels + ordering for CRM responsibility buckets. Provider /
# inherited / not_applicable run first because those short-circuit the LLM —
# the AO should see what was *inherited* (and from whom) before scrolling
# to the shared/local rows that got a full assessment.
_CRM_BUCKETS_ORDERED: list[tuple[str, str, str]] = [
    ("provider", "Provider-Owned",
     "Inherited from the service provider. The customer assessment did not "
     "evaluate these controls — the responsibility lives upstream."),
    ("inherited", "Inherited from Authorizing System",
     "Inherited from a parent or authorizing system. Recorded as Compliant "
     "by inheritance; the upstream ATO carries the implementation evidence."),
    ("not_applicable", "Not Applicable per CRM",
     "Marked Not Applicable by the CSP — typically because the control "
     "category does not apply to the service model."),
    ("hybrid", "Shared / Hybrid Responsibility",
     "Implementation is shared. The provider operates one half; the customer "
     "configures the other. Full assessment runs against the customer half; "
     "the CRM narrative below scopes what that half was."),
    ("customer", "Customer-Owned (CRM-Confirmed)",
     "Explicitly assigned to the customer in the CRM. Same assessment path as "
     "a control with no CRM row — listed here only when the CRM included a "
     "narrative worth preserving for the audit trail."),
]


def _appendix_crm_responsibilities(data: _SarData, sty: dict) -> list:
    """Appendix — CRM (Customer Responsibility Matrix) assignments.

    Groups every CRM-tagged control by responsibility bucket. Renders the
    CRM-supplied customer narrative verbatim when present so the AO can see
    what the CSP told us about each control. Skips the ``customer`` bucket
    entries that have no narrative — those are no-ops indistinguishable from
    a control with no CRM row, and listing them would just add noise.

    Reuses the tailored-out table style from §3 for visual consistency.
    """
    if not data.crm_by_responsibility:
        return []

    # Drop empty/no-op customer-without-narrative entries up front so we can
    # decide whether the appendix has anything to show.
    filtered: dict[str, list[tuple[str, str | None, str]]] = {}
    for bucket, entries in data.crm_by_responsibility.items():
        if bucket == "customer":
            kept = [(cid, narr, src) for (cid, narr, src) in entries if narr]
            if kept:
                filtered[bucket] = kept
        else:
            if entries:
                filtered[bucket] = entries
    if not filtered:
        return []

    total = sum(len(v) for v in filtered.values())
    story: list = [
        Paragraph("Appendix F. CRM Responsibility Assignments", sty["h1"]),
        Paragraph(
            f"This system has {total} control"
            f"{'s' if total != 1 else ''} with explicit responsibility "
            "assignments drawn from one or more attached Customer "
            "Responsibility Matrix (CRM) overlays. This table reflects the "
            "CRM's declared responsibility scope at attach time. For the "
            "runtime ledger of which CCIs were actually skipped because of "
            "this declaration, see Appendix G.",
            sty["small"],
        ),
        Spacer(1, 0.1 * inch),
    ]

    for bucket_key, bucket_label, bucket_blurb in _CRM_BUCKETS_ORDERED:
        entries = filtered.get(bucket_key)
        if not entries:
            continue
        story.append(
            Paragraph(
                f"{bucket_label} "
                f"<font color='#64748b' size='9'>({len(entries)})</font>",
                sty["h2"],
            )
        )
        story.append(Paragraph(bucket_blurb, sty["small"]))
        story.append(Spacer(1, 0.05 * inch))

        tdata: list[list] = [
            [
                Paragraph("<b>Control</b>", sty["small"]),
                Paragraph("<b>Customer responsibility narrative</b>", sty["small"]),
                Paragraph("<b>CRM source</b>", sty["small"]),
            ]
        ]
        for ctl_id, narrative, source_name in entries:
            tdata.append([
                Paragraph(f"<b>{ctl_id}</b>", sty["small"]),
                Paragraph(
                    _truncate(narrative, 360) if narrative else "<i>—</i>",
                    sty["small"],
                ),
                Paragraph(_truncate(source_name, 80), sty["small"]),
            ])
        ttbl = Table(
            tdata,
            colWidths=[1.0 * inch, 4.5 * inch, 1.5 * inch],
            repeatRows=1,
        )
        ttbl.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#f8fafc")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(ttbl)
        story.append(Spacer(1, 0.18 * inch))

    return story


def _appendix_crm_short_circuits(data: _SarData, sty: dict) -> list:
    """Appendix G — CRM short-circuit runtime events.

    The companion to Appendix F. F shows what the CRM *declared*; G shows
    what the assessment loop actually *did* because of that declaration.
    A control listed in F but missing here means no CCI in that control
    was assessed against the active CRM — the declaration sat unused.

    Each row pins responsibility (provider / inherited / not_applicable —
    the three short-circuit buckets; customer/hybrid never reach this
    table because they don't short-circuit), the CrmSuspicionLog severity
    bucket + raw score that was latest at decision time, and the wall
    clock. Rows are grouped by control_id ascending, then by
    created_at descending within each control so the most-recent event
    for a control surfaces first.
    """
    if not data.crm_short_circuit_events:
        return []

    # In-memory regroup: the SQL ordered desc by created_at globally, but
    # we want control_id asc + created_at desc within each control. A
    # stable sort on a list already in created_at-desc order yields the
    # desired secondary ordering for free.
    grouped: dict[str, list[tuple[str, str, str | None, float | None, datetime]]] = (
        defaultdict(list)
    )
    for ev in data.crm_short_circuit_events:
        grouped[ev[0]].append(ev)
    ordered_control_ids = sorted(grouped.keys())

    total = len(data.crm_short_circuit_events)
    story: list = [
        Paragraph("Appendix G. CRM Short-Circuit Events", sty["h1"]),
        Paragraph(
            f"Runtime ledger of the {total} CCI assessment"
            f"{'s' if total != 1 else ''} the engine short-circuited because "
            "an attached CRM declared the control provider / inherited / "
            "not-applicable. Distinct from Appendix F: F is the CRM's "
            "<i>declared</i> responsibility scope at attach time; G is what "
            "the assessment loop <i>actually</i> skipped because of that "
            "declaration. A control listed in F but missing here means no "
            "CCI in that control was assessed against the active CRM. The "
            "<b>Suspicion at decision time</b> column shows the CRM "
            "suspicion bucket and raw score that were latest when each "
            "event fired — an em-dash means no suspicion score had been "
            "computed yet.",
            sty["small"],
        ),
        Spacer(1, 0.1 * inch),
    ]

    tdata: list[list] = [
        [
            Paragraph("<b>Control</b>", sty["small"]),
            Paragraph("<b>Responsibility</b>", sty["small"]),
            Paragraph("<b>Suspicion at decision time</b>", sty["small"]),
            Paragraph("<b>When</b>", sty["small"]),
        ]
    ]
    for ctl_id in ordered_control_ids:
        for _, responsibility, severity, score, created_at in grouped[ctl_id]:
            if severity is None or score is None:
                suspicion_cell = Paragraph("—", sty["small"])
            else:
                color = _SUSPICION_BUCKET_COLOR.get(severity, "#0f172a")
                suspicion_cell = Paragraph(
                    f"<font color='{color}'><b>{severity}</b></font> "
                    f"({score:.2f})",
                    sty["small"],
                )
            tdata.append([
                Paragraph(f"<b>{ctl_id}</b>", sty["small"]),
                Paragraph(_xml(responsibility), sty["small"]),
                suspicion_cell,
                Paragraph(
                    created_at.strftime("%Y-%m-%d %H:%M UTC"),
                    sty["small"],
                ),
            ])

    ttbl = Table(
        tdata,
        colWidths=[1.0 * inch, 1.4 * inch, 2.4 * inch, 2.2 * inch],
        repeatRows=1,
    )
    ttbl.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f8fafc")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(ttbl)
    story.append(Spacer(1, 0.18 * inch))

    return story


def _appendix_odp_value_history(data: _SarData, sty: dict) -> list:
    """Appendix H — ODP value-history ledger.

    The defensible answer to "what did this ODP say when you decided
    Compliant?" months later, after a workbook has been regenerated.
    Every row is one overwrite recorded by the workbook ingest path
    (``ccis_workbook.apply``) — the placeholder token, the channel that
    overwrote it (``who``, e.g. ``CCIS-workbook-ingest:<filename>``),
    the UTC wall clock, and the value diff.

    Rows are grouped by control_id ascending, then by odp_id within
    each control, then by ``when`` descending so the most-recent
    overwrite for each ODP surfaces first. Controls/ODPs that were
    ingested once and never re-overwritten do not appear — the empty
    case is the common one (first-ingest workbooks) and a present-but-
    empty appendix would falsely imply missing audit data.
    """
    if not data.odp_audit_events:
        return []

    # Two-level regroup: control_id -> odp_id -> [events]. The SQL came
    # back ordered by control_id asc and when desc, so within each
    # (control, odp) bucket the events are already in the desired
    # most-recent-first order.
    by_control: dict[str, dict[str, list[tuple[str, str, str, str, str, str, datetime]]]] = (
        defaultdict(lambda: defaultdict(list))
    )
    for ev in data.odp_audit_events:
        by_control[ev[0]][ev[1]].append(ev)

    ordered_control_ids = sorted(by_control.keys())
    total_events = len(data.odp_audit_events)
    distinct_odps = sum(len(odps) for odps in by_control.values())

    story: list = [
        Paragraph("Appendix H. ODP Value History", sty["h1"]),
        Paragraph(
            f"Append-only audit trail of every Organization-Defined "
            f"Parameter (ODP) value overwrite recorded during this "
            f"assessment — {total_events} change"
            f"{'s' if total_events != 1 else ''} across "
            f"{distinct_odps} distinct ODP"
            f"{'s' if distinct_odps != 1 else ''} in "
            f"{len(ordered_control_ids)} control"
            f"{'s' if len(ordered_control_ids) != 1 else ''}. Each row "
            "pairs the placeholder token, the ingest channel "
            "(<b>Who</b>) that overwrote it, and the UTC timestamp. "
            "Controls and ODPs that were ingested once and never "
            "re-overwritten do not appear — the absence of a row is "
            "not the absence of a value, it is the absence of a "
            "change. This is the defensible answer to <i>\"what did "
            "this ODP say at the moment the assessor made its "
            "verdict?\"</i> after a workbook has been regenerated.",
            sty["small"],
        ),
        Spacer(1, 0.1 * inch),
    ]

    tdata: list[list] = [
        [
            Paragraph("<b>Control</b>", sty["small"]),
            Paragraph("<b>ODP</b>", sty["small"]),
            Paragraph("<b>When (UTC)</b>", sty["small"]),
            Paragraph("<b>Who</b>", sty["small"]),
            Paragraph("<b>Was → Is</b>", sty["small"]),
        ]
    ]
    for ctl_id in ordered_control_ids:
        ordered_odp_ids = sorted(by_control[ctl_id].keys())
        for odp_id in ordered_odp_ids:
            for _, _, _assigned_from, prev_value, new_value, who, when in (
                by_control[ctl_id][odp_id]
            ):
                prev_cell = _xml(prev_value) if prev_value else "<i>∅</i>"
                new_cell = _xml(new_value) if new_value else "<i>∅</i>"
                tdata.append([
                    Paragraph(f"<b>{ctl_id}</b>", sty["small"]),
                    Paragraph(f"<font face='Courier'>{odp_id}</font>", sty["small"]),
                    Paragraph(when.strftime("%Y-%m-%d %H:%M UTC"), sty["small"]),
                    Paragraph(f"<font face='Courier'>{_xml(who)}</font>", sty["small"]),
                    Paragraph(f"{prev_cell} → {new_cell}", sty["small"]),
                ])

    ttbl = Table(
        tdata,
        colWidths=[0.8 * inch, 1.1 * inch, 1.2 * inch, 1.9 * inch, 2.0 * inch],
        repeatRows=1,
    )
    ttbl.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f8fafc")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(ttbl)
    story.append(Spacer(1, 0.18 * inch))

    return story


def _appendix_narratives(data: _SarData, sty: dict) -> list:
    """Appendix D — Per-objective narratives for every Non-Compliant CCI.

    Compliant narratives stay in the compliance report; the SAR keeps the
    appendix focused on what the AO needs to act on.
    """
    nc_rows = [r for r in data.rows if r.status == ComplianceStatus.NON_COMPLIANT]
    if not nc_rows:
        return []

    story: list = [Paragraph("Appendix D. Non-Compliant Objective Narratives", sty["h1"])]
    story.append(
        Paragraph(
            f"Full assessor narratives for each of the {len(nc_rows)} Non-Compliant "
            "objectives in the assessment. Cross-reference with §5 findings.",
            sty["small"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    nc_rows.sort(key=lambda r: (r.control_id, r.cci_id))
    for r in nc_rows:
        finding = (
            data.objective_finding_ref.get(r.objective_pk, "—")
            if r.objective_pk is not None
            else "—"
        )
        block: list = [
            Paragraph(
                f"<b>{r.control_id}</b> · "
                f"<font face='Courier' size='8'>{r.cci_id or '—'}</font> · "
                f"Finding {_xml(finding)}",
                sty["h2"],
            ),
            Paragraph(
                _xml(r.narrative) or "<i>No narrative recorded.</i>",
                sty["body"],
            ),
            Spacer(1, 0.1 * inch),
        ]
        story.append(KeepTogether(block))

    return story


def _appendix_evidence_disposition(data: _SarData, sty: dict) -> list:
    """Appendix I — Evidence disposition audit (examined vs. deferred).

    The whole point of the token-budget ranker is that *nothing is silently
    dropped*: every tagged artifact is recorded as either ``examined`` (shown
    to the model) or ``deferred`` (held back under the token budget, NOT shown).
    This appendix is the human-readable proof of that promise.

    It is deliberately a *summary* — one row per (control, CCI) aggregating how
    many artifacts were examined vs. deferred and why. The exhaustive
    row-by-row trail (one line per artifact) lives in the companion transparency
    CSV (``build_evidence_disposition_csv`` → ``…/evidence-disposition.csv``),
    which an Excel reviewer can AutoFilter to answer "what did you examine for
    AC-2, and what didn't you?".

    Skip entirely when there were no deferrals: if every artifact the model was
    handed was examined, Appendix A already enumerates them and a second
    "nothing was held back" table is noise. The appendix exists to make
    *deferral* traceable; absent deferral there is nothing to disclose here.
    """
    if not data.evidence_dispositions:
        return []

    deferred_total = sum(
        1
        for d in data.evidence_dispositions
        if d.disposition == DISPOSITION_DEFERRED
    )
    if deferred_total == 0:
        return []

    # Aggregate per (control, CCI): counts + the distinct deferral reasons.
    @dataclass
    class _Agg:
        examined: int = 0
        deferred: int = 0
        reasons: set = field(default_factory=set)

    by_cci: dict[tuple[str, str], _Agg] = {}
    for d in data.evidence_dispositions:
        key = (d.control_id, d.cci_id)
        agg = by_cci.setdefault(key, _Agg())
        if d.disposition == DISPOSITION_DEFERRED:
            agg.deferred += 1
            if d.deferred_reason:
                agg.reasons.add(d.deferred_reason)
        else:
            agg.examined += 1

    affected = sum(1 for agg in by_cci.values() if agg.deferred > 0)
    examined_total = sum(
        1
        for d in data.evidence_dispositions
        if d.disposition == DISPOSITION_EXAMINED
    )

    story: list = [
        Paragraph("Appendix I. Evidence Disposition Audit", sty["h1"]),
        Paragraph(
            f"The assessor admits tagged evidence to the model under a token "
            f"budget rather than a fixed artifact cap — so for high-evidence "
            f"controls some artifacts are <b>deferred</b> (recorded but not "
            f"shown to the model) rather than silently discarded. Across this "
            f"assessment <b>{examined_total}</b> artifact"
            f"{'s were' if examined_total != 1 else ' was'} examined and "
            f"<b>{deferred_total}</b> "
            f"{'were' if deferred_total != 1 else 'was'} deferred, affecting "
            f"<b>{affected}</b> objective{'s' if affected != 1 else ''}. Every "
            "deferred artifact remains fully traceable: the row-by-row trail "
            "(one line per artifact, examined and deferred) is available as the "
            "companion <font face='Courier' size='8'>evidence-disposition.csv</font> "
            "export. Objectives with no deferrals are omitted here — their "
            "evidence is enumerated in Appendix A.",
            sty["small"],
        ),
        Spacer(1, 0.1 * inch),
    ]

    header = [
        Paragraph("<b>Control</b>", sty["small"]),
        Paragraph("<b>CCI / AP</b>", sty["small"]),
        Paragraph("<b>Examined</b>", sty["small"]),
        Paragraph("<b>Deferred</b>", sty["small"]),
        Paragraph("<b>Deferral reason(s)</b>", sty["small"]),
    ]
    rows: list[list] = [header]
    for (ctl, cci), agg in sorted(
        by_cci.items(), key=lambda kv: (-kv[1].deferred, kv[0][0], kv[0][1])
    ):
        if agg.deferred == 0:
            continue
        reason_text = ", ".join(sorted(agg.reasons)) if agg.reasons else "—"
        rows.append([
            Paragraph(f"<b>{ctl or '—'}</b>", sty["small"]),
            Paragraph(
                f"<font face='Courier' size='7'>{cci or '—'}</font>",
                sty["small"],
            ),
            Paragraph(str(agg.examined), sty["small"]),
            Paragraph(str(agg.deferred), sty["small"]),
            Paragraph(_truncate(reason_text, 120), sty["small"]),
        ])

    t = Table(
        rows,
        colWidths=[1.1 * inch, 1.3 * inch, 0.9 * inch, 0.9 * inch, 2.8 * inch],
        repeatRows=1,
    )
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f8fafc")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(t)
    return story


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_sar_report(session: Session, workbook_id: int) -> bytes:
    """Render a NIST SP 800-53A Security Assessment Report PDF.

    Raises ValueError if the workbook can't be located. Raises ImportError if
    reportlab is missing (caller maps to HTTP 503).
    """
    data = _gather(session, workbook_id)
    sty = _styles()

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
        title=f"Security Assessment Report — {data.workbook.filename}",
        author="CCIS Assessor",
    )

    story: list = []
    story.extend(_section_cover(data, sty))
    story.append(PageBreak())
    story.extend(_section_executive_summary(data, sty))
    story.append(PageBreak())
    story.extend(_section_scope(data, sty))
    story.append(PageBreak())
    story.extend(_section_methodology(data, sty))
    story.append(PageBreak())
    story.extend(_section_results(data, sty))
    story.append(PageBreak())
    story.extend(_section_findings(data, sty))
    story.append(PageBreak())
    story.extend(_section_recommendations(data, sty))
    story.append(PageBreak())
    story.extend(_appendix_evidence(data, sty))
    stig = _appendix_stig(data, sty)
    if stig:
        story.append(PageBreak())
        story.extend(stig)
    story.append(PageBreak())
    story.extend(_appendix_plan(data, sty))
    overlays = _appendix_overlays(data, sty)
    if overlays:
        story.append(PageBreak())
        story.extend(overlays)
    crm = _appendix_crm_responsibilities(data, sty)
    if crm:
        story.append(PageBreak())
        story.extend(crm)
    crm_events = _appendix_crm_short_circuits(data, sty)
    if crm_events:
        story.append(PageBreak())
        story.extend(crm_events)
    odp_history = _appendix_odp_value_history(data, sty)
    if odp_history:
        story.append(PageBreak())
        story.extend(odp_history)
    narratives = _appendix_narratives(data, sty)
    if narratives:
        story.append(PageBreak())
        story.extend(narratives)
    disposition = _appendix_evidence_disposition(data, sty)
    if disposition:
        story.append(PageBreak())
        story.extend(disposition)

    sys_name = data.system.name if data.system else data.workbook.filename

    def _footer(canvas, doc_):  # noqa: ANN001
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(
            doc_.leftMargin,
            0.4 * inch,
            f"Security Assessment Report — {sys_name} — CUI",
        )
        canvas.drawRightString(
            LETTER[0] - doc_.rightMargin,
            0.4 * inch,
            f"Page {canvas.getPageNumber()}",
        )
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def build_evidence_disposition_csv(session: Session, workbook_id: int) -> str:
    """Render the full evidence-disposition audit trail as CSV text.

    This is the exhaustive companion to SAR Appendix I: one row per
    ``AssessmentEvidenceShown`` record — *examined and deferred alike* — so a
    3PAO/JAB reviewer can open it in Excel, AutoFilter on any value, and prove
    that nothing the assessor was handed went unrecorded. The token-budget
    ranker partitions tagged evidence into examined/deferred but never drops;
    this export is where "anything not examined must be traceable" becomes a
    file someone can audit.

    Row-explode convention (feedback_csv_export_row_explode): one CSV row per
    artifact-disposition pair, never packed cells, so a filter for a single
    evidence title or CCI always resolves. Rows are ordered by control, then
    CCI, then the order_index the ranker assigned (admission ordering), so
    examined artifacts sort ahead of the deferred ones within an objective.

    Raises ValueError if the workbook can't be located (via ``_gather``).
    """
    data = _gather(session, workbook_id)

    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Control",
        "CCI",
        "Evidence Title",
        "Doc #",
        "Chunk SHA-256",
        "Order",
        "Disposition",
        "Rank Score",
        "Deferred Reason",
    ])
    for d in sorted(
        data.evidence_dispositions,
        key=lambda x: (x.control_id, x.cci_id, x.order_index),
    ):
        writer.writerow([
            d.control_id,
            d.cci_id,
            d.evidence_title,
            d.doc_number,
            d.chunk_sha,
            d.order_index,
            d.disposition,
            "" if d.rank_score is None else f"{d.rank_score:.4f}",
            d.deferred_reason or "",
        ])
    return buf.getvalue()
