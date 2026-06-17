"""Per-CCI input builder — the (CcisRow, EvidenceBlock) producer.

The assessor kernel (`engine.assessor.Assessor.assess`) is intentionally
session-free and operates per-CCI. Both the production batch route and
the eval CLI need to feed it the same triple — `(CcisRow,
EvidenceBlock, CrmContext)` — so the input-building primitives live here
in the engine layer, not in any single caller.

The CRM context is workbook-scoped, not per-CCI; callers build it once
via `engine.crm_context.build_crm_context` and reuse across every
`build_assessment_inputs(...)` call in the batch.

This module owns what used to be `routes.controls._build_evidence_block`
and `_is_coverage_control`. The route still imports them (re-exported
under their old underscore names) so prior behavior is unchanged.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from sqlmodel import Session

_log = logging.getLogger(__name__)

from ..excel.ccis_reader import CcisRow, read_workbook_index
from ..evidence.asset_crosscheck import (
    render_coverage_block,
    summarize_asset_coverage,
)
from .crm_context import CrmContext, build_crm_context
from .evidence_bundle import (
    AFFECTED_HOSTS_HEADER,
    CORROBORATING_FINDINGS_HEADER,
    EvidenceBlock,
    build_tagged_evidence_with_payload,
    has_nonscan_evidence,
)
from .evidence_ranker import OverflowDecision


# Asset-coverage-sensitive control families. The asset coverage report
# is appended to per-CCI evidence only for these families — every other
# control gets the bare tagged-evidence bundle. Matches the base control
# plus any enhancement (e.g. "CM-8", "CM-8(1)", "CM-8 (3)"); the
# word-boundary anchor prevents accidental matches against future
# families like CM-80.
_COVERAGE_CONTROL_RE = re.compile(r"^(CM-8|CM-6|CA-3|CA-7|PM-5|RA-5)(\b|\()")


def _is_coverage_control(control_id: str | None) -> bool:
    """Return True iff ``control_id`` is in the asset-coverage-sensitive set."""
    if not control_id:
        return False
    return bool(_COVERAGE_CONTROL_RE.match(control_id))


def build_evidence_block(
    *,
    objective_pk: int,
    control_id: str | None,
    workbook_id: int,
    s: Session,
) -> EvidenceBlock:
    """Compose the user-message evidence block for one CCI.

    Always tries to render the per-objective tagged-evidence bundle. For
    coverage-sensitive controls (CM-8 / CM-6 / CA-3 / CA-7 / PM-5 / RA-5)
    additionally appends the auto-derived asset coverage report so the
    LLM can flag boundary-completeness and scan-coverage gaps the CCIS
    row alone wouldn't surface. Concatenation order is fixed (evidence
    first, coverage second) so the cache prefix stays bit-identical
    across calls within the same family.

    Returns an ``EvidenceBlock`` envelope (not a bare string) so the
    assessor's no-evidence short-circuit (``Assessor.assess`` Step 1.65)
    can distinguish *retrieved artifacts* from *context wrappers*
    (coverage report, CRM hybrid prepend) without re-parsing the text.
    Coverage-only blocks have ``is_only_context=True`` so the rule fires
    and the LLM doesn't get a prompt that pretends a workbook-wide
    boilerplate report is per-objective evidence.
    """
    # ---- Per-source graceful degrade (Bug 11) ----------------------------
    # Each evidence source is wrapped in its own try/except so a failure
    # in ONE source (e.g. a corrupt extracted-text file, a DB join error
    # on the findings table) doesn't nuke the whole CCI from the batch.
    # Failed sources record a structured warning and continue — the CCI
    # still gets assessed with whatever evidence survived. If ALL sources
    # fail, the block comes back with text=None and has_artifacts=False,
    # so the assessor's no-evidence short-circuit (Step 1.65) fires and
    # the CCI either gets the deterministic no-evidence rule or flows
    # into the needs_review/abstain path. Warnings are threaded into the
    # EvidenceBlock so the route layer can surface them to the UI.
    source_warnings: list[str] = []

    # Source 1: tagged evidence bundle + audit payload + overflow verdict
    tagged: str | None = None
    evidence_payload: list = []
    overflow: OverflowDecision | None = None
    try:
        tagged, evidence_payload, overflow = build_tagged_evidence_with_payload(
            objective_pk, s, workbook_id=workbook_id
        )
    except Exception as exc:  # noqa: BLE001 — per-source degrade
        _log.warning(
            "evidence build: tagged_evidence for objective pk=%s raised %s: %s",
            objective_pk, type(exc).__name__, exc,
        )
        source_warnings.append(f"tagged_evidence: {type(exc).__name__}: {exc}")

    payload_tuple = tuple(evidence_payload)
    has_artifacts = tagged is not None
    # build_tagged_evidence emits the corroboration sub-section markers
    # as module-level constants — checking presence is structural, not a
    # free-form regex hunt. False positives are not a risk: the markers
    # are reserved producer output, not strings the artifact text could
    # plausibly contain.
    has_findings = has_artifacts and CORROBORATING_FINDINGS_HEADER in tagged  # type: ignore[operator]
    has_hosts = has_artifacts and AFFECTED_HOSTS_HEADER in tagged  # type: ignore[operator]

    # Source 2: nonscan-evidence corroboration signal
    has_nonscan = False
    try:
        has_nonscan = has_nonscan_evidence(objective_pk, s)
    except Exception as exc:  # noqa: BLE001 — per-source degrade
        _log.warning(
            "evidence build: has_nonscan_evidence for objective pk=%s raised %s: %s",
            objective_pk, type(exc).__name__, exc,
        )
        source_warnings.append(f"has_nonscan_evidence: {type(exc).__name__}: {exc}")

    if not _is_coverage_control(control_id):
        return EvidenceBlock(
            text=tagged,
            has_artifacts=has_artifacts,
            has_coverage=False,
            has_findings=has_findings,
            has_hosts=has_hosts,
            has_nonscan_artifact=has_nonscan,
            evidence_shown=payload_tuple,
            source_warnings=tuple(source_warnings),
            overflow=overflow,
        )

    # Source 3: asset coverage report (coverage-sensitive controls only)
    coverage: str | None = None
    try:
        report = summarize_asset_coverage(workbook_id, s)
        coverage = render_coverage_block(report)
    except Exception as exc:  # noqa: BLE001 — per-source degrade
        _log.warning(
            "evidence build: asset_coverage for workbook %s raised %s: %s",
            workbook_id, type(exc).__name__, exc,
        )
        source_warnings.append(f"asset_coverage: {type(exc).__name__}: {exc}")

    if coverage is None:
        return EvidenceBlock(
            text=tagged,
            has_artifacts=has_artifacts,
            has_coverage=False,
            has_findings=has_findings,
            has_hosts=has_hosts,
            has_nonscan_artifact=has_nonscan,
            evidence_shown=payload_tuple,
            source_warnings=tuple(source_warnings),
            overflow=overflow,
        )
    if tagged is None:
        # Coverage-only path: workbook-wide context with no per-objective
        # artifact text. is_only_context will be True because has_artifacts
        # / has_findings / has_hosts are all False — Step 1.65 fires.
        # evidence_shown is empty tuple (no per-objective artifacts).
        return EvidenceBlock(
            text=coverage,
            has_artifacts=False,
            has_coverage=True,
            has_findings=False,
            has_hosts=False,
            has_nonscan_artifact=has_nonscan,
            evidence_shown=(),
            source_warnings=tuple(source_warnings),
        )
    # Two distinct sections; blank line between them so the LLM treats
    # them as separate context blocks rather than one bag of text.
    return EvidenceBlock(
        text=f"{tagged}\n\n{coverage}",
        has_artifacts=has_artifacts,
        has_coverage=True,
        has_findings=has_findings,
        has_hosts=has_hosts,
        has_nonscan_artifact=has_nonscan,
        evidence_shown=payload_tuple,
        source_warnings=tuple(source_warnings),
        overflow=overflow,
    )


@dataclass(frozen=True)
class WorkbookInputs:
    """Workbook-scoped inputs shared across every CCI in a batch.

    Built ONCE per workbook (or per eval-CLI run). Each per-CCI call to
    ``build_assessment_inputs`` reuses this — the CRM lookup is a dict
    hit, and the workbook index is the only thing that holds CcisRows.
    """

    workbook_id: int
    workbook_path: Path
    cci_to_row: dict[str, CcisRow]
    crm_context: CrmContext


def build_workbook_inputs(
    workbook_id: int,
    workbook_path: str | Path,
    session: Session,
) -> WorkbookInputs:
    """Read workbook index + build CRM context. Call once per workbook."""
    wb_path = Path(workbook_path)
    index = read_workbook_index(wb_path)
    return WorkbookInputs(
        workbook_id=workbook_id,
        workbook_path=wb_path,
        cci_to_row=index.by_cci(),
        crm_context=build_crm_context(workbook_id, session),
    )


@dataclass(frozen=True)
class AssessmentInputs:
    """Per-CCI input triple fed to ``Assessor.assess``."""

    row: CcisRow
    evidence_block: EvidenceBlock
    crm_context: CrmContext


def build_assessment_inputs(
    *,
    workbook_inputs: WorkbookInputs,
    objective_pk: int,
    objective_cci_id: str,
    control_id: str | None,
    session: Session,
) -> AssessmentInputs | None:
    """Produce the (row, evidence, crm) triple for one objective.

    Returns ``None`` when the workbook no longer contains the CCI — the
    baseline still references it (soft-deleted or manually edited), so
    the caller should treat that case as "skip, not in workbook" rather
    than raise. Mirrors the route's ``cci_to_row.get(...) is None``
    branch at routes/controls.py around the batch evidence-build loop.
    """
    row = workbook_inputs.cci_to_row.get(objective_cci_id)
    if row is None:
        return None
    evidence_block = build_evidence_block(
        objective_pk=objective_pk,
        control_id=control_id,
        workbook_id=workbook_inputs.workbook_id,
        s=session,
    )
    return AssessmentInputs(
        row=row,
        evidence_block=evidence_block,
        crm_context=workbook_inputs.crm_context,
    )
