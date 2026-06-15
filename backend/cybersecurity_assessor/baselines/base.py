"""Baseline source protocol.

A :class:`BaselineSource` adapter turns *some* artifact into a
``Baseline`` + ``BaselineObjective`` set in the database. The artifact
might be a CCIS workbook, an OSCAL SSP, an ISO SoA spreadsheet, or
nothing at all (manual UI picks).

The Protocol intentionally exposes only ``apply`` — write-back of
assessment results is the job of a *separate* protocol (not all sources
round-trip; e.g. OSCAL profiles are read-only baselines). When we add
write-back in v0.2 it will live in a sibling ``BaselineWriter`` protocol
so read-only sources don't have to stub it out.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from sqlmodel import Session

from ..models import Baseline, BaselineSourceType


@dataclass
class BaselineApplyResult:
    """What an adapter's ``apply`` produced.

    ``baseline`` is the (possibly just-created, possibly refreshed) row.

    Scoping counts are at the Control/Enhancement level because that's
    where tailoring decisions live:
      - controls_in_scope: BaselineControl rows with in_scope=True
      - controls_out_of_scope: BaselineControl rows tailored out
      - controls_unknown: source mentioned control_ids the catalog does
        not have (workbook references a control not in the loaded rev)

    Objective counts are book-keeping for CCI-level metadata sync (each
    CCIS workbook row creates a BaselineObjective for source_row tracking),
    not a scoping signal:
      - objectives_seen: BaselineObjective rows added/updated
      - objectives_unknown: source mentioned CCIs the catalog lacks

    Adapter-specific detail goes in ``notes``.
    """

    baseline: Baseline
    controls_in_scope: int = 0
    controls_out_of_scope: int = 0
    controls_unknown: int = 0
    objectives_seen: int = 0
    objectives_unknown: int = 0
    notes: dict[str, object] | None = None


@runtime_checkable
class BaselineSource(Protocol):
    """Adapter contract.

    Implementations live in sibling modules (``ccis_workbook``,
    ``oscal_ssp``, ``manual``, ...) and are registered in
    :func:`get_source_for_type` so the routes layer can resolve a stored
    ``Baseline.source_type`` back to its adapter for refresh.
    """

    source_type: BaselineSourceType

    def apply(self, session: Session, *, framework_id: int) -> BaselineApplyResult:
        """Parse the source, upsert Baseline + BaselineObjective rows.

        Idempotent: running twice on the same source must converge — no
        duplicate Baselines, no orphan BaselineObjectives.
        """
        ...


# Registry — kept tiny on purpose. Adapters that take constructor args
# (like a file path) are usually created fresh by the route handler that
# owns the artifact; this map is for cases where we only know the
# stored ``source_type`` + ``source_ref`` and want to refresh.
def get_source_for_type(
    source_type: BaselineSourceType, *, source_ref: str | None
) -> BaselineSource:
    """Return an adapter instance for a stored Baseline."""
    if source_type == BaselineSourceType.CCIS_WORKBOOK:
        if not source_ref:
            raise ValueError("CCIS workbook baseline requires source_ref (workbook path)")
        from .ccis_workbook import CcisWorkbookBaselineSource

        return CcisWorkbookBaselineSource(workbook_path=source_ref)
    if source_type == BaselineSourceType.CRM:
        if not source_ref:
            raise ValueError("CRM baseline requires source_ref (xlsx path)")
        from .crm_xlsx import CrmXlsxBaselineSource

        return CrmXlsxBaselineSource(workbook_path=source_ref)
    if source_type == BaselineSourceType.OTHER:
        if not source_ref:
            raise ValueError("Other baseline requires source_ref (xlsx path)")
        from .other_xlsx import OtherXlsxBaselineSource

        return OtherXlsxBaselineSource(workbook_path=source_ref)
    raise NotImplementedError(f"No adapter registered for source_type={source_type}")
