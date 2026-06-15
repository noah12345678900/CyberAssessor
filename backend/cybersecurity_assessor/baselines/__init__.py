"""Baseline adapters.

A :class:`BaselineSource` parses a tailoring artifact (CCIS workbook,
OSCAL SSP, ISO SoA, manual UI picks, ...) and writes a :class:`Baseline`
+ per-objective :class:`BaselineObjective` rows that say which catalog
``Objective`` rows are in scope for one specific system.

Adapters are the *only* code that knows about source-specific formats.
The rest of the app (assessment, evidence, UI, reports) reads only
``Baseline`` and ``BaselineObjective``, so adding a new framework or
source format means writing a new adapter — not editing the engine.
"""

from .base import BaselineApplyResult, BaselineSource, get_source_for_type
from .ccis_workbook import CcisWorkbookBaselineSource
from .crm_xlsx import CrmXlsxBaselineSource

__all__ = [
    "BaselineApplyResult",
    "BaselineSource",
    "CcisWorkbookBaselineSource",
    "CrmXlsxBaselineSource",
    "get_source_for_type",
]
