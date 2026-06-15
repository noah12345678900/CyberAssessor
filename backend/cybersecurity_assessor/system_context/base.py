"""Adapter Protocol for SystemContext sources.

Mirrors ``baselines/base.py``'s BaselineSource Protocol. Each adapter takes
a workbook id + LLM extractor and returns a populated SystemContext row.

The registry (``get_source_for_type``) is a thin dispatch table so new
adapters slot in with one branch — no schema change, no engine edit.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlmodel import Session

from ..llm.extractor import LlmExtractorClient
from ..models import SystemContext, SystemContextSourceType


@dataclass
class SystemContextApplyResult:
    """What an adapter returns after upserting a SystemContext row.

    ``notes`` is a free-form dict for adapter-specific telemetry — the
    freeform adapter stores ``extraction_error`` here when the LLM call
    fails so the route can surface it as a UI toast.
    """

    context: SystemContext
    tokens_extracted: int
    confidence: float
    notes: dict


class SystemContextSource:  # Protocol-shaped; concrete classes inherit for typing convenience
    """Adapter contract.

    Implementations must expose ``source_type`` (a SystemContextSourceType
    member) and ``apply(session, *, workbook_id, extractor, **kwargs)``.
    The freeform adapter accepts additional kwargs for its four markdown
    blobs; future adapters (eMASS SSP xlsx, OSCAL) will take a file path.
    """

    source_type: SystemContextSourceType

    def apply(
        self,
        session: Session,
        *,
        workbook_id: int,
        extractor: LlmExtractorClient,
        **kwargs,
    ) -> SystemContextApplyResult:
        raise NotImplementedError


def get_source_for_type(
    source_type: SystemContextSourceType,
    source_ref: str | None = None,  # noqa: ARG001 — reserved for file-based adapters
) -> SystemContextSource:
    """Dispatch table — one branch per Tier."""
    if source_type == SystemContextSourceType.FREEFORM_MARKDOWN:
        from .freeform import FreeformContextSource

        return FreeformContextSource()
    if source_type == SystemContextSourceType.DOCX_NARRATIVE:
        # Boundary-doc adapter — reads Evidence rows tagged is_boundary_doc.
        # No source_ref needed; the adapter scopes by workbook_id at apply().
        from .boundary_docs import BoundaryDocsContextSource

        return BoundaryDocsContextSource()
    # Roadmap slots — raise NotImplementedError until adapters land.
    raise NotImplementedError(
        f"SystemContext source {source_type!r} not yet implemented"
    )
