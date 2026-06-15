"""SystemContext adapters.

A :class:`SystemContextSource` parses (or extracts from) a seed artifact
— freeform markdown, eMASS SSP xlsx, docx narrative, OSCAL SSP JSON —
and writes a :class:`SystemContext` row whose ``extracted_tokens`` feed
the boundary-aware sweep fingerprint.

Adapters are the only code that knows about source-specific formats.
The rest of the app (sweep, UI, fingerprint) reads only ``SystemContext``,
so adding a new context source format means writing a new adapter — not
editing the sweep engine.
"""

from .base import SystemContextApplyResult, SystemContextSource, get_source_for_type
from .brief import build_boundary_brief, format_boundary_brief
from .freeform import FreeformContextSource

__all__ = [
    "FreeformContextSource",
    "SystemContextApplyResult",
    "SystemContextSource",
    "build_boundary_brief",
    "format_boundary_brief",
    "get_source_for_type",
]
