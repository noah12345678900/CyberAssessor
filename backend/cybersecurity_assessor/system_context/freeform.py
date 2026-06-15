"""Tier 1 freeform-markdown adapter — the floor adapter.

Input: four markdown blobs (boundary / stakeholders / tech_inventory /
requirement_hints) typed into the UI by the assessor. Output: a
:class:`SystemContext` row with ``extracted_tokens`` populated by the LLM.

Failure mode: if LLM extraction raises or returns no tokens, the
SystemContext is still saved (so the freeform text isn't lost); confidence
drops to 0.2 and ``notes['extraction_error']`` is populated. The assessor
can manually paste tokens into the form on retry.

Why save even on extraction failure: losing the assessor's freeform
narrative on a transient API error is a much worse UX than saving with
low confidence — the route surface a toast about the error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlmodel import Session, select

from ..llm.extractor import LlmExtractorClient
from ..models import SystemContext, SystemContextSourceType
from .base import SystemContextApplyResult


_EXTRACTION_PROMPT = """\
You are helping a NIST 800-53 assessor build a system fingerprint. Read
the four sections below and emit a JSON object with these fields:

  tokens: list of short identifiers (hostnames, service names, environment
          labels, vendor product names, acronyms). Keep them lowercase.
          Strip punctuation. Skip generic words ("system", "service",
          "the", "a", "data", "user", "users", "application").
  confidence: float 0.0-1.0 estimating how concrete the inputs are.
              0.9 = lots of named hosts/products; 0.3 = mostly prose.

## boundary
{boundary}

## stakeholders
{stakeholders}

## tech_inventory
{tech_inventory}

## requirement_hints
{requirement_hints}

Return ONLY the JSON object. No prose.
"""


# Lightweight normalizer: lowercase, strip outer punctuation, collapse
# whitespace runs. The LLM is asked to do this, but defense in depth
# costs nothing.
_PUNCT_RE = re.compile(r"^[^\w]+|[^\w]+$")


def _normalize_token(t: str) -> str:
    t = (t or "").strip().lower()
    t = _PUNCT_RE.sub("", t)
    return t


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class FreeformContextSource:
    """Tier 1 adapter — markdown blobs in, JSON tokens out via LLM."""

    source_type: SystemContextSourceType = field(
        default=SystemContextSourceType.FREEFORM_MARKDOWN
    )

    def apply(
        self,
        session: Session,
        *,
        workbook_id: int | None,
        extractor: LlmExtractorClient,
        boundary: str | None = None,
        stakeholders: str | None = None,
        tech_inventory: str | None = None,
        requirement_hints: str | None = None,
        **_: object,  # tolerate future kwargs from the route
    ) -> SystemContextApplyResult:
        prompt = _EXTRACTION_PROMPT.format(
            boundary=boundary or "",
            stakeholders=stakeholders or "",
            tech_inventory=tech_inventory or "",
            requirement_hints=requirement_hints or "",
        )
        tokens: list[str] = []
        confidence: float = 0.5
        notes: dict = {"adapter": "freeform"}
        try:
            result = extractor.extract_system_context(prompt)
            raw_tokens = result.get("tokens", []) or []
            tokens = [
                tok
                for tok in (_normalize_token(t) for t in raw_tokens if t)
                if tok  # drop empty after normalization
            ]
            # De-duplicate while preserving order.
            seen: set[str] = set()
            tokens = [t for t in tokens if not (t in seen or seen.add(t))]
            confidence = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
        except Exception as exc:  # noqa: BLE001 — degrade gracefully
            confidence = 0.2
            notes["extraction_error"] = str(exc)

        ctx = self._upsert(
            session,
            workbook_id,
            boundary=boundary,
            stakeholders=stakeholders,
            tech_inventory=tech_inventory,
            requirement_hints=requirement_hints,
            tokens=tokens,
            confidence=confidence,
        )
        session.commit()
        session.refresh(ctx)
        return SystemContextApplyResult(
            context=ctx,
            tokens_extracted=len(tokens),
            confidence=confidence,
            notes=notes,
        )

    # ------------------------------------------------------------------

    def _upsert(
        self,
        session: Session,
        workbook_id: int | None,
        *,
        boundary: str | None,
        stakeholders: str | None,
        tech_inventory: str | None,
        requirement_hints: str | None,
        tokens: list[str],
        confidence: float,
    ) -> SystemContext:
        # NULL doesn't match `==` in SQL — branch on the pending case so the
        # singleton pending row (workbook_id IS NULL) is found on subsequent
        # POSTs and updated in-place instead of triggering a UNIQUE collision
        # against `ix_systemcontext_pending_singleton`.
        if workbook_id is None:
            existing = session.exec(
                select(SystemContext).where(SystemContext.workbook_id.is_(None))
            ).first()
        else:
            existing = session.exec(
                select(SystemContext).where(SystemContext.workbook_id == workbook_id)
            ).first()
        if existing:
            existing.boundary = boundary
            existing.stakeholders = stakeholders
            existing.tech_inventory = tech_inventory
            existing.requirement_hints = requirement_hints
            existing.extracted_tokens = tokens
            existing.confidence = confidence
            existing.source_type = SystemContextSourceType.FREEFORM_MARKDOWN
            existing.source_ref = "freeform"
            existing.updated_at = _utcnow()
            session.add(existing)
            return existing
        ctx = SystemContext(
            workbook_id=workbook_id,
            source_type=SystemContextSourceType.FREEFORM_MARKDOWN,
            source_ref="freeform",
            boundary=boundary,
            stakeholders=stakeholders,
            tech_inventory=tech_inventory,
            requirement_hints=requirement_hints,
            extracted_tokens=tokens,
            confidence=confidence,
        )
        session.add(ctx)
        return ctx
