"""Tier 2 boundary-docs adapter — extract sweep tokens from uploaded SSPs/diagrams.

Input: every :class:`Evidence` row attached to this workbook with
``is_boundary_doc=True``. Output: a :class:`SystemContext` row with
``extracted_tokens`` populated by feeding the docs' extracted text to the
LLM token extractor.

This is the replacement for the legacy four-prose-textarea flow — the
assessor already produces SSPs/SSPPs/ATO letters/network diagrams as part
of RMF steps 1-3, so retyping them as prose into the form was busywork.
Boundary docs ride the same Evidence pipeline (same extraction, same DB
row); this adapter only adds a "concatenate the text and extract" step.

Failure modes:
  - No boundary docs attached: returns a SystemContext with zero tokens
    and confidence=0.0. The route returns that and the UI tells the user
    to attach a doc first. No exception — empty is a valid intermediate
    state, not an error.
  - One or more docs have no extracted text (extraction failed at ingest):
    they're silently skipped. The notes dict records the skipped count
    so the route can surface a partial-success toast.
  - LLM extraction raises: same degrade-gracefully shape as freeform —
    save the row, drop confidence to 0.2, record ``extraction_error``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete as sa_delete
from sqlmodel import Session, select

from ..llm.extractor import LlmExtractorClient
from ..models import (
    BoundaryTokenSource,
    Evidence,
    SystemContext,
    SystemContextSourceType,
)
from .base import SystemContextApplyResult


# Per-doc text cap. SSPs can run hundreds of pages; we don't need the
# whole thing to fingerprint hostnames/products. 40k chars ~= 10k tokens
# per doc; with a typical 1-4 doc bundle we stay well inside the
# extractor's context budget.
_PER_DOC_CHAR_CAP = 40_000

_EXTRACTION_PROMPT = """\
You are a NIST 800-53 assessor extracting system-boundary identifiers from
SSP, SSPP, ATO letter, and architecture/network-diagram excerpts so a
downstream SharePoint sweep can find supporting evidence for those exact
identifiers.

OUTPUT CONTRACT
---------------
Return ONE JSON object and nothing else (no prose, no markdown fence):

  {{
    "tokens": ["..."],         // short identifiers, lowercase, punctuation
                               // stripped at the edges; deduplicate
    "confidence": 0.0-1.0      // 0.9 = many concrete named hosts/products;
                               //  0.3 = mostly prose with few proper nouns
  }}

EMIT TOKENS FOR (categories — bias only, not a schema)
------------------------------------------------------
  * Hostnames and FQDNs              (server01, bastion01.acme.local)
  * IP addresses and CIDR blocks     (10.20.0.0/16, 192.168.4.7)
  * Identity / service identifiers   (okta, ping-federate, ldap, saml-idp)
  * Network zones and enclaves       (dmz, mgmt-vlan, prod-enclave)
  * Environments                     (dev, staging, prod, iat, sit)
  * Cloud regions and accounts       (us-gov-west-1, gcc-high)
  * FedRAMP package IDs, CAGE codes  (fr1234567890, cage 0abc1)
  * Vendor product names             (splunk, tenable-sc, crowdstrike)
  * Service names and acronyms       (acas, ckl, stig, scap)

DO NOT EMIT
-----------
  * Placeholders or template debris: tbd, redacted, n/a, na, none,
    example.com, your-hostname-here, hostname1, <fqdn>, xxx
  * Generic English nouns: the server, our network, system, service,
    application, data, user, users, environment, the, a
  * Aspirational or future-tense mentions: "will deploy okta",
    "plans to migrate to AWS GovCloud" — only emit what the system
    ACTUALLY runs today
  * Marketing prose, mission statements, page headers/footers

POSITIVE EXAMPLE
----------------
Input excerpt:
  "The Example System ground segment hosts the mission application on
   server01.acme.local and server02.acme.local in the prod enclave
   (10.20.0.0/16). Authentication is brokered by Okta via SAML; logs ship
   to Splunk Enterprise Security. CAGE 1abc2."

Correct extraction:
  {{
    "tokens": ["example-system", "server01.acme.local", "server02.acme.local",
               "prod", "10.20.0.0/16", "okta", "saml", "splunk",
               "splunk-enterprise-security", "cage-1abc2"],
    "confidence": 0.9
  }}

COUNTER-EXAMPLE (what NOT to do)
--------------------------------
Input excerpt:
  "The system will be hosted on TBD infrastructure. Authentication shall
   be provided by an enterprise identity provider (e.g. example.com).
   Users will access the application through their workstation."

WRONG extraction (DO NOT do this):
  {{"tokens": ["tbd", "example.com", "users", "the system",
              "workstation", "enterprise identity provider"],
   "confidence": 0.8}}

Correct extraction:
  {{"tokens": [], "confidence": 0.2}}

Reason: every candidate is either a placeholder (`tbd`, `example.com`),
aspirational (`will be hosted`, `shall be provided`), or a generic noun
(`users`, `the system`, `workstation`). Nothing is concretely deployed.

INPUT
-----
Document excerpts follow. Each section is delimited by a
``## {{kind}}: {{filename}}`` header so you can tell SSP prose from
architecture-diagram captions. Extract from all sections jointly.

{docs}

Return ONLY the JSON object.
"""

_PUNCT_RE = re.compile(r"^[^\w]+|[^\w]+$")

# Soft suffixes that show up in internal-only hostnames and that the LLM
# sometimes drops/keeps inconsistently. Stripping these in the normalized
# retry lets ``bastion01.acme.local`` (extractor) match ``bastion01.acme``
# (text body) and vice versa without false positives on real public FQDNs.
_SOFT_SUFFIXES = (".local", ".internal", ".lan", ".corp")

# Provenance snippet cap. Schema allows 512 but ~240 chars (≈80 chars of
# context on either side of the match) keeps the side-table compact and
# the 3PAO read-out scannable.
_SNIPPET_CAP = 240
_SNIPPET_WINDOW = 80


def _normalize_token(t: str) -> str:
    t = (t or "").strip().lower()
    t = _PUNCT_RE.sub("", t)
    return t


def _strip_soft_suffix(t: str) -> str:
    """Strip one trailing soft suffix (``.local`` etc.). Idempotent past one."""
    low = t.lower()
    for suf in _SOFT_SUFFIXES:
        if low.endswith(suf) and len(low) > len(suf):
            return t[: -len(suf)]
    return t


def _extract_snippet(haystack: str, needle: str) -> str | None:
    """Return ``±_SNIPPET_WINDOW`` chars of context around the first match.

    Case-insensitive search; returns the slice from the ORIGINAL haystack
    (preserves casing for the 3PAO read-out). Returns ``None`` if no match.
    """
    if not haystack or not needle:
        return None
    low_h = haystack.lower()
    low_n = needle.lower()
    idx = low_h.find(low_n)
    if idx < 0:
        return None
    start = max(0, idx - _SNIPPET_WINDOW)
    end = min(len(haystack), idx + len(needle) + _SNIPPET_WINDOW)
    snippet = haystack[start:end].strip()
    return snippet[:_SNIPPET_CAP]


def _attribute_token(
    raw_token: str,
    sections: list[str],
    evidence_ids: list[int],
) -> tuple[int | None, str | None, str]:
    """Stacked match: substring → normalized → bail with ``unattributed``.

    Returns ``(source_evidence_id, snippet, source_kind)``. The token
    string itself is NOT mutated — what hits the side table is whatever
    the LLM produced (already normalized by ``_normalize_token``); only
    the search shape changes between stack rungs. ``sections`` and
    ``evidence_ids`` are parallel: ``sections[i]`` was built from
    Evidence row ``evidence_ids[i]``. First-match wins (sections are
    iterated in ``ingested_at`` order — oldest doc gets credit, which
    matches assessor intuition: the SSP cited it first).
    """
    if not raw_token or not sections:
        return (None, None, "unattributed")

    # Rung 1 — cheap case-insensitive substring against the unmodified
    # section concatenation. Catches hostnames, IPs, FQDNs, vendor names
    # that the LLM echoed verbatim.
    needle = raw_token.strip()
    if needle:
        for sec, ev_id in zip(sections, evidence_ids):
            snippet = _extract_snippet(sec, needle)
            if snippet is not None:
                return (ev_id, snippet, "doc_extracted")

    # Rung 2 — normalize both sides (lower, strip soft suffix) and retry.
    # Lets ``bastion01.acme.local`` (token) catch ``bastion01.acme`` (body)
    # without false positives on punctuation-bearing text. Use the
    # normalizer the rest of the module already trusts.
    norm = _strip_soft_suffix(_normalize_token(needle)).lower()
    if norm and norm != needle.lower():
        for sec, ev_id in zip(sections, evidence_ids):
            snippet = _extract_snippet(sec, norm)
            if snippet is not None:
                return (ev_id, snippet, "doc_extracted")

    # Rung 3 — bail. Token still lands in extracted_tokens (the sweep
    # still uses it); provenance degrades to unattributed and the 3PAO
    # detail pane shows "source could not be traced".
    return (None, None, "unattributed")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _read_text(path: str | None) -> str | None:
    """Read an extracted-text artifact if the file is locally resolvable.

    Returns None when the path is missing, unreadable, or empty so the
    caller can skip the doc cleanly. We do NOT raise here — a single
    unreadable doc shouldn't tank the whole extraction.
    """
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    text = text.strip()
    return text or None


@dataclass
class BoundaryDocsContextSource:
    """Tier 2 adapter — boundary-doc Evidence rows in, JSON tokens out via LLM."""

    source_type: SystemContextSourceType = field(
        default=SystemContextSourceType.DOCX_NARRATIVE
    )

    def apply(
        self,
        session: Session,
        *,
        workbook_id: int | None,
        extractor: LlmExtractorClient,
        **_: object,  # tolerate future kwargs from the route
    ) -> SystemContextApplyResult:
        # NULL workbook_id = "pending" mode: find boundary docs that haven't
        # been associated with a workbook yet. SQL `==` won't match NULL, so
        # we branch on `.is_(None)` for the pending lookup.
        if workbook_id is None:
            docs = session.exec(
                select(Evidence)
                .where(
                    Evidence.workbook_id.is_(None),  # type: ignore[union-attr]
                    Evidence.is_boundary_doc.is_(True),  # type: ignore[union-attr]
                )
                .order_by(Evidence.ingested_at)
            ).all()
        else:
            docs = session.exec(
                select(Evidence)
                .where(
                    Evidence.workbook_id == workbook_id,
                    Evidence.is_boundary_doc.is_(True),  # type: ignore[union-attr]
                )
                .order_by(Evidence.ingested_at)
            ).all()

        notes: dict = {"adapter": "boundary_docs", "doc_count": len(docs)}

        if not docs:
            # Empty is a valid state — let the route render "attach a doc
            # first" rather than throwing. Confidence 0.0 so any prior
            # extraction's badge clears too.
            ctx = self._upsert(
                session,
                workbook_id,
                tokens=[],
                confidence=0.0,
                source_ref="evidence:[]",
            )
            session.commit()
            session.refresh(ctx)
            return SystemContextApplyResult(
                context=ctx,
                tokens_extracted=0,
                confidence=0.0,
                notes=notes,
            )

        # Concatenate available text under per-doc captions so the LLM
        # can see which fragment came from which doc kind. Skipped docs
        # are tracked so the route can surface a partial-extraction toast.
        sections: list[str] = []
        used_evidence_ids: list[int] = []
        skipped_no_text = 0
        for d in docs:
            text = _read_text(d.extracted_text_path)
            if text is None:
                skipped_no_text += 1
                continue
            caption_kind = d.boundary_doc_kind or "Document"
            caption_label = d.title or Path(d.path).name
            section = (
                f"## {caption_kind}: {caption_label}\n"
                f"{text[:_PER_DOC_CHAR_CAP]}"
            )
            sections.append(section)
            if d.id is not None:
                used_evidence_ids.append(d.id)
        notes["skipped_no_text"] = skipped_no_text
        notes["docs_used"] = len(used_evidence_ids)

        tokens: list[str] = []
        confidence: float = 0.5

        if not sections:
            # Every attached doc had no extracted text. Save the empty
            # extraction so the UI shows confidence 0 + the partial-fail
            # toast rather than silently keeping a stale token cloud.
            confidence = 0.0
        else:
            prompt = _EXTRACTION_PROMPT.format(docs="\n\n".join(sections))
            try:
                result = extractor.extract_system_context(prompt)
                raw_tokens = result.get("tokens", []) or []
                tokens = [
                    tok
                    for tok in (_normalize_token(t) for t in raw_tokens if t)
                    if tok
                ]
                seen: set[str] = set()
                tokens = [t for t in tokens if not (t in seen or seen.add(t))]
                confidence = max(
                    0.0, min(1.0, float(result.get("confidence", 0.5)))
                )
            except Exception as exc:  # noqa: BLE001 — degrade gracefully
                confidence = 0.2
                notes["extraction_error"] = str(exc)

        source_ref = "evidence:[" + ",".join(str(i) for i in used_evidence_ids) + "]"
        ctx = self._upsert(
            session,
            workbook_id,
            tokens=tokens,
            confidence=confidence,
            source_ref=source_ref,
        )

        # --- Per-token provenance (0004 side table) ---
        # Flush so a NEW ctx gets its PK assigned before we hang child
        # rows off it. Existing ctx rows already have an id; flush is a
        # no-op for them. We then nuke prior BoundaryTokenSource rows for
        # this SC — _upsert just *replaced* the full extracted_tokens
        # list, so leaving the old provenance ledger in place would let
        # stale (token, source) pairs survive a re-extract. CASCADE
        # handles SC-DELETE; this DELETE handles SC-UPDATE.
        session.flush()
        if ctx.id is not None:
            session.exec(  # type: ignore[call-overload]
                sa_delete(BoundaryTokenSource).where(
                    BoundaryTokenSource.system_context_id == ctx.id
                )
            )
            attributed_count = 0
            for tok in tokens:
                ev_id, snippet, kind = _attribute_token(
                    tok, sections, used_evidence_ids
                )
                if kind != "unattributed":
                    attributed_count += 1
                session.add(
                    BoundaryTokenSource(
                        system_context_id=ctx.id,
                        token=tok,
                        source_evidence_id=ev_id,
                        source_snippet=snippet,
                        source_kind=kind,
                        confidence=confidence,
                    )
                )
            notes["tokens_attributed"] = attributed_count
            notes["tokens_unattributed"] = max(0, len(tokens) - attributed_count)

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
        tokens: list[str],
        confidence: float,
        source_ref: str,
    ) -> SystemContext:
        """Upsert the SystemContext row, preserving any legacy prose fields.

        We deliberately do NOT touch boundary/stakeholders/tech_inventory/
        requirement_hints — those are the read-only legacy prose fallback
        rendered in a <details> block on the rewritten UI. Overwriting
        them here would silently delete the assessor's prior work the
        first time they upload a doc.

        NULL workbook_id = pending singleton; branch on `.is_(None)` so the
        existing pending row is found and updated instead of the upsert
        colliding with `ix_systemcontext_pending_singleton`.
        """
        if workbook_id is None:
            existing = session.exec(
                select(SystemContext).where(SystemContext.workbook_id.is_(None))
            ).first()
        else:
            existing = session.exec(
                select(SystemContext).where(SystemContext.workbook_id == workbook_id)
            ).first()
        if existing:
            existing.extracted_tokens = tokens
            existing.confidence = confidence
            existing.source_type = SystemContextSourceType.DOCX_NARRATIVE
            existing.source_ref = source_ref
            existing.updated_at = _utcnow()
            session.add(existing)
            return existing
        ctx = SystemContext(
            workbook_id=workbook_id,
            source_type=SystemContextSourceType.DOCX_NARRATIVE,
            source_ref=source_ref,
            extracted_tokens=tokens,
            confidence=confidence,
        )
        session.add(ctx)
        return ctx
