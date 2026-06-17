"""Build the per-CCI evidence bundle that the LLM sees as ``tagged_evidence``.

The kernel today renders only the CCIS row — the model never sees any
ingested artifact when proposing a (status, narrative). That's the root
cause of generic narratives that don't cite specific evidence: the
``tagged_evidence`` placeholder in ``llm/prompts/assess_control.md`` was
defined but never wired.

This module joins ``EvidenceTag`` → ``Evidence`` for one objective, loads
a budgeted slice of each artifact's extracted text, and returns a single
string the prompt builder drops in verbatim. Returns ``None`` when no
tags exist so the caller can skip the placeholder entirely — leaving the
prompt prefix bit-identical to the no-evidence path keeps Anthropic /
OpenAI prompt caching warm across the (much more common) early-stage
CCIs that haven't been tagged yet.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from sqlmodel import Session, select

from ..models import (
    BoundarySegment,
    Evidence,
    EvidenceBoundary,
    EvidenceKind,
    EvidenceTag,
    Objective,
    ScopeLinkSource,
)
from .evidence_ranker import (
    DISPOSITION_DEFERRED,
    DISPOSITION_EXAMINED,
    OVERFLOW_NONE,
    OverflowDecision,
    RankerConfig,
    classify_overflow,
    rank_artifacts,
)
from .finding_corroboration import affected_hosts, corroborating_findings, format_finding_citation

if TYPE_CHECKING:
    from collections.abc import Sequence

    # Audit v1 — TYPE_CHECKING-only import keeps the runtime free of the
    # circular: assessor.py imports EvidenceBlock from us, so importing
    # EvidenceShownPayload from assessor.py at module load would deadlock.
    # Function bodies that build payloads use a local runtime import.
    from .assessor import EvidenceShownPayload

# Scan-product kinds (STIG outputs + Nessus exports). The corroboration
# validator (validator.py, v0.3) treats these as findings-only evidence
# that cannot stand alone as proof of compliance — see
# feedback_corroborate_stig_findings.md. Any kind NOT in this set counts
# as a corroborator (policy, SSP, baseline doc, etc.).
_SCAN_EVIDENCE_KINDS: frozenset[EvidenceKind] = frozenset(
    {
        EvidenceKind.STIG_CKL,
        EvidenceKind.STIG_CKLB,
        EvidenceKind.STIG_XCCDF,
        EvidenceKind.NESSUS,
    }
)

# Section markers emitted by this module. Exposed as module constants so
# the route-layer assembler (``_build_evidence_block``) can detect which
# corroboration sub-sections rendered without re-parsing free-form text
# or duplicating the literal strings. Detection stays structural — we
# match on a producer-emitted constant, not a heuristic phrase.
TAGGED_EVIDENCE_HEADER = "## tagged_evidence"
CORROBORATING_FINDINGS_HEADER = "## corroborating_findings"
AFFECTED_HOSTS_HEADER = "## affected_hosts"


@dataclass(frozen=True)
class EvidenceBlock:
    """The structured envelope ``_build_evidence_block`` hands the assessor.

    ``text`` is the rendered string passed to the prompt template (or
    ``None`` when nothing should be inserted at all). The booleans let
    the deterministic no-evidence short-circuit (``Assessor.assess``
    Step 1.65) decide whether anything decision-quality is present
    without re-parsing the string. Context wrappers — the asset coverage
    report (CM-8/CM-6/CA-3/CA-7/PM-5/RA-5 families) and the CRM hybrid
    responsibility-split prepend — are workbook-wide framing, not
    per-objective retrieved artifacts. Without this signal the gate
    can't tell them apart from real evidence, and the rule never fires.

    ``is_only_context`` is True when ``text`` is non-empty but contains
    nothing the LLM could reason from — i.e. only coverage / hybrid
    wrappers. The short-circuit fires on that OR on ``text is None``.

    Audit v1: ``evidence_shown`` carries the per-chunk payload list (one
    entry per artifact block in ``text``) so the route layer can persist
    AssessmentEvidenceShown rows linking each chunk to its source
    Evidence + sha256 of the exact bytes shown. Coverage / findings /
    hosts sub-sections are aggregated context, not per-chunk artifacts,
    so they don't appear in this list. Defaults to ``[]`` so existing
    test constructors that only pass the original fields keep working.
    """

    text: str | None
    has_artifacts: bool        # build_tagged_evidence returned non-None
    has_coverage: bool         # asset_coverage_report block appended
    has_findings: bool         # corroborating_findings section present
    has_hosts: bool            # affected_hosts section present
    # v0.3 corroboration gate (feedback_corroborate_stig_findings.md). True
    # when at least one tagged artifact is a non-scan kind (PDF/DOCX/PPTX/
    # XLSX/TEXT/OTHER) — i.e. a policy/baseline/config document that can
    # corroborate a STIG finding. A COMPLIANT verdict resting purely on
    # STIG scan output without any policy/config corroborator is a
    # precision-over-recall violation; the validator rejects it.
    has_nonscan_artifact: bool = False
    # Audit v1. Tuple keeps the frozen dataclass actually frozen — list
    # default_factory would still be mutable through the attribute. Empty
    # tuple is the no-evidence path; route layer wraps to list for the
    # persistence loop.
    evidence_shown: tuple["EvidenceShownPayload", ...] = field(default_factory=tuple)
    # Per-source graceful-degrade warnings (Bug 11). Each entry is a
    # structured string ``"source_name: ErrorType: message"`` recorded when
    # one evidence source raised but the remaining sources succeeded. Empty
    # tuple = all sources healthy. The route layer threads these into the
    # decision dict so the UI can surface per-CCI degrade notices without
    # the CCI vanishing from the batch entirely.
    source_warnings: tuple[str, ...] = field(default_factory=tuple)
    # Token-budget overflow verdict (evidence_ranker.classify_overflow). None
    # on the no-evidence path and for context-only blocks (no per-objective
    # artifacts ranked). When present, ``strategy`` is OVERFLOW_NONE /
    # finalize_on_examined / escalate. The assessor's Step 1.65 routes an
    # ``escalate`` block to ``_abstain`` (needs_review) so a verdict is never
    # silently based on a subset of decisive evidence; ``reason`` flows into
    # the review_reason / SAR appendix verbatim. Defaulted to None so frozen-
    # dataclass test constructors and the context-only paths keep working.
    overflow: "OverflowDecision | None" = None

    @property
    def is_only_context(self) -> bool:
        """True when ``text`` is non-empty but lacks any per-objective
        artifact evidence — only context wrappers (coverage report /
        CRM hybrid prepend) are present. Step 1.65 short-circuits the
        LLM call when this is True OR when ``text`` is None.
        """
        return self.text is not None and not (
            self.has_artifacts or self.has_findings or self.has_hosts
        )

# Per-artifact snippet budget. The OLD fixed ``MAX_ARTIFACTS = 6`` cap is
# RETIRED — it silently discarded artifacts 7..N for any enterprise control
# with 30-50+ tagged artifacts, and those drops never reached the model OR
# the audit trail (see evidence_ranker.py module docstring). Admission is now
# a token budget (evidence_ranker.rank_artifacts): every artifact is either
# examined or recorded as deferred, never dropped. ``PER_ARTIFACT_CHARS``
# still bounds each individual snippet's size (head/tail truncation in
# ``_load_snippet``) so one giant file can't dominate the budget.
#
# Raised 3000 → 9000 (2026-06-10): a 3 KB window was too thin to carry the
# decision-relevant passage of a real evidence artifact — assessors saw
# generic narratives because the model was reasoning on a sliver. The ranker
# (evidence_ranker.rank_artifacts) still budgets the OVERALL prompt and defers
# (never drops) the tail, so a wider per-artifact window trades artifact count
# for depth on the highest-ranked few — which is the right call when the top
# matches are the ones that actually decide the verdict.
PER_ARTIFACT_CHARS = 9000

# When an artifact's extracted text exceeds the budget, keep the front
# (titles, scope, intro) and tail (signatures, dates, conclusions) rather
# than a middle slice. Compliance docs put the load-bearing facts at the
# edges; the body is mostly boilerplate. Kept HEAD+TAIL < PER_ARTIFACT_CHARS
# so truncation always shrinks an over-budget file (the boundary guard in
# ``_load_snippet`` returns raw for borderline files between 8 KB and 9 KB).
HEAD_CHARS = 5000
TAIL_CHARS = 3000

# Anchor-aware window (blindspot fix 2026-06-10). Head/tail truncation drops
# the entire middle of an over-budget artifact. If the token that JUSTIFIED
# the tag (a CCI ref, control ID, or doc number — matched against the body by
# the tagger) lives in that dropped middle, the LLM never sees the passage it's
# supposed to assess and writes a confident verdict on text it can't cite. When
# we know the anchor(s) for an artifact, we carve a context window around the
# first occurrence found in the dropped middle and splice it between head and
# tail, so the matched passage is always shown. Width is the full window
# (split evenly before/after the match). Scaled with the wider head/tail
# (2026-06-10) so the anchored middle window carries enough surrounding
# context to actually read the matched passage, not just the keyword.
MATCH_CONTEXT_CHARS = 1500

# Caps for the corroboration sections. Findings: 5 is enough to surface the
# most-severe failures without flooding the prompt with the long tail of
# medium/low findings on a busy CKL. Hosts: 20 matches the POAM narrative
# cap (poam/generator.py) so the assessor and POAM cite the same scope when
# both render.
FINDINGS_CAP = 5
HOSTS_CAP = 20

# Detail summary length — short enough that 5 findings + headers fit in
# ~1 KB total prompt overhead, long enough to convey what the rule failed on.
FINDING_DETAIL_CHARS = 200


def _first_sentence(text: str | None, max_chars: int) -> str:
    """First sentence (or first ``max_chars``) with an ellipsis if cut.

    Local copy rather than importing from ``poam.generator`` — engine layer
    can't depend on the POAM module without inverting the layering.
    """
    if not text:
        return ""
    t = text.strip()
    if not t:
        return ""
    for sep in (". ", "! ", "? ", ".\n", "!\n", "?\n"):
        idx = t.find(sep)
        if 0 < idx <= max_chars:
            return t[: idx + 1].strip()
    if len(t) <= max_chars:
        return t
    return t[: max_chars - 1].rstrip() + "\u2026"


# Markers the image extractor writes when no pixel text was recovered (no OCR
# binary, or OCR found nothing). An image carrying one of these is existence-
# only — the prompt forbids it from substantiating a technical setting, so it
# must ALSO not count as a corroborator for the STIG-pass gate. Kept in sync
# with extractors/image.py.
_IMAGE_NO_TEXT_MARKERS = ("[image — no OCR]", "[image — OCR found no text]")


def _image_has_real_text(extracted_text_path: str | None) -> bool:
    """True when an IMAGE artifact's extracted text is actual OCR'd content.

    Reads only the small head of the file (the marker, if any, is on line 1).
    Returns False for the unread-image markers or a missing/empty file — so an
    un-OCR'd screenshot can't masquerade as a corroborating document.
    """
    if not extracted_text_path:
        return False
    p = Path(extracted_text_path)
    if not p.exists():
        return False
    try:
        head = p.read_text(encoding="utf-8", errors="replace")[:200].lstrip()
    except OSError:
        return False
    if not head:
        return False
    return not any(head.startswith(m) for m in _IMAGE_NO_TEXT_MARKERS)


def has_nonscan_evidence(objective_id: int, session: Session) -> bool:
    """True iff at least one non-superseded tagged artifact on ``objective_id``
    is a non-scan kind (policy/SSP/baseline doc/config/etc.).

    Used by the route-layer ``_build_evidence_block`` to populate
    ``EvidenceBlock.has_nonscan_artifact`` so the validator's corroboration
    gate can fire: a COMPLIANT verdict resting only on STIG scan output
    without any corroborating policy/config artifact is rejected. See
    feedback_corroborate_stig_findings.md.

    Mirrors ``build_tagged_evidence``'s supersession filter — superseded
    artifacts are not allowed to satisfy corroboration any more than they
    are allowed to be fed to the LLM as current evidence.

    IMAGE artifacts only corroborate when their pixels were actually OCR'd —
    an ``[image — no OCR]`` / ``[image — OCR found no text]`` screenshot is
    existence-only (the prompt forbids it from substantiating a setting), so it
    must not silently satisfy the corroboration gate either.
    """
    rows = session.exec(
        select(Evidence.kind, Evidence.extracted_text_path)
        .join(EvidenceTag, EvidenceTag.evidence_id == Evidence.id)
        .where(EvidenceTag.objective_id == objective_id)
        .where(Evidence.superseded_by_id.is_(None))
    ).all()
    for kind, text_path in rows:
        if kind in _SCAN_EVIDENCE_KINDS:
            continue
        if kind == EvidenceKind.IMAGE and not _image_has_real_text(text_path):
            continue  # un-OCR'd image is not a corroborator
        return True
    return False


# Boundary-attribution rendering (multi-tenant narrative integrity).
#
# For multi-boundary systems (e.g. AWS GovCloud + Azure Gov tenants) the
# assessor writes per-scope narratives. An artifact that legally applies to ONE
# tenant but carries no cloud-specific keywords (a global IAM policy, a shared
# SIEM runbook) would otherwise have its boundary GUESSED by the LLM from prose
# — silent cross-boundary misattribution that invalidates the SSP/SAR. Three
# independent model reviews held that deterministic structured signals must beat
# prompt-faith for a federal 800-53 assessor.
#
# Two hard guards keep this from doing more harm than good:
#   1. EXPLICIT links only. ``EvidenceBoundary`` rows backfilled from the legacy
#      ``is_boundary_doc`` flag (``ScopeLinkSource.BACKFILL``) are unreliable —
#      rendering them would launder bad data into authoritative-looking headers.
#      We render only AUTO (ingest inference) / MANUAL (assessor click) links.
#   2. MULTI-BOUNDARY only. In a single-boundary workbook the header line is
#      pure noise AND it would perturb the prompt prefix for every CCI, cold-
#      busting the prompt cache. We render boundary lines only when the workbook
#      actually has >=2 BoundarySegments. Single-boundary decks stay byte-
#      identical to the pre-feature bundle.
# In a multi-boundary workbook, an artifact with no explicit link renders
# ``boundary: unspecified`` so the model knows to fall back to text reasoning
# for that one rather than silently assuming a tenant.

# Links created by these sources are trustworthy enough to render. BACKFILL is
# deliberately excluded (see guard #1 above).
_EXPLICIT_LINK_SOURCES: frozenset[ScopeLinkSource] = frozenset(
    {ScopeLinkSource.AUTO, ScopeLinkSource.MANUAL}
)

BOUNDARY_UNSPECIFIED = "unspecified"


def _workbook_is_multi_boundary(workbook_id: int | None, session: Session) -> bool:
    """True when the workbook defines >=2 BoundarySegments.

    Cheap COUNT-style probe (LIMIT 2). Returns False on ``workbook_id is None``
    (the session-free / single-shot paths) so those bundles render exactly as
    before. Single-boundary workbooks return False → no boundary lines, prompt
    prefix unchanged, cache stays warm.
    """
    if workbook_id is None:
        return False
    rows = session.exec(
        select(BoundarySegment.id)
        .where(BoundarySegment.workbook_id == workbook_id)
        .limit(2)
    ).all()
    return len(rows) >= 2


def _explicit_boundary_labels_by_evidence(
    evidence_ids: "Sequence[int]",
    session: Session,
    workbook_id: int | None = None,
) -> dict[int, list[str]]:
    """Batched evidence_id -> [BoundarySegment label] for EXPLICIT links only.

    One query, no N+1. Filters out ``ScopeLinkSource.BACKFILL`` so only
    trustworthy (AUTO/MANUAL) attributions reach the header. Label is
    ``"<name>"`` or ``"<name> (<kind>)"`` when the segment carries a kind
    (dmz/internal/mgmt/tenant). Returns ``{}`` when no explicit links exist.

    ``workbook_id`` scopes the segment join to the active workbook. Evidence
    today is per-workbook (composite-unique on ``(workbook_id, sha256)``), so a
    link can only reference its own workbook's segments in practice — but the
    join itself is unconstrained, so we pin it defensively. Without this filter,
    if an Evidence row were ever shared across workbooks, this could render
    another workbook's tenant label and cause the exact cross-boundary
    misattribution the feature exists to prevent. None preserves the legacy
    (unscoped) behavior for callers that don't have a workbook in hand.
    """
    ids = [eid for eid in evidence_ids if eid is not None]
    if not ids:
        return {}
    query = (
        select(
            EvidenceBoundary.evidence_id,
            BoundarySegment.name,
            BoundarySegment.kind,
        )
        .join(
            BoundarySegment,
            BoundarySegment.id == EvidenceBoundary.boundary_segment_id,
        )
        .where(EvidenceBoundary.evidence_id.in_(ids))  # type: ignore[union-attr]
        .where(EvidenceBoundary.source.in_(_EXPLICIT_LINK_SOURCES))  # type: ignore[union-attr]
    )
    if workbook_id is not None:
        query = query.where(BoundarySegment.workbook_id == workbook_id)
    rows = session.exec(query).all()
    out: dict[int, list[str]] = {}
    for ev_id, name, kind in rows:
        label = f"{name} ({kind})" if kind else str(name)
        bucket = out.setdefault(ev_id, [])
        if label not in bucket:
            bucket.append(label)
    for bucket in out.values():
        bucket.sort()  # deterministic header ordering
    return out


def build_tagged_evidence(objective_id: int, session: Session) -> str | None:
    """Render the EvidenceTag rows for one objective as a prompt block.

    Returns ``None`` when no (non-superseded) tags exist so callers can
    skip the placeholder entirely — keeps the prompt prefix stable for
    cache hits on the no-evidence path. When tags do exist, the returned
    string may additionally include ``## corroborating_findings`` and
    ``## affected_hosts`` sub-sections; either is omitted when its source
    query returns empty (precision over recall — no empty headers).

    Thin wrapper around :func:`build_tagged_evidence_with_payload` —
    preserved as the primary public API because the test suite and the
    route layer both call it. Callers that need the audit payload or the
    overflow decision (route layer, ``_build_evidence_block``) call the
    underscored sibling.
    """
    text, _payload, _overflow = build_tagged_evidence_with_payload(
        objective_id, session
    )
    return text


def build_tagged_evidence_with_payload(
    objective_id: int,
    session: Session,
    *,
    config: RankerConfig | None = None,
    workbook_id: int | None = None,
) -> tuple[str | None, list["EvidenceShownPayload"], OverflowDecision]:
    """Audit-v1 variant of :func:`build_tagged_evidence`.

    Returns ``(text, payload, overflow)`` where:

    * ``text``     — the prompt block string (same as the plain wrapper).
      Only the **examined** artifacts (those admitted under the token
      budget) are rendered into the ``## tagged_evidence`` items — the
      deferred tail is intentionally NOT shown to the model.
    * ``payload``  — one :class:`EvidenceShownPayload` per artifact, for
      BOTH examined AND deferred artifacts. Deferred entries carry
      ``disposition="deferred"`` + a ``deferred_reason`` so the audit
      trail records exactly what was held back and why. This is the core
      of the silent-drop fix: ``len(payload)`` always equals the full
      tagged set, never a truncated prefix.
    * ``overflow`` — the :class:`OverflowDecision` from
      :func:`classify_overflow`. ``OVERFLOW_NONE`` when everything was
      examined; ``finalize_on_examined`` when the deferred tail is pure
      low-relevance corroboration; ``escalate`` when high-relevance
      evidence exceeded the budget (the caller routes to needs_review).

    Each payload carries the literal snippet bytes the LLM saw plus
    sha256(snippet) so an auditor can verify replay byte-equivalence —
    the file-level ``Evidence.sha256`` is not enough because the bundle
    head+tail-truncates anything over ``PER_ARTIFACT_CHARS``.

    Empty payload + ``OVERFLOW_NONE`` when no rows exist (the no-evidence
    path) and ``text`` is None.
    """
    # Local import — assessor.py imports EvidenceBlock from this module,
    # so a top-level import of EvidenceShownPayload would deadlock the
    # circular. Cheap at call time, the symbol is already loaded by the
    # time any assess path reaches us.
    from .assessor import EvidenceShownPayload

    rows = session.exec(
        select(EvidenceTag, Evidence)
        .join(Evidence, Evidence.id == EvidenceTag.evidence_id)
        .where(EvidenceTag.objective_id == objective_id)
        # Never feed a superseded artifact to the LLM as if it were current;
        # the supersession chain exists precisely so legacy USD docs don't
        # come back as "evidence" after the new tier ships.
        .where(Evidence.superseded_by_id.is_(None))
    ).all()
    if not rows:
        return None, [], OverflowDecision(OVERFLOW_NONE, "no tagged evidence", 0)

    # Token-budget partition (replaces the old ``rows[:MAX_ARTIFACTS]``
    # truncation). The ranker sorts by (relevance, confidence) descending —
    # byte-identical to the historical sort — then greedily admits highest-
    # ranked first while the running snippet-token sum stays within budget.
    # ``load_snippet`` is the SAME head/tail truncation the renderer uses,
    # so the bytes the ranker budgeted are the exact bytes shown + hashed.
    # Anchor map: the matched token(s) per artifact, so the snippet loader can
    # center its truncation window on the passage that justified the tag rather
    # than blindly head/tail-dropping the middle (blindspot fix 2026-06-10).
    # One tag per (evidence, objective) pair on this objective_id query, so the
    # ev.id key is unambiguous.
    anchor_map: dict[int, list[str]] = {
        ev.id: _anchors_from_tag(tag) for tag, ev in rows if ev.id is not None
    }
    # Boundary attribution — only for multi-boundary workbooks (guard #2). In a
    # single-boundary workbook (or session-free path) this stays empty and the
    # header is byte-identical to the pre-feature bundle, keeping the prompt
    # prefix cache-stable. ``boundary_map`` carries only EXPLICIT (AUTO/MANUAL)
    # links (guard #1); BACKFILL is excluded so legacy guesses aren't laundered.
    render_boundaries = _workbook_is_multi_boundary(workbook_id, session)
    boundary_map: dict[int, list[str]] = (
        _explicit_boundary_labels_by_evidence(
            [ev.id for _tag, ev in rows if ev.id is not None],
            session,
            workbook_id=workbook_id,
        )
        if render_boundaries
        else {}
    )
    result = rank_artifacts(
        [(tag, ev) for tag, ev in rows],
        load_snippet=lambda ev: _load_snippet(
            ev.extracted_text_path, anchors=anchor_map.get(ev.id)
        ),
        config=config,
    )

    blocks: list[str] = []
    payload: list[EvidenceShownPayload] = []

    # Examined artifacts — rendered into the prompt AND audited as examined.
    for ranked in result.examined:
        tag = ranked.tag
        ev = ranked.evidence
        snippet = ranked.snippet
        locator = _section_locator(snippet, ranked.order_index)
        header_lines = [
            f"- title: {ev.title or ev.path}",
            f"  kind: {ev.kind.value if hasattr(ev.kind, 'value') else ev.kind}",
            f"  section: {locator}",
        ]
        # Boundary line — multi-boundary workbooks only (else render_boundaries
        # is False and this block never adds a line). Explicit link → the
        # segment label(s); no explicit link → ``unspecified`` so the model
        # falls back to text reasoning for THIS artifact rather than silently
        # assuming a tenant. Single-boundary bundles never reach here.
        if render_boundaries:
            bsegs = boundary_map.get(ev.id) if ev.id is not None else None
            header_lines.append(
                f"  boundary: {', '.join(bsegs) if bsegs else BOUNDARY_UNSPECIFIED}"
            )
        if ev.doc_number:
            header_lines.append(f"  doc_number: {ev.doc_number}")
        header_lines.append(
            f"  relevance: {tag.relevance:.2f} (source={tag.source})"
        )
        header = "\n".join(header_lines)
        # Injection-hardening (finding #7): neutralize triple-quotes inside
        # the untrusted artifact snippet so a malicious/odd artifact can't
        # close the DATA block and have following text read as instructions.
        # Lazy import avoids a circular dep (llm.client imports engine.assessor,
        # which imports this module). The chunk_sha below intentionally hashes
        # the ORIGINAL snippet (what the file contains) so audit replay matches
        # the source, not the sanitized presentation.
        from ..llm.client import _sanitize_untrusted

        safe_snippet = _sanitize_untrusted(snippet)
        blocks.append(f'{header}\n  text: """\n{safe_snippet}\n"""')

        # Audit v1: chunk_sha hashes the budgeted snippet (after head/tail
        # truncation), not the underlying file — Evidence.sha256 is the file
        # hash and would mismatch on every over-budget artifact. NOTE: the
        # model is shown the injection-sanitized form (triple-quotes
        # neutralized, finding #7); the sha/chunk_text capture the pre-sanitize
        # bytes so the audit trail reflects the artifact's true content. The
        # two diverge ONLY when an artifact literally contains ``\"\"\"``.
        # Order_index is 0-based and matches the
        # block ordering in ``text`` so the UI's "show chunk N" can map
        # directly. tag_source / relevance are denormalized at capture
        # time so a later retag doesn't rewrite history.
        payload.append(
            EvidenceShownPayload(
                evidence_id=ev.id,
                chunk_sha=hashlib.sha256(snippet.encode("utf-8")).hexdigest(),
                chunk_text=snippet,
                order_index=ranked.order_index,
                relevance=tag.relevance,
                tag_source=tag.source,
                disposition=DISPOSITION_EXAMINED,
                rank_score=ranked.rank_score,
                deferred_reason=None,
            )
        )

    # Deferred artifacts — NOT rendered into the prompt, but fully audited
    # so a reviewer can see exactly what exceeded the budget and why. This
    # is what makes "anything not examined must be traceable" true: the
    # snippet bytes + sha are still captured even though the model never
    # saw them.
    for ranked in result.deferred:
        tag = ranked.tag
        ev = ranked.evidence
        snippet = ranked.snippet
        payload.append(
            EvidenceShownPayload(
                evidence_id=ev.id,
                chunk_sha=hashlib.sha256(snippet.encode("utf-8")).hexdigest(),
                chunk_text=snippet,
                order_index=ranked.order_index,
                relevance=tag.relevance,
                tag_source=tag.source,
                disposition=DISPOSITION_DEFERRED,
                rank_score=ranked.rank_score,
                deferred_reason=ranked.deferred_reason,
            )
        )

    overflow = classify_overflow(result, config=config)

    sections: list[str] = [f"{TAGGED_EVIDENCE_HEADER}\n" + "\n\n".join(blocks)]

    # Corroborating findings: the same join the POAM narrative uses, scoped
    # to this single objective so the LLM sees evidence relevant to THIS
    # status decision — not the whole cluster. The cluster-level rollup
    # happens later in POAM generation.
    objective = session.get(Objective, objective_id)
    if objective is not None:
        findings_section = _render_findings_section(objective_id, objective.objective_id, session)
        if findings_section:
            sections.append(findings_section)
        hosts_section = _render_hosts_section(objective_id, session)
        if hosts_section:
            sections.append(hosts_section)

    return "\n\n".join(sections), payload, overflow


def _render_findings_section(
    objective_id: int, cci_id: str, session: Session
) -> str | None:
    """Top-N OPEN STIG findings tied to this objective's evidence + CCI.

    Returns None when nothing corroborates — caller omits the section
    entirely to avoid an empty header (precision over recall).
    """
    pairs = corroborating_findings([objective_id], {cci_id}, session)
    if not pairs:
        return None
    # Already severity-sorted by the shared module; take the top slice.
    top = pairs[:FINDINGS_CAP]
    lines = [CORROBORATING_FINDINGS_HEADER]
    for finding, ev_label in top:
        sev = finding.severity or "unknown"
        citation = format_finding_citation(finding, ev_label)
        detail = _first_sentence(finding.finding_details, FINDING_DETAIL_CHARS)
        if detail:
            lines.append(f"- {citation} ({sev}): {detail}")
        else:
            lines.append(f"- {citation} ({sev})")
    if len(pairs) > FINDINGS_CAP:
        lines.append(f"- (+{len(pairs) - FINDINGS_CAP} more findings omitted)")
    return "\n".join(lines)


def _render_hosts_section(objective_id: int, session: Session) -> str | None:
    """Sorted host union from tagged evidence's host_inventory.

    Returns None when no tagged evidence carries inventory — common for
    policy-only controls. Caps at HOSTS_CAP with a ``(+N more)`` suffix to
    keep the prompt bounded without losing the scope-count signal.
    """
    hosts = affected_hosts([objective_id], session)
    if not hosts:
        return None
    shown = hosts[:HOSTS_CAP]
    suffix = f" (+{len(hosts) - HOSTS_CAP} more)" if len(hosts) > HOSTS_CAP else ""
    return (
        f"{AFFECTED_HOSTS_HEADER} ({len(hosts)})\n"
        f"{', '.join(shown)}{suffix}"
    )


_HEADING_RE = re.compile(r"^#{1,4}\s+(.+)$", re.MULTILINE)
_PAGE_RE = re.compile(r"(?:^|\n)\s*(?:Page|PAGE|pg\.?)\s+(\d+)", re.MULTILINE)

# Tokens the tagger embeds verbatim in ``EvidenceTag.rationale`` to record
# what it matched against the artifact body: a CCI id (Tier 2), a control id
# (Tier 3), or a doc number (Tier 1). We re-extract them as truncation anchors
# so the snippet window centers on the passage that earned the tag.
_ANCHOR_RE = re.compile(
    r"CCI-\d{6}"  # CCI reference (Tier 2)
    r"|[A-Za-z]{2}-\d{1,2}(?:\.\d+)?(?:\(\d+\))?"  # control id, e.g. CM-8 / CM-7.5 / AC-2(1) (Tier 3)
    r"|[A-Z]{2,4}\d{6,}"  # doc number, e.g. USD00050010 (Tier 1)
)


def _anchors_from_tag(tag: "EvidenceTag") -> list[str]:
    """Pull the literal matched token(s) out of a tag's rationale.

    The tagger writes the token it matched (``CCI-000074``, ``CM-8``,
    ``USD00050010``) into the human-readable rationale. Re-extracting them
    here — rather than re-querying the Objective/Control — keeps the snippet
    loader self-contained and uses the EXACT string the tagger matched on.
    Returns ``[]`` for tiers whose rationale carries no body token (Tier 4
    evidence-type classification says "content shape", not a keyword), in
    which case truncation falls back to plain head/tail.
    """
    rationale = getattr(tag, "rationale", None)
    if not rationale:
        return []
    # Dedupe preserving order so the earliest-listed token wins ties later.
    seen: dict[str, None] = {}
    for m in _ANCHOR_RE.findall(rationale):
        seen.setdefault(m, None)
    return list(seen.keys())


def _section_locator(snippet: str, order_index: int) -> str:
    """Return the cheapest unambiguous 'where in the doc' tag for a snippet.

    Priority:
      1. First markdown heading found in the snippet text (human-readable,
         repeatable by the model without hallucination — it's literally in
         the snippet the model reads).
      2. First 'Page N' / 'pg. N' marker extracted from PDF text layers.
      3. Stable chunk index (order of admission into the evidence bundle),
         expressed as "chunk <n>" so the auditor knows which admitted
         artifact this is for this assessment.

    The returned string is embedded into the prompt header verbatim so the
    model can echo it in its narrative citation without inventing anything.
    Only cite what is literally present in the snippet — all three options
    here are derived from the snippet content or its position, never from
    external metadata.
    """
    m = _HEADING_RE.search(snippet)
    if m:
        heading = m.group(1).strip()[:80]
        return f"§ {heading}"
    pm = _PAGE_RE.search(snippet)
    if pm:
        return f"page {pm.group(1)}"
    return f"chunk {order_index}"


def _load_snippet(
    text_path: str | None,
    anchors: "Sequence[str] | None" = None,
) -> str:
    """Read the extracted text, head/tail-truncating if over budget.

    The extractor writes plain UTF-8; ``errors="replace"`` defends against
    the occasional Latin-1 byte that slipped through a PDF text layer.

    When ``anchors`` is supplied (the matched token(s) for this artifact's
    tag) and an anchor appears in the dropped middle of an over-budget file,
    a context window is carved around its first occurrence and spliced
    between head and tail — the blindspot fix so the LLM always sees the
    passage that justified the tag. With no anchors (or none found in the
    middle) the function is byte-identical to the old head/tail behavior.
    """
    if not text_path:
        return "(extracted text unavailable)"
    p = Path(text_path)
    if not p.exists():
        return "(extracted text unavailable)"
    raw = p.read_text(encoding="utf-8", errors="replace")
    if len(raw) <= PER_ARTIFACT_CHARS:
        return raw

    head_end = HEAD_CHARS
    tail_start = len(raw) - TAIL_CHARS

    # Anchor-aware path: find the earliest anchor that lands in the dropped
    # middle (positions [head_end, tail_start)). Anchors already inside the
    # head or tail are visible anyway and need no extra window.
    if anchors and tail_start > head_end:
        lowered = raw.lower()
        best: int | None = None
        for a in anchors:
            if not a:
                continue
            idx = lowered.find(a.lower())
            if idx != -1 and head_end <= idx < tail_start and (
                best is None or idx < best
            ):
                best = idx
        if best is not None:
            win_start = max(head_end, best - MATCH_CONTEXT_CHARS // 2)
            win_end = min(tail_start, best + MATCH_CONTEXT_CHARS // 2)
            truncated = (
                f"{raw[:head_end]}"
                f"\n...[truncated {win_start - head_end} chars]...\n"
                f"{raw[win_start:win_end]}"
                f"\n...[truncated {tail_start - win_end} chars]...\n"
                f"{raw[tail_start:]}"
            )
            # Same boundary guard as below: never pad past the raw input.
            if len(truncated) >= len(raw):
                return raw
            return truncated

    skipped = len(raw) - HEAD_CHARS - TAIL_CHARS
    truncated = f"{raw[:HEAD_CHARS]}\n...[truncated {skipped} chars]...\n{raw[-TAIL_CHARS:]}"
    # Boundary guard: for files barely over PER_ARTIFACT_CHARS the marker
    # overhead can make the truncated string LONGER than the raw input. If
    # truncation isn't actually shorter, return raw — the budget exists to
    # shrink the prompt, not pad it.
    if len(truncated) >= len(raw):
        return raw
    return truncated
