"""Boundary-aware sweep scoring — pure logic, no Graph calls, no IO.

Sits between "configure SharePoint" and "ingest". Given a workbook + a
list of candidate files (name, path, snippet) pulled from Graph metadata,
ranks each candidate against the workbook's boundary (host inventory,
in-scope control families, CRM responsibility table, doc-number prefixes)
and proposes CCI mappings.

See :doc:`SHAREPOINT_SWEEP_DESIGN.md` for the contract this implements.

Why a separate module: the scorer is the part that needs to be unit-
testable without a live Graph session. :class:`SharePointSource` owns
the Graph plumbing and calls into here for every candidate it enumerates.
The route handler builds the fingerprint, hands it to the source, returns
the result — never writes Evidence.

Tagger reuse: we share :data:`tagger._CONTROL_ID_RE` and
:func:`tagger._normalize_control_id` so "AC-2(1)" → "ac-2.1" matches the
canonical form used everywhere else (tags, decisions, CRM lookups). The
filename family-keyword table that used to live in tagger was removed
2026-06-04 (it was generating 99.87% of all auto-tags at 0.35 confidence
— too noisy for tagging, but exactly the right shape for *triage*
scoring, where the user gets a final say before anything persists). So
we keep a deliberately small local copy here.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import quote, unquote, urlparse

from sqlmodel import Session, select

from ..tagger import _CONTROL_ID_RE, _normalize_control_id
from ...engine.crm_context import CrmContext, build_crm_context
from ...models import (
    Assessment,
    BaselineControl,
    BaselineObjective,
    BoundaryTokenSource,
    Control,
    Evidence,
    Objective,
    SweepWeights,
    SystemContext,
    Workbook,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Triage-only family keywords
# ---------------------------------------------------------------------------
# Deliberately narrow. These show up in SharePoint filenames frequently
# enough to be a useful signal but aren't so generic that every doc hits.
# Each token is lowercased; we match as a whole-word substring against the
# combined `name + path + snippet`. Multiple tokens per family — at least
# one must match for the family signal to fire.
#
# The CRM narrative path (crm_keywords) covers the long tail of program-
# specific phrasing (e.g. "AWS Config rule …", "GitLab role …"); this
# table only needs to cover the generic doc-naming conventions assessors
# actually use.
_FAMILY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "AC": ("access control", "account management", "least privilege", "rbac"),
    "AU": ("audit log", "audit record", "auditing", "audit policy"),
    "AT": ("training", "awareness"),
    "CM": ("configuration", "baseline", "inventory", "asset list", "stig", "scap"),
    "CP": ("contingency", "backup", "disaster recovery", "continuity"),
    "IA": ("identification", "authentication", "credential", "mfa", "piv", "cac"),
    "IR": ("incident response", "incident handling"),
    "MA": ("maintenance",),
    "MP": ("media protection", "media sanitization"),
    "PE": ("physical", "facility"),
    "PL": ("plan", "policy"),
    "PS": ("personnel", "screening"),
    "RA": ("risk assessment", "vulnerability", "scan", "nessus"),
    "SA": ("system acquisition", "sdlc", "supply chain"),
    "SC": ("system communication", "boundary protection", "firewall", "vpn", "tls"),
    "SI": ("system integrity", "patching", "patch management", "malware", "antivirus", "clamav"),
}


# Stopwords stripped from CRM narrative before tokenization. Keep tight
# — over-aggressive filtering kills the signal. Anything ≤ 3 chars is
# also dropped (see _extract_narrative_tokens).
_NARRATIVE_STOPWORDS: frozenset[str] = frozenset(
    {
        "the", "and", "for", "with", "this", "that", "from", "into", "shall",
        "must", "will", "responsible", "responsibility", "customer", "provider",
        "ensure", "ensures", "ensuring", "implement", "implements", "implementing",
        "system", "systems", "control", "controls", "security", "based", "such",
        "their", "they", "have", "been", "when", "where", "which", "where",
        "applicable", "appropriate", "required", "requirement", "requirements",
        "policy", "policies", "procedure", "procedures", "document", "documentation",
    }
)

_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{3,}")


# ---------------------------------------------------------------------------
# Pre-credit URI normalization
# ---------------------------------------------------------------------------
# ``SweepCandidate.path`` is drive-relative to the configured scan root
# (``SharePointSource.folder_path``), but ``Evidence.path`` is the full
# ``sharepoint://host/<server-relative-url>`` form. This helper reconstructs
# the canonical URI so the route layer can do a single batched IN-lookup
# against the unique-indexed ``Evidence.path`` column.
#
# Format must stay byte-identical to ``sharepoint._sharepoint_uri`` — that
# module imports from here, so we can't import the other direction without a
# circular import. If you change the ingest URI shape, change both places.
def normalize_sp_candidate_uri(
    candidate_path: str,
    site_url: str,
    library: str | None,
    folder_path: str | None = None,
) -> str:
    """Render a sweep ``SweepCandidate.path`` as a ``sharepoint://`` URI.

    Mirrors ``SharePointSource``'s ingest-time URI construction:
    ``sharepoint://{host}{site_path}/{library}/{folder_path}/{candidate_path}``
    with the path portion URL-quoted using ``safe='/'``. Idempotent and
    case-preserving — call site can pass either bare names or pre-stripped
    relative paths.

    Args:
        candidate_path: ``SweepCandidate.path`` — relative to the sweep's
            scan root (i.e. has ``folder_path`` already stripped if set).
        site_url: Full SharePoint site URL
            (e.g. ``https://host/sites/PRGM-EXAMPLE``).
        library: Document library name (defaults to ``Documents`` to match
            ``SharePointSource.__init__``).
        folder_path: The source's configured scan-root subfolder, or
            ``None``/empty when sweeping from the library root.
    """
    parsed = urlparse(site_url.rstrip("/"))
    host = parsed.netloc or parsed.path
    site_path = parsed.path if parsed.netloc else ""
    lib = (library or "Documents").strip("/")
    library_root = f"{site_path}/{lib}".replace("//", "/")
    folder = (folder_path or "").strip("/")
    cand = (candidate_path or "").strip("/")
    parts = [library_root.rstrip("/")]
    if folder:
        parts.append(folder)
    if cand:
        parts.append(cand)
    server_rel = "/".join(parts).replace("//", "/")
    return f"sharepoint://{host}{quote(server_rel, safe='/')}"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BoundaryFingerprint:
    """One-shot snapshot of what makes a file "boundary-relevant".

    Built per sweep request from the workbook + CRM + already-ingested
    evidence. Frozen so the scorer can't accidentally mutate it mid-pass.

    All token sets are lowercased.
    """

    # Either workbook_id OR system_context_id is set (at least one). Pre-
    # workbook sweeps (boundary docs ingested before a workbook is opened)
    # carry only system_context_id; once promoted, the same SystemContext
    # gains a workbook_id and both fields are populated for subsequent
    # sweeps. The route layer enforces "at least one"; this dataclass
    # itself stays permissive so unit tests can build fingerprints without
    # a full DB.
    workbook_id: int | None = None
    system_context_id: int | None = None
    host_tokens: frozenset[str] = frozenset()
    control_families: frozenset[str] = frozenset()  # e.g. {"AC", "AU"}
    in_scope_control_ids: frozenset[str] = frozenset()  # OSCAL canonical, e.g. {"ac-2", "ac-2.1"}
    crm_skip_families: frozenset[str] = frozenset()
    # control_id (lowercase canonical) -> set of tokens lifted from CRM narrative
    crm_keywords: dict[str, frozenset[str]] = field(default_factory=dict)
    doc_number_prefixes: frozenset[str] = frozenset()
    # control_id -> list of OSCAL-canonical CCI ids ("ac-2.1") for proposed mapping
    control_ccis: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # URL-decoded, lowercased, host-stripped path fragments lifted from the
    # user's saved priority links (Settings → SharePoint → Priority Links).
    # Each entry is a substring we match against the candidate's drive-
    # relative path — e.g. for a bookmarked
    # ``https://contoso.sharepoint.us/sites/MySite/Shared%20Documents/Policies``
    # we stash ``/sites/mysite/shared documents/policies`` AND the trailing
    # ``shared documents/policies`` and ``policies`` segments so we match
    # against both Graph webUrls and drive-relative paths the sweeper hands
    # to ``score_candidate``. ``label_by_prefix`` keeps the human label on
    # hand so the matched_signal can render as ``priority:Policies`` rather
    # than the opaque path slug.
    priority_path_prefixes: frozenset[str] = frozenset()
    label_by_priority_prefix: dict[str, str] = field(default_factory=dict)
    # Per-token provenance (Phase 2 — additive). Parallel to ``host_tokens``
    # but carries source attribution: each tuple is
    # ``(token, source_evidence_id_or_None, source_kind)`` where
    # ``source_kind`` is one of ``"doc_extracted"`` | ``"inferred"`` |
    # ``"unattributed"``. Defaults to empty for backward-compat — callers
    # that build fingerprints by hand (sweep_test.py) keep working without
    # touching this field. Tuple-of-tuples preserves the frozen dataclass's
    # hashability; readers MUST treat ``host_tokens`` as authoritative for
    # scoring (membership test) and ``host_token_sources`` as a parallel
    # provenance index for UI / 3PAO drill-down.
    host_token_sources: tuple[tuple[str, int | None, str], ...] = ()
    # Composite narrative pulled from SystemContext's freeform fields
    # (boundary / stakeholders / tech_inventory / requirement_hints).
    # Passed verbatim to the LLM judge so it can make semantic relevance
    # calls on candidates whose filename/path/snippet have no token
    # overlap with host_tokens — e.g. a network diagram described in
    # business-domain language with no hostnames in its filename. None
    # when the workbook has no SystemContext row yet, or all four
    # freeform fields are blank.
    system_narrative: str | None = None
    # Keywords lifted from the WORKBOOK ITSELF — the named artifacts an
    # eMASS CCIS workbook tells the assessor to look for. Sourced from the
    # in-scope objectives' implementation_guidance / assessment_procedures
    # and any prior-assessor narrative (column Q). This is the signal that
    # makes a workbook-only sweep (no SystemContext, no CRM, no host
    # inventory) actually find the documents the workbook names: e.g. a CCI
    # whose procedure says "examine the account management policy" yields
    # {"account", "management", "policy"} and lets "Account Mgmt Policy.docx"
    # surface even with zero host-token overlap. Lowercased, stopword- and
    # length-filtered at build time (precision over recall — generic
    # compliance verbs are dropped so this doesn't match everything).
    workbook_artifact_keywords: frozenset[str] = frozenset()

    def to_snapshot_dict(self) -> dict:
        """JSON-safe representation for round-tripping in sweep responses.

        Used by the UI's POST /sweep/decisions handler — the assessor's
        check/uncheck record needs the fingerprint frozen at decision
        time so batch recalibration can recompute features later even if
        the underlying workbook has changed (controls added/removed, CRM
        swapped, evidence retagged). Sorted everywhere so the same input
        produces the same JSON blob — that lets us dedupe identical
        snapshots at batch fit time.
        """
        return {
            "workbook_id": self.workbook_id,
            "system_context_id": self.system_context_id,
            "host_tokens": sorted(self.host_tokens),
            "control_families": sorted(self.control_families),
            "in_scope_control_ids": sorted(self.in_scope_control_ids),
            "crm_skip_families": sorted(self.crm_skip_families),
            "crm_keywords": {
                k: sorted(v) for k, v in sorted(self.crm_keywords.items())
            },
            "doc_number_prefixes": sorted(self.doc_number_prefixes),
            "control_ccis": {
                k: list(v) for k, v in sorted(self.control_ccis.items())
            },
            "priority_path_prefixes": sorted(self.priority_path_prefixes),
            "label_by_priority_prefix": dict(
                sorted(self.label_by_priority_prefix.items())
            ),
            # Parallel provenance index — sorted by token so the JSON blob is
            # deterministic for snapshot dedupe at batch-fit time.
            "host_token_sources": [
                {"token": tok, "source_evidence_id": ev_id, "source_kind": kind}
                for tok, ev_id, kind in sorted(self.host_token_sources)
            ],
            "system_narrative": self.system_narrative,
            "workbook_artifact_keywords": sorted(self.workbook_artifact_keywords),
        }


@dataclass(frozen=True)
class SweepCandidate:
    """One ranked file from the sweep. Ephemeral — not persisted.

    v0.2 semantic widening: ``score`` is now the *blended* score
    (``_KW_BLEND_WEIGHT * keyword_score + _LLM_BLEND_WEIGHT * llm_score``)
    when the LLM judge ran; falls back to ``keyword_score`` for rows where
    the judge wasn't called (judge disabled, cost cap hit mid-batch, or
    per-call API error). ``keyword_score`` and ``llm_score`` are preserved
    so the UI can show the breakdown; ``judge_used`` lets the row tell its
    own story.
    """

    name: str
    path: str
    web_url: str
    size: int | None
    modified: str | None  # ISO-8601 from Graph
    score: float
    matched_signals: tuple[str, ...]
    proposed_ccis: tuple[str, ...]
    snippet: str | None
    download_url: str | None  # @microsoft.graph.downloadUrl captured at walk
    # v0.2 judge fields. Default to "pure keyword" semantics so unit tests
    # that build SweepCandidate directly (sweep_test.py) keep working.
    keyword_score: float = 0.0
    llm_score: float | None = None
    judge_reasoning: str | None = None
    judge_used: bool = False
    # Pre-credit fields populated by the route layer after scoring (via
    # ``dataclasses.replace``). True when the candidate's stable URI already
    # exists in ``Evidence.path`` — the UI uses this to default-uncheck the
    # row, show an "In Evidence" badge, and keep coverage math honest.
    # See ``feedback_evidence_vs_sweep_split`` memory: sweep reads Evidence,
    # never writes it.
    already_in_evidence: bool = False
    existing_evidence_id: int | None = None

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "web_url": self.web_url,
            "size": self.size,
            "modified": self.modified,
            "score": round(self.score, 3),
            "matched_signals": list(self.matched_signals),
            "proposed_ccis": list(self.proposed_ccis),
            "snippet": self.snippet,
            "download_url": self.download_url,
            "keyword_score": round(self.keyword_score, 3),
            "llm_score": (
                round(self.llm_score, 3) if self.llm_score is not None else None
            ),
            "judge_reasoning": self.judge_reasoning,
            "judge_used": self.judge_used,
            "already_in_evidence": self.already_in_evidence,
            "existing_evidence_id": self.existing_evidence_id,
        }


@dataclass(frozen=True)
class SweepResult:
    """Outcome of one sweep pass. The UI renders this verbatim.

    Workbook decoupling (2026-06-05): ``workbook_id`` is now optional.
    Pre-workbook sweeps (boundary docs ingested before a workbook is
    opened) carry ``system_context_id`` only; once the pending
    SystemContext is promoted onto a workbook, future sweeps populate
    both. The route layer guarantees at least one is set.
    """

    scan_root: str
    workbook_id: int | None
    system_context_id: int | None
    candidates: tuple[SweepCandidate, ...]
    families_skipped_by_crm: tuple[str, ...]
    truncated: bool
    elapsed_ms: int
    # ID of the SweepWeights row that produced every score in this result.
    # None when the call ran with the hand-tuned constants (no active row in
    # DB, or tests calling score_candidate directly). The UI passes this
    # back on POST /sweep/decisions so each decision is anchored to the
    # exact weight vector that scored it — required for online SGD updates
    # to compute meaningful gradients later.
    weights_version_id: int | None = None
    # JSON-safe snapshot of the BoundaryFingerprint that produced these
    # candidates. The UI passes this back verbatim on POST /sweep/decisions
    # so each decision is anchored to the exact boundary state the assessor
    # saw. None for sweeps that don't intend to log decisions.
    fingerprint_snapshot: dict | None = None
    # ------------------------------------------------------------------
    # v0.2 LLM-judge telemetry. Defaults are "judge didn't run" so older
    # callers (and tests building SweepResult directly) keep working.
    # ------------------------------------------------------------------
    llm_cost_usd: float = 0.0
    llm_tokens_in_total: int = 0
    llm_tokens_out_total: int = 0
    cache_read_tokens_total: int = 0
    candidates_judged: int = 0
    judge_model: str | None = None
    judge_used: bool = False
    judge_fallback_reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "scan_root": self.scan_root,
            "workbook_id": self.workbook_id,
            "system_context_id": self.system_context_id,
            "candidates": [c.as_dict() for c in self.candidates],
            "families_skipped_by_crm": list(self.families_skipped_by_crm),
            "truncated": self.truncated,
            "elapsed_ms": self.elapsed_ms,
            "weights_version_id": self.weights_version_id,
            "fingerprint_snapshot": self.fingerprint_snapshot,
            "llm_cost_usd": round(self.llm_cost_usd, 6),
            "llm_tokens_in_total": self.llm_tokens_in_total,
            "llm_tokens_out_total": self.llm_tokens_out_total,
            "cache_read_tokens_total": self.cache_read_tokens_total,
            "candidates_judged": self.candidates_judged,
            "judge_model": self.judge_model,
            "judge_used": self.judge_used,
            "judge_fallback_reason": self.judge_fallback_reason,
        }


# ---------------------------------------------------------------------------
# Scoring weights — keep in lockstep with SHAREPOINT_SWEEP_DESIGN.md table
# ---------------------------------------------------------------------------
# These are the *historical hand-tuned defaults*. db.py seeds them into a
# v1 ``SweepWeights`` row at init, and the live sweep loads weights from
# DB via :func:`load_active_weights`. Tests that call :func:`score_candidate`
# without passing ``weights=`` fall back here, keeping unit tests session-
# free. SGD online updates and batch recalibration write *new* SweepWeights
# rows; these constants are never updated.

_W_HOST = 0.40
_W_CONTROL_ID = 0.30
_W_FAMILY = 0.20
_W_CRM_KEYWORD = 0.15
# 6th tier: candidate path matches a user-bookmarked priority-link folder
# (Settings → SharePoint → Priority Links). Weighted alongside CRM keyword
# because the assessor is *explicitly* telling us where the good evidence
# lives — that's at least as load-bearing as inferring it from a CRM
# narrative. Capped to 0.15 (not higher) so a junk PDF that happens to be
# inside a priority folder still needs another signal to pre-check; lone
# priority hits clear the surface threshold (0.30) only when combined
# with at least a doc-prefix or family-keyword match. That keeps "I
# bookmarked the whole library" from drowning the triage list.
_W_PRIORITY_LINK = 0.15
_W_DOC_PREFIX = 0.10

# Surface threshold — below this, a candidate is dropped before the UI
# ever sees it. Per the design memo: training the user to ignore noise
# kills the value of triage. Lowered to 0.05 (2026-06-07) because the
# content-fetch fallback now attaches a real text snippet to every
# ingestible item, and the LLM judge in Pass 2 (precheck threshold 0.60)
# is the real precision gate. Keeping the surface threshold high here
# was throwing out items the judge would have recognised as semantic
# matches even when keyword scoring alone couldn't find them.
SCORE_SURFACE_THRESHOLD = 0.05

# Pre-check threshold — rows ≥ this are checked by default in the UI so
# the common path is "review, uncheck noise, click ingest".
SCORE_PRECHECK_THRESHOLD = 0.60

# ---------------------------------------------------------------------------
# Keyword × LLM-judge blend (v0.2)
# ---------------------------------------------------------------------------
# When the LLM judge runs, the final SweepCandidate.score is
#   _KW_BLEND_WEIGHT * keyword_score + _LLM_BLEND_WEIGHT * llm_score
# Tilted 70/30 toward the LLM because the user picked accuracy over cost
# (2026-06-04 directive). Keyword keeps a third of the weight so a strong
# host/control-ID match isn't wiped out by an unconfident judge.
# Constants here (not in sharepoint.py) so unit tests can verify the blend
# without standing up the sweep route.
_KW_BLEND_WEIGHT = 0.30
_LLM_BLEND_WEIGHT = 0.70


# ---------------------------------------------------------------------------
# Active weights loader
# ---------------------------------------------------------------------------


def load_active_weights(session: Session) -> SweepWeights | None:
    """Return the currently-active ``SweepWeights`` row, or ``None``.

    The sidecar seeds a v1 ``source="manual"`` row at init (see
    ``db._seed_initial_sweep_weights``) so this normally returns the
    seeded record on first call. SGD online updates and batch recalibration
    write new rows with ``is_active=False``; operator flips ``is_active``
    after spot-check — at most one row carries the flag at any time.

    Callers should treat ``None`` as "use the hand-tuned defaults" so the
    sweep keeps working on a DB where init hasn't run yet (e.g. unit tests
    against an empty schema).
    """
    return session.exec(
        select(SweepWeights).where(SweepWeights.is_active.is_(True)).limit(1)  # type: ignore[union-attr]
    ).first()


# ---------------------------------------------------------------------------
# Fingerprint construction
# ---------------------------------------------------------------------------


def build_boundary_fingerprint(
    *,
    session: Session,
    workbook_id: int | None = None,
    system_context_id: int | None = None,
    priority_links: list[dict] | None = None,
) -> BoundaryFingerprint:
    """Materialize the boundary signal set for one workbook or pending scope.

    At least one of ``workbook_id`` / ``system_context_id`` must be set; the
    function ``ValueError``s otherwise. The route layer in
    ``routes/sharepoint.py`` enforces the same invariant on inbound requests
    so this is a belt-and-suspenders check for direct callers (tests,
    background jobs, etc.).

    Resolution rules:

    * If ``system_context_id`` is given, look that row up directly.
    * Else if ``workbook_id`` is given, find the SystemContext whose
      ``workbook_id`` matches.
    * Else (workbook_id only, no SystemContext yet) fall back to the
      singleton pending row (``workbook_id IS NULL``) — present on
      first launch only if the user ingested boundary docs before
      opening a workbook.

    Reads from four sources (in order):

    1. ``Evidence.host_inventory`` JSON across rows already ingested under
       this workbook — gives us the hostnames the assessor cares about.
       Falls back to an empty set on a fresh workbook OR pre-workbook sweep
       (still useful — the control-family and CRM signals carry the sweep).
    2. ``BaselineControl`` rows joined to ``Control`` — every in-scope
       control gives us a family letter and a control_id string. Out-of-
       scope rows are silently dropped (their CCIs are tailored out and
       we shouldn't be hunting for their evidence). **No baseline (no
       workbook, or workbook without a baseline) → empty in-scope sets**;
       per overlay-default-local that means *every* candidate is fair game
       and the scorer falls back to host/doc-prefix/priority signals only.
    3. :func:`build_crm_context` — the CRM responsibility map. A family
       is skip-eligible only when EVERY one of its in-scope controls has
       a CRM entry of provider/inherited/not_applicable. A single
       customer/hybrid control keeps the whole family in scope (per the
       overlay-default-local rule: silence = full customer assessment).
       Skipped entirely when no workbook is present.
    4. CRM narrative text — tokenized into per-control keyword sets,
       capped to 50 tokens per control.

    All token sets are lowercased. control_id strings are OSCAL canonical
    form ("ac-2", "ac-2.1") — same shape the Control table stores, so the
    scorer's intersection check after normalize_control_id() works directly.
    """
    if workbook_id is None and system_context_id is None:
        raise ValueError(
            "build_boundary_fingerprint requires at least one of "
            "workbook_id or system_context_id"
        )

    workbook: Workbook | None = None
    if workbook_id is not None:
        workbook = session.get(Workbook, workbook_id)
        if workbook is None:
            log.warning(
                "build_boundary_fingerprint: workbook %s not found", workbook_id
            )
            # Honor the original empty-fingerprint contract for callers
            # that pass a stale workbook_id, but only if no
            # system_context_id was supplied to fall back on.
            if system_context_id is None:
                return BoundaryFingerprint(workbook_id=workbook_id)

    # --- SystemContext resolution ---
    # Prefer the explicit system_context_id; else find one owned by the
    # workbook; else fall back to the singleton pending row. The pending
    # fallback only fires when a workbook was passed AND it has no
    # SystemContext of its own — useful for the just-promoted edge case
    # where the route layer hands us a workbook but extracted_tokens
    # still live on a row that hasn't been reparented yet.
    sc: SystemContext | None = None
    if system_context_id is not None:
        sc = session.get(SystemContext, system_context_id)
        if sc is None:
            log.warning(
                "build_boundary_fingerprint: SystemContext %s not found",
                system_context_id,
            )
    elif workbook_id is not None:
        sc = session.exec(
            select(SystemContext).where(SystemContext.workbook_id == workbook_id)
        ).first()
        if sc is None:
            sc = session.exec(
                select(SystemContext).where(SystemContext.workbook_id.is_(None))  # type: ignore[union-attr]
            ).first()

    # --- host_tokens (+ parallel provenance) ---
    # host_tokens stays AUTHORITATIVE for scoring (membership test in
    # score_candidate); host_token_sources is a parallel ledger keyed by
    # token for UI/3PAO drill-down. First-seen wins per token — duplicates
    # across Evidence rows collapse the same way host_tokens (a set) does.
    host_tokens: set[str] = set()
    host_source_by_token: dict[str, tuple[str, int | None, str]] = {}

    ev_rows = session.exec(
        select(Evidence.id, Evidence.host_inventory).where(  # type: ignore[arg-type]
            Evidence.host_inventory.is_not(None)  # type: ignore[union-attr]
        )
    ).all()
    for ev_id, blob in ev_rows:
        if not blob:
            continue
        try:
            hosts = json.loads(blob)
        except (TypeError, ValueError):
            continue
        if isinstance(hosts, list):
            for h in hosts:
                if isinstance(h, str) and h.strip():
                    tok = h.strip().lower()
                    host_tokens.add(tok)
                    host_source_by_token.setdefault(
                        tok, (tok, ev_id, "doc_extracted")
                    )

    # SystemContext seed tokens (Phase 2). Same weight as host_inventory
    # because these ARE host/service identifiers (hostnames, service names,
    # env labels) distilled from the assessor's freeform description by the
    # extraction LLM. Merging here keeps _W_HOST = 0.40 the highest weight
    # without inventing a new constant or re-tuning SCORE_SURFACE_THRESHOLD.
    #
    # Length + stopword filter (2026-06-07): the LLM occasionally hands back
    # narrative noise ("the", "policy", "do") alongside real host/env tokens.
    # Without a floor here, those words score +0.40 against every artifact
    # that happens to mention them — exactly the kind of spurious surface
    # credit that erodes 3PAO trust in the boundary signal. We use len>=3
    # (NOT the narrative path's len>=4) because real env labels like "iat",
    # "vpc", "aws" are 3 chars and load-bearing — the boundary eval cases
    # in tests/eval/boundary/cases/ssp_hosts_example_system.json pin this.
    #
    # Provenance: for each SC token, look up BoundaryTokenSource by
    # (sc.id, token). Pre-v0.2 SCs have no rows in the side table — those
    # tokens land in host_tokens (scoring keeps working) but degrade to
    # source_kind="unattributed" in the provenance ledger. This is the
    # 0004 migration's "no backfill" guarantee in action.
    if sc and sc.extracted_tokens:
        for raw_tok in sc.extracted_tokens:
            if not (isinstance(raw_tok, str) and raw_tok.strip()):
                continue
            tok = raw_tok.strip().lower()
            if len(tok) < 3 or tok in _NARRATIVE_STOPWORDS:
                continue
            host_tokens.add(tok)
            if tok in host_source_by_token:
                continue  # doc_extracted already attributed this token
            bts_row = None
            if sc.id is not None:
                bts_row = session.exec(
                    select(BoundaryTokenSource).where(
                        BoundaryTokenSource.system_context_id == sc.id,
                        BoundaryTokenSource.token == raw_tok,
                    )
                ).first()
            if bts_row is not None:
                host_source_by_token[tok] = (
                    tok,
                    bts_row.source_evidence_id,
                    bts_row.source_kind,
                )
            else:
                host_source_by_token[tok] = (tok, None, "unattributed")

    # --- in-scope controls ---
    # No workbook → no baseline → empty in-scope sets. Per
    # overlay-default-local that means every candidate is fair game and
    # the scorer falls back to host/doc-prefix/priority signals only.
    baseline_id = workbook.baseline_id if workbook is not None else None
    control_families: set[str] = set()
    in_scope_control_ids: set[str] = set()
    in_scope_controls_by_family: dict[str, list[str]] = {}

    if baseline_id is not None:
        rows = session.exec(
            select(Control)
            .join(BaselineControl, BaselineControl.control_id == Control.id)  # type: ignore[arg-type]
            .where(BaselineControl.baseline_id == baseline_id)
            .where(BaselineControl.in_scope.is_(True))  # type: ignore[union-attr]
        ).all()
        for ctrl in rows:
            family = (ctrl.family or "").upper().strip()
            if not family:
                continue
            control_families.add(family)
            in_scope_control_ids.add(ctrl.control_id)
            in_scope_controls_by_family.setdefault(family, []).append(ctrl.control_id)

    # --- control_id -> CCIs (for proposed_ccis) ---
    # Also harvest the workbook's *named-artifact* signal here: the catalog
    # guidance (Objective.implementation_guidance / assessment_procedures)
    # names the documents an assessor should go find ("examine the Account
    # Management Policy", "verify the audit log configuration"). A workbook-
    # only sweep otherwise has almost nothing to match on — host tokens come
    # from a SystemContext that may be empty, doc-prefixes need a pre-ingested
    # numbered doc — so without this the sweep enumerates SharePoint and
    # matches nothing useful. We accumulate the in-scope guidance text now and
    # tokenize it once at the end (one global cap) rather than per-objective.
    control_ccis: dict[str, tuple[str, ...]] = {}
    in_scope_objective_ids: set[int] = set()
    artifact_text_parts: list[str] = []
    if baseline_id is not None and in_scope_control_ids:
        # Exclude soft-deleted CCIs — evidence sweep should propose only
        # CCIs that the workbook currently surfaces, not dropped rows.
        cci_rows = session.exec(
            select(
                Control.control_id,
                Objective.objective_id,
                Objective.id,
                Objective.implementation_guidance,
                Objective.assessment_procedures,
            )
            .join(Objective, Objective.control_id_fk == Control.id)  # type: ignore[arg-type]
            .join(BaselineObjective, BaselineObjective.objective_id == Objective.id)  # type: ignore[arg-type]
            .where(
                BaselineObjective.baseline_id == baseline_id,
                BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
            )
        ).all()
        by_ctrl: dict[str, list[str]] = {}
        for ctrl_id, obj_id, obj_pk, impl_guidance, assess_proc in cci_rows:
            if ctrl_id not in in_scope_control_ids:
                continue
            by_ctrl.setdefault(ctrl_id, []).append(obj_id)
            if obj_pk is not None:
                in_scope_objective_ids.add(obj_pk)
            if impl_guidance and impl_guidance.strip():
                artifact_text_parts.append(impl_guidance)
            if assess_proc and assess_proc.strip():
                artifact_text_parts.append(assess_proc)
        control_ccis = {k: tuple(sorted(set(v))) for k, v in by_ctrl.items()}

    # --- prior-assessor narratives (column Q) as a search hint ---
    # The prior narrative is NEVER evidence on its own, but as a hint about
    # *which documents to look for* it's legitimate signal — a prior assessor
    # who wrote "examined the GitLab CI pipeline export" tells us the artifact
    # exists and roughly what it's called. Scoped to in-scope objectives only
    # so a deprecated/out-of-scope row's stale narrative can't pollute the
    # search. Skipped entirely when there are no in-scope objectives.
    if in_scope_objective_ids:
        narrative_rows = session.exec(
            select(Assessment.narrative_q).where(
                Assessment.workbook_id == workbook_id,
                Assessment.objective_id.in_(in_scope_objective_ids),  # type: ignore[union-attr]
            )
        ).all()
        for narrative in narrative_rows:
            if narrative and narrative.strip():
                artifact_text_parts.append(narrative)

    # Tokenize the combined artifact text once, with a single global cap so
    # the per-candidate scoring loop stays bounded regardless of workbook
    # size. _extract_narrative_tokens already lowercases, drops len<4 and the
    # generic stopwords ("policy", "procedure", "document", "control"...), so
    # "Account Management Policy" → {"account", "management"} — precise enough
    # not to match every file in the library.
    workbook_artifact_keywords: frozenset[str] = frozenset(
        _extract_narrative_tokens("\n".join(artifact_text_parts), limit=200)
    )

    # --- CRM skip families + per-control keywords ---
    crm = build_crm_context(workbook_id, session) if baseline_id is not None else CrmContext.empty()
    crm_skip_families: set[str] = set()
    crm_keywords: dict[str, frozenset[str]] = {}

    SKIP_RESPONSIBILITIES = {"provider", "inherited", "not_applicable"}
    for family, ctrl_ids in in_scope_controls_by_family.items():
        if not ctrl_ids:
            continue
        # Conservative: skip only when EVERY control in the family has a
        # skip-eligible CRM responsibility. A single customer/hybrid (or
        # *missing*, per overlay-default-local) entry keeps the family in.
        all_skip = True
        any_decisive = False
        for ctrl_id in ctrl_ids:
            entry = crm.lookup(_oscal_lower(ctrl_id))
            if entry is None:
                # No CRM entry → defaults to customer. Family stays in.
                all_skip = False
                break
            any_decisive = True
            if entry.responsibility not in SKIP_RESPONSIBILITIES:
                all_skip = False
                break
        if all_skip and any_decisive:
            crm_skip_families.add(family)

    # Per-control narrative keywords (only for non-skip controls).
    for ctrl_id in in_scope_control_ids:
        entry = crm.lookup(_oscal_lower(ctrl_id))
        if entry is None or not entry.narrative:
            continue
        if _family_of(ctrl_id) in crm_skip_families:
            continue
        toks = _extract_narrative_tokens(entry.narrative)
        if toks:
            crm_keywords[ctrl_id] = frozenset(toks)

    # --- doc number prefixes ---
    doc_prefixes: set[str] = set()
    dn_rows = session.exec(
        select(Evidence.doc_number).where(Evidence.doc_number.is_not(None))  # type: ignore[union-attr]
    ).all()
    for dn in dn_rows:
        if not dn:
            continue
        # Strip trailing digits to get the prefix (USD00050010 -> USD).
        m = re.match(r"^([A-Za-z]{2,})", dn.strip())
        if m:
            doc_prefixes.add(m.group(1).upper())
    # No fallback prefix: a "USD" default at one point seemed pragmatic but in
    # practice it issued a tenant-wide /search returning ~7k hits in ~100s per
    # sweep — pure cost, zero precision, because USD numbers are scattered
    # across every program. If a workbook has zero evidence with a doc_number,
    # let doc_prefixes stay empty; the host_tokens / control IDs / priority
    # prefixes still drive the sweep, and the user can ingest a single
    # numbered doc to bootstrap the prefix set legitimately.

    # --- priority-link prefixes (user-bookmarked folders) ---
    priority_prefixes, label_by_prefix = _extract_priority_prefixes(priority_links or [])

    # --- system narrative (for the LLM judge's semantic-relevance call) ---
    # The four freeform fields on SystemContext are the operator-curated
    # description of what the system IS — far richer signal than the
    # extracted_tokens list. Joining them with section headers so the
    # judge can tell scope language from inventory language from
    # requirements language.
    system_narrative: str | None = None
    if sc is not None:
        narrative_parts: list[str] = []
        if sc.boundary and sc.boundary.strip():
            narrative_parts.append("## Boundary\n" + sc.boundary.strip())
        if sc.stakeholders and sc.stakeholders.strip():
            narrative_parts.append("## Stakeholders\n" + sc.stakeholders.strip())
        if sc.tech_inventory and sc.tech_inventory.strip():
            narrative_parts.append("## Tech inventory\n" + sc.tech_inventory.strip())
        if sc.requirement_hints and sc.requirement_hints.strip():
            narrative_parts.append("## Requirements / standards\n" + sc.requirement_hints.strip())
        if narrative_parts:
            system_narrative = "\n\n".join(narrative_parts)

    return BoundaryFingerprint(
        workbook_id=workbook_id,
        system_context_id=sc.id if sc is not None else system_context_id,
        host_tokens=frozenset(host_tokens),
        host_token_sources=tuple(sorted(host_source_by_token.values())),
        control_families=frozenset(control_families),
        in_scope_control_ids=frozenset(in_scope_control_ids),
        crm_skip_families=frozenset(crm_skip_families),
        crm_keywords=crm_keywords,
        doc_number_prefixes=frozenset(doc_prefixes),
        control_ccis=control_ccis,
        priority_path_prefixes=frozenset(priority_prefixes),
        label_by_priority_prefix=label_by_prefix,
        system_narrative=system_narrative,
        workbook_artifact_keywords=workbook_artifact_keywords,
    )


def _extract_priority_prefixes(
    priority_links: list[dict],
) -> tuple[set[str], dict[str, str]]:
    """Lift matchable path fragments from saved priority-link URLs.

    For each ``{"label": ..., "url": ...}`` entry we generate up to three
    fragments from the URL's path:

      1. The full server-relative path (``/sites/mysite/shared documents/policies``)
      2. The path with the ``/sites/<site>/`` prefix stripped, since the
         sweeper hands ``score_candidate`` a drive-relative path that starts
         AFTER the document library segment.
      3. The trailing leaf segment alone (``policies``), so a deeply nested
         candidate still matches even if the leading segments differ in case
         or in encoding.

    All fragments are URL-decoded and lowercased. Empty / non-HTTP URLs are
    skipped silently. ``label_by_prefix`` keeps the original label keyed by
    every fragment so :func:`score_candidate` can surface the human-readable
    bookmark name in the matched_signals list.
    """
    prefixes: set[str] = set()
    label_by_prefix: dict[str, str] = {}

    for entry in priority_links:
        if not isinstance(entry, dict):
            continue
        url = (entry.get("url") or "").strip()
        label = (entry.get("label") or "").strip() or url
        if not url:
            continue
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        raw_path = unquote(parsed.path or "").strip().lower()
        if not raw_path or raw_path == "/":
            continue

        fragments: list[str] = [raw_path]
        # Strip leading "/sites/<sitename>/" — Graph drive-relative paths
        # don't carry the site prefix so a literal substring match would
        # never fire otherwise.
        m = re.match(r"^/sites/[^/]+/(.+)$", raw_path)
        if m:
            fragments.append("/" + m.group(1))
            fragments.append(m.group(1))
        # Trailing leaf — catches deeply nested artifacts even when their
        # parent libraries are renamed mid-assessment.
        leaf = raw_path.rstrip("/").rsplit("/", 1)[-1]
        if leaf and len(leaf) >= 3:
            fragments.append(leaf)

        for frag in fragments:
            frag = frag.strip()
            if len(frag) < 3:
                continue
            prefixes.add(frag)
            # First-write-wins on label — if the user bookmarks two overlapping
            # paths with different labels, the first-registered one keeps the
            # signal. Acceptable; both labels would point to the same folder.
            label_by_prefix.setdefault(frag, label)

    return prefixes, label_by_prefix


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def score_candidate(
    name: str,
    path: str,
    snippet: str | None,
    fingerprint: BoundaryFingerprint,
    *,
    weights: SweepWeights | None = None,
) -> tuple[float, list[str], list[str]]:
    """Score one file against the fingerprint. Pure function.

    Returns ``(score, matched_signals, proposed_ccis)``.

    ``score`` is float in [0.0, 1.0], additive cap. Signals beyond the
    cap don't compound — once we hit 1.0 we stop. ``matched_signals``
    is human-readable tags like ``["host:server01", "family:AC",
    "crm-kw:gitlab", "priority:Policies"]`` for the UI. ``proposed_ccis``
    is OSCAL-canonical CCI ids ("ac-2.1") for the controls this file
    looks like it touches, sorted and capped at 8 to keep the UI chips
    readable.

    ``weights`` — if provided, use the per-feature weights from a
    :class:`SweepWeights` row (typically loaded via
    :func:`load_active_weights`). Defaults to the module-level hand-tuned
    constants so tests and code paths that don't have a session stay
    working without a DB round-trip.

    Hard rule: a file whose only matched family is on
    ``crm_skip_families`` returns ``(0.0, [], [])`` — the caller drops it
    entirely. This is the "skip the whole AU family because the provider
    owns auditing" path.
    """
    # Resolve effective weights once at the top so the rest of the function
    # reads cleanly. None → hand-tuned constants (kernel-friendly default).
    w_host = weights.weight_host if weights is not None else _W_HOST
    w_control_id = weights.weight_control_id if weights is not None else _W_CONTROL_ID
    w_family = weights.weight_family if weights is not None else _W_FAMILY
    w_crm_keyword = weights.weight_crm_keyword if weights is not None else _W_CRM_KEYWORD
    w_doc_prefix = weights.weight_doc_prefix if weights is not None else _W_DOC_PREFIX
    w_priority_link = (
        weights.weight_priority_link if weights is not None else _W_PRIORITY_LINK
    )

    blob = " ".join(s.lower() for s in (name, path, snippet or "") if s)

    score = 0.0
    signals: list[str] = []
    matched_controls: set[str] = set()
    matched_families: set[str] = set()
    matched_non_skip_family = False
    # Tracks whether any signal independent of control-family matched
    # (host token, doc-number prefix, priority-link folder). The skip-family
    # veto below must NOT drop these candidates even when their only family
    # signal is on the skip list — a doc matching host:server01 AND a stray
    # "audit log" keyword is still evidence for the host, not pure provider
    # noise. Without this, host evidence vanishes silently whenever the doc
    # also brushes against a skip-family keyword.
    matched_non_family_signal = False

    # --- host tokens (+w_host, cap once) ---
    if fingerprint.host_tokens:
        for host in fingerprint.host_tokens:
            if _whole_word_in(host, blob):
                score = min(1.0, score + w_host)
                signals.append(f"host:{host}")
                matched_non_family_signal = True
                break  # cap once regardless of multi-hit

    # --- control id literals in name/path/snippet (+w_control_id) ---
    # Find all "AC-2", "AC-2(1)" style mentions; normalize to OSCAL canonical
    # ("ac-2", "ac-2.1") so the intersection with in_scope_control_ids — which
    # comes from Control.control_id, stored lowercase per _normalize_control_id
    # — actually matches. The regex only matches uppercase because that's the
    # convention assessors use in filenames; the DB convention is lowercase.
    found_ctrl_ids = set()
    for m in _CONTROL_ID_RE.finditer(blob.upper()):
        cid = _normalize_control_id(m.group(1))
        if cid in fingerprint.in_scope_control_ids:
            found_ctrl_ids.add(cid)
    if found_ctrl_ids:
        score = min(1.0, score + w_control_id)
        for cid in sorted(found_ctrl_ids):
            signals.append(f"control:{cid}")
            matched_controls.add(cid)
            matched_families.add(_family_of(cid))
            if _family_of(cid) not in fingerprint.crm_skip_families:
                matched_non_skip_family = True

    # --- family keyword hit (+w_family) ---
    family_hits: set[str] = set()
    for family, kws in _FAMILY_KEYWORDS.items():
        if family not in fingerprint.control_families:
            continue
        for kw in kws:
            if kw in blob:
                family_hits.add(family)
                break
    if family_hits:
        score = min(1.0, score + w_family)
        for fam in sorted(family_hits):
            signals.append(f"family:{fam}")
            matched_families.add(fam)
            if fam not in fingerprint.crm_skip_families:
                matched_non_skip_family = True

    # --- CRM narrative keyword hit (+w_crm_keyword) ---
    crm_kw_hits: set[tuple[str, str]] = set()  # (control_id, token)
    for ctrl_id, tokens in fingerprint.crm_keywords.items():
        if _family_of(ctrl_id) in fingerprint.crm_skip_families:
            continue
        for tok in tokens:
            if _whole_word_in(tok, blob):
                crm_kw_hits.add((ctrl_id, tok))
                break
    if crm_kw_hits:
        score = min(1.0, score + w_crm_keyword)
        # Surface the most distinctive 3 to keep signals list short.
        for ctrl_id, tok in sorted(crm_kw_hits)[:3]:
            signals.append(f"crm-kw:{tok}")
            matched_controls.add(ctrl_id)
            matched_families.add(_family_of(ctrl_id))
            matched_non_skip_family = True

    # --- doc number prefix in filename (+w_doc_prefix) ---
    for prefix in fingerprint.doc_number_prefixes:
        if prefix.lower() in name.lower():
            score = min(1.0, score + w_doc_prefix)
            signals.append(f"doc-prefix:{prefix}")
            matched_non_family_signal = True
            break

    # --- priority-link folder match (+w_priority_link) ---
    # The candidate's drive-relative path is checked against every fragment
    # the fingerprint extracted from the user's bookmarked priority links.
    # Cap once: a candidate that lives inside two overlapping bookmarks (a
    # parent and a child folder both saved) still only gets the boost once,
    # otherwise stacking would dominate the additive cap. The full path is
    # lowercased for case-insensitive containment.
    if fingerprint.priority_path_prefixes:
        lower_path = path.lower()
        for frag in fingerprint.priority_path_prefixes:
            if frag in lower_path:
                score = min(1.0, score + w_priority_link)
                label = fingerprint.label_by_priority_prefix.get(frag, frag)
                signals.append(f"priority:{label}")
                matched_non_family_signal = True
                break

    # --- skip-family veto ---
    # If we matched ONLY families on the skip list, drop the candidate.
    # (If even one non-skip family matched, the file probably touches
    # both and should still surface.)
    #
    # ``matched_non_family_signal`` guards against false negatives: a doc
    # matching host:server01 AND a stray skip-family keyword still
    # represents real host evidence, so don't veto it. Only pure-skip-
    # family-keyword matches with no other signal get dropped.
    if (
        matched_families
        and not matched_non_skip_family
        and not matched_non_family_signal
    ):
        return 0.0, [], []

    proposed = _propose_ccis(matched_controls, fingerprint)
    return score, signals, proposed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _whole_word_in(token: str, blob: str) -> bool:
    """Whole-word (or whole-phrase) substring match, lowercased.

    A bare ``in`` substring check fires for "ac" inside "track" — useless
    for short host names. We require the token to be word-bounded on
    both sides.
    """
    if not token:
        return False
    if " " in token:
        # Multi-word phrase — substring is fine; phrases of length ≥ 4
        # don't suffer the same false-positive risk.
        return token in blob
    pattern = r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])"
    return bool(re.search(pattern, blob))


def _extract_narrative_tokens(narrative: str, limit: int = 50) -> list[str]:
    """Lowercase, dedupe, stopword-filter, length-filter a CRM narrative.

    Returns up to ``limit`` tokens. Order preserved (first-seen wins) so
    the most prominent terms dominate when the cap bites.
    """
    seen: set[str] = set()
    out: list[str] = []
    for m in _TOKEN_RE.findall(narrative):
        tok = m.lower()
        if len(tok) < 4:
            continue
        if tok in _NARRATIVE_STOPWORDS:
            continue
        if tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
        if len(out) >= limit:
            break
    return out


def _family_of(control_id: str) -> str:
    """Extract the two-letter family from a control id ("AC-2(1)" → "AC")."""
    m = re.match(r"^([A-Z]{2})", control_id.upper())
    return m.group(1) if m else ""


def _oscal_lower(control_id: str) -> str:
    """Cheap lowercase + dot-normalize for CRM lookups.

    "AC-2(1)" → "ac-2.1", matching :func:`tagger._normalize_control_id`
    output that the CRM table keys against.
    """
    return _normalize_control_id(control_id)


def _propose_ccis(
    matched_controls: Iterable[str], fingerprint: BoundaryFingerprint
) -> list[str]:
    """Resolve matched control_ids → OSCAL canonical CCI list, capped at 8."""
    out: list[str] = []
    seen: set[str] = set()
    for ctrl_id in matched_controls:
        for cci in fingerprint.control_ccis.get(ctrl_id, ()):
            if cci in seen:
                continue
            seen.add(cci)
            out.append(cci)
            if len(out) >= 8:
                return sorted(out)
    return sorted(out)
