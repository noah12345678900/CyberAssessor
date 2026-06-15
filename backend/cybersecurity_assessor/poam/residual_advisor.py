"""POAM residual-risk advisor — LLM-powered, environment-aware.

Reads one :class:`Poam`, its contributing :class:`StigFinding` rows, and the
:class:`Assessment` narratives on every linked control, then asks the model
to propose a residual risk level after accounting for the system's boundary
and any compensating controls. The card is purely advisory — the assessor
applies (or ignores) the suggestion via the dedicated
``POST /poams/{id}/apply-residual-suggestion`` endpoint, which is the only
codepath that flips ``residual_risk_source`` to ``"llm_suggested"``.

Design contract (per plan dazzling-singing-blum.md and
``feedback_precision_over_recall``):

* The model MUST abstain (``suggested_residual = None``) when boundary
  context is insufficient — a wrong-but-confident residual is worse than
  no residual because suggestions surface as the UI default.
* The model MUST NOT propose a residual ABOVE ``raw_severity`` — residual
  analysis only downgrades or holds. An upgrade would mean the 800-30
  raw inputs are wrong, which the assessor owns on the likelihood / impact
  fields directly. ``validate_response`` enforces this server-side.
* The model output is rejected and a single retry is issued on JSON
  malformation OR enum-membership violation OR raw-severity overshoot.
  After the retry, hard-abstain (return a low-confidence None with a
  rationale that explains the parse failure) rather than crash the UI
  advisor card.

Caching mirrors :mod:`engine.decision_cache`:

* ``ADVISOR_KERNEL_VERSION`` bump invalidates every cached suggestion on
  the next render — used to ship reasoning-framework fixes without a
  manual cache wipe.
* ``ADVISOR_PROMPT_SHA`` is the sha256 of ``residual_advisor.md`` at
  import time — editing the prompt requires a sidecar restart to take
  effect, matching the assess-control prompt's invalidation behavior.
* Cache key is the sha256 over (advisor_version, prompt_sha, poam_id,
  input_digest) where ``input_digest`` hashes the POAM body + linked
  assessment narratives + contributing finding ids + raw_severity. Any
  edit to the linked narratives (which carry the boundary description)
  re-computes the digest and the next render is a clean miss.

Module is session-aware but session-free at import (matches the kernel's
session-free contract — route handlers own the session, the advisor just
consumes the lookup result).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol

from sqlmodel import Session, select

from ..models import (
    Assessment,
    Control,
    Objective,
    Poam,
    PoamObjective,
    ResidualSuggestionCache,
    RiskLevel,
    StigFinding,
)
from .risk import SCORES

# ---------------------------------------------------------------------------
# Invalidation knobs
# ---------------------------------------------------------------------------

# Bump on ANY advisor-logic change: prompt rewrite, validator rule edit,
# never-above-raw-severity threshold tweak, input-digest field addition,
# output-shape extension. Same contract as
# :data:`engine.decision_cache.KERNEL_VERSION` — semver-style bumps
# automatically invalidate every cached suggestion without touching the DB,
# so reviewers re-evaluate under the new contract on the very next render.
#
# 0.1.0 — Initial release. POAM residual-risk advisor with four-signal
# reasoning framework (network exposure, compensating controls, exploit
# prerequisites, POAM mitigation text). Abstain contract enforces
# precision-over-recall.
ADVISOR_KERNEL_VERSION = "0.1.0"

# Sha256 of the on-disk system prompt. Editing the prompt file requires a
# process restart to take effect — same restart story / same invalidation
# behavior as the assess-control prompt's PROMPT_SHA.
_PROMPT_PATH = (
    Path(__file__).resolve().parent.parent
    / "llm"
    / "prompts"
    / "residual_advisor.md"
)


def _compute_prompt_sha() -> str:
    """Sha256 of the on-disk advisor prompt; empty-sha sentinel if missing.

    The empty-string fallback never matches a real prompt hash, so the
    cache safely misses (rather than silently hitting a stale entry) when
    the prompt is unavailable for any reason.
    """
    try:
        return hashlib.sha256(_PROMPT_PATH.read_bytes()).hexdigest()
    except OSError:
        return ""


ADVISOR_PROMPT_SHA: str = _compute_prompt_sha()


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

# Control families whose linked narratives are the most reliable carriers
# of boundary / compensating-control information. Used by ``build_advisor_prompt``
# to highlight which linked-control narratives the model should weight
# heaviest. Not a filter — every linked control's narrative is included,
# but these get a ``** boundary-relevant **`` tag in the user message so
# the model can apply the reasoning-framework signal #1 (network exposure)
# without having to learn the control catalog.
BOUNDARY_RELEVANT_CONTROLS: frozenset[str] = frozenset(
    {
        "SC-7",   # Boundary protection
        "AC-3",   # Access enforcement
        "AC-17",  # Remote access
        "AC-4",   # Information flow enforcement
        "CA-3",   # System interconnections
        "SC-8",   # Transmission confidentiality
        "SC-32",  # System partitioning
        "SA-9",   # External system services
    }
)


_VALID_RESIDUAL: frozenset[str] = frozenset(
    level.value for level in RiskLevel
)
# Case-insensitive lookup: RiskLevel.value is title-case ("Moderate"), but the
# model emits whatever casing it likes (usually lowercase "moderate"). Without
# this normalization every well-formed suggestion failed the membership check
# and the advisor hard-abstained on every POAM. Mirrors the assess-loop's
# ``_STATUS_NORMALIZERS`` pattern in llm/client.py.
_RESIDUAL_NORMALIZERS: dict[str, RiskLevel] = {
    level.value.lower(): level for level in RiskLevel
}
_VALID_CONFIDENCE: frozenset[str] = frozenset({"low", "medium", "high"})
_MAX_KEY_FACTORS = 6
_KEY_FACTOR_MAX_CHARS = 80  # prompt says ≤60; allow modest slack before truncation
_RATIONALE_MAX_CHARS = 800  # prompt says ≤400; allow slack before truncation


@dataclass
class ResidualSuggestion:
    """LLM-proposed residual-risk verdict for one POAM.

    Travels round-trip through the cache as JSON. ``suggested_residual``
    is ``None`` whenever the model abstained OR the validator rejected
    the raw payload after the retry (an abstain on parse-failure path,
    distinguishable via ``confidence == "low"`` + a rationale that starts
    with ``"[parse_error]"`` or ``"[validation_error]"``).
    """

    suggested_residual: RiskLevel | None
    rationale: str
    confidence: Literal["low", "medium", "high"]
    key_factors: list[str] = field(default_factory=list)
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # Stamped by ``replay()`` so callers can distinguish a fresh LLM call
    # from a cache hit without losing the original-source distinction.
    cache_source: str | None = None


class LlmResidualClient(Protocol):
    """Structural Protocol for the LLM backend the advisor calls.

    Both :class:`llm.client.AnthropicClient` and
    :class:`llm.client.OpenAIClient` already expose
    ``extract_system_context(prompt) -> dict`` — that method is a generic
    "prompt in, JSON dict out" extractor (the system-context extractor's
    name is historical). We re-use it here rather than minting a parallel
    method so adapters don't need a residual-advisor-specific code path.

    Implementations MUST:
    * Return the parsed JSON envelope as a ``dict``.
    * Raise ``ValueError`` (or subclass) on malformed JSON so the advisor's
      retry loop can degrade gracefully to a parse-error abstain instead
      of crashing the UI card.
    """

    def extract_system_context(self, prompt: str) -> dict:  # pragma: no cover - Protocol
        ...


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _LinkedControlNarrative:
    """One linked-control's narrative bundle, ready for prompt formatting.

    Pulled by ``_collect_linked_narratives`` so ``build_advisor_prompt``
    stays a pure string builder. ``narrative_q`` is the canonical text;
    ``narrative_on_prem`` and ``narrative_cloud`` are the dual-narrative
    halves that hybrid systems split (see Assessment model). When the
    halves are populated the prompt prints both so the model can
    distinguish on-prem boundary descriptions from cloud ones.
    """

    control_id: str
    family: str
    title: str
    narrative_q: str
    narrative_on_prem: str | None
    narrative_cloud: str | None


def _collect_linked_narratives(
    poam: Poam, session: Session
) -> list[_LinkedControlNarrative]:
    """Return one narrative bundle per Control linked to ``poam``.

    Walks Poam → PoamObjective → Objective → Control, then loads the
    latest non-needs_review Assessment per (workbook, objective) and
    rolls up to the Control level by picking the first Assessment per
    Control. Deduped on ``Control.control_id``; sorted by family then id
    for stable prompt-byte output (matters for the input_digest hash).
    """
    if poam.id is None:
        return []

    rows = session.exec(
        select(Objective, Control)
        .join(PoamObjective, PoamObjective.objective_id == Objective.id)
        .join(Control, Control.id == Objective.control_id_fk)
        .where(PoamObjective.poam_id == poam.id)
    ).all()
    if not rows:
        return []

    # Group objective ids by control_id so we can pick the first available
    # Assessment per control. PoamObjective only retains objective ids that
    # were failing at POAM creation time — those are exactly the ones whose
    # narratives carry the relevant assessment-time judgment.
    by_control: dict[str, dict[str, object]] = {}
    for obj, ctrl in rows:
        ck = ctrl.control_id
        bucket = by_control.setdefault(
            ck,
            {
                "control_id": ck,
                "family": ctrl.family,
                "title": ctrl.title or "",
                "objective_ids": [],
            },
        )
        if obj.id is not None:
            bucket["objective_ids"].append(obj.id)  # type: ignore[union-attr]

    out: list[_LinkedControlNarrative] = []
    for ck in sorted(by_control, key=lambda k: (by_control[k]["family"], k)):
        bucket = by_control[ck]
        obj_ids = bucket["objective_ids"]  # type: ignore[assignment]
        if not obj_ids:
            continue
        # Pick the most recent non-abstain Assessment across those
        # objective ids inside this workbook. needs_review rows are
        # explicitly excluded — their narratives carry the LLM's guess
        # rather than the assessor's vetted text, which would poison the
        # boundary signal.
        asmt = session.exec(
            select(Assessment)
            .where(Assessment.workbook_id == poam.workbook_id)
            .where(Assessment.objective_id.in_(obj_ids))  # type: ignore[union-attr]
            .where(Assessment.needs_review == False)  # noqa: E712 — SQLAlchemy idiom
            .order_by(Assessment.created_at.desc())
        ).first()
        if asmt is None or not (asmt.narrative_q or asmt.narrative_on_prem or asmt.narrative_cloud):
            continue
        out.append(
            _LinkedControlNarrative(
                control_id=bucket["control_id"],  # type: ignore[arg-type]
                family=bucket["family"],  # type: ignore[arg-type]
                title=bucket["title"],  # type: ignore[arg-type]
                narrative_q=asmt.narrative_q or "",
                narrative_on_prem=asmt.narrative_on_prem,
                narrative_cloud=asmt.narrative_cloud,
            )
        )
    return out


def _collect_contributing_findings(
    poam: Poam, session: Session
) -> list[StigFinding]:
    """Return distinct StigFinding rows whose cci_refs touch this POAM's CCIs.

    Mirrors the join shape that ``poam/generator._collect_stig_findings_for_cluster``
    uses but inlined here so the advisor doesn't carry a hard dependency on
    the generator module. Distinct on ``rule_id`` so the same STIG check
    landing on multiple hosts only contributes once to the prompt.
    """
    if poam.id is None:
        return []
    cci_rows = session.exec(
        select(Objective.objective_id)
        .join(PoamObjective, PoamObjective.objective_id == Objective.id)
        .where(PoamObjective.poam_id == poam.id)
        .where(Objective.source == "CCI")
    ).all()
    ccis = {row for row in cci_rows if row}
    if not ccis:
        return []

    # SQLite has no array contains, so we LIKE-scan StigFinding.cci_refs
    # (comma-joined string). Cheap enough for the per-render cardinality
    # (single POAM = O(10) CCIs × O(100) findings).
    candidates = session.exec(select(StigFinding)).all()
    matched: dict[str, StigFinding] = {}
    for f in candidates:
        if not f.cci_refs:
            continue
        refs = {r.strip() for r in f.cci_refs.split(",") if r.strip()}
        if refs & ccis:
            # Dedup on rule_id — same rule across hosts = one prompt entry.
            matched.setdefault(f.rule_id, f)
    return sorted(matched.values(), key=lambda f: (f.severity or "", f.rule_id))


def _format_finding(f: StigFinding) -> str:
    sev = f.severity or "unknown"
    detail = (f.finding_details or "").strip()
    if len(detail) > 600:
        detail = detail[:600].rstrip() + "\u2026"
    return (
        f"- rule_id: {f.rule_id}\n"
        f"  severity: {sev}\n"
        f"  finding_details: {detail or '(no details)'}"
    )


def _format_narrative(n: _LinkedControlNarrative) -> str:
    tag = " ** boundary-relevant **" if n.control_id.upper() in BOUNDARY_RELEVANT_CONTROLS else ""
    lines = [f"### {n.control_id} — {n.title}{tag}"]
    if n.narrative_q:
        lines.append(f"narrative_q: {n.narrative_q.strip()}")
    if n.narrative_on_prem:
        lines.append(f"narrative_on_prem: {n.narrative_on_prem.strip()}")
    if n.narrative_cloud:
        lines.append(f"narrative_cloud: {n.narrative_cloud.strip()}")
    return "\n".join(lines)


def _level_str(level: RiskLevel | None) -> str:
    return level.value if level is not None else "(null)"


def build_advisor_prompt(
    poam: Poam,
    findings: list[StigFinding],
    narratives: list[_LinkedControlNarrative],
) -> str:
    """Render the user message for one residual-advisor LLM call.

    The system prompt (``residual_advisor.md``) is loaded by the LLM
    client itself; this function emits only the structured user message
    the prompt's "What you are reasoning over" section describes — three
    headers (``## POAM``, ``## Contributing findings``, ``## Linked control
    narratives``) and the per-field payload underneath each.
    """
    parts: list[str] = ["## POAM"]
    parts.append(f"vulnerability_description: {(poam.vulnerability_description or '').strip()}")
    if poam.mitigations:
        parts.append(f"mitigations: {poam.mitigations.strip()}")
    if poam.comments:
        parts.append(f"comments: {poam.comments.strip()}")
    if poam.relevance_of_threat is not None:
        parts.append(f"relevance_of_threat: {_level_str(poam.relevance_of_threat)}")
    parts.append(f"raw_severity: {_level_str(poam.raw_severity)}")
    parts.append(f"likelihood: {_level_str(poam.likelihood)}")
    if poam.likelihood_rationale:
        parts.append(f"likelihood_rationale: {poam.likelihood_rationale.strip()}")
    if poam.likelihood_source:
        parts.append(f"likelihood_source: {poam.likelihood_source}")
    parts.append(f"impact: {_level_str(poam.impact)}")
    if poam.impact_rationale:
        parts.append(f"impact_rationale: {poam.impact_rationale.strip()}")
    if poam.impact_source:
        parts.append(f"impact_source: {poam.impact_source}")

    parts.append("")
    parts.append("## Contributing findings")
    if findings:
        parts.extend(_format_finding(f) for f in findings)
    else:
        parts.append("(none)")

    parts.append("")
    parts.append("## Linked control narratives")
    if narratives:
        parts.extend(_format_narrative(n) for n in narratives)
    else:
        parts.append("(none)")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class ValidationError(ValueError):
    """Raised when the LLM payload violates the output contract.

    Distinct from a vanilla ``ValueError`` so ``suggest_residual``'s
    retry loop can tell apart "model returned bad JSON" (caught by the
    client itself) from "JSON parsed fine but didn't honor the contract"
    (caught here). Both paths feed the same retry, but the hard-abstain
    rationale messages differ so an auditor can tell what went wrong.
    """


def validate_response(
    raw: dict,
    *,
    raw_severity: RiskLevel | None,
) -> ResidualSuggestion:
    """Coerce the parsed JSON dict into a :class:`ResidualSuggestion`.

    Enforced rules (any violation → :class:`ValidationError` for retry):

    * ``suggested_residual`` is one of the 5 RiskLevel strings OR JSON null.
    * ``confidence`` is one of {"low", "medium", "high"}.
    * ``rationale`` is a string (truncated at :data:`_RATIONALE_MAX_CHARS`).
    * ``key_factors`` is a list of strings, at most :data:`_MAX_KEY_FACTORS`
      items, each truncated at :data:`_KEY_FACTOR_MAX_CHARS`.
    * Never propose a residual ABOVE ``raw_severity`` — the canonical hard
      rule. SCORES from poam.risk gives the ordinal comparison.
    """
    if not isinstance(raw, dict):
        raise ValidationError(f"expected JSON object, got {type(raw).__name__}")

    # suggested_residual: enum string OR null.
    sr_raw = raw.get("suggested_residual")
    suggested: RiskLevel | None
    if sr_raw is None:
        suggested = None
    elif isinstance(sr_raw, str) and sr_raw.strip().lower() in _RESIDUAL_NORMALIZERS:
        suggested = _RESIDUAL_NORMALIZERS[sr_raw.strip().lower()]
    else:
        raise ValidationError(
            f"suggested_residual must be one of {sorted(_VALID_RESIDUAL)} or null; "
            f"got {sr_raw!r}"
        )

    # Never above raw_severity. Only compare when both ends are set —
    # raw_severity should never be null in practice (the generator seeds
    # it from defaults if assessor inputs are missing), but defensive code
    # here means an early-development POAM doesn't crash the advisor.
    if suggested is not None and raw_severity is not None:
        if SCORES[suggested] > SCORES[raw_severity]:
            raise ValidationError(
                f"suggested_residual {_level_str(suggested)} exceeds "
                f"raw_severity {_level_str(raw_severity)}; residual analysis "
                "must only downgrade or hold."
            )

    # confidence: enum string (normalize casing — same defect class as
    # suggested_residual; the model may emit "High" instead of "high").
    conf_raw = raw.get("confidence")
    if isinstance(conf_raw, str):
        conf_raw = conf_raw.strip().lower()
    if not isinstance(conf_raw, str) or conf_raw not in _VALID_CONFIDENCE:
        raise ValidationError(
            f"confidence must be one of {sorted(_VALID_CONFIDENCE)}; got {conf_raw!r}"
        )

    # rationale: string, truncated.
    rationale_raw = raw.get("rationale", "")
    if not isinstance(rationale_raw, str):
        raise ValidationError(
            f"rationale must be a string; got {type(rationale_raw).__name__}"
        )
    rationale = rationale_raw.strip()
    if len(rationale) > _RATIONALE_MAX_CHARS:
        rationale = rationale[: _RATIONALE_MAX_CHARS - 1].rstrip() + "\u2026"

    # key_factors: list of strings, capped + per-item truncated.
    kf_raw = raw.get("key_factors", [])
    if not isinstance(kf_raw, list):
        raise ValidationError(
            f"key_factors must be a list; got {type(kf_raw).__name__}"
        )
    key_factors: list[str] = []
    for item in kf_raw[:_MAX_KEY_FACTORS]:
        if not isinstance(item, str):
            raise ValidationError(
                f"key_factors items must be strings; got {type(item).__name__}"
            )
        s = item.strip()
        if not s:
            continue
        if len(s) > _KEY_FACTOR_MAX_CHARS:
            s = s[: _KEY_FACTOR_MAX_CHARS - 1].rstrip() + "\u2026"
        key_factors.append(s)

    return ResidualSuggestion(
        suggested_residual=suggested,
        rationale=rationale,
        confidence=conf_raw,  # type: ignore[arg-type] — narrowed by the check above
        key_factors=key_factors,
    )


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _input_digest(
    poam: Poam,
    findings: list[StigFinding],
    narratives: list[_LinkedControlNarrative],
) -> str:
    """Sha256 over the POAM-content + linked-narrative + finding signal.

    Stable across process restarts via ``sort_keys + separators`` on the
    JSON encoder. Includes ``raw_severity`` so an assessor edit that
    changes likelihood/impact (and thus the computed raw) re-renders the
    advisor card.
    """
    payload = {
        "poam": {
            "vulnerability_description": poam.vulnerability_description or "",
            "mitigations": poam.mitigations or "",
            "comments": poam.comments or "",
            "raw_severity": _level_str(poam.raw_severity),
            "likelihood": _level_str(poam.likelihood),
            "impact": _level_str(poam.impact),
            "likelihood_rationale": poam.likelihood_rationale or "",
            "impact_rationale": poam.impact_rationale or "",
            "relevance_of_threat": _level_str(poam.relevance_of_threat),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity or "",
                "finding_details": (f.finding_details or "")[:600],
            }
            for f in findings
        ],
        "narratives": [
            {
                "control_id": n.control_id,
                "narrative_q": n.narrative_q,
                "narrative_on_prem": n.narrative_on_prem or "",
                "narrative_cloud": n.narrative_cloud or "",
            }
            for n in narratives
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return _sha(encoded)


def fingerprint(
    *,
    poam_id: int,
    input_digest: str,
) -> str:
    """Return the stable sha256 cache key for one advisor render.

    Mirrors :func:`engine.decision_cache.fingerprint` shape: sorted-keys
    JSON over the version knobs + the per-render input digest, then
    sha256. ``input_digest`` is computed separately so callers can reuse
    it (the route layer hashes once, looks up, and stores under the same
    digest on cache miss).
    """
    payload = {
        "advisor_version": ADVISOR_KERNEL_VERSION,
        "prompt_sha": ADVISOR_PROMPT_SHA,
        "poam_id": poam_id,
        "input_digest": input_digest,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return _sha(encoded)


def lookup_cache(
    session: Session, fp: str
) -> ResidualSuggestionCache | None:
    """Return the cached row for ``fp`` or None on miss. Side-effect-free.

    Hit-count bookkeeping is the caller's job (via :func:`bump_hit`); the
    inspect-only path stays clean so dry-run tooling can probe the cache
    without polluting telemetry.
    """
    return session.get(ResidualSuggestionCache, fp)


def bump_hit(session: Session, cached: ResidualSuggestionCache) -> None:
    """Increment ``hit_count`` and refresh ``last_hit_at`` on a cache hit."""
    cached.hit_count += 1
    cached.last_hit_at = datetime.now(timezone.utc)
    session.add(cached)
    session.commit()


def store_cache(
    session: Session,
    fp: str,
    *,
    poam_id: int,
    suggestion: ResidualSuggestion,
) -> None:
    """Persist ``suggestion`` under ``fp``. Idempotent on duplicate fp.

    SQLite's PK uniqueness gives us INSERT-OR-IGNORE semantics: a
    concurrent writer that beat us to the same fingerprint wins, we
    silently no-op. Both writes carry the same suggestion payload by
    construction — same fingerprint requires same inputs.
    """
    existing = session.get(ResidualSuggestionCache, fp)
    if existing is not None:
        return
    row = ResidualSuggestionCache(
        fingerprint=fp,
        advisor_version=ADVISOR_KERNEL_VERSION,
        prompt_sha=ADVISOR_PROMPT_SHA,
        poam_id=poam_id,
        decided_at=datetime.now(timezone.utc),
        payload_json=_serialize_suggestion(suggestion),
        hit_count=0,
        last_hit_at=None,
    )
    session.add(row)
    session.commit()


def _serialize_suggestion(s: ResidualSuggestion) -> str:
    """Encode a :class:`ResidualSuggestion` as JSON for cache storage.

    Round-trips losslessly through :func:`_deserialize_suggestion`.
    ``cache_source`` is NOT persisted — it's a transient tag stamped on
    replay so callers can distinguish hits from fresh decisions.
    """
    data = dataclasses.asdict(s)
    # Enum → value, datetime → ISO, drop transient cache_source.
    if isinstance(data.get("suggested_residual"), RiskLevel):
        data["suggested_residual"] = data["suggested_residual"].value
    if isinstance(data.get("decided_at"), datetime):
        data["decided_at"] = data["decided_at"].isoformat()
    data.pop("cache_source", None)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _deserialize_suggestion(payload_json: str) -> ResidualSuggestion:
    """Inverse of :func:`_serialize_suggestion`. Returns a fresh dataclass."""
    raw = json.loads(payload_json)
    sr = raw.get("suggested_residual")
    if isinstance(sr, str):
        raw["suggested_residual"] = RiskLevel(sr)
    if isinstance(raw.get("decided_at"), str):
        raw["decided_at"] = datetime.fromisoformat(raw["decided_at"])
    raw.setdefault("key_factors", [])
    raw.setdefault("cache_source", None)
    return ResidualSuggestion(**raw)


def replay(cached: ResidualSuggestionCache) -> ResidualSuggestion:
    """Materialize a :class:`ResidualSuggestion` from a cached row.

    Stamps ``cache_source = "cache_hit"`` so telemetry / UI can distinguish
    a fresh advisor render from a replayed one without an extra round-trip
    to the cache table.
    """
    suggestion = _deserialize_suggestion(cached.payload_json)
    suggestion.cache_source = "cache_hit"
    return suggestion


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _hard_abstain(reason: str, *, exc: Exception | None = None) -> ResidualSuggestion:
    """Build a low-confidence abstain when the model can't be trusted.

    Used after the retry budget is exhausted for parse errors, validation
    errors, or unrecoverable client errors. Tagged so the UI advisor card
    can render a distinct "parse failed" state rather than presenting the
    fallback as if it were a genuine model abstain.
    """
    detail = f": {exc}" if exc is not None else ""
    return ResidualSuggestion(
        suggested_residual=None,
        rationale=f"[{reason}]{detail}",
        confidence="low",
        key_factors=[],
    )


def suggest_residual(
    *,
    poam_id: int,
    session: Session,
    llm: LlmResidualClient,
    force_refresh: bool = False,
) -> ResidualSuggestion:
    """Render — or cache-hit — one residual-risk suggestion for a POAM.

    Caller is responsible for the session lifecycle. ``force_refresh=True``
    bypasses cache lookup and overwrites any existing entry — used by the
    UI's "Refresh suggestion" button.

    Returns a low-confidence abstain (``suggested_residual=None``,
    ``rationale="[parse_error: ...]"`` or ``"[validation_error: ...]"``)
    when the model output cannot be coerced after one retry — never
    raises, so the UI advisor card always has something to render. The
    abstain payload is NOT cached so the next render gets a fresh attempt.
    """
    poam = session.get(Poam, poam_id)
    if poam is None:
        raise ValueError(f"Poam {poam_id} not found")

    findings = _collect_contributing_findings(poam, session)
    narratives = _collect_linked_narratives(poam, session)
    digest = _input_digest(poam, findings, narratives)
    fp = fingerprint(poam_id=poam_id, input_digest=digest)

    if not force_refresh:
        cached = lookup_cache(session, fp)
        if cached is not None:
            bump_hit(session, cached)
            return replay(cached)

    prompt = build_advisor_prompt(poam, findings, narratives)

    # One retry on JSON-parse OR validation failure. The two are caught
    # together because the model's recovery move is the same for both:
    # re-issue the prompt verbatim. We don't add a "you got it wrong"
    # nudge because the temp-0 model would just repeat the same answer —
    # the second call is a probabilistic recovery, not a guided fix.
    raw_payload: dict | None = None
    last_exc: Exception | None = None
    last_reason = "parse_error"
    for attempt in range(2):
        try:
            raw_payload = llm.extract_system_context(prompt)
        except ValueError as exc:
            last_exc = exc
            last_reason = "parse_error"
            continue
        try:
            suggestion = validate_response(
                raw_payload, raw_severity=poam.raw_severity
            )
        except ValidationError as exc:
            last_exc = exc
            last_reason = "validation_error"
            continue
        # Success path — cache and return.
        store_cache(session, fp, poam_id=poam_id, suggestion=suggestion)
        return suggestion

    # Retry budget exhausted. Hard-abstain WITHOUT caching so the next
    # render gets a fresh attempt rather than replaying the parse failure
    # forever.
    return _hard_abstain(last_reason, exc=last_exc)
