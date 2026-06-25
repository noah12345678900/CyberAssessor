"""Decision fingerprint cache for the patent-kernel orchestrator.

A re-run over an unchanged (CcisRow + tagged_evidence + CRM context +
prompt + kernel version) tuple must return the prior :class:`Decision`
without a fresh LLM call. The cache is keyed by a stable sha256
fingerprint that deliberately excludes:

* ``excel_row``        — re-orderings don't invalidate
* ``decided_at``        — timestamps don't invalidate
* row ``raw`` blob      — openpyxl metadata isn't part of the contract

…and deliberately INCLUDES:

* :data:`KERNEL_VERSION` — bumped on every kernel-logic change
* :data:`PROMPT_SHA`     — sha256 of ``assess_control.md`` (system prompt)
* sha of ``tagged_evidence`` — evidence re-ingest changes the hash
* CRM responsibility + narrative for the row's parent OSCAL control

When any of those change the fingerprint changes, and the next
``lookup()`` is a clean miss. There is no time-based eviction — the
cache is content-addressed and benign to grow.

Only LLM-derived Decisions are cached. Deterministic short-circuits
(rule 8a / 8b / CRM provider / CRM inherited / SDA 8c) are cheap to
recompute, and abstain rows are intentionally re-evaluated in case the
kernel learns better between runs.

The module is session-aware but session-free at import: callers pass a
:class:`sqlmodel.Session` only at lookup / store time. This matches the
kernel's session-free contract — route handlers own the session, the
kernel just consumes the lookup result.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from ..excel.ccis_reader import (
    CcisRow,
    _ccis_to_oscal_control_id,
    _normalize_control,
)
from ..models import (
    ComplianceStatus,
    DecisionCache,
    NarrativeClass,
)
from .crm_context import CrmContext

# ---------------------------------------------------------------------------
# Invalidation knobs
# ---------------------------------------------------------------------------

# Bump on ANY kernel-logic change: validator rule edit, supersession
# registry edit, rule #8 trigger change, dual-pass / confidence / boundary
# gate tuning, abstain-row contract change, CRM short-circuit change. The
# point of this string is that semver-style bumps automatically invalidate
# every cache entry without touching the DB — so reviewers re-evaluate
# under the new contract on the very next run.
#
# 0.4.0 — Audit v1 (verdict-to-evidence traceability). Adds
# ``trace_payload`` and ``evidence_shown`` fields to Decision. Old 0.3.0
# cache entries lack those fields, so a cache hit against a pre-0.4.0
# blob would replay an Assessment with no trace rows — defeating the
# auditability guarantee. Bumping the version forces every CCI to re-run
# under the new contract on first batch after upgrade, populating the
# audit tables for everything an auditor might subsequently inspect.
# 0.5.0 — Eval fixes from eval_v1.json forensic synthesis:
#   (1) Rule_8c now flips needs_review=True when the SDA-mapping whitelist
#       fires with no customer-side artifact tagged (review_reason carries
#       the mapping ID), so cache replays of a pre-0.5.0 8c hit would
#       silently ship a status=COMPLIANT row that the new contract would
#       have queued for review.
#   (2) Validator classifier is now hybrid-aware (splits on
#       ``## responsibility_split`` / "On-prem:" / "Cloud:" before phrase
#       matching) so cached "abstain via AMBIGUOUS" rows on hybrid
#       narratives would replay an abstain even though the new validator
#       would accept the verdict.
#   (3) Hard-abstain rows now coerce ``status=None`` and preserve the
#       LLM's guess on ``proposed_status``. Pre-0.5.0 cache blobs lack
#       ``proposed_status`` entirely and shipped status=<LLM-guess>, so a
#       cache replay would round-trip an un-coerced verdict.
# 0.6.0 — Dual-pass is now challenger-style instead of temperature-variance.
# Pass 0 is the initial verdict at temp 0.0; pass 1 is a CONFIRM-or-CHALLENGE
# review at temp 0.0 that sees pass 0's verdict + narrative + citations.
# Pre-0.6.0 cache entries carry pass 1 trace rows that were generated at
# temp 0.3 with the *base* user message (no challenger framing) — replaying
# them would mis-label the Audit trail panel's "Pass 1 (challenger review)"
# tab and lie to the auditor about how the verdict was vetted. Bumping the
# version forces every cached CCI to re-run under the challenger contract
# so the persisted trace matches the UI's narrative about it.
# 0.7.0 — CRM-absent → cloud-narrative bug fix. Pre-0.7.0 user messages
# omitted the ``crm_responsibility: <value>`` line entirely, so the system
# prompt's "absent → customer (on-prem only)" default rule had no signal
# to bind to — the LLM hallucinated cloud narratives on rows with no CRM
# attached. A cache replay against a pre-0.7.0 blob would round-trip the
# hallucinated cloud narrative even after the prompt-side fix lands,
# defeating the fix for every CCI already cached. Bumping the version
# forces every cached CCI to re-run under the new prompt contract so the
# persisted narrative actually reflects the absent-CRM signal.
# 0.8.0 — Rule 8c no longer uses program-specific control (PSC) text as
# evidence. Pre-0.8.0, a verified SDA Controls mapping short-circuited to
# COMPLIANT by restating the requirement's shall-statement as the
# narrative — i.e. the program-control requirement text was treated as
# proof the control was met, even with zero customer-side artifacts. The
# new contract demotes the mapping to a scope/applicability hint: no
# artifact → deterministic Non-Compliant gap (POA&M); artifact present →
# LLM assesses the artifacts with the mapping as context only. Cache
# replays of pre-0.8.0 8c blobs would round-trip the bogus COMPLIANT
# verdict (and its requirement-restatement narrative) past the fix, so
# every cached CCI must re-run under the new kernel.
# 0.9.0 — Boundary-context v1. Every narrative now carries the system
# boundary as a first-class part of the verdict story, and the kernel
# reasons explicitly about WHERE cloud (CSP) responsibility ends and
# customer/on-prem responsibility begins so it can derive the gaps that
# live at that seam. A deterministic boundary brief
# (system_context/brief.py) is woven into the assessment prompt after the
# corrective-context block and before the row, the prompt instructs the
# LLM to situate the verdict in the boundary and emit per-scope
# narratives keyed by scope_label, and ``narratives_by_scope`` is now
# populated on accepted Decisions. Pre-0.9.0 cache blobs were assessed
# with no boundary signal at all — replaying them would ship
# boundary-blind narratives (and empty ``narratives_by_scope``) past the
# fix, defeating the top-priority guarantee for every cached CCI. The
# boundary brief also participates in the fingerprint (``boundary_sha``)
# so two boundaries can never collide on a shared (row, evidence, CRM)
# tuple. Bumping forces every cached CCI to re-run boundary-aware.
# 0.10.0 — No-evidence short-circuit abstains instead of asserting failure.
# Pre-0.10.0, Step 1.65 minted a confident Non-Compliant
# (``source="rule_no_evidence"``, ``status=NON_COMPLIANT``,
# ``confidence=1.0``, ``needs_review=False``) whenever the evidence bundle
# was empty / context-only / None. Measured against the human-reviewed gold
# workbook this rule was wrong on 88% of the rows it touched (104 of 118):
# a missed retrieval is indistinguishable from a real gap at this layer, so
# asserting failure on zero evidence is a false Non-Compliant — the worst
# error class under FPR-first. The path now abstains (``source="abstain"``,
# ``status=None``, ``proposed_status=None``, ``confidence=None``,
# ``needs_review=True``) so the row is held for manual review and suppressed
# from the export rather than shipped as a fabricated failure. Cache replays
# of pre-0.10.0 no-evidence blobs would round-trip the confident NC past the
# fix for every CCI already cached, so every cached CCI must re-run under the
# new abstain contract.
#
# 0.11.0 — rule #8 rewrite (engine/rules.classify_row). The col-K/J-only
# rule_8b filter was inert in production (the generic DISA template text it
# matched never carries scope-exclusion rationale); NA is now recovered from
# the assessor's own col Q (results) / col U (previous_results) rationale via
# an explicit scope-exclusion recognizer, COMPLIANCE_GUARD-gated so a
# compliance claim in the same cell suppresses the NA lane. CSP / external-
# provider inheritance in Q/U now resolves COMPLIANT (inherited != NA), with
# the narrative paraphrasing the provider rather than quoting the NA-class
# trigger verbatim. Check order is load-bearing: col-K DoD-auto "automatically
# compliant" claims the row Compliant before any NA recognizer runs. Cached
# pre-0.11.0 decisions predate the Q/U NA lane and would replay ~0 NA verdicts
# past the fix, so every cached CCI must re-run.
#
# 0.12.0 — two prompt-hardening fixes to assess_control.md (no kernel/code
# change; both alter what the real LLM produces, so the cache must re-run):
#   (C) No phantom cloud scopes. A control whose descriptive prose (col F/J/K)
#       merely *mentions* cloud platforms ("differs by cloud: AWS GovCloud …
#       Azure Government …") made the LLM invent those clouds as assessment
#       scopes even with NO CRM and NO boundary block, then fault their absent
#       evidence → a wrong Non-Compliant despite sufficient on-prem evidence
#       (au-6 was the proven case). The prompt now states descriptive prose is
#       context, not a scope directive: with no CRM and no boundary block there
#       are no cloud scopes, so missing cloud evidence is not a finding.
#   (B) Per-scope citation hygiene. The LLM sometimes cited one boundary's
#       evidence inside another scope's narrative (e.g. an on-prem host STIG
#       written into a cloud scope's text), misattributing evidence across the
#       boundary seam in the stitched col-Q deliverable. The prompt now tells the
#       model to determine each artifact's owning boundary from its own content
#       and cite it only in that scope (shared enterprise-wide artifacts may span
#       scopes only when their text actually covers each).
#   0.13.0 (2026-06-22): hybrid-RAG evidence tagging. The Tier-5 candidate
#       selector was replaced (TF-IDF-only → sparse+HyDE+dense+triage+folder
#       fused by RRF) and images now get a vision description in addition to
#       OCR. Both change which evidence reaches which control — i.e. the tagged
#       evidence bundle a cached assessment was computed against — so every
#       cached decision must re-run against the new tag set.
# 0.14.0 (2026-06-24): Tier-5 escalation re-judge + modality-routed judge rubric.
#       A clean Haiku all-abstain on a substantive, non-command-error body now
#       re-judges once with the Opus escalation model, and the judge rubric gained
#       a terminal-vs-image routing branch (terminal failure-to-execute scores
#       0.0; image verification-step failure does not negate a deployed
#       mechanism). Both change which evidence reaches which control, so every
#       cached decision must re-run against the new tag set. The rubric lives in
#       tagger.py (NOT assess_control.md), so PROMPT_SHA does NOT capture it —
#       the KERNEL_VERSION bump is the ONLY thing forcing re-run here.
# 0.15.0 (2026-06-24): LOCATE-don't-drop. A failed/empty-but-tool-named artifact
#       is no longer dropped to zero tags; the single-purpose floor now emits a
#       distinct source="located_nonaffirming" tag when the judge ran and
#       declined (or a command-error suppressed escalation), at true-to-aboutness
#       relevance. The artifact is LOCATED/citable under its control and reaches
#       the verdict layer (where the rubric scores the failure 0.0 → NC/needs_
#       review with the artifact cited as examined-but-insufficient) but is NEVER
#       counted as affirming/compliant evidence. This changes the tag SET for
#       affected controls, so cached decisions must re-run. Tagger-side, not
#       PROMPT_SHA-visible — the bump is the re-run trigger.
# 0.16.0 (2026-06-24): tool-name tier scalability + tokenization fix. The
#       tool->control map moved from a hardcoded dict to config-driven YAML
#       (bundled default + per-program override); the filename tokenizer was
#       fixed (underscore was a word char, so CTP-013_clam_av_step8 never matched
#       key 'clamav'); and a broken folder x tool family-agreement guard was
#       removed (it suppressed cross-family floors like aide->SI-7 under CM).
#       Terse tool-named CTP files now floor their specific control -> tag set
#       changes -> cached decisions must re-run.
# 0.17.0 (2026-06-24): never-zero backstop + vision retry. A NON-EMPTY evidence
#       file can no longer end with zero tags: after all tiers + judge +
#       escalation + tool-floor, an untagged non-empty file is floored
#       located_nonaffirming to the judge's best declined candidate (>=0.3) or
#       the CA-2 quarantine control. describe_image also gets a bounded outer
#       retry so a 429-storm doesn't silently zero a valid image. Tag set grows
#       for previously-zero non-empty files -> cached decisions must re-run.
KERNEL_VERSION = "0.17.0"

# Sha256 of the system prompt that drives the LLM. Computed once at
# import time so editing the prompt file requires a process restart to
# take effect (matches ``llm.client._load_system_prompt``'s lru_cache
# semantic — same restart story, same invalidation behavior).
_PROMPT_PATH = (
    Path(__file__).resolve().parent.parent
    / "llm"
    / "prompts"
    / "assess_control.md"
)


def _compute_prompt_sha() -> str:
    """Sha256 of the on-disk system prompt; empty-sha sentinel if missing.

    The empty-string fallback never matches a real prompt hash, so the
    cache safely misses (rather than silently hitting a stale entry) when
    the prompt is unavailable for any reason.
    """
    try:
        return hashlib.sha256(_PROMPT_PATH.read_bytes()).hexdigest()
    except OSError:
        return ""


PROMPT_SHA: str = _compute_prompt_sha()


def _compute_validator_phrase_sha() -> str:
    """Sha256 of the validator's narrative-classification phrase tables.

    Finding #12 — folding the phrase tables into the fingerprint makes any
    edit to ``_AFFIRMING_PHRASES`` / ``_NA_PHRASES`` / ``_GAP_PHRASES``
    auto-invalidate cached decisions, instead of relying on a reviewer
    remembering to bump KERNEL_VERSION. A cached decision whose narrative
    classification was computed under the OLD phrase set must not be
    replayed once the table changes — the new table might classify the
    same narrative differently.

    Safe to import validator at module load: it imports only
    ``..excel.ccis_reader`` and ``..models`` (both already imported here)
    and does NOT import decision_cache or assessor, so there is no
    circular dependency.

    Serialized in a stable (sorted) order so a pure reordering of a table
    does not needlessly invalidate the cache, while any add/remove/edit
    does change the hash.
    """
    from .validator import _AFFIRMING_PHRASES, _GAP_PHRASES, _NA_PHRASES

    serialized = json.dumps(
        {
            "affirming": sorted(_AFFIRMING_PHRASES),
            "na": sorted(_NA_PHRASES),
            "gap": sorted(_GAP_PHRASES),
        },
        sort_keys=True,
    )
    return _sha(serialized)


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# Sha256 of the validator phrase tables, computed once at import (after
# ``_sha`` is defined). Folds into every fingerprint so a phrase-table
# edit auto-invalidates the cache — see _compute_validator_phrase_sha and
# Finding #12.
VALIDATOR_PHRASE_SHA: str = _compute_validator_phrase_sha()


def _row_fingerprint_payload(row: CcisRow) -> dict[str, Any]:
    """Pull only the kernel-relevant fields off ``row``.

    ``excel_row`` and ``raw`` are excluded on purpose so re-ordering /
    re-parsing the same workbook returns the same fingerprint.
    """
    return {
        "cci_id": row.cci_id or "",
        "control_id": row.control_id or "",
        "ap_acronym": row.ap_acronym or "",
        "implementation_status": row.implementation_status or "",
        "designation": row.designation or "",
        "narrative": row.narrative or "",
        "definition": row.definition or "",
        "guidance": row.guidance or "",
        "procedures": row.procedures or "",
        "inherited": row.inherited or "",
        "remote_inheritance": row.remote_inheritance or "",
        "previous_status": row.previous_status or "",
        "previous_results": row.previous_results or "",
    }


def _crm_fingerprint_payload(
    row: CcisRow, crm_context: CrmContext | None
) -> dict[str, Any]:
    """Resolve the CRM entry for ``row`` (if any) into a stable dict.

    CRM lookup is keyed on the OSCAL canonical id (``ac-2.1``), matching
    the assessor's own ``_lookup_crm`` path. When no CRM context is
    supplied or the row has no entry, return ``{}`` so the fingerprint
    cleanly differentiates "no CRM attached" from "CRM attached but
    silent on this control".
    """
    if crm_context is None or not row.control_id:
        return {"present": False}
    normalized = _normalize_control(row.control_id)
    if not normalized:
        return {"present": False}
    oscal_id = _ccis_to_oscal_control_id(normalized)
    entry = crm_context.lookup(oscal_id)
    if entry is None:
        return {"present": False}
    return {
        "present": True,
        "control_id": entry.control_id,
        "responsibility": entry.responsibility,
        "narrative": entry.narrative or "",
        "responsibility_onprem": entry.responsibility_onprem or "",
        "narrative_onprem": entry.narrative_onprem or "",
        "source_baseline_id": entry.source_baseline_id,
    }


def fingerprint(
    *,
    row: CcisRow,
    tagged_evidence: str | None,
    crm_context: CrmContext | None,
    audit_citations: bool = False,
    boundary_brief: str | None = None,
    override_epoch: int = 0,
) -> str:
    """Return the stable sha256 fingerprint for a (row, evidence, CRM) tuple.

    See module docstring for the exact set of fields included / excluded
    and the invalidation contract.

    ``audit_citations`` (Audit v1) participates in the fingerprint so a
    cached payload generated under flag=OFF (no ``citations`` array) does
    not silently satisfy a flag=ON run. Without this, flipping the toggle
    in Settings appears to be a no-op until the cache is manually cleared
    — the assess loop replays the citation-free Decision and the audit
    trail stays empty. Adding the bool here costs one extra cache entry
    per (CCI, evidence-set) pair when an operator toggles the flag mid-run
    — acceptable since the audit-prep workflow is the explicit reason to
    flip it on.

    ``boundary_brief`` (Boundary v1) is the deterministic system-boundary
    brief woven into the assessment prompt. It MUST participate in the
    fingerprint: the same CCI + evidence + CRM tuple assessed under two
    different system boundaries (e.g. a cloud CSP slice vs an on-prem
    slice, or two distinct programs that happen to share a CCI row and an
    evidence file) yields legitimately different boundary-situated
    narratives. Without the boundary in the key, the second workbook's
    assess would hit the first workbook's cached narrative and
    misattribute evidence across boundaries — the exact failure the
    boundary-context work exists to prevent. Hashed (not embedded) so the
    key stays fixed-width regardless of brief length.

    ``override_epoch`` (manual-override invalidation) is a per-objective
    counter bumped each time a reviewer manually edits a verdict via
    ``POST /api/assessments``. It MUST participate in the fingerprint:
    a manual override leaves the content (row + evidence + CRM) unchanged,
    so without the epoch a later ``/assess`` recomputes the identical key,
    hits the cache, and replays the stale pre-override Decision — silently
    clobbering the human's correction and re-raising ``needs_review``. The
    epoch defaults to 0, so a never-overridden objective computes exactly
    the legacy fingerprint and keeps sharing cache entries across
    workbooks; only the specific overridden CCI misses the cache and
    re-assesses fresh.
    """
    # Local import — assessor.py imports this module, so importing it at
    # module load would deadlock the circular. Cheap at call time.
    from .assessor import kernel_config_signature

    payload = {
        "kernel_version": KERNEL_VERSION,
        "prompt_sha": PROMPT_SHA,
        # v0.3 audit item #4: snapshot the active tuning configuration
        # (CONFIDENCE_THRESHOLD, DUAL_PASS_ENABLED) into the fingerprint
        # so a knob flip — by an operator or by a test monkeypatch —
        # automatically invalidates cached decisions made under the old
        # values. Without this, lowering the confidence floor would
        # silently leave high-confidence cached needs_review verdicts in
        # place, masking the precision-over-recall change.
        "kernel_config": kernel_config_signature(),
        # Finding #12 — phrase-table edits auto-invalidate the cache. Any
        # add/remove/edit to the validator's classification tables changes
        # this sha, so a decision whose narrative classification depended
        # on the old phrase set cleanly misses on the next lookup instead
        # of replaying a now-stale classification.
        "validator_phrase_sha": VALIDATOR_PHRASE_SHA,
        "row": _row_fingerprint_payload(row),
        "evidence_sha": _sha(tagged_evidence) if tagged_evidence else "",
        "crm": _crm_fingerprint_payload(row, crm_context),
        "audit_citations": bool(audit_citations),
        "boundary_sha": _sha(boundary_brief) if boundary_brief else "",
    }
    # Only inject the override epoch when it is non-zero. At the default
    # (0 — never manually overridden) the key is omitted entirely, so the
    # payload is byte-identical to the legacy one: the whole existing cache
    # survives this deploy and never-overridden objectives keep sharing
    # entries across workbooks. The key appears only for the specific
    # overridden CCI, forcing exactly that fingerprint to diverge.
    if override_epoch:
        payload["override_epoch"] = int(override_epoch)
    # Sorted keys + no whitespace → byte-stable across process restarts.
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return _sha(encoded)


# ---------------------------------------------------------------------------
# Lookup / store
# ---------------------------------------------------------------------------


def lookup(session: Session, fp: str) -> DecisionCache | None:
    """Return the cached row for ``fp`` or None if no hit.

    Hit-count bookkeeping is the caller's job (via :func:`bump_hit`); we
    keep lookup side-effect-free so dry-run / replay tooling can probe
    the cache without polluting telemetry.
    """
    return session.get(DecisionCache, fp)


def bump_hit(session: Session, cached: DecisionCache) -> None:
    """Increment ``hit_count`` and refresh ``last_hit_at`` on a hit.

    Split from :func:`lookup` so the inspect-only path stays clean.

    COMMITS immediately — and this is load-bearing, do NOT remove it (regression
    2026-06-20). A prior "perf" change dropped the commit on the theory that the
    staged counter could ride the next ``store`` commit. But the worker cache
    Session has autoflush ON: the worker's NEXT ``lookup`` (session.get) flushes
    this dirty UPDATE, acquiring SQLite's single write lock — and with no commit
    the lock is HELD for the rest of the batch. Eight batch workers each holding
    an uncommitted writer deadlock-contend on that lock → ``database is locked``
    after busy_timeout → 500 (hit hard on re-assess-after-CRM-attach, which is
    almost all cache hits). Committing here acquires AND releases the lock
    instantly, which is the non-contending behavior. A per-hit commit is cheap;
    a held lock is not.
    """
    cached.hit_count += 1
    cached.last_hit_at = datetime.now(timezone.utc)
    session.add(cached)
    session.commit()


def store(session: Session, fp: str, decision: "Decision") -> None:
    """Persist ``decision`` under ``fp``. Idempotent on duplicate fp.

    SQLite's PK uniqueness gives us INSERT-OR-IGNORE semantics: a
    concurrent writer that beat us to the same fingerprint wins, we
    silently no-op. That's the right behavior — both writes carry the
    same Decision payload by construction.
    """
    # Finding #11 — self-guard against caching a transient refusal.
    # Precision over recall: an abstain / needs_review / non-authoritative
    # verdict is NEVER a permanent answer — it must be re-evaluated on the
    # next run in case the user has since added the missing evidence.
    # Persisting it here would replay the stale refusal under the same
    # fingerprint forever, masking that new evidence. Today the only caller
    # guards this by convention; this makes the guard intrinsic so a future
    # caller or refactor cannot silently cache a false-negative. Skipping
    # the write is a no-op (caching is an optimization) — never raise.
    if (
        decision.needs_review
        or not decision.accepted
        or decision.status is None
    ):
        return
    existing = session.get(DecisionCache, fp)
    if existing is not None:
        return
    row = DecisionCache(
        fingerprint=fp,
        kernel_version=KERNEL_VERSION,
        prompt_sha=PROMPT_SHA,
        decided_at=datetime.now(timezone.utc),
        payload_json=_serialize_decision(decision),
        hit_count=0,
        last_hit_at=None,
    )
    session.add(row)
    session.commit()


# ---------------------------------------------------------------------------
# Decision serialize / replay
# ---------------------------------------------------------------------------


def _serialize_decision(decision: "Decision") -> str:
    """Encode a :class:`Decision` as JSON for cache storage.

    Handles the non-JSON-native field types (enums, datetimes, tuples
    inside ``rewrite_requested_refs``, nested dataclasses inside
    ``rejection_log`` / ``supersession_log`` / ``crm_short_circuit``).
    Round-trips losslessly through :func:`_deserialize_decision`.
    """
    data = asdict(decision)

    # Enum → value
    if isinstance(data.get("status"), ComplianceStatus):
        data["status"] = data["status"].value
    elif data.get("status") is not None and not isinstance(data["status"], str):
        # asdict() already unwrapped the enum value on most Pythons; this
        # branch is the belt-and-suspenders.
        data["status"] = str(data["status"])
    # Eval fix #3 — proposed_status is a ComplianceStatus | None mirror of
    # status used on abstain rows; serialize the same way.
    if isinstance(data.get("proposed_status"), ComplianceStatus):
        data["proposed_status"] = data["proposed_status"].value
    elif data.get("proposed_status") is not None and not isinstance(
        data["proposed_status"], str
    ):
        data["proposed_status"] = str(data["proposed_status"])
    if isinstance(data.get("narrative_class"), NarrativeClass):
        data["narrative_class"] = data["narrative_class"].value
    elif data.get("narrative_class") is not None and not isinstance(
        data["narrative_class"], str
    ):
        data["narrative_class"] = str(data["narrative_class"])

    # datetime → ISO 8601 string
    if isinstance(data.get("decided_at"), datetime):
        data["decided_at"] = data["decided_at"].isoformat()

    # Tuples inside rewrite_requested_refs serialize fine as JSON arrays;
    # we re-tuple them on the way back in _deserialize_decision.
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _deserialize_decision(payload_json: str) -> "Decision":
    """Inverse of :func:`_serialize_decision`. Returns a Decision instance.

    Local import of :class:`Decision` to avoid a circular import — this
    module is imported by ``engine/assessor.py``.
    """
    # Local import — Decision lives in assessor.py which imports us.
    from .assessor import Decision, EvidenceShownPayload, TracePayload
    from .measurement import CrmShortCircuit, SupersessionHit, ValidatorRejection

    raw = json.loads(payload_json)

    # Reconstruct enums.
    if raw.get("status") is not None:
        raw["status"] = ComplianceStatus(raw["status"])
    if raw.get("proposed_status") is not None:
        raw["proposed_status"] = ComplianceStatus(raw["proposed_status"])
    if raw.get("narrative_class") is not None:
        raw["narrative_class"] = NarrativeClass(raw["narrative_class"])

    # Reconstruct datetime.
    if isinstance(raw.get("decided_at"), str):
        raw["decided_at"] = datetime.fromisoformat(raw["decided_at"])

    # Reconstruct nested dataclasses.
    raw["rejection_log"] = [
        _rehydrate_dataclass(ValidatorRejection, d) for d in raw.get("rejection_log", [])
    ]
    raw["supersession_log"] = [
        _rehydrate_dataclass(SupersessionHit, d) for d in raw.get("supersession_log", [])
    ]
    if raw.get("crm_short_circuit") is not None:
        raw["crm_short_circuit"] = _rehydrate_dataclass(
            CrmShortCircuit, raw["crm_short_circuit"]
        )

    # JSON arrays inside rewrite_requested_refs → tuples (matches dataclass annotation).
    refs = raw.get("rewrite_requested_refs")
    if refs is not None:
        raw["rewrite_requested_refs"] = [tuple(pair) for pair in refs]

    # Audit v1 — rehydrate trace + evidence-shown lists. Defaults to []
    # so 0.4.0+ cache entries written before this codepath landed (none
    # currently exist, KERNEL_VERSION bumped concurrently) still load.
    raw["trace_payload"] = [
        _rehydrate_dataclass(TracePayload, d) for d in raw.get("trace_payload", [])
    ]
    raw["evidence_shown"] = [
        _rehydrate_dataclass(EvidenceShownPayload, d)
        for d in raw.get("evidence_shown", [])
    ]

    return Decision(**raw)


def _rehydrate_dataclass(cls, data: Any) -> Any:
    """Best-effort dataclass rehydrate that tolerates field drift.

    Only known fields are passed to ``cls(**...)``; unknown keys (e.g.
    fields added in a future KERNEL_VERSION) are silently dropped. The
    KERNEL_VERSION bump invariant means a real schema drift triggers a
    cache miss anyway, so this loop is just defensive.
    """
    if data is None:
        return None
    if not dataclasses.is_dataclass(cls):
        return data
    known = {f.name for f in dataclasses.fields(cls)}
    filtered = {k: v for k, v in data.items() if k in known}
    return cls(**filtered)


def replay(cached: DecisionCache) -> "Decision":
    """Materialize a :class:`Decision` from a :class:`DecisionCache` row.

    The replayed Decision keeps its original ``source`` (e.g. ``"llm"``,
    ``"rule_8a"``) — that's the semantic verdict source. The caller is
    responsible for stamping ``cache_source = "cache_hit"`` on the
    returned object so telemetry can distinguish a fresh decision from a
    replayed one without losing the original-source distinction.
    """
    decision = _deserialize_decision(cached.payload_json)
    decision.cache_source = "cache_hit"
    return decision


# ---------------------------------------------------------------------------
# Operator helpers
# ---------------------------------------------------------------------------


def clear_all(session: Session) -> int:
    """Wipe every cache row. Returns the number deleted.

    CLI escape hatch: ``cybersec cache clear``. Useful when a reviewer
    has corrected evidence outside the ingest path and wants to force
    re-evaluation of an entire workbook without bumping KERNEL_VERSION.
    """
    rows = session.exec(select(DecisionCache)).all()
    count = len(rows)
    for r in rows:
        session.delete(r)
    session.commit()
    return count
