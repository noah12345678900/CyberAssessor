# Invention Disclosure A1 — Content-Addressed Decision Cache with Semantic Auto-Invalidation

> Grounding note: every mechanism described below was verified against the
> shipped source tree before writing. File paths and symbol names are real.
> Aspirational items from `CLAIMS_OUTLINE.md` that are not yet in code are
> explicitly marked **PLANNED — not yet reduced to practice**.

## Title

Content-addressed cache for machine-generated compliance decisions whose key
incorporates a semantic signature of the decision logic, providing automatic
invalidation on reasoning-logic change without an explicit cache-bust step.

## Field of the Invention

Automated information-security compliance assessment; specifically, caching of
non-deterministic, language-model-derived control verdicts so that re-running an
assessment over unchanged inputs is cheap and reproducible, while any change to
the underlying reasoning artifacts forces fresh evaluation.

## Background / Problem

Language-model-backed control assessment is expensive (per-call token cost,
wall-clock latency) and non-deterministic. A naive cache keys only on the input
record, so when the *reasoning logic* changes — the system prompt, the
deterministic rule kernel, or a tuning knob such as a confidence threshold — the
cache silently serves verdicts produced under stale logic. Conventional caches
require a human to remember to flush, and they cannot prove that a cached verdict
was produced under the logic currently in force. For a federal compliance tool
that must defend each verdict to a 3PAO/JAB, serving a stale verdict under a new
contract is a defensibility failure, not merely a performance one.

## Summary of the Invention

The cache key (a "fingerprint") is a SHA-256 hash computed over **both** a
normalized representation of the inputs **and** a semantic signature of the
decision logic. The semantic signature comprises (a) a `KERNEL_VERSION` string
that is hand-bumped on any rule-kernel change, (b) `PROMPT_SHA`, the SHA-256 of
the on-disk LLM system prompt file computed at import time, and (c) a
content-addressed `kernel_config_signature()` over the active tuning knobs
(confidence threshold, dual-pass flag). Because these participate in the key,
editing the prompt or bumping the kernel version changes every fingerprint, so
the next lookup is a clean miss and every prior verdict is *automatically*
invalidated — no DB migration, no manual flush. Volatile non-semantic fields
(spreadsheet row ordinal, parse timestamps, raw workbook metadata) are
deliberately excluded so cosmetic edits do not thrash the cache. Only
validator-accepted, LLM-derived decisions are written; cheap deterministic
short-circuits and abstentions are intentionally never cached.

## Detailed Description (shipped implementation)

The cache lives in `backend/cybersecurity_assessor/engine/decision_cache.py`.

- **Fingerprint construction.** `fingerprint(*, row, tagged_evidence,
  crm_context, audit_citations)` builds a payload dict containing
  `kernel_version` (`KERNEL_VERSION`, currently `"0.8.0"`), `prompt_sha`
  (`PROMPT_SHA`), `kernel_config` (`kernel_config_signature()` imported from
  `engine/assessor.py`), a `row` sub-payload from `_row_fingerprint_payload`, an
  `evidence_sha` (`_sha(tagged_evidence)`), a `crm` sub-payload from
  `_crm_fingerprint_payload`, and a boolean `audit_citations`. It serializes with
  `json.dumps(..., sort_keys=True, separators=(",", ":"))` for byte-stability and
  returns `_sha(encoded)`.
- **Deliberate exclusions.** `_row_fingerprint_payload` pulls only
  kernel-relevant fields and the module docstring documents the explicit
  exclusion of `excel_row`, `decided_at`, and the row `raw` blob — so reordering
  or re-parsing the same workbook yields the same fingerprint.
- **Prompt hashing.** `_compute_prompt_sha()` reads
  `llm/prompts/assess_control.md` and returns its SHA-256, with an empty-string
  sentinel on `OSError` that can never collide with a real hash (safe miss rather
  than a false hit).
- **Config signature.** In `engine/assessor.py`, `KernelConfig`,
  `active_kernel_config()`, and `kernel_config_signature()` snapshot the
  module-level `CONFIDENCE_THRESHOLD` and `DUAL_PASS_ENABLED` constants on every
  call (not memoized, so a test monkeypatch is observed) and hash them; the
  truncated hash is folded into the fingerprint payload.
- **Validator-gated write.** In `engine/assessor.py::_run`, the cache store call
  (`decision_cache.store(...)`) fires only on the validator-accepted LLM path
  (inside the `if result.ok:` branch), after `Decision(accepted=True, ...)` is
  minted. Deterministic short-circuits and abstain rows are never stored — the
  module docstring states this explicitly and the abstain path returns before any
  store call.
- **Lookup / replay.** `_run` computes the fingerprint unconditionally (sub-ms;
  also used by calibration telemetry), then under a lock (`self._cache_lock`,
  because the batch route fans work across worker threads sharing one session)
  calls `decision_cache.lookup()`, `bump_hit()`, and `replay()`. `replay()`
  deserializes the stored `Decision` and stamps `cache_source = "cache_hit"` so a
  replay is distinguishable from a fresh decision without losing the original
  semantic `source`.
- **Persistence model.** `models.py::DecisionCache` stores `fingerprint`
  (primary key), indexed `kernel_version` and `prompt_sha`, `payload_json`,
  `hit_count`, and `last_hit_at`. `store()` is idempotent via SQLite PK
  uniqueness.
- **Toggle-aware eviction.** The `audit_citations` flag is threaded into the
  fingerprint so flipping the audit toggle does not silently replay a
  citation-free decision; this is wired at the lookup site via
  `getattr(self._llm, "_audit_citations", False)`.

### Replay-after-evidence-arrival (PLANNED)

`CLAIMS_OUTLINE.md` Invention 1 cites an `engine/invalidation.py` that admits a
`rule_no_evidence` replay once evidence lands and flags the Assessment row. A
file/symbol search of the shipped tree did not locate `engine/invalidation.py`.
This dependent element is therefore marked **PLANNED — not yet reduced to
practice**; the shipped cache does not cache `rule_no_evidence` decisions at all
(deterministic short-circuit, never stored), so the described partial-invalidation
seam is not present in code as described.

## Novel / Non-obvious Elements

1. A cache key that hashes a *semantic signature of the decision logic*
   (kernel version + prompt hash + tuning-config hash) jointly with the inputs,
   such that a change to the reasoning artifacts auto-invalidates prior verdicts
   with no explicit bust step.
2. Computing the prompt signature as a content hash of the on-disk prompt file at
   import time, binding cache identity to the exact prompt text in force.
3. A snapshotted, content-addressed configuration signature over runtime tuning
   knobs that invalidates the cache on a knob change observed even via test
   monkeypatch.
4. Deliberate exclusion of presentation-only fields (row ordinal, timestamps,
   parser metadata) from the key, conferring immunity to cosmetic workbook edits.
5. A write policy that caches only downstream-validator-accepted decisions and
   never caches deterministic short-circuits or abstentions — conferring
   poisoning resistance and ensuring only trusted verdicts are reused.
6. Stamping replayed decisions with a cache-provenance marker that preserves the
   original semantic verdict source for telemetry.

## Example Embodiment

A reviewer assesses a 3,000-CCI workbook. On first run, each non-deterministic
verdict is produced by an LLM call and, if validator-accepted, written to
`DecisionCache` under its fingerprint. The reviewer cosmetically re-sorts the
workbook rows and re-runs: every fingerprint is unchanged (row ordinal excluded),
so all verdicts replay from cache with zero LLM calls. The team then edits
`assess_control.md` to tighten a narrative rule and redeploys; `PROMPT_SHA`
changes, every fingerprint changes, and the next run cleanly misses and
re-evaluates each CCI under the new prompt — without anyone clearing the table.

## Reduction to Practice

REDUCED TO PRACTICE. Implemented and shipped in
`engine/decision_cache.py` (fingerprint, lookup, store, replay, clear_all),
`engine/assessor.py` (config signature + lookup/store wiring in `_run`), and
`models.py::DecisionCache`. The `engine/invalidation.py` replay-after-evidence
element is PLANNED.
