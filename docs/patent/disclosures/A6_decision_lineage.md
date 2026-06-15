# Invention Disclosure A6 — Provenance-Complete Decision Lineage with Verdict-Source Discriminator

> Grounding note: every mechanism described below was verified against the
> shipped source tree before writing. File paths and symbol names are real.
> Aspirational items from `CLAIMS_OUTLINE.md` not yet in code are explicitly
> marked **PLANNED — not yet reduced to practice**.

## Title

A verdict-record store that binds each machine compliance verdict to a complete,
replayable lineage — the exact prompt and prompt hash, model identity / version /
temperature / request id, raw response, pass index, the per-chunk content-hashed
evidence actually shown, the verified citations, and a discriminator naming which
ordered decision gate produced the verdict.

## Field of the Invention

Automated information-security compliance assessment; specifically, the audit and
provenance data model that lets a 3PAO/JAB reconstruct and attribute every
automated verdict to the exact logic, inputs, and mechanism that produced it.

## Background / Problem

Auditors of an automated assessment must be able to reconstruct *why* a verdict
was reached, not merely read the answer. Existing tools store the conclusion (a
status and a narrative) but not the full causal chain: the exact prompt text, the
exact evidence the model was shown (as opposed to what merely existed in a file
somewhere), the model and version actually served, the decoding temperature, a
replay handle, and — critically — *which* of several decision mechanisms (a
deterministic rule, a CRM inheritance, a cache replay, the LLM, an abstention)
produced the verdict. Without that chain, a verdict cannot be defended, replayed,
or attributed to the logic in force when it was made.

## Summary of the Invention

Every verdict is bound to a complete, replayable lineage stored across four tables
plus an enum discriminator. A deduplicated `PromptSnapshot` (keyed by sha256)
stores the system prompt once. `AssessmentTrace` records, per LLM call, the
verbatim user message, the system-prompt sha (FK to the snapshot), the requested
model, the version actually served, temperature, max_tokens, request id, the full
raw response JSON, token usage, and a `pass_index`. `AssessmentEvidenceShown`
records the exact head/tail-truncated snippet the model saw, hashed per chunk
(`chunk_sha`) with its order and frozen relevance — proving "the model saw THIS
EXACT TEXT," not "the file contained this text somewhere." `AssessmentCitation`
links narrative claims to the evidence chunk that supports them. Finally, a
`VerdictSource` discriminator names the terminating gate from the cascade (rule /
CRM / SDA / no-evidence / cache / LLM / abstain), so each verdict is independently
reconstructable and attributable. The same `PROMPT_SHA` that keys the snapshot is
the prompt component of the decision cache fingerprint (disclosure A1), unifying
cache identity and provenance.

## Detailed Description (shipped implementation)

The lineage tables live in `backend/cybersecurity_assessor/models.py`; the
discriminator mapping and the persistence wiring live in
`backend/cybersecurity_assessor/routes/controls.py`.

- **Prompt snapshot (dedup by hash).** `models.py::PromptSnapshot` has `sha256` as
  primary key plus `text` and `prompt_kind`. The same prompt is shared across
  thousands of assessments per run, so it is stored once and referenced by hash.
- **Per-call trace.** `models.py::AssessmentTrace` is 1:N with Assessment, one row
  per LLM call: `system_prompt_sha` (FK to `PromptSnapshot`), `user_message`
  stored verbatim, `model` (requested), `anthropic_model_version` (served, after
  alias resolution), `temperature`, `max_tokens`, `request_id` (the response id —
  a deterministic replay handle), `raw_response_json` (the full parsed response),
  token counters, and `pass_index` (0 for single-pass, 0/1 for the dual-pass
  challenger of disclosure A4). The docstring is explicit that verbatim storage is
  chosen over reconstruction-on-demand precisely to preserve auditability across
  prompt/schema changes, and that request_id + temp-0 give byte-identical replay.
  Deterministic short-circuits write zero trace rows — there is no LLM call to
  trace.
- **Evidence-shown ledger.** `models.py::AssessmentEvidenceShown` records the
  exact snippet shown (`chunk_text`, including head+tail truncation), its
  `chunk_sha`, `order_index`, and frozen `relevance` / `tag_source` denormalized
  at capture time. It is distinct from the file hash (`Evidence.sha256`) and from
  the objective-scoped `EvidenceTag` — the point is to prove the model saw exactly
  this text in exactly this position.
- **Verified citations.** `models.py::AssessmentCitation` links a `claim_text` in a
  named `narrative_field` to an `evidence_shown_id` and a verbatim `source_quote`,
  with best-effort char offsets and an `extraction_method` discriminator. This is
  the persisted form of the citations verified by the guard in disclosure A3.
- **Verdict-source discriminator.** `models.py::VerdictSource` enumerates
  `RULE_8A/8B/8C`, `RULE_NO_EVIDENCE`, `CRM_PROVIDER/INHERITED/NOT_APPLICABLE/`
  `HYBRID_MIXED`, `CACHE_HIT`, `LLM_ACCEPT`, `LLM_AFTER_RETRY`, and `ABSTAIN`.
  `routes/controls.py::_decision_to_verdict_source` is the single source of truth
  that maps a kernel `Decision` to this enum, in a documented order: `cache_source
  == "cache_hit"` wins first (a replay keeps its original `source` string for
  telemetry but is tagged `CACHE_HIT` so cost queries don't double-count it as a
  fresh call); `needs_review` maps to `ABSTAIN` next; otherwise it dispatches on
  `Decision.source` (with the CRM family matched by prefix and a `+onprem_` suffix
  collapsing to `CRM_HYBRID_MIXED`); an unknown source falls back to `ABSTAIN` so
  a new emission site is never silently mis-tagged as a trusted bucket.
- **Persistence orchestration.** `routes/controls.py::_persist_audit_trail` writes
  the `PromptSnapshot` (insert-if-absent on its sha PK) + `AssessmentTrace` +
  `AssessmentEvidenceShown` + `AssessmentCitation` rows for one decided
  Assessment, and is a no-op for short-circuit decisions that carry empty
  trace/evidence payloads. The caller owns the commit boundary so the
  single-control and batch sites reuse their existing commit cadence.
- **Unified cache/provenance identity.** The prompt component of the cache
  fingerprint (`decision_cache.PROMPT_SHA`, disclosure A1) is the sha256 of the
  same on-disk system prompt that keys `PromptSnapshot.sha256`. Cache identity and
  audit provenance are therefore anchored to the same prompt hash, demonstrating a
  unified architecture rather than a bolted-on audit layer.

### Append-only downstream history (PARTIAL — disclosed)

The dependent element "append-only risk/decision history for downstream artifacts"
maps to `models.py::PoamRiskHistory` and `models.py::OdpAuditLog`, both present in
the shipped schema. These cover POA&M risk-score history and ODP-resolution audit
logging respectively; they are downstream-artifact histories rather than the
core verdict-lineage tables, and are cited here as supporting dependents. Their
full integration into a single cross-artifact lineage view is **PLANNED — not yet
reduced to practice** as a unified surface.

## Novel / Non-obvious Elements

1. Binding each verdict to a replayable trace: verbatim user message + system-
   prompt hash + requested model + served version + temperature + max_tokens +
   request id + raw response + pass index, chosen over reconstruction-on-demand
   specifically to survive prompt/schema drift.
2. An evidence-shown ledger that hashes the exact truncated snippet the model saw
   (`chunk_sha`) with order and frozen relevance — proving the model saw this
   exact text, distinct from the file hash and from objective-scoped tags.
3. A verdict-source discriminator naming the terminating decision gate, tying the
   provenance record directly to the ordered cascade of disclosure A2.
4. A documented, total mapping from kernel decision to discriminator in which
   cache-replay provenance wins first (so cost/reuse queries are correct) and any
   unknown or untrusted source defaults to the reviewer-queue bucket.
5. Unifying cache identity and audit provenance through a shared prompt hash
   (`PROMPT_SHA` == `PromptSnapshot.sha256`), so the same artifact that
   auto-invalidates the cache also anchors the audit lineage.
6. A persistence orchestration that is a precise no-op for deterministic short-
   circuits (no LLM call, no trace) yet writes a complete ledger for every
   model-produced verdict.

## Example Embodiment

An auditor opens a verdict produced by the LLM after one retry. The record's
`VerdictSource` reads `LLM_AFTER_RETRY`. Its two `AssessmentTrace` rows (a first
attempt and the retry) show the verbatim user messages, the served model version,
temperature 0, and request ids; re-issuing the request at temperature 0 returns a
byte-identical response, proving no drift. The `AssessmentEvidenceShown` rows show
the exact snippets the model saw, each with a `chunk_sha`, and the
`AssessmentCitation` rows tie each narrative claim to a specific shown chunk. A
sibling verdict reads `CRM_INHERITED` with zero trace rows — correctly showing no
model was consulted. The auditor can thus reconstruct and attribute every verdict
to its originating logic.

## Reduction to Practice

REDUCED TO PRACTICE. Implemented and shipped in `models.py` (`VerdictSource`,
`PromptSnapshot`, `AssessmentTrace`, `AssessmentEvidenceShown`,
`AssessmentCitation`, plus `PoamRiskHistory` / `OdpAuditLog`) and in
`routes/controls.py` (`_decision_to_verdict_source`, `_persist_audit_trail`),
with the shared `PROMPT_SHA` anchoring both cache identity (A1) and audit
provenance. A unified cross-artifact lineage view over the downstream history
tables is PLANNED.
