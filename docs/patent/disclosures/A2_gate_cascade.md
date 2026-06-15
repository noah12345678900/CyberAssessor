# Invention Disclosure A2 — Deterministic-Rule + LLM Ordered-Precedence Gate Cascade

> Grounding note: every mechanism described below was verified against the
> shipped source tree before writing. File paths and symbol names are real.
> Aspirational items from `CLAIMS_OUTLINE.md` not yet in code are explicitly
> marked **PLANNED — not yet reduced to practice**.

## Title

A strictly ordered cascade of deterministic decision gates that can terminate a
machine compliance verdict before any language-model call, consulting an LLM only
as the last resort and tagging each verdict with the gate that produced it.

## Field of the Invention

Automated information-security compliance assessment; specifically, the control
flow by which a hybrid rules-plus-LLM engine decides each control requirement,
guaranteeing that cheap, certain determinations are made deterministically and
the costly non-deterministic model is invoked only when no deterministic gate
applies.

## Background / Problem

Pure-LLM compliance tools hallucinate and cannot guarantee that an obvious,
certain determination (e.g. an explicitly inherited control, or a control with no
evidence at all) is made deterministically. Pure rules-engines cannot read
free-text evidence. Existing hybrids typically run a rules engine and an LLM in
parallel and then reconcile the two, which is non-deterministic, double the cost,
and hard to audit because no single locus "decided" the verdict. For a federal
compliance tool that must defend each verdict, the engine must make the cheap
certain calls without a model, spend exactly one model budget when judgement is
genuinely required, and record which mechanism was responsible.

## Summary of the Invention

The engine evaluates each requirement record through a **fixed-precedence
cascade** of gates, each able to terminate and return a verdict before the next
is consulted: (1) deterministic rule #8a/#8b short-circuits; (1.5) a
customer-responsibility-matrix (CRM) short-circuit that returns inherited /
provider / not-applicable verdicts without a model call, plus a hybrid-enrichment
branch that prepends a responsibility-split block when only one scope is
inheritable; (1.6) a verified program-overlay (SDA Controls / rule 8c) gate that
emits a deterministic non-compliant gap when the mapping is in-scope but no
artifact is tagged, else demotes the mapping to a scope hint; (1.65) a
no-evidence gate that emits a deterministic non-compliant finding when the
artifact bundle is empty; (1.7) a content-addressed decision-cache lookup; and
only then (2) a single LLM call inside a validate-and-retry loop. Precedence is
total and the terminating gate is recorded, so every verdict carries which gate
decided it. The LLM is the last resort, not the default path.

## Detailed Description (shipped implementation)

The cascade is implemented in
`backend/cybersecurity_assessor/engine/assessor.py::Assessor._run`.

- **Step 1 — deterministic rule #8.** `rules.classify_row(row)` returns an
  `AutoStatusVerdict`. `COMPLIANT_8A` and `NOT_APPLICABLE_8B` each return
  immediately via `_finalize_rule_decision(..., source="rule_8a"|"rule_8b")`. No
  model is consulted.
- **Step 1.5 — CRM short-circuit / hybrid enrichment.** `self._lookup_crm(row,
  crm_context)` resolves the CRM entry. Both scopes (`responsibility`,
  `responsibility_onprem`) are collected; if every specified scope is in
  `_CRM_SHORT_CIRCUIT_SET = frozenset({"provider", "inherited",
  "not_applicable"})`, the engine returns `_finalize_crm_decision(...)` with no
  model call. If a scope is `hybrid` or the two scopes disagree, a
  responsibility-split block (`_render_hybrid_block`) is prepended to the evidence
  so the downstream LLM sees the boundary. The comment block documents the
  ordering invariant: rule #8 wins over CRM.
- **Step 1.6 — rule 8c (verified SDA overlay).**
  `supersession.lookup_verified_sda_mapping(row.cci_id)` gates this branch. When
  a mapping fires and no customer-side artifact is tagged, the engine returns
  `_finalize_sda_gap_decision(...)` — a deterministic non-compliant gap, no model
  call (absence of evidence is a finding, not a guess). When an artifact is
  present, the mapping is demoted to a scope hint (`_render_sda_scope_hint`)
  prepended to the evidence and the cascade falls through to the LLM.
- **Step 1.65 — no-evidence short-circuit.** When `evidence_block.text is None or
  evidence_block.is_only_context` (or, for legacy string callers, the
  `tagged_evidence` is blank), the engine returns
  `_finalize_no_evidence_decision(...)` — a deterministic non-compliant verdict
  (`source="rule_no_evidence"`, confidence 1.0, `needs_review=False`). The
  structural `is_only_context` check distinguishes a bundle containing only
  workbook-wide context wrappers from a real artifact bundle.
- **Step 1.7 — decision cache.** The fingerprint is computed unconditionally via
  `decision_cache.fingerprint(...)` (also used for calibration telemetry). Under
  `self._cache_lock` (the batch route fans work across worker threads sharing one
  session), `decision_cache.lookup` / `bump_hit` / `replay` short-circuit a hit
  before any LLM call. See disclosure A1 for the cache mechanism.
- **Step 2 — LLM within a validate-and-retry loop.** Only when all preceding
  gates decline does `_run` enter the `for attempt_no in range(self._max_retries +
  1)` loop that calls the model and runs `validator.validate(...)`. A null client
  routes to `_abstain` rather than failing. Even a validator-approved verdict
  whose self-reported confidence is `< CONFIDENCE_THRESHOLD` (0.35) is demoted to
  an abstain. The single-LLM-call economy is explicit: the comment at Step 1.7
  states "From this point on we're about to burn an LLM call."
- **Per-gate provenance tagging.** The terminating gate is recorded on
  `Decision.source` and mapped to a persisted discriminator by
  `routes/controls.py::_decision_to_verdict_source`, which dispatches
  `rule_8a` → `RULE_8A`, `rule_8b` → `RULE_8B`, `rule-8c` → `RULE_8C`,
  `rule_no_evidence` → `RULE_NO_EVIDENCE`, `crm_*` → the CRM family,
  `llm`/`llm_after_retry` → the LLM buckets, and routes any abstain or unknown
  source to `ABSTAIN`. Cache replays are tagged `CACHE_HIT` first. (See
  disclosure A6 for the full lineage.)

### Optional challenger stage (capability present, off by default)

The dependent "optional dual-pass / challenger stage" is implemented inside Step
2 behind `DUAL_PASS_ENABLED` (`engine/assessor.py`), which currently defaults to
`False`. The cascade therefore ships with the challenger path present but not
exercised by default. This is described fully in disclosure A4; for the cascade
claim it is a dependent capability, not part of the operative default path.

## Novel / Non-obvious Elements

1. A total, fixed-precedence ordering of decision gates in which each gate may
   terminate the verdict before the next is consulted, with the LLM occupying the
   final position rather than running in parallel with the rules.
2. A customer-responsibility short-circuit that returns inherited / provider /
   not-applicable verdicts with no model call, using a frozenset membership test
   over both cloud and on-prem scopes, and a hybrid-enrichment fallthrough that
   prepends a responsibility-split block only when exactly one scope is
   inheritable.
3. A program-overlay gate that distinguishes "in-scope but undemonstrated"
   (deterministic non-compliant gap, no model call) from "in-scope with
   artifacts" (overlay demoted to a non-evidentiary scope hint, fall through to
   the model) — refusing to treat a requirement restatement as proof.
4. A structural no-evidence gate that fires on a context-only bundle
   (`is_only_context`), not merely an empty string, preventing wrapper-only
   bundles from reaching the model.
5. Single-LLM-call economy: every deterministic gate that can decide does so
   before any token budget is spent, and the cache is consulted immediately
   before the model.
6. Recording the terminating gate as a per-verdict discriminator so every
   decision is attributable to the mechanism that produced it.

## Example Embodiment

A reviewer assesses a control whose CRM entry marks both scopes "inherited." Step
1.5 short-circuits to an inherited verdict with zero LLM calls. The next control
has no CRM entry and no tagged artifacts; rule #8 declines, CRM declines, the SDA
overlay declines, and Step 1.65 emits a deterministic non-compliant finding —
again zero LLM calls. A third control has artifacts and no deterministic answer;
gates 1 through 1.65 decline, the cache misses, and exactly one LLM call is made
inside the retry loop. Each of the three verdicts is persisted with a distinct
`VerdictSource` (`CRM_INHERITED`, `RULE_NO_EVIDENCE`, `LLM_ACCEPT`), so an auditor
can see precisely which mechanism decided each row.

## Reduction to Practice

REDUCED TO PRACTICE. Implemented and shipped in
`engine/assessor.py::Assessor._run` (the ordered cascade and all gate
finalizers), `engine/assessor.py` constants (`_CRM_SHORT_CIRCUIT_SET`,
`CONFIDENCE_THRESHOLD`), and `routes/controls.py::_decision_to_verdict_source`
(per-gate provenance). The optional challenger stage ships behind
`DUAL_PASS_ENABLED`, which defaults to `False`; it is a present-but-not-default
dependent capability (see A4).
