# Invention Disclosure A5 — Precision-Over-Recall Abstention with Evidence-Absence as a Finding

> Grounding note: every mechanism described below was verified against the
> shipped source tree before writing. File paths and symbol names are real.
> A known rule-path persistence seam is disclosed explicitly per
> `CLAIMS_OUTLINE.md` §X.2 rather than recited as fully enabled.

## Title

A machine compliance engine tuned to decline rather than guess: when confidence
is insufficient or the assessor cannot be trusted, it emits a status-less,
durably-persisted review record; and it records documented absence of evidence as
an affirmative finding distinct from a non-compliance verdict.

## Field of the Invention

Automated information-security compliance assessment; specifically, the outcome
model and persistence policy that govern when the engine produces a verdict versus
when it abstains, and how the legally distinct "no evidence" condition is
recorded.

## Background / Problem

Compliance tools optimize coverage — they answer every requirement — and thereby
produce confident wrong verdicts that auditors must later unwind, which is more
expensive than an honest "needs review." Two failure modes are acute. First, an
abstention is often discarded (a dropped row), so the human never sees that the
machine was unsure. Second, tools conflate "no evidence was provided" with
"non-compliant," which is legally and procedurally distinct: the former is an
evidence-collection gap, the latter is an assessed deficiency. A defensible
federal tool must make abstention a first-class, durable outcome and must record
evidence-absence as its own finding.

## Summary of the Invention

The engine implements two coupled rules. (1) **Abstention is a first-class,
persisted outcome.** When the LLM's self-reported confidence is below a threshold,
when the challenger disagrees, when the model parse-errors, when citations cannot
be verified after retries, or when no LLM client is configured, the engine mints a
`needs_review=True` decision with `status=None`. Crucially it sets
`accepted=True` so the persistence layer *writes the row*; the export gates
(workbook writer, POA&M exporter) then filter on `needs_review` to keep untrusted
verdicts out of deliverables. The LLM's last guess is preserved on
`proposed_status` for reviewer triage and calibration, but `status` is coerced to
`None` so no untrusted verdict leaks to consumers that don't check `needs_review`.
(2) **Evidence-absence is an affirmative finding.** When the artifact bundle is
empty after all deterministic gates decline, the engine emits a deterministic
Non-Compliant finding (`source="rule_no_evidence"`, confidence 1.0,
`needs_review=False`) with a reviewer-friendly gap narrative — distinct from an
abstain, and distinct from a model-guessed non-compliance.

## Detailed Description (shipped implementation)

The two rules live in `engine/assessor.py` and are honored by the persistence
layer in `routes/controls.py`.

- **Confidence-floor abstain.** In `_run`'s LLM loop, even a validator-approved
  verdict (`if result.ok:`) is demoted when `proposal.confidence is not None and
  proposal.confidence < CONFIDENCE_THRESHOLD` (0.35): the engine returns
  `_abstain(..., status=proposal.status, ...)`. The inline comment names this the
  "implicit-abstain gate."
- **Abstain helper and hard status coercion.** `_abstain(...)` mints a Decision
  with `accepted=True` (so the row is written), `status=None`, and
  `proposed_status=status` (the LLM's guess preserved separately). Its docstring
  cites `feedback_precision_over_recall.md` and eval finding #3: prior behavior
  shipped the LLM's last status even when `needs_review=True`, feeding
  un-validated verdicts to consumers that don't check the flag; the coercion to
  `status=None` closes that. `_abstain` is the common exit for validator
  exhaustion, parse error, unverified cites, dual-pass disagreement, and the
  no-LLM-client path; it carries `trace_payload` and `evidence_shown` so an
  abstain is still fully auditable.
- **Evidence-absence as a finding.** `_finalize_no_evidence_decision(...)` returns
  a Decision with `status=ComplianceStatus.NON_COMPLIANT`, `confidence=1.0`,
  `needs_review=False`, `source="rule_no_evidence"`, and a narrative stating that
  no artifacts were retrieved so the objective is presumed not satisfied pending
  evidence. Its docstring is explicit that this is a *finding the assessor reports
  directly — not an abstain* (abstain is reserved for assessor-failure cases), and
  that downstream POA&M generation can latch onto `source="rule_no_evidence"` to
  cluster these into a single evidence-gap remediation. This separates the "no
  evidence" condition from both an abstain and a model-guessed NC.
- **Persistence preserves abstentions.** Because `_abstain` sets `accepted=True`,
  the batch persistence gate `if decision.accepted:` in `routes/controls.py`
  writes the row. The single-control and batch sites persist `needs_review` onto
  the Assessment, and the export gates downstream filter on it.
- **Abstain-persistence coercion (mitigation for the rule-path seam).**
  `routes/controls.py::_coerce_abstain_persistence_fields` exists so that a
  hard-abstain that would otherwise carry `status=None` is coerced for storage
  (Non-Compliant placeholder + `needs_review=True`) rather than silently dropped,
  per `feedback_abstain_status_none_drops.md`. This is the consumer-side guard
  that keeps status-less abstains visible in the reviewer queue.

### Known rule-path seam (disclosed, not recited as enabled)

`CLAIMS_OUTLINE.md` §X.2 flags that the *deterministic rule* path can still drop a
verdict: `_finalize_rule_decision` sets `accepted_narrative = narrative if accepted
else None` and returns `status = auto.status if accepted else None` when a rule
narrative fails the validator, and that rejected record is appended to the live
response but is not necessarily persisted on the rule path the way an LLM-path
abstain is. This disclosure therefore claims the *intended* abstain-persists
behavior — fully shipped on the LLM/abstain path and backed on the consumer side
by `_coerce_abstain_persistence_fields` — and does **not** recite the rejected
rule-narrative path as a reliably-persisted abstain. Closing that seam on the rule
path is **PLANNED — not yet reduced to practice**.

### Downstream-exporter preservation (PARTIAL — disclosed)

The dependent element "batch persistence preserving abstentions through downstream
exporters (SAR/POA&M)" is only partly shipped: per `CLAIMS_OUTLINE.md` §X.4, the
POA&M exporter and SAR exporter are not yet `needs_review`-gated, so abstentions
can leak into non-compliant counts in those artifacts. The persistence-layer
preservation of abstentions is shipped; the exporter-side gating is **PLANNED —
not yet reduced to practice**.

## Novel / Non-obvious Elements

1. Abstention as a first-class, durably-persisted outcome: a status-less
   `needs_review=True` record written to storage (via `accepted=True`) and
   surfaced for human adjudication, rather than a dropped row.
2. Hard status coercion on abstain (`status=None`) with the model's guess
   preserved on a separate `proposed_status` field, so no untrusted verdict leaks
   to consumers that don't check `needs_review`, while reviewers and calibration
   retain triage context.
3. A single abstain locus serving multiple failure modes (low confidence,
   challenger disagreement, parse error, unverified cites, no-client), each
   carrying full trace and evidence-shown payloads so an abstain is auditable.
4. Recording documented absence of evidence as an affirmative deterministic
   finding (`rule_no_evidence`, confidence 1.0) — distinct from an abstain and
   distinct from a model-guessed non-compliance — with a stable source tag that
   downstream remediation can cluster on.
5. A consumer-side coercion guard ensuring status-less abstains remain visible in
   the reviewer queue rather than being silently filtered by export gates.

## Example Embodiment

For one control the model returns Compliant at confidence 0.30. The verdict passes
the validator, but 0.30 < 0.35, so the engine abstains: it writes a
`needs_review=True`, `status=None` row preserving `proposed_status=Compliant`, with
the full trace attached. The reviewer sees the row in the queue, reads the model's
guess and its evidence, and makes the call. For an adjacent control no artifacts
were tagged; after every deterministic gate declines, the engine emits a
`rule_no_evidence` Non-Compliant finding at confidence 1.0 with a gap narrative —
which a POA&M step later clusters with other evidence-gap rows into one
remediation. The first row is honestly undecided; the second is an honest,
non-guessed gap; neither is a confident wrong answer.

## Reduction to Practice

REDUCED TO PRACTICE (with disclosed seams). Implemented and shipped in
`engine/assessor.py::_abstain` (first-class persisted abstain, status coercion),
the confidence-floor demotion in `_run`, `_finalize_no_evidence_decision`
(evidence-absence-as-finding), the `if decision.accepted:` persistence gate and
`_coerce_abstain_persistence_fields` in `routes/controls.py`. The rejected-rule-
narrative persistence seam and the SAR/POA&M `needs_review` exporter gating are
PLANNED.
