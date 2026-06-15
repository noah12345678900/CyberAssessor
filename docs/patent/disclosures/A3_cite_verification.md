# Invention Disclosure A3 — Literal Cite-Verification Hallucination Guard

> Grounding note: every mechanism described below was verified against the
> shipped source tree before writing. File paths and symbol names are real.
> Aspirational items from `CLAIMS_OUTLINE.md` not yet in code are explicitly
> marked **PLANNED — not yet reduced to practice**.

## Title

A deterministic guard that rejects a machine-generated compliance narrative when
any citation token it contains does not literally appear in the evidence text,
driving a re-prompt and ultimately an abstention rather than persisting a
fabricated reference.

## Field of the Invention

Automated information-security compliance assessment; specifically, post-hoc
verification of language-model-generated narratives to prevent fabricated
citations to evidence the model never actually had, as a hard, non-probabilistic
gate distinct from confidence thresholds.

## Background / Problem

Language models fabricate citations — they will cite a document number, STIG rule
ID, CCI reference, or control ID that was never in the evidence presented. A
self-reported confidence score does not catch this; the model is often most
confident precisely when it invents a plausible-looking reference. For a federal
compliance narrative that a 3PAO/JAB will read, a single hallucinated citation to
a nonexistent document is a defensibility failure: the auditor pulls the doc, it
isn't there, and trust in the entire automated assessment collapses. Probabilistic
"groundedness" scorers from the RAG literature do not give a hard guarantee.

## Summary of the Invention

After the model returns a narrative, a deterministic verifier extracts every
citation-shaped token (document numbers, STIG rule IDs, CCI references, control
IDs) using a fixed set of regexes and checks, by **literal case-insensitive
substring membership**, that each token actually appears in the evidence text that
was supplied for this assessment. Tokens that appear nowhere in the evidence are
returned as "unverified." Any unverified token causes the validator to emit an
`UNSUPPORTED_DOC_CITATION` rejection, which fails the verdict and drives the
retry loop; on retry exhaustion the engine abstains. The CCI ID and control ID of
the row under assessment are exempt (they are named in the prompt, not the
evidence), as are a small set of exempt sentinels (external CSPs, the
deterministic rule-8a sentinel). This is a hard membership gate, not a score.

## Detailed Description (shipped implementation)

The verifier lives in
`backend/cybersecurity_assessor/engine/validator.py::_verify_cites` and is wired
into the main `validate()` path.

- **Token extraction and membership test.** `_verify_cites(*, narrative,
  evidence_text, row)` lowercases both narrative and evidence, then iterates four
  compiled patterns — `_CITE_USD_RE`, `_CITE_STIG_RE`, `_CITE_CCI_RE`,
  `_CITE_CONTROL_ID_RE` — over the narrative. For each matched token it skips
  duplicates (via a `seen` set), skips row exemptions, and appends the token to
  `unverified` unless `token_lower in evidence_lower`. The function returns the
  list of unverified tokens; an empty list means all citations are verified (or
  there were none).
- **Row exemptions.** When a `row` is supplied, `row.cci_id` and `row.control_id`
  are added to `row_exemptions` and never flagged — these identify the control
  being assessed and legitimately appear in the prompt rather than the evidence.
- **Sentinel exemptions.** `_CITE_EXEMPT_SUBSTRINGS` covers narratives that are
  wholly an exempt sentinel (external CSP, deterministic rule-8a text); the loop
  does not return early, so any *other* citation accompanying a sentinel is still
  checked.
- **Wiring into the validator and retry loop.** In `validator.validate(...)`, the
  cite check runs only when `evidence_text` is present (deterministic rule-#8
  paths short-circuit before any LLM call and supply no evidence text). If
  `_verify_cites` returns a non-empty `unverified` list, the validator appends a
  `(RejectionReason.UNSUPPORTED_DOC_CITATION, ...)` rejection whose message names
  the offending tokens and instructs the model to remove the citation or
  re-attach evidence. A non-empty `rejections` list makes `ValidationResult.ok`
  false.
- **Retry / abstain consequence.** In `engine/assessor.py::_run`, a non-ok
  validation drives the next attempt of the `for attempt_no in
  range(self._max_retries + 1)` loop with corrective context; on exhaustion the
  loop falls through to `_abstain(...)`, which mints a `needs_review=True` decision
  so an unverifiable narrative is never persisted as a trusted verdict.
- **Stored evidence-shown ledger (provenance, co-shipped).** The evidence the
  model actually saw is captured per chunk in `models.py::AssessmentEvidenceShown`
  (`chunk_sha` + `chunk_text` + `order_index`), populated from the
  `EvidenceShownPayload` list snapshotted in `_run`. Citations that pass
  verification are persisted in `models.py::AssessmentCitation`. Together these
  give an auditor a stored record of both what was shown and what was cited.

### Relationship to the audit-citations co-emission path

`llm/client.py::build_user_message` contains an `audit_citations` addendum that
asks the model to co-emit a citations array for the audit trail. That co-emission
is a provenance feature; it is **not** the hallucination gate. The load-bearing
deterministic guard is `engine/validator.py::_verify_cites` described above, which
operates by literal membership against the evidence text regardless of whether the
audit-citations addendum was active.

### Per-call shown-token ledger (PARTIALLY as-shipped / scope note)

`CLAIMS_OUTLINE.md` Invention 3 frames the verified set as the exact tokens
"shown to the model in this call." As shipped, `_verify_cites` checks membership
against the full `evidence_text` passed into `validate()` (the same text supplied
to the model for that assessment), with per-chunk hashes recorded separately in
`AssessmentEvidenceShown`. The verification is therefore against the assessment's
evidence text rather than against a separately reconstructed per-call shown-token
set; a tighter coupling that verifies against the persisted per-chunk ledger
itself is a reasonable continuation but is **PLANNED — not yet reduced to
practice** as described. The membership-against-evidence-text guard and the
retry/abstain consequence are fully shipped.

## Novel / Non-obvious Elements

1. A hard, non-probabilistic hallucination gate: literal case-insensitive
   substring membership of each extracted citation token against the evidence
   text, rejecting any narrative containing a citation absent from the evidence.
2. A typed citation extractor (document number, STIG rule ID, CCI reference,
   control ID regexes) that bounds the gate to the reference forms that matter for
   compliance traceability.
3. Row-scoped exemptions (the assessed control's own CCI/control IDs) and sentinel
   exemptions (external CSPs, deterministic rule sentinels) that prevent
   false-positive rejections of legitimately prompt-named identifiers.
4. Coupling the gate to a retry loop with corrective context, and to an
   abstention on exhaustion, so an unverifiable narrative is never persisted as a
   trusted verdict.
5. A co-stored evidence-shown ledger (per-chunk content hashes) and verified-
   citation records, making the gate's basis independently auditable after the
   fact.

## Example Embodiment

The model returns a Compliant narrative for an audit-logging control that cites
"STIG rule SV-220123r1_rule" and "DoDI 8500.01." The evidence bundle for this CCI
contains the STIG rule ID but not "DoDI 8500.01." `_verify_cites` extracts both
tokens, finds the STIG ID in the evidence and the DoDI number absent, and returns
`["DoDI 8500.01"]`. The validator emits `UNSUPPORTED_DOC_CITATION`, the verdict
fails, and the retry loop re-prompts the model with instruction to drop the
unsupported citation. If the model keeps fabricating it across all retries, the
engine abstains with `needs_review=True`, and the row lands in the reviewer queue
instead of shipping a fabricated reference.

## Reduction to Practice

REDUCED TO PRACTICE. Implemented and shipped in
`engine/validator.py::_verify_cites` and its wiring in `validator.validate(...)`
(producing `RejectionReason.UNSUPPORTED_DOC_CITATION`), the retry/abstain
consequence in `engine/assessor.py::_run`, and the co-stored ledger in
`models.py::AssessmentEvidenceShown` / `AssessmentCitation`. The tighter
verify-against-the-persisted-per-chunk-ledger coupling is PLANNED.
