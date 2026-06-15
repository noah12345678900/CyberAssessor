# Invention Disclosure A4 — Adversarial Challenger Second Pass at Temperature 0

> Grounding note: every mechanism described below was verified against the
> shipped source tree before writing. File paths and symbol names are real.
> The default-disabled state of the capability is disclosed explicitly per
> `CLAIMS_OUTLINE.md` §X.3.

## Title

A deterministic adversarial second pass in which the same language model, at
decoding temperature 0, is asked to confirm or challenge its own first verdict,
and any material disagreement demotes the decision to an abstention rather than
resolving it by vote.

## Field of the Invention

Automated information-security compliance assessment; specifically, a self-review
mechanism that improves precision of language-model verdicts without resorting to
high-temperature self-consistency sampling or correlated ensembles.

## Background / Problem

Single-pass LLM verdicts are over-confident. The standard remedies are costly and
imperfect: ensembling/voting runs many correlated models and resolves
disagreement by majority, which can outvote the correct cautious answer;
self-consistency sampling *raises* temperature to diversify samples, which
increases hallucination — exactly the wrong direction for a compliance tool that
must defend each verdict. What is needed is a reproducible, auditable second look
that, when it disagrees with the first, makes the system *decline* rather than
*guess*.

## Summary of the Invention

When enabled, every LLM proposal is produced twice by the same model at
temperature 0. Pass 0 is the initial verdict. Pass 1 is a **challenger**: it is
prompted at temperature 0 with pass 0's verdict, narrative, and emitted citations,
and asked to CONFIRM or CHALLENGE. Because both passes are at temperature 0, the
challenger is reproducible and auditable. The comparison rule is
precision-preserving: a status mismatch (a CHALLENGE) demotes the decision to an
abstention flagged for human review — it is not resolved by vote. A status match
(a CONFIRM) keeps pass 0's narrative and citations as canonical and adopts the
lower confidence floor. Both passes are recorded with a `pass_index` so an auditor
can see exactly how the verdict was vetted.

## Detailed Description (shipped implementation)

The challenger logic lives in `engine/assessor.py::_run` (Step 2) behind the
module constant `DUAL_PASS_ENABLED`, with the two-call mechanism in
`llm/client.py`.

- **Two passes at temperature 0.** When `DUAL_PASS_ENABLED` is true, `_run` calls
  `self._llm.propose_twice(...)`. In `llm/client.py`, both the Anthropic and
  OpenAI implementations run pass 0 and pass 1 at `self._temperature` (the engine
  configures this to 0.0). Pass 0 uses the canonical user message
  (`build_user_message`); pass 1 uses `build_challenger_user_message`, which
  embeds pass 0's verdict + narrative + citations and asks the model to CONFIRM or
  CHALLENGE.
- **Disagreement → abstain (not vote).** Back in `_run`, after both passes return:
  if either pass set `abstain` (e.g. a `[parse_error]` sentinel), `_run` returns
  `_abstain(...)`. Otherwise, `if pass0.status != pass1.status:` the engine sets
  `outcome.dual_pass_disagreement = True`, builds a `dual-pass-disagreement`
  detail string naming both statuses and confidences, and returns `_abstain(...)`
  with `confidence=0.0` and both pass narratives recorded in `notes`. A CONFIRM
  (matching statuses) keeps pass 0 canonical.
- **Pass-0-canonical citation contract.** The inline comment pins the rule that
  the persister reads citations only from `pass_index == 0`, so pass 0 must remain
  the source of truth for the Assessment row even after a CONFIRM.
- **Per-pass provenance.** For each pass, `_run` appends a `TracePayload` with
  `pass_index` (0 = initial, 1 = challenger) plus model, model_version,
  temperature, request_id, raw_response_json, token usage, and emitted citations.
  These persist as `models.py::AssessmentTrace` rows carrying `pass_index`, so the
  audit trail can label the "Pass 1 (challenger review)" tab truthfully (see
  disclosure A6).
- **Composition with other gates.** The challenger sees the same shown-evidence
  set as pass 0 (it is built from the same `tagged_evidence`), so it composes with
  the literal cite-verification guard of disclosure A3; and because disagreement
  routes through `_abstain` with `needs_review=True`, it composes with the
  precision-over-recall abstention of disclosure A5.

### Cost-control gating on borderline confidence (PLANNED)

`CLAIMS_OUTLINE.md` Invention 4 cites a dependent element that gates the second
pass on borderline first-pass confidence, to spend the extra call only when the
first verdict is shaky. As shipped, the second pass runs unconditionally whenever
`DUAL_PASS_ENABLED` is true (no confidence-band gate around `propose_twice`). The
confidence-gated-challenger element is therefore **PLANNED — not yet reduced to
practice**.

### Default-disabled state (disclosed)

`DUAL_PASS_ENABLED` currently defaults to `False` in `engine/assessor.py`. The
challenger capability is fully implemented and exercised when the flag is enabled,
but it is not on the default decision path. Consistent with the outline's drafting
guidance, this disclosure recites the capability as **present and reduced to
practice but selectively enabled**; any reliance on it as the operative default
path requires enabling the flag first.

## Novel / Non-obvious Elements

1. A deterministic adversarial second pass by the *same* model at temperature 0,
   prompted with the first verdict and asked to CONFIRM or CHALLENGE — reproducible
   and auditable, unlike high-temperature self-consistency.
2. A precision-preserving comparison rule: material disagreement demotes the
   decision to an abstention for human review rather than resolving by majority
   vote.
3. A pass-0-canonical contract: on CONFIRM, pass 0's narrative and citations
   remain the source of truth and the lower confidence floor is adopted.
4. Per-pass provenance via a `pass_index`-tagged trace, enabling an audit panel to
   distinguish the initial verdict from the challenger review.
5. Constraining the challenger to the same shown-evidence set, composing cleanly
   with literal cite verification and with first-class abstention.

## Example Embodiment

With the challenger enabled, a control's pass 0 returns Compliant at confidence
0.6. Pass 1, at temperature 0, is shown pass 0's verdict and narrative and asked
to confirm or challenge; it concludes the cited configuration does not actually
cover the control objective and returns Non-Compliant. Because the statuses
differ, the engine does not pick a winner — it abstains with
`dual_pass_disagreement = True`, records both passes as `AssessmentTrace` rows
(`pass_index` 0 and 1), and queues the row for a human, who can read exactly why
the model disagreed with itself.

## Reduction to Practice

REDUCED TO PRACTICE (selectively enabled). Implemented and shipped in
`engine/assessor.py::_run` (the `DUAL_PASS_ENABLED` branch, disagreement→abstain
logic, per-pass `TracePayload`), `llm/client.py` (`propose_twice` /
`build_challenger_user_message`, both passes at temperature 0), and
`models.py::AssessmentTrace` (`pass_index`). The flag `DUAL_PASS_ENABLED` defaults
to `False`. The confidence-gated-challenger cost-control element is PLANNED.
