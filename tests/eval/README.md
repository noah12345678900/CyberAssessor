# LLM eval harness — scaffold + 11 seed cases + live-LLM mode

Data-driven regression eval for `Assessor.assess(...)`. Each JSON file
under `cases/` pins one frozen `(CcisRow, tagged_evidence,
LLM-stub-proposals) → expected (status, source, needs_review, narrative
regex)` tuple. Adding a case is a one-file diff.

This exists because the strategic-priorities memory
(`project_ccis_assessor_priorities_v01plus.md`) ranks LLM eval harness
as gap #3 — every other test in `backend/tests/engine/` is either
unit-golden or full-integration; neither catches "the prompt changed
but verdict accuracy regressed."

## Scope

- Deterministic stub LLM (`_stubs.StubLlmClient`) — no token spend, no
  network, no cost. Always-on; runs in default CI.
- Live-LLM mode — same JSON cases against a real `AnthropicClient`,
  gated three ways: `@pytest.mark.live_llm` marker, per-case `live_llm`
  opt-in block, API-key availability. Skipped by default; opt-in via
  `pytest -m live_llm`.
- 11 seed cases. The corpus is intended to grow to 50-100 hand-curated
  cases per the priorities memo — add one as a real CCI surfaces during
  an assessment session.
- Exact `(status, source, needs_review)` match + `narrative` /
  `review_reason` regex assertions. Narrative-quality LLM-as-judge is
  explicitly **out** per the priorities memo.

## Running

Default (stub-only, fast, offline):

```bash
cd backend
uv run --no-sync pytest ../tests/eval/ -v
```

Single case by name (test ID matches filename stem):

```bash
uv run --no-sync pytest ../tests/eval/ -v -k abstain_low_confidence
```

Live-LLM mode (real Claude on the wire; requires API key):

```bash
cd backend
uv run --no-sync pytest ../tests/eval/ -v -m live_llm
```

Live mode skips cleanly when:
- No `ANTHROPIC_API_KEY` env var / keyring entry / config endpoint
  token is available → `pytest.skip` (not failure).
- The case has no top-level `live_llm` block → `pytest.skip`. Most
  cases pin engineered stub behavior a real model wouldn't reproduce
  (e.g. `future_tense_rejection` forces a contradiction); only cases
  where a real model has a clear correct answer carry the block.

## Fixture schema

One JSON file per case (one-file diff, `git blame` works per case).

```json
{
  "name": "<case-name-matches-filename>",
  "description": "<one or two sentences — why this case exists>",
  "ccis_row": {
    "control_id": "AC-2",
    "ap_acronym": "AC-2.1",
    "cci_id": "CCI-000015",
    "guidance": "...",
    "procedures": "...",
    "inherited": null,
    "narrative": null,
    "definition": null
  },
  "tagged_evidence": "## Tagged evidence\n- USD... — covers ...\n",
  "llm_stub_proposals": [
    {
      "status": "Compliant",
      "narrative": "Per USD00099999 ...",
      "confidence": 0.9
    }
  ],
  "expected": {
    "status": "Compliant",
    "source_in": ["llm", "llm_after_retry"],
    "needs_review": false,
    "llm_calls": 1,
    "narrative_contains_regex": "USD\\d{8}",
    "review_reason_contains_regex": null
  },
  "live_llm": {
    "expected_status": "Compliant",
    "expected_needs_review": false,
    "expected_source_in": ["llm", "llm_after_retry"]
  }
}
```

### Field notes

- `ccis_row` — only fields you need to set; the runner's `_build_row`
  fills the rest with well-formed defaults. Unknown keys raise
  `TypeError` (catches typos loudly).
- `tagged_evidence` — pass `null` to exercise the Step 1.65 no-evidence
  short-circuit; otherwise mimic the `## Tagged evidence\n- USD... — ...`
  format the kernel produces in production. Citation tokens in
  `llm_stub_proposals[*].narrative` must literally appear here or the
  validator's cite-verifier will reject the proposal.
- `llm_stub_proposals` — list of dicts mapped to `LlmProposal(**dict)`.
  `status` is a string (`"Compliant"` / `"Non-Compliant"` /
  `"Not Applicable"`) — the runner coerces to the enum. Empty list `[]`
  is valid for cases that expect a deterministic short-circuit before
  the LLM is consulted; the stub raises `AssertionError` if the
  orchestrator tries to call it.
- `expected.source_in` — list of acceptable `Decision.source` strings
  (`"rule_8a"`, `"rule_8b"`, `"rule_no_evidence"`, `"llm"`,
  `"llm_after_retry"`, `"abstain"`, `"crm_provider"`, etc.). Use a list
  for cases where multiple deterministic paths are equally correct.
- `expected.status` — string OR `null`. `null` asserts a hard abstain
  pre-route coercion (status really is `None` on the Decision).
- `expected.llm_calls` — integer count of `stub.propose` /
  `propose_twice` invocations recorded. Use `0` to assert "no LLM
  consulted" for rule short-circuits.
- `expected.narrative_contains_regex` / `review_reason_contains_regex`
  — `re.search` (not `fullmatch`) so you pin citation tokens or
  reason-prefix substrings without nailing every word.

All `expected.*` fields are optional — declare only what you want
asserted. A case file with only `{"status": "Compliant"}` in `expected`
is valid.

### Optional `live_llm` block

Add this top-level block to opt a case into live-LLM mode. Cases
without the block skip silently when running `pytest -m live_llm`.

```json
"live_llm": {
  "expected_status": "Compliant",
  "expected_needs_review": false,
  "expected_source_in": ["llm", "llm_after_retry"]
}
```

All three fields are required when the block is present. Live mode
assertions are **deliberately looser** than stub mode:

- `llm_calls` is NOT asserted (real model may succeed where stub
  retried, or vice versa).
- `narrative_contains_regex` is NOT asserted (real models phrase
  things differently per request).
- `review_reason_contains_regex` is NOT asserted (same reason).

The high-signal contract is `(status, needs_review, source_in)` —
what the user actually sees in the workbook.

**When NOT to add a `live_llm` block:**

- Rule short-circuits (8a/8b/no-evidence) — the LLM is never called,
  so live mode adds nothing over stub mode.
- Engineered abstain modes (`future_tense_rejection`,
  `unsupported_doc_citation`, `abstain_low_confidence`,
  `abstain_self_signaled`) — these force the validator into a
  rejection path a real model usually wouldn't reproduce. Running
  them live would waste tokens and yield noisy failures.

## Adding a case

1. Copy the closest existing case as a starting template.
2. Edit `ccis_row`, `tagged_evidence`, `llm_stub_proposals`, and
   `expected` for the new scenario.
3. Update `name` and `description` — the description is where future-you
   reads "why does this case exist".
4. Run `pytest ../tests/eval/ -v -k <new_case_name>`.
5. If the first-run result disagrees with your `expected`, **the case
   is the source of truth** — adjust `expected` to match observed
   behavior, document the surprise in `description`. (Per the
   approved plan: "future prompt/kernel changes that flip these cases
   force an explicit decision.")

## Seed cases (current corpus, 11 files)

| File | Path exercised | Live? |
|---|---|---|
| `compliant_doc_citation.json` | LLM-accepted Compliant with `USD\d{8}` cited | ✓ |
| `gap_describing_nc.json` | LLM-accepted Non-Compliant; `_GAP_PHRASES` ('no documentation', 'POA&M') drive `GAP_DESCRIBING` | ✓ |
| `llm_after_retry.json` | Ambiguous attempt 0 → STATUS_NARRATIVE_MISMATCH → retry → accept (`source='llm_after_retry'`) | ✓ |
| `nc_no_evidence.json` | Step 1.65 no-evidence abstain short-circuit (`source='abstain'`, `needs_review`, 0 LLM calls) | — |
| `na_external_csp_rule_8b.json` | Rule 8a CSP-inheritance short-circuit (col Q rationale → Compliant, `source='rule_8a'`, 0 LLM calls) | — |
| `rule_8a_auto_compliant.json` | Rule 8a explicit-text short-circuit (col K text trigger, `source='rule_8a'`) | — |
| `rule_8a_structural_l.json` | Rule 8a structural short-circuit (col L inheritance, non-CSP) | — |
| `abstain_low_confidence.json` | Implicit-abstain demote: `confidence < CONFIDENCE_THRESHOLD` → `source='abstain'`, `needs_review=True` | — |
| `abstain_self_signaled.json` | Model self-signal: `abstain=True` → `source='abstain'`, `needs_review=True` | — |
| `future_tense_rejection.json` | `FUTURE_TENSE_COMPLIANCE` rejection × 3 → retry exhausts → `validator-exhausted` abstain | — |
| `unsupported_doc_citation.json` | `UNSUPPORTED_DOC_CITATION` (hallucinated USD) × 3 → retry exhausts → abstain | — |

Cases marked `✓` in the **Live?** column carry an opt-in `live_llm`
block and run when `pytest -m live_llm` is invoked. The rest are
deterministic-stub-only by design (see "When NOT to add a `live_llm`
block" above).

## Not in this slice (explicit deferral)

- **Corpus growth to 50-100.** Each case is a hand-curated judgement
  call; bulk-adding without per-case review defeats the purpose. Grow
  the corpus as real CCIs surface during assessment sessions.
- **Citation-source verification.** Asserting every cited ref appears
  in `tagged_evidence`. Defer to v0.2.
- **LLM-as-judge narrative quality.** Explicitly out per
  `project_ccis_assessor_priorities_v01plus.md`.
- **Coverage report.** Which control families / rule paths / abstain
  triggers are covered. Useful once corpus reaches 50+.
- **Mutation testing.** mutmut against `engine/assessor.py` with the
  eval as oracle. Needs a real corpus first.

## Why `tests/eval/` and not `backend/tests/eval/`

`backend/pyproject.toml:154` sets `testpaths = ["../tests"]` — the
top-level `tests/` is the canonical CI suite. Putting the harness here
means every `pytest` invocation exercises it; putting it under
`backend/tests/` would require explicit invocation and silent rot.

Top-level `tests/conftest.py` already wires `sys.path` to include
`backend/`, so `cybersecurity_assessor.*` imports work cleanly.
