# Boundary-doc extraction eval — case files

Each `*.json` here freezes one boundary-doc extraction scenario. The two
test runners — `test_boundary_extraction.py` (stub mode) and
`test_boundary_extraction_live_llm.py` (live mode, opt-in) — both glob
this directory and parametrize one test per file. The pytest test ID is
the filename stem, so `pytest -k empty_doc_low_confidence` selects
exactly one case.

These cases pin **current kernel behavior** of
`BoundaryDocsContextSource.apply` (`backend/cybersecurity_assessor/system_context/boundary_docs.py`).
A flip means deliberate work: either intended (re-record + bump
`description`) or a regression (revert).

---

## Case-file schema

```jsonc
{
  // Required — human-readable identity. Filename stem is the test ID;
  // "name" is for documentation parity with other harnesses.
  "name": "ssp_hosts_example_system",

  // Required — one sentence on what THIS case proves. Read by
  // future-you when triaging a failure.
  "description": "Canonical SSP prose → host + IP tokens survive normalization.",

  // Optional. Each entry is materialized to disk by _fixtures._load_doc_evidence
  // and seeded as an Evidence row with is_boundary_doc=True. The adapter
  // reads Evidence.extracted_text_path off the filesystem; the original
  // binary is never opened, so "text" IS the ground-truth extractor
  // output. Empty / omitted = empty-docs short-circuit case.
  "fixture_docs": [
    {
      "filename": "ssp.docx",                      // required; must be unique within case
      "boundary_doc_kind": "SSP",                  // optional; surfaces in prompt header "## SSP: ..."
      "title": "Acme Production SSP v1.2",         // optional; defaults to filename
      "text": "Hostnames: server01..."             // required; written to tmp dir as <filename>.txt
      // "sha256": "..."                            // optional; derived from text if absent
    }
  ],

  // Required for stub mode; OMIT for live-only cases (test skips cleanly).
  // The adapter's at-most-one extractor call per apply() pops THIS envelope.
  "stub_extractor": {
    "tokens":     ["server01.acme.local", "10.0.0.0/24", "..."],
    "confidence": 0.85
  },

  // Required for stub mode. Drives both kernel assertions (legible 3PAO
  // contract) and snapshot drift (catches token additions/removals the
  // kernel doesn't name).
  "expected": {
    "expected_tokens":   ["server01.acme.local"],   // MUST be present after normalization
    "banned_tokens":     ["example.com", "tbd"],    // MUST NOT be present
    "snapshot_tokens":   ["10.0.0.0/24", "..."],    // EXACT full set (sorted); re-record on intentional change
    "min_confidence":    0.6,                        // floor; 0.0 for empty-docs path, 0.2 for extractor-exception path
    "max_unattributed_ratio": 0.10                   // Phase 2 gate — fraction of tokens with source_kind == "unattributed"
  },

  // Optional. Present ⇒ the live-LLM twin exercises this case under
  // `pytest -m live_llm_boundary`. Absent ⇒ test_boundary_extraction_live_llm.py
  // skips cleanly (stub-only by design). All three sub-fields required
  // when the block is present; partial blocks raise KeyError.
  "live_llm_boundary": {
    "expected_tokens": ["server01.acme.local"],   // typically a STRICTER subset of stub's
    "banned_tokens":   ["example.com"],
    "min_confidence":  0.5                          // typically LOOSER than stub's — real model is less certain
  }
}
```

---

## Stub vs live — which block to fill in

| Scenario | `stub_extractor` | `expected` | `live_llm_boundary` |
|---|---|---|---|
| Real-fixture case (SSP / architecture doc with realistic prose) | ✅ canned envelope | ✅ kernel + snapshot | ✅ stricter kernel, lower floor |
| Engineered edge case (placeholder rejection, unicode survival, empty doc) | ✅ engineered envelope | ✅ kernel + snapshot | ❌ omit — running against a real LLM wastes tokens and produces noisy failures because the engineered stub IS the point |
| Future live-only case (probing real-model behavior with no stub mirror) | ❌ omit (stub runner will `pytest.skip`) | ❌ omit | ✅ kernel + floor |

The two runners both walk `cases/*.json`; each one skips cases that
don't declare the block it cares about. That's intentional — one source
of truth per scenario, no parallel case dirs.

---

## Capturing / re-recording `snapshot_tokens`

Snapshot drift is a **loose** check: kernel must hold, but the full set
is allowed to change as long as you re-record deliberately.

### First-time record (stub mode)

1. Author the case file with `stub_extractor.tokens` + the kernel
   (`expected_tokens` / `banned_tokens`).
2. Leave `snapshot_tokens` as `[]` initially.
3. Run `pytest tests/eval/boundary/test_boundary_extraction.py -k <case_stem>`.
4. The snapshot assertion fails and prints the actual sorted set.
5. Paste that set into `snapshot_tokens`. Re-run — green.

### Intentional re-record (after prompt or normalizer change)

The failure message names the case file and prints both sides:

```
snapshot drift in ssp_hosts_example_system.json:
  expected (8): ['10.0.0.0/24', 'server01', ...]
  actual   (9): ['10.0.0.0/24', 'server01', 'server02', ...]
If intentional, re-record snapshot_tokens; otherwise the prompt or normalizer regressed.
```

If the diff matches intent: copy `actual` over `snapshot_tokens`, bump
the case's `description` to note WHY the drift happened
(e.g. "prompt now emits per-host enumeration"), commit alongside the
prompt/normalizer change so reviewers see them together.

### Phase 3 live-mode A-B (planned)

1. Before swapping `_EXTRACTION_PROMPT`: run
   `pytest tests/eval/boundary/ -m live_llm_boundary` against the real
   LLM; record observed full sets as a baseline (commit notes, not
   `snapshot_tokens` — live mode does NOT assert snapshot).
2. Swap the prompt.
3. Re-run live mode. Per case, the `live_llm_boundary` kernel
   (`expected_tokens` recall, `banned_tokens` leakage) must not
   regress. If it does, the prompt swap reverts.

---

## Seed cases shipped on day-1

Real-fixture cases (mirror docs actually in `tests/fixtures/`, expressed
as inline text in `fixture_docs[*].text`):

| File | Purpose |
|---|---|
| `ssp_hosts_example_system.json` | Canonical SSP prose; hostnames + IPs survive normalization. |
| `architecture_hosts_example_system.json` | Architecture doc; service identifiers (LDAP/SAML/etc) + zones. |
| `architecture_hosts_alt.json` | Alternate architecture revision; checks consistency across doc revisions. |
| `acct_mgmt_policy_demo.json` | Policy prose (less host-dense); confidence floor + lower token count. |
| `ia_procedures_pdf_demo.json` | I&A procedures; service identifiers + vendor product names. |

Engineered edge cases (stub-only):

| File | Purpose |
|---|---|
| `empty_doc_low_confidence.json` | No docs → adapter short-circuits → `confidence == 0.0`, no extractor call. |
| `placeholder_text_rejected.json` | `TBD`, `REDACTED`, `example.com` listed in `banned_tokens`; stub envelope simulates rejection. |
| `unicode_hostname_preserved.json` | Non-ASCII hostnames survive normalization (lowercase + strip-punct does not mangle them). |

---

## Sanity guard

`test_boundary_extraction.py::test_cases_directory_is_not_empty` fails
loud if this directory is missing or empty — without it, an accidentally
deleted `cases/` would collect zero parametrize IDs and report a green
test run, masking total harness failure.
