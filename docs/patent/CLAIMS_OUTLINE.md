# Cybersecurity Assessor — Patent Claims Outline (Handoff Draft)

**Status:** Authoring scaffold for a downstream drafting team. NOT legal advice; NOT
final claim language. Every mechanism below is grounded to a `file:line` anchor so a
drafter (or agent) can read the implementation before writing claim text.

**Doctrine reminder for downstream agents:**
- This is a **review/authoring-only** artifact. Do **not** modify application code while
  drafting claims — there is other work in flight.
- The Engine + LLM subsystems are the "brain"; they are ordered first and carry the
  strongest independent claims.
- **Accuracy claims are currently unsupported by measurement.** `scripts/eval_workbook.py`
  measures *self-agreement against prior verdicts*, not ground-truth precision/recall
  (lines 173-207). Any claim that recites "accurate," "high-precision," or a numeric
  performance bound MUST be backed by a real labeled eval before filing, or it is a
  validity risk. See **§X. Cross-cutting drafting hazards**.

---

## How to use this document

Each invention entry has a fixed shape so drafters can parallelize:

1. **Title** — working name.
2. **Problem / prior-art gap** — what existing tools do and why it falls short.
3. **Inventive step (non-obvious core)** — the one or two sentences a claim must capture.
4. **Independent claim skeleton** — element-by-element scaffold (method form; mirror as
   system/CRM medium claims).
5. **Dependent claim elements** — narrowing features, each independently patentable-ish.
6. **Evidence anchors** — `file:line` into the codebase.
7. **Drafting notes / hazards** — pitfalls, enablement gaps, prior-art to distinguish.

Priority tiers:
- **Tier A (Brain — file first):** Inventions 1–6.
- **Tier B (Evidence & data integrity):** Inventions 7–11.
- **Tier C (Downstream artifacts):** Inventions 12–13.

---

# TIER A — ENGINE + LLM "BRAIN"

## Invention 1 — Content-addressed decision cache with semantic auto-invalidation

**Problem / prior-art gap.** LLM-backed assessment is non-deterministic and expensive.
Naive caching keys on the input row, so a change to the *reasoning logic* (prompt, rule
kernel) silently serves stale verdicts. Conventional caches require manual cache-busting
and cannot prove a cached verdict was produced under the *current* logic.

**Inventive step.** The cache key (fingerprint) is a content hash over **both the inputs
and a semantic signature of the decision logic** — `KERNEL_VERSION + PROMPT_SHA +
kernel_config_signature` combined with the row/evidence/CRM payload. Changing the prompt
or the deterministic rule kernel changes the fingerprint, so prior verdicts are
*automatically* invalidated without any explicit bust step; only LLM-*accepted* decisions
are cached. Volatile, non-semantic fields (excel_row position, timestamp) are deliberately
excluded so cosmetic workbook edits do not thrash the cache.

**Independent claim skeleton (method).**
- receiving a control requirement record and an associated evidence set;
- computing a decision-logic signature comprising (a) a version identifier of a
  deterministic rule kernel and (b) a hash of an active LLM prompt template;
- computing a content-addressed fingerprint by hashing the decision-logic signature
  together with a normalized representation of the requirement record and evidence set,
  *excluding* presentation-only fields;
- querying a persistent store keyed by the fingerprint;
- on miss, generating a compliance decision and persisting it under the fingerprint **only
  if** the decision was accepted by a downstream validator;
- on hit, returning the cached decision as provenance-bound to the decision-logic
  signature under which it was produced.

**Dependent claim elements.**
- excluding row-ordinal and timestamp fields from the fingerprint (cosmetic-edit immunity);
- caching only validator-accepted decisions (poisoning resistance);
- the kernel_config_signature further incorporating confidence threshold / dual-pass flags;
- replay-after-evidence-arrival admission for a specific rule class (`rule_no_evidence`).

**Evidence anchors.**
- `engine/decision_cache.py:202` — `fingerprint` = sha256 over KERNEL_VERSION + PROMPT_SHA
  + kernel_config_signature + row/evidence/CRM.
- `engine/invalidation.py:82` (whole file) — admits `rule_no_evidence` replay once evidence
  lands; flags the Assessment row.
- `engine/assessor.py:1058` — cache lookup site in the gate cascade.

**Drafting notes.** Distinguish from generic memoization and from RAG response caches: the
novelty is *semantic* invalidation tied to the reasoning artifacts, plus the
validator-gated write. Note the partial-invalidation seam (invalidation flags the
Assessment but not the decision cache) as a possible continuation, not a current claim.

---

## Invention 2 — Deterministic-rule + LLM ordered-precedence hybrid ("gate cascade")

**Problem / prior-art gap.** Pure-LLM compliance tools hallucinate and cannot guarantee
that cheap, certain determinations are made deterministically; pure rules-engines cannot
read free-text evidence. Existing hybrids run them in parallel and reconcile, which is
non-deterministic and hard to audit.

**Inventive step.** A **strictly ordered cascade** where each gate can terminate the
decision before the LLM is ever consulted: rule short-circuits → CRM responsibility
short-circuit → program-overlay rule → no-evidence abstention → cache → and only then a
single LLM call inside a validator retry loop. Precedence is fixed and recorded, so every
verdict carries *which gate decided it* (see Invention 6's `VerdictSource`). The LLM is the
last resort, not the default path.

**Independent claim skeleton (method).**
- evaluating a requirement record through an ordered sequence of decision gates;
- a first gate applying deterministic compliance rules; a second gate applying a customer-
  responsibility short-circuit; a further gate emitting an abstention when no admissible
  evidence exists; a further gate consulting a content-addressed decision cache;
- only upon all preceding gates declining to terminate, invoking a language model within a
  validation-and-retry loop;
- tagging the resulting decision with a discriminator identifying the terminating gate.

**Dependent claim elements.**
- CRM short-circuit returning inherited/provider verdicts without LLM invocation;
- a confidence threshold gating acceptance of the LLM verdict (`CONFIDENCE_THRESHOLD`);
- an optional dual-pass / challenger stage (links to Invention 4);
- the no-evidence gate emitting *evidence-absence-as-a-finding* (links to Invention 5).

**Evidence anchors.**
- `engine/assessor.py:904` (`_run`) — cascade entry; rule#8 @917, CRM @930, SDA-8c @991,
  no-evidence @1030, cache @1058, LLM retry loop @1133.
- `engine/assessor.py:404-405` — `DUAL_PASS_ENABLED`, `CONFIDENCE_THRESHOLD = 0.35`.

**Drafting notes.** The patentable hook is *fixed precedence + per-gate provenance*, not
"use rules and an LLM." Emphasize single-LLM-call economy and determinism of the non-LLM
gates.

---

## Invention 3 — Literal cite-verification hallucination guard

**Problem / prior-art gap.** LLMs fabricate citations to evidence that was never shown.
Confidence scores and self-grading do not catch fabricated references. Reviewers cannot
trust an auto-generated compliance narrative that cites a document the model invented.

**Inventive step.** After the model returns a narrative + cited tokens, a deterministic
verifier checks that **every cited token literally appears in the evidence actually
presented to the model** in this call. A narrative citing anything outside the shown-
evidence token set is rejected and triggers a retry — a hard, non-probabilistic
hallucination gate distinct from confidence thresholds.

**Independent claim skeleton (method).**
- presenting a bounded evidence set to a language model and recording the exact tokens
  shown;
- receiving a generated narrative comprising one or more citations;
- verifying, by literal token membership, that each citation resolves to the recorded
  shown-evidence tokens;
- rejecting the narrative and re-prompting when any citation fails membership;
- persisting only narratives whose citations are fully verified.

**Dependent claim elements.**
- recording shown evidence as per-chunk content hashes for audit (`chunk_sha`);
- combining literal verification with a phrase-table status classifier (link to validator);
- bounding retries and falling back to abstention on exhaustion.

**Evidence anchors.**
- `engine/validator.py:1073` (`_verify_cites`).
- `llm/client.py:228-258` (`audit_citations`).
- `models.py:2432` (`AssessmentEvidenceShown` — chunk_sha + chunk_text) and `:2460`
  (`AssessmentCitation`).

**Drafting notes.** Distinguish from RAG "groundedness" scorers (probabilistic). The novelty
is *literal membership against an audited shown-set*, tied to a retry loop and to a stored
evidence-shown ledger.

---

## Invention 4 — Adversarial challenger second pass at temperature 0

**Problem / prior-art gap.** Single-pass LLM verdicts are over-confident; ensembling/voting
is costly and still correlated. Self-consistency sampling raises temperature, increasing
hallucination.

**Inventive step.** A **deterministic adversarial second pass**: the same model is asked to
challenge/attack its own first verdict at temperature 0, and disagreement forces
abstention or re-examination rather than majority vote. Determinism (temp 0) makes the
challenge reproducible and auditable.

**Independent claim skeleton (method).**
- generating a first compliance verdict for a requirement;
- invoking a second, adversarial prompt instructing the model to identify why the first
  verdict may be wrong, executed at a deterministic decoding temperature;
- comparing the passes and, on material disagreement, demoting the decision to an
  abstention flagged for human review rather than selecting by vote.

**Dependent claim elements.**
- gating the second pass on borderline first-pass confidence (cost control);
- recording both passes with a `pass_index` for provenance;
- challenger constrained to the same shown-evidence set (composes with Invention 3).

**Evidence anchors.**
- `llm/client.py:262-367` (`propose_twice`).
- `models.py:2396` (`AssessmentTrace` carries `pass_index`).
- `engine/assessor.py:404` (`DUAL_PASS_ENABLED`) — currently False; draft as
  "selectively enabled" and note enablement requirement.

**Drafting notes.** Distinguish from self-consistency / debate ensembles: single model,
temp 0, *disagreement→abstain* (precision-preserving) rather than vote. Flag that the flag
is off by default — claims should recite the capability, and the team should confirm it is
exercised before relying on it for an "operative" claim.

---

## Invention 5 — Precision-over-recall abstention with evidence-absence-as-a-finding

**Problem / prior-art gap.** Compliance tools optimize coverage (answer everything),
producing confident wrong verdicts that auditors must unwind. They also conflate "no
evidence" with "non-compliant," which is legally distinct.

**Inventive step.** Two coupled rules: (1) when the model is not confident, it emits a
**status-less `needs_review` record that is still persisted** (abstention is a first-class,
durable outcome, not a dropped row); and (2) **absence of evidence is recorded as an
affirmative finding** distinct from a non-compliance verdict. The system is tuned to
*decline* rather than guess.

**Independent claim skeleton (method).**
- producing, for a requirement, one of: a status-bearing verdict, or a status-less review
  record;
- emitting the status-less review record when a confidence criterion is not met **or** when
  no admissible evidence is present;
- persisting the status-less record with its evidence ledger such that it is surfaced for
  human adjudication rather than discarded;
- treating documented evidence-absence as a recorded finding distinct from non-compliance.

**Dependent claim elements.**
- the confidence criterion derived from the LLM and/or pass-disagreement (Invention 4);
- validator phrase-table enforcement that abstention narratives use non-affirming language;
- batch persistence preserving abstentions through downstream exporters (SAR/POA&M).

**Evidence anchors.**
- `engine/assessor.py:1030` (no-evidence gate) and `_abstain` (~1823/1889, accepted=True so
  abstentions persist).
- `engine/validator.py` phrase tables `_AFFIRMING/_GAP/_NA_PHRASES`.
- `routes/controls.py:1131/1656` persistence gate `if decision.accepted:`.

**Drafting notes — KNOWN BUG to disclose carefully.** The *rule* path can drop a verdict:
`_finalize_rule_decision` (`assessor.py:1738-1753`) sets `accepted_narrative=None` and
returns `status=None` when a rule narrative fails the validator, and that record is appended
to the live response (`controls.py:1774+`) but **not persisted** (`controls.py:1771-1772`).
Drafters: claim the *intended* abstain-persists behavior; do **not** recite the buggy rule
path as enabled. This is an enablement seam — the team in flight should fix it before any
claim leans on "all abstentions are persisted."

---

## Invention 6 — Provenance-complete decision lineage with verdict-source discriminator

**Problem / prior-art gap.** Auditors (3PAO/JAB) must be able to reconstruct *why* an
automated verdict was reached. Existing tools store the answer, not the full causal chain
(exact prompt, exact evidence shown, model/version/temp, which gate decided).

**Inventive step.** Every verdict is bound to a **complete, replayable lineage**: the exact
user message + system-prompt hash + model/version/temperature/request_id + raw response +
pass index (`AssessmentTrace`), the per-chunk hashed evidence actually shown
(`AssessmentEvidenceShown`), the verified citations (`AssessmentCitation`), and a
**`VerdictSource` discriminator** naming the terminating gate from Invention 2. This makes
each verdict independently reconstructable and attributable.

**Independent claim skeleton (system).**
- a verdict record store associating each compliance verdict with: a prompt snapshot
  comprising a system-prompt hash and the literal user message; model identity, version,
  decoding temperature, and request identifier; the raw model response; a pass index; a
  set of content-hashed evidence chunks actually shown; a set of verified citations; and a
  source discriminator identifying which of a plurality of ordered decision gates produced
  the verdict;
- whereby any stored verdict is replayable and attributable to its originating logic.

**Dependent claim elements.**
- the source discriminator enumerating rule/CRM/cache/LLM/abstain origins;
- append-only risk/decision history for downstream artifacts (`PoamRiskHistory`,
  `OdpAuditLog`);
- linkage of the prompt-snapshot hash to the cache fingerprint of Invention 1 (shared
  PROMPT_SHA), unifying cache identity and provenance.

**Evidence anchors.**
- `models.py:2396` (`AssessmentTrace`), `:2432` (`AssessmentEvidenceShown`), `:2460`
  (`AssessmentCitation`), `:87-141` (`VerdictSource` enum), `:1815` (`PoamRiskHistory`),
  `:1221` (`OdpAuditLog`), `:2276` (`DecisionCache.fingerprint`).

**Drafting notes.** Strong system + CRM-medium claims. The defensibility story (Invention 6)
is also the company's strategic moat — weight it. Tie PROMPT_SHA reuse to Invention 1 to
show the architecture is unified, not bolted-on.

---

# TIER B — EVIDENCE & DATA INTEGRITY

## Invention 7 — Scan-only corroboration gate (no Compliant from scans alone)

**Problem / prior-art gap.** Vulnerability/STIG scanners report machine state but not
*managed* compliance; tools that accept a clean scan as proof of a control overstate
assurance.

**Inventive step.** A verdict of Compliant is **forbidden when the only admissible evidence
is scan output**; a non-scan artifact (policy/config/procedure) must corroborate, enforced
by a dual-condition guard (CCI-set intersection **and** tag-to-objective co-membership).

**Independent claim skeleton (method).**
- classifying each evidence item as scan-derived or non-scan-derived;
- permitting a compliant determination only when at least one non-scan item corroborates a
  scan finding, corroboration requiring both a control-identifier-set intersection and
  co-membership against the control objective;
- otherwise demoting to a finding or abstention.

**Dependent claim elements.** bounded evidence bundle (MAX_ARTIFACTS, head/tail char
windows); per-chunk hashing for the audit ledger.

**Evidence anchors.** `engine/evidence_bundle.py:164` (`has_nonscan_evidence`), `:279`
(chunk_sha); `engine/finding_corroboration.py:134` (dual-condition guard).

---

## Invention 8 — Multi-source asset universe auto-derivation for coverage cross-check

**Problem / prior-art gap.** Coverage analysis needs an authoritative host/asset list;
program teams maintain it manually and inconsistently across scanners and inventories.

**Inventive step.** The host universe is **auto-derived as the union of three independent
sources** — ACAS/Nessus scans ∪ STIG checklists (CKL/CKLB/XCCDF) ∪ declared inventory —
and used for *cross-check only* (program team still owns the official list), with coverage
gaps mapped to control families.

**Independent claim skeleton (method).** parse heterogeneous scanner/checklist/inventory
inputs; compute a unioned asset set; identify assets present in some sources but absent in
others; map coverage gaps to affected control families; surface as cross-check, not as the
system of record.

**Dependent claim elements.** format adapters per source; coverage-gap→family mapping.

**Evidence anchors.** `evidence/asset_crosscheck.py:114` (gap→family), `:277`
(`del workbook_id` — accepts but discards; note as seam).

---

## Invention 9 — Render-time ODP resolution with positional-bridge abstention

**Problem / prior-art gap.** Organization-Defined Parameters must be substituted into
control text; baking them at ingest loses the unparameterized catalog and breaks
multi-overlay reuse. Aligning ODP values to placeholders by position silently
mis-substitutes when counts differ.

**Inventive step.** ODP values are stored in a framework-scoped assignment table and
**substituted only at render time** (the canonical control statement is never mutated);
when a positional bridge between values and placeholders has mismatched counts, the system
**abstains** instead of guessing the alignment.

**Independent claim skeleton (method).** store ODP assignments keyed by framework; on
render, resolve placeholders against assignments without mutating the stored statement;
when value/placeholder counts diverge under positional bridging, emit an abstention rather
than a substituted statement.

**Dependent claim elements.** multi-overlay coexistence via composite PK; render-time
two-tier resolution; audit log of ODP resolution.

**Evidence anchors.** `baselines/ccis_workbook.py:236-260` (scope OR-aggregation), `:517-526`
(positional-zip abstain); `controls/odp_render.py` (`resolve_odps`, never mutates
`Control.statement`); `models.py:1221` (`OdpAuditLog`).

---

## Invention 10 — Resolver-dispatch overlay ingestion with inert audited receipt

**Problem / prior-art gap.** Program control identifiers are arbitrary across overlays
(CRM, PSC, ISO SOA, CIS CSAT); hard-coding one schema per format does not scale, and
auto-ingesting external mappings risks acting on unvetted data.

**Inventive step.** Overlays are ingested by **resolver dispatch** — any identifier is
acceptable so long as a registered resolver maps it to a CCI or control family — and the
ingested overlay is recorded as an **inert, audited receipt** that informs but does not by
itself flip a verdict (the LLM/gate still decides), with absence-of-overlay defaulting to
full local responsibility.

**Independent claim skeleton (method).** receive an overlay with arbitrary control
identifiers; dispatch to a registered resolver yielding CCI/family bindings; persist the
overlay as an audited receipt; treat the receipt as advisory input to the decision gates;
default unmapped controls to full local assessment responsibility.

**Dependent claim elements.** new format = new resolver, no schema change; CRM tags
customer/provider/hybrid/inherited; PSC overlays without a CCI column resolved via global
DISA mapping at resolve time.

**Evidence anchors.** `engine/crm_context.py` (`by_control`; self-flagged
`FIXME(crm-audit):171-183` — disclose as known order-dependence seam);
`engine/crm_sanity.py:499/503-511/243-280` (label-free adversarial scoring — see Invention
13); baselines/overlay resolvers.

---

## Invention 11 — Surgical .xlsx verify-or-rollback writes

**Problem / prior-art gap.** Round-tripping a complex compliance workbook through a library
reflows formatting/macros and corrupts auditor-facing files; blind writes can silently
mis-place a status.

**Inventive step.** Targeted cell writes via XML/COM surgery that **verify the written value
by re-reading and roll back on mismatch**, and that **skip rows flagged needs_review** so
abstentions are never overwritten with a guessed status.

**Independent claim skeleton (method).** locate target cells by content; write the value;
re-read to confirm; revert the write on mismatch; exclude needs_review rows from status
writes.

**Dependent claim elements.** sentinel-cell handling; eMASS template structural contract
(header/data-start rows).

**Evidence anchors.** `excel/ccis_writer.py:365-432` (safe_write verify-or-rollback),
`:224-225/490-496` (needs_review skip); `poam/exporter.py` (eMASS DATA_START_ROW=13,
sentinel).

---

# TIER C — DOWNSTREAM ARTIFACTS

## Invention 12 — Remediation-boundary POA&M clustering

**Problem / prior-art gap.** Per-CCI POA&Ms explode into unmanageable lists; family-level
POA&Ms underscope and hide distinct fixes.

**Inventive step.** Findings are clustered into POA&M items at the **remediation boundary** —
grouped by shared owner + fix + schedule — yielding right-sized, defensible items, with
grounded auto-remediation text (verbatim STIG/vendor) and severity-window milestone dates
from a policy table.

**Independent claim skeleton (method).** group open findings by tuple of remediation owner,
remediation action, and schedule; emit one POA&M item per group; populate remediation text
from authoritative source verbatim; derive milestone dates from a severity→window table.

**Evidence anchors.** POA&M clustering doctrine (memory: feedback_poam_scoping);
`poam/exporter.py:119-121` (selects all Poam rows — note SAR/POA&M needs_review-gate gap as
hazard); `models.py:1688` (Poam *_source/*_rationale), `:1815` (`PoamRiskHistory`).

**Hazard.** `poam/exporter.py:119-121` and `reports/sar.py:427` are **not** needs_review-
gated — abstentions can leak into NC counts. Disclose; don't claim gating that isn't there.

---

## Invention 13 — Label-free adversarial CRM/overlay scoring

**Problem / prior-art gap.** Overlay-vs-local-evidence contradictions need detection, but
no labels exist for "this CRM claim is wrong."

**Inventive step.** **Unsupervised** anomaly scoring (IsolationForest over a corpus ≥ 10 +
TF-IDF/contradiction signals) blended by **max, not mean**, to flag overlay claims that
contradict local evidence — label-free yet not heuristic-only.

**Independent claim skeleton (method).** vectorize overlay claims and local evidence;
compute multiple unsupervised anomaly signals including a local-evidence-contradiction
signal; blend by maximum; flag claims exceeding a threshold for review.

**Evidence anchors.** `engine/crm_sanity.py:499` (max-blend), `:503-511` (IsolationForest
n≥10), `:243-280` (local_evidence_contradiction).

---

# §X. Cross-cutting drafting hazards (read before writing any claim)

1. **Accuracy is unmeasured.** `scripts/eval_workbook.py:173-207` measures self-agreement,
   not precision/recall vs. ground truth. **Do not** recite numeric accuracy or
   "high-precision" without a real labeled eval. This is the #1 validity risk for the whole
   portfolio and the #1 strategic gap for the product. Recommend the in-flight team build a
   labeled eval harness; claims that depend on measured accuracy should wait for it.
2. **Abstain-persistence rule-path bug** (Invention 5 / `assessor.py:1738-1753`,
   `controls.py:1771-1774`): claim intended behavior, not the buggy rule path.
3. **Dual-pass disabled by default** (Invention 4 / `assessor.py:404`): recite as a
   capability; confirm it is exercised before any "operative" framing.
4. **SAR/POA&M needs_review gate missing** (Invention 12 / `poam/exporter.py:119-121`,
   `sar.py:427`): do not claim gating that isn't implemented.
5. **CRM `by_control` order-dependence** (Invention 10 / self-flagged FIXME): disclose seam.
6. **Latent cosmetic typo** `validator.py:938` (`* None` vs `| None`) — harmless under
   `from __future__ import annotations` (line 29); irrelevant to claims, listed for
   completeness so a reviewer isn't alarmed.
7. **Pricing alias drift** `llm/pricing.py:50-74` — non-inventive; ignore for claims.

---

# §Y. Suggested claim-set packaging for the drafting team

- **Application 1 (Brain / core):** Inventions 1, 2, 5, 6 as one family (cache + cascade +
  abstention + provenance are mutually reinforcing; 6 ties them together). Lead independent
  claim = Invention 2 (cascade) with 1/5/6 as the substantive dependents, plus standalone
  independents for 1 and 6.
- **Application 2 (Anti-hallucination):** Inventions 3 + 4 (literal cite verification +
  adversarial temp-0 challenger). Strong, self-contained.
- **Application 3 (Evidence integrity):** Inventions 7, 8, 9, 10, 11.
- **Application 4 (Artifacts):** Inventions 12, 13 (or fold into Application 3 if thin).

For each application, draft method + system + non-transitory-medium independents to maximize
infringement coverage.

---

# §Z. Handoff checklist for downstream agents

- [ ] Read each anchored `file:line` before writing the corresponding claim.
- [ ] For every "intended behavior" flagged in §X, confirm current code state; flag to the
      in-flight team rather than fixing.
- [ ] Do not modify application code.
- [ ] Before any accuracy-dependent claim, require a labeled eval (see §X.1).
- [ ] Mirror each method claim as system + CRM medium.
- [ ] Cross-reference Invention 1 ↔ 6 on the shared PROMPT_SHA to show a unified
      architecture (strengthens non-obviousness).
