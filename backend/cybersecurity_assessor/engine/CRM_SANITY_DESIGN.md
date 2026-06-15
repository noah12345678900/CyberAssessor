# CRM Sanity (Adversarial CRM Guardrails) — Design Spec

Target audience: implementing agent. Read `crm_sanity.py`, `crm_ml.py`,
`narrative_embeddings.py`, and `crm_context.py` first. Then skim
`Assessor._finalize_crm_decision` in `assessor.py` and the route handler
in `routes/baselines.py` (`compute_crm_suspicion`) — those two are where
this module gets exercised.

## What this protects against

`Assessor._finalize_crm_decision` short-circuits the LLM whenever a CRM
row says `provider` / `inherited` / `not_applicable`. The overlay-default-local
rule (memory: `feedback_overlay_default_local`) protects against
**missing** CRM data — a control with no CRM entry defaults to fully
customer-owned, full LLM path. It does **not** protect against **wrong**
CRM data: a vendor-supplied document that incorrectly claims everything
is inherited produces a wall of false-COMPLIANT verdicts with zero LLM
oversight.

This module is the wrong-data guard. It scores every CRM upload and
surfaces a banner in the Baselines UI before the assessor commits to
running an assessment against it.

## Three tiers, with graceful degradation

| Tier | Signal                                          | Cold-start behavior                                      |
|------|-------------------------------------------------|----------------------------------------------------------|
| 1    | Four hand-coded heuristics                      | Works on the FIRST CRM ever uploaded                     |
| 2a   | TF-IDF intra-CRM narrative similarity           | Works on the FIRST CRM (folded into the boilerplate heuristic) |
| 2b   | Embedding-based narrative quality               | Works on the FIRST CRM if OpenAI key or TF-IDF fallback available |
| 3    | IsolationForest cross-CRM anomaly score         | Activates once `n_corpus >= MIN_CORPUS_SIZE` (10)        |

Heuristic floor always emits. ML tiers emit only when their preconditions
are met; the UI greys out missing rows rather than hiding them, so the
assessor sees that ML scoring was unavailable rather than silently
trusting a heuristic-only verdict.

## Heuristics (tier 1)

All four live in `crm_sanity.py` as `_eval_*` helpers. Each returns
`(CrmSuspicionFlag | None, component_score)` where the component is a
continuous `[0, 1]` signal even when the flag itself doesn't fire — so
the overall heuristic score has gradient regardless of threshold crossings.

| Flag                             | Trigger                                                                                   | Severity         | Component score                          |
|----------------------------------|-------------------------------------------------------------------------------------------|------------------|------------------------------------------|
| `high_inheritance`               | `off_loaded_pct >= HIGH_INHERITANCE_WARN` (0.70) → warn; `>= HIGH_INHERITANCE_ALERT` (0.90) → alert | warn / alert     | Linear ramp from 0.0 at 50% to 1.0 at 100% off-loaded |
| `local_evidence_contradiction`   | Any family fully claimed off-loaded AND `tagged_evidence_by_family[fam] > 0`              | alert            | `min(1.0, n_contradicting_families / 5)` |
| `narrative_poverty`              | `empty_pct >= NARRATIVE_POVERTY_THRESHOLD` (0.30) of inherited/provider/hybrid claims     | warn             | Linear from 0.0 at 0% empty to 1.0 at 60% empty |
| `boilerplate_narrative`          | `max_intra_tfidf_cosine > BOILERPLATE_SIMILARITY_THRESHOLD` (0.85) AND `mean > 0.425`     | warn             | `min(1.0, mean_sim / 0.8)`               |

**Why max-of-components for the heuristic score** — each heuristic detects
an independent failure mode. A CRM that scores 0.0 on three and 1.0 on
`local_evidence_contradiction` is still maximally suspicious; averaging
would dilute the alert. This is a different choice from the inter-tier
blend (below), which uses a weighted average because tiers are correlated
signals about the same property.

**Why `local_evidence_contradiction` is hard-alert** — the assessor
literally has on-disk evidence the vendor said wouldn't exist. There's no
charitable reading; either the CRM is wrong or the evidence tagging is
wrong, and both need human eyes before the LLM bypass runs.

**Why TF-IDF replaces the original exact-match boilerplate check** — the
plan's first draft used exact narrative matches across rows. That misses
the common pattern of one paragraph with whitespace/punctuation varied
per control. Cosine similarity on TF-IDF vectors catches the semantic
duplication; the dual-threshold (`max > 0.85` AND `mean > 0.425`)
prevents firing on a single duplicated pair amid otherwise-distinct
narratives.

The TF-IDF stats come from `CrmFeatureVector.intra_crm_tfidf_*`, which is
already computed for the IsolationForest feature extraction. The
boilerplate heuristic re-uses them rather than running the vectorizer
twice — keeps tier 1 cheap.

## ML anomaly (tier 3)

`crm_ml.score_anomaly(model_blob, feature_vector) -> float` is called
when **all** of these hold:

1. `anomaly_model_blob is not None` (route handler resolved an active
   `CrmAnomalyModel` row).
2. `n_corpus >= MIN_CORPUS_SIZE` (10 — pinned in `crm_ml.MIN_CORPUS_SIZE`).
3. `feature_vector.schema_version == CURRENT_FEATURE_SCHEMA_VERSION`.

Wrapped in `try/except` — any sklearn / joblib failure returns `None`
rather than crashing the report. ML being unavailable is a soft signal
("we couldn't score this"), not a hard error.

Schema-version guard is the load-bearing piece for refit safety. Bumping
`CURRENT_FEATURE_SCHEMA_VERSION` in `crm_ml.py` means every persisted
`CrmCorpusFeatures` row at the old version is silently skipped at refit
AND at score time — old model blob can't be mis-applied to new vectors,
even if an operator forgets to flip `is_active` on a stale model.

## Narrative quality (tier 2b)

`narrative_embeddings.score_narrative_quality(narratives, provider) -> NarrativeQualityResult`
returns per-narrative substantiveness scores in `[0, 1]` (higher =
further from the canned-filler centroid). The CRM's quality score is the
mean across all inherited/provider/hybrid entries with non-empty
narratives.

Provider plug points (`narrative_embeddings.resolve_provider`):

| `prefer=` | When to use                                          | Resolution                                      |
|-----------|------------------------------------------------------|-------------------------------------------------|
| `"openai"`| Operator wants the LLM-provider embeddings explicitly | `RuntimeError` if no API key configured         |
| `"tfidf"` | Air-gapped (SCIF) deployments or unit tests          | Always succeeds — sklearn is a runtime dep      |
| `None` (auto) | Production default                               | Try OpenAI; on RuntimeError silently fall back to TF-IDF |

TF-IDF is the universal floor — the pilot deployment runs in a SCIF
where outbound HTTPS to OpenAI is blocked, so the offline path is the
only available one there. Quality of the TF-IDF embedding is degraded
relative to a real LLM embedding but still ranks substantive narratives
above filler-lookalikes (pinned by
`test_narrative_embeddings::test_substantive_narratives_score_higher_than_filler_lookalikes`).

Cache key is `(narrative_sha256, provider, model_name)` per
`CrmNarrativeEmbedding`. Filler-version suffix on `model_name` (e.g.
`"tfidf-filler-v1"`) prevents cache hits across filler-corpus revisions —
re-tuning the filler set invalidates old embeddings naturally rather
than requiring a cache wipe.

## Blend formula

When all three tiers report:

```
overall = BLEND_W_HEURISTIC * heuristic_score
        + BLEND_W_ML_ANOMALY * ml_anomaly_score
        + BLEND_W_NARRATIVE  * (1 - narrative_quality_score)
```

With current constants: `0.50` heuristic, `0.30` ML anomaly, `0.20`
narrative. Narrative is inverted (higher quality = lower suspicion
contribution).

**Weight redistribution** — when ML anomaly or narrative quality are
missing (`None`), `_blend` drops them from the components list and
re-normalizes by the sum of remaining weights. Cold-start (`n_corpus < 10`,
no embeddings provider) reduces to `overall == heuristic_score`. This is
the right behavior: an artificial low score from "missing tiers count as
zero" would make cold-start CRMs look less suspicious than they should.

Result is clipped to `[0, 1]`.

## Severity buckets

| `overall_suspicion`        | Severity | UI treatment                                   |
|----------------------------|----------|------------------------------------------------|
| `< OVERALL_INFO_MAX` (0.30) | `info`  | Clean — no banner, just a status chip          |
| `< OVERALL_WARN_MAX` (0.60) | `warn`  | Yellow banner with expand-details, no gate     |
| `>= 0.60`                  | `alert`  | Red banner with "Proceed anyway" confirmation gate |

`CrmSuspicionReport.severity` is a derived property — UI styles
exclusively off this rather than re-bucketing the float, so banner color
can't drift from the persisted score.

## Public surface

```python
score_crm_suspicion(
    *,
    workbook_id: int,
    crm_baseline_id: int,
    crm_context: CrmContext,
    in_scope_control_ids: Sequence[str],
    tagged_evidence_by_family: dict[str, int],
    n_corpus: int = 0,
    anomaly_model_blob: bytes | None = None,
    embeddings_provider: EmbeddingsProvider | None = None,
    computed_at: datetime | None = None,
) -> CrmSuspicionReport
```

Session-free by design. The route handler in `routes/baselines.py`
builds inputs (fetches active model blob, resolves embeddings provider,
counts corpus rows at current schema version, runs the
`EvidenceTag`-by-family group-by) and persists the returned report to
`CrmSuspicionLog`.

`CrmSuspicionReport.to_json_safe()` strips the embedded `feature_vector`
(large, only useful to the persistence layer) and ISO-formats the
datetime — that's the shape the FastAPI endpoint serializes.

## What NOT to do

- **Don't hide ML rows when their tier is unavailable.** Show them
  greyed-out with "corpus too small (n=4 / 10)" or "no embeddings
  provider configured" so the assessor sees that the heuristic floor is
  doing all the work. Silent omission makes a heuristic-only score look
  like a confirmed three-tier score.
- **Don't average heuristic components.** Use `max`. Averaging dilutes
  the `local_evidence_contradiction` alert into the noise of three
  passing checks.
- **Don't gate the whole report on heuristics passing.** Even a clean
  heuristic score may have ML anomaly fire (cross-CRM outliers that no
  single heuristic catches). All tiers run independently; the blend is
  what gates the banner.
- **Don't run the TF-IDF vectorizer twice.** The boilerplate heuristic
  reads `feature_vector.intra_crm_tfidf_*` rather than re-vectorizing.
- **Don't crash the report on ML failure.** Both `score_anomaly` and
  `score_narrative_quality` are wrapped in `try/except` returning `None`.
  An IsolationForest unpickle error must not 500 the suspicion endpoint.
- **Don't promote auto-fitted models without review.** `refit_crm_anomaly_model.py`
  always writes `is_active=False`; operator flips activation explicitly
  via `--activate`. Same rule as the SGD weight updates in the sweep
  calibrator.
- **Don't bump `CURRENT_FEATURE_SCHEMA_VERSION` without a refit plan.**
  Old `CrmCorpusFeatures` rows survive (for diagnostics) but stop
  contributing to fits. After a bump, the corpus effectively resets to
  zero new-version rows until enough new CRMs are uploaded.
- **Don't treat `assessor_marked_false_positive=True` as silently
  suppressing the banner forever.** That field exists to build the
  labeled corpus for the v0.3+ supervised classifier; the banner still
  shows on re-compute, just with the prior mark surfaced.

## Test plan

- **Unit (heuristics):** `test_crm_sanity_heuristics.py` — each of the
  four rules fires at its threshold, doesn't fire below it, and the
  component score is continuous across the boundary. Pin the
  `local_evidence_contradiction` saturation at 5 families.
- **Unit (blend):** `test_crm_sanity_hybrid_blend.py` — every combination
  of `None` / present for ML anomaly and narrative quality; weight
  redistribution normalizes correctly; result clipped to `[0, 1]`;
  cold-start reduces to heuristic-only.
- **Unit (features):** `test_crm_ml_features.py` — `extract_features` is
  deterministic and stable across runs; `schema_version` matches
  `CURRENT_FEATURE_SCHEMA_VERSION`; in-scope filter excludes
  out-of-scope CRM rows.
- **Unit (anomaly):** `test_crm_ml_anomaly.py` — `fit_anomaly_model`
  refuses `n < MIN_CORPUS_SIZE`; refuses mixed-version corpus; synthetic
  outlier scores higher than centroid samples.
- **Unit (embeddings):** `test_narrative_embeddings.py` — TF-IDF works
  without API; OpenAI provider batches in one SDK call; misbehaving
  provider falls back to zero scores; `resolve_provider` resolution
  matrix.
- **Unit (kernel hook):** `test_assessor_logs_short_circuits.py` — three
  short-circuits in one run produce three `CrmShortCircuit` records
  with correct `cci` / `control_id` / `responsibility` / `baseline_id`;
  customer/hybrid rows emit no short-circuit; decision and outcome
  carry the **same** object (identity, not equality).
- **Integration (endpoint):** `test_crm_suspicion_endpoint.py` — happy
  path returns the JSON-safe shape and persists a `CrmSuspicionLog`;
  cold-start (`n_corpus < 10`) returns `ml_anomaly_score=None`;
  no-API-key returns `narrative_quality_score=None`; both missing
  returns heuristic-only.
- **End-to-end (manual, against a hand-crafted adversarial CRM):** upload
  a CRM that marks every AC control inherited despite the workbook
  having AC EvidenceTag rows. Confirm the banner fires with
  `local_evidence_contradiction` alert, overall ≥ 0.60, and a
  "Proceed anyway" gate.

## Open questions (defer; capture as TODOs in code)

1. **Per-family suspicion drilldown.** `per_family` carries enough data
   for a per-family breakdown in the "expand details" panel, but we
   don't yet score each family independently. v0.3 idea: surface the
   top-3 most-suspicious families inline.
2. **Cross-tenant peer comparison.** The IsolationForest corpus is
   per-installation. A multi-tenant SaaS deployment could pool features
   (with consent) for a much larger corpus. Deferred to v0.3+ — needs
   tenant isolation thought-out.
3. **Supervised "this CRM lied" classifier.** Once
   `CrmSuspicionLog.assessor_marked_false_positive` accumulates enough
   labels (probably ~50 confirmed-real and ~50 confirmed-false-positive),
   a supervised classifier on top of the same `CrmFeatureVector` would
   replace the IsolationForest tier with a calibrated probability.
   Deferred to v0.3+ — gated on label availability.
