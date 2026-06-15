# ML Architecture — Top-Level Map

Target audience: new contributor trying to understand "where does ML happen
in this codebase, and what are the rules." Read this once before touching
`crm_sanity.py`, `crm_ml.py`, `narrative_embeddings.py`, `sweep_online.py`,
or either of the two `scripts/` refit/recalibrate entry points. The
per-system specs (`CRM_SANITY_DESIGN.md` and
`evidence/sources/SHAREPOINT_SWEEP_DESIGN.md`) cover the details; this
doc covers the **shared patterns**.

## The two ML systems

v0.2 ships two independent ML pipelines that follow the same shape:

| System                | Purpose                                                    | Live serve module                | Train-time module                            | Persisted as                                          |
|-----------------------|------------------------------------------------------------|----------------------------------|----------------------------------------------|-------------------------------------------------------|
| **Sweep weights**     | Drift the SharePoint sweep scoring weights toward observed assessor check/uncheck behavior | `evidence/sources/sweep.py::score_candidate` reads weights row | `engine/sweep_online.py::update_weights_online` (SGD, background) + `scripts/recalibrate_sweep_weights.py` (batch LR) | `SweepWeights` (one row per fit, `is_active=True` on the served row) |
| **CRM suspicion**     | Score every uploaded CRM for "the vendor lied to us" before the assessor relies on it | `engine/crm_sanity.py::score_crm_suspicion` (heuristics + ML tiers) | `scripts/refit_crm_anomaly_model.py` (IsolationForest fit on accumulated feature corpus) | `CrmAnomalyModel` (model blob), `CrmCorpusFeatures` (training rows), `CrmNarrativeEmbedding` (per-narrative cache), `CrmSuspicionLog` (audit trail of every served score) |

Neither system has supervised labels yet. The CRM `assessor_marked_false_positive`
field on `CrmSuspicionLog` and the `included` field on `SweepDecision`
are the eventual label sources — the v0.3+ supervised classifiers gate
on those corpora reaching usable size.

## Train / serve split

Strictly enforced. The serve path never trains; the train path never
short-circuits a route handler.

```
Serve path (sync, on every request):
  route handler
    └─ pull active model row from DB
        └─ call engine module (crm_sanity / sweep) — pure, session-free
            └─ joblib.loads(blob) + sklearn estimator.score()

Train path (async, operator-triggered or background hook):
  scripts/refit_*.py   OR   engine/sweep_online.py::update_weights_online
    └─ pull training corpus from DB
        └─ fit sklearn estimator
            └─ joblib.dumps(...) → new DB row with is_active=False
```

The serve path imports sklearn (cheap — feature math + `score_samples`).
The train path imports `SGDClassifier`, `IsolationForest`, etc. Both
import lazily inside the function that needs them, so a sidecar startup
that never touches ML never pays the import cost. This matters for the
test suite — unit tests that don't exercise the ML path are sklearn-free.

## sklearn is a runtime dep, not training-only

Original plan called for sklearn as a dev-only extra. That was wrong:
`SGDClassifier.partial_fit` runs **live** in the background task after
every triage session, and `score_anomaly` runs **live** on every CRM
suspicion recompute. Both need sklearn installed in the sidecar.

Footprint is acceptable (~30 MB pure-Python on top of numpy/scipy).
`backend/pyproject.toml` lists `scikit-learn` under the runtime
dependencies; the `[offline-embeddings]` extra adds
`sentence-transformers` for sites that want an LLM-quality embedding
without an OpenAI key.

## Operator review before promotion

Every auto-fitted artifact (SGD weight update, IsolationForest refit)
lands `is_active=False`. The operator promotes explicitly:

| Path                                                            | Auto-activation? | Operator action to activate                         |
|-----------------------------------------------------------------|------------------|-----------------------------------------------------|
| `update_weights_online` (background, after `/sweep/decisions`)  | No               | `recalibrate_sweep_weights.py --activate` (or future UI button) |
| `recalibrate_sweep_weights.py`                                  | No (default)     | Re-run with `--activate`, OR future UI button       |
| `refit_crm_anomaly_model.py`                                    | No (default)     | Re-run with `--activate`                            |

This is non-negotiable. An auto-fit that goes degenerate (single-class
training batch, all-included sweep decisions, etc.) must not silently
take over the served weights and break every subsequent assessment. The
auto path **collects evidence**; the operator **commits the change**.

Activation is implemented as an atomic swap inside one DB transaction:
the new row goes `is_active=True` and the previously-active row goes
`is_active=False` in the same commit. Exactly one active row at all
times — pinned by `test_refit_crm_anomaly_model.py::test_activate_flips_swap_atomically`
and the matching sweep-side test.

## Versioned active-row pattern

Both systems use the same DB shape: a table where every fit writes a
new row, exactly one row has `is_active=True`, and the lineage is
walked via `parent_weights_id` / `parent_active_model_id`.

```sql
SELECT * FROM crm_anomaly_model WHERE is_active = 1;  -- the served model
SELECT * FROM sweep_weights      WHERE is_active = 1;  -- the served weights
```

Benefits:
- **Atomic rollback** — flip the active flag back to the parent row.
- **Audit trail** — every served decision references a specific
  `weights_version_id` / model row id via `CrmSuspicionLog` /
  `SweepDecision`, so we can re-derive what the assessor saw.
- **No silent overwrites** — a bad fit doesn't destroy the prior good
  one; it just lives alongside it as an inactive row.

## Schema-version guard

`CrmFeatureVector.schema_version` and `CrmCorpusFeatures.feature_schema_version`
both reference `crm_ml.CURRENT_FEATURE_SCHEMA_VERSION`. The guard
fires in three places:

1. **At fit time** — `fit_anomaly_model` filters the corpus to current
   version. Mixed-version corpora produce a fit that scores wrong
   vectors against wrong centroids.
2. **At score time** — `score_anomaly` returns 0.0 (neutral, not
   anomalous) if the served model's version doesn't match the live
   feature vector's. Defensive against an operator forgetting to
   bump `is_active` after a schema bump.
3. **In persistence** — `CrmCorpusFeatures` rows at the old version
   survive (useful for diagnostics) but stop contributing to fits.

Bumping `CURRENT_FEATURE_SCHEMA_VERSION` therefore **resets the
training corpus to zero** for the new version. After a bump, the IF
tier is dormant until enough new CRMs are uploaded — same as cold
start. Plan the bump accordingly.

The sweep side does not yet have a schema version on `SweepDecision`
features. Signal additions (e.g. a new "priority link match" weight)
just add a new `SweepWeights` column with default 0.0; existing
decisions get re-scored as if the new signal didn't fire. If a future
signal change is not back-compatible (e.g. semantics of an existing
weight flip), introduce a `feature_schema_version` column then.

## Cold-start behavior

| System              | Cold-start tier(s)                                     | When richer tiers light up                              |
|---------------------|---------------------------------------------------------|----------------------------------------------------------|
| Sweep               | Hand-tuned `SweepWeights` v1 seeded at `init_db`        | After 25+ unconsumed `SweepDecision` rows → first SGD fit; after 50+ ever → batch LR is allowed |
| CRM heuristics      | All four `_eval_*` rules — fires on the FIRST CRM       | n/a — always on                                          |
| CRM TF-IDF boilerplate | Re-uses `CrmFeatureVector.intra_crm_tfidf_*` — first CRM | n/a — always on                                          |
| CRM narrative quality | TF-IDF fallback provider works without API on the first CRM; OpenAI provider works on the first CRM if key configured | n/a — always on when a provider is resolvable           |
| CRM IsolationForest | Dormant — `_blend` redistributes weight to heuristic+narrative | `n_corpus >= MIN_CORPUS_SIZE` (10) AND an `is_active` `CrmAnomalyModel` row exists at the current schema version |

The blend redistributes weight when a tier is unavailable so that
cold-start CRMs aren't artificially "less suspicious" than scored
ones. See `CRM_SANITY_DESIGN.md` for the redistribution math.

UI surfaces unavailable tiers as greyed-out rows ("corpus too small
(n=4 / 10)") rather than hiding them. Hiding would make a heuristic-only
score look like a confirmed multi-tier score.

## Reproducibility

Both systems snapshot enough context with every served decision to
re-derive the score later, even if the underlying data has moved:

- **Sweep**: `SweepDecision.weights_version_id` + `fingerprint_snapshot_json`
  + `signals_json`. An audit can pull the historical weights row and
  recompute `score_candidate` against the snapshot fingerprint.
- **CRM**: `CrmSuspicionLog` stores per-tier scores, the flag list, the
  per-family breakdown, and `n_corpus` at compute time. Pair with the
  active `CrmAnomalyModel` row id (resolvable from `computed_at` and
  the model row's `fitted_at`) to re-derive.

This is the load-bearing piece for the future supervised classifiers
— labels are only useful if we can replay the features that produced
them.

## Where the v0.3+ supervised classifiers plug in

Both systems are explicitly designed so that today's unsupervised /
heuristic tiers can be swapped (or supplemented) with a supervised
classifier once labels accumulate.

| System | Label source                                              | Plug point                                          | Min labels (rough)                |
|--------|-----------------------------------------------------------|-----------------------------------------------------|-----------------------------------|
| Sweep  | `SweepDecision.included` (already labeled per row)       | `engine/sweep_online.py` already runs SGD — swap the loss / estimator | n/a — labeled from day one        |
| CRM    | `CrmSuspicionLog.assessor_marked_false_positive`         | New tier between heuristics and IsolationForest in `crm_sanity._blend` | ~50 confirmed-real + ~50 confirmed-FP |

The sweep side is already supervised in spirit — the `included`
checkbox IS the label. The CRM side is one column away: once the
"Mark as false positive" UI accumulates enough decisions, a
calibrated probability classifier replaces the IsolationForest tier
(or runs alongside it in the blend).

This is why the data model bothers persisting `flags_json` and
`per_family_json` on `CrmSuspicionLog` — those are the candidate
features for the v0.3+ classifier, not just UI render fodder.

## What NOT to do

- **Don't auto-activate.** Every auto-fit lands `is_active=False`.
  The operator decides what gets served.
- **Don't import sklearn at module top-level in engine code.** Lazy
  imports inside the train/score functions. Tests that don't exercise
  ML must stay sklearn-free.
- **Don't write new active-model tables without the `is_active` swap
  pattern.** Two active rows at once = inconsistent serving. Pin it
  with an atomic-swap test as both `test_refit_crm_anomaly_model.py`
  and the sweep-side test do.
- **Don't bypass the schema-version guard.** A served model loaded
  against the wrong feature schema produces silent nonsense, not a
  loud error. The guard is the only thing preventing that.
- **Don't store training-only artifacts in the route-handler path.**
  Anything sklearn touches at train time (corpus, scaler stats, fit
  metadata) lives in a `*Model` / `*CorpusFeatures` / `*Weights` table
  written by the script or background task — never written
  opportunistically from a request handler.
- **Don't conflate "no labels" with "no ML."** Unsupervised ML
  (IsolationForest, TF-IDF, embeddings) ships today; supervised ML
  is deferred only until labels accumulate. The two systems above
  are unsupervised-by-design and still provide real signal.
