# SharePoint Boundary-Aware Sweep — Design Spec

Target audience: implementing agent. Read `sharepoint.py` (existing connector),
`tagger.py` (filename + content heuristics), `engine/crm_context.py` (responsibility
lookup), and `evidence/asset_crosscheck.py` (boundary fingerprint patterns) first.
The sweep reuses all four; it does not invent new matching primitives.

## What this is

A **no-download triage step** that sits between the "configure SharePoint" and
"ingest" phases. Given a configured scan root and a loaded program workbook, it:

1. Enumerates the scan root via Graph metadata only (no file bytes pulled).
2. Runs Graph `/search(q='…')` for each boundary-derived token to get snippets.
3. Scores every candidate file against (a) workbook host inventory, (b) CCI
   control-family keywords, and (c) the CRM responsibility table.
4. Returns a ranked candidate list with proposed CCI mappings — **no Evidence
   rows are written**.
5. The user confirms a subset; only then does a real ingest run pull bytes
   via the existing `file_paths` cherry-pick path.

The win: instead of asking the user to point at a folder and ingest everything,
we surface the 30 files in a 4,000-file site that look like they belong to
*this* boundary, pre-tagged with proposed CCIs, before any download cost.

## Why CRM changes the design

Per `feedback_overlay_default_local.md`, a control with no CRM entry defaults
to fully-customer responsibility — the assessor runs the full LLM path.
The sweep can use this asymmetrically:

| CRM responsibility   | Sweep behavior                                          |
|----------------------|---------------------------------------------------------|
| customer / null      | Sweep aggressively — this is the assessor's problem     |
| hybrid               | Sweep, but mark candidates "shared — provider may suffice" |
| provider             | Skip the family unless the user explicitly opts in      |
| inherited            | Skip entirely; surface a one-line "inherited via X" note|
| not_applicable       | Skip entirely                                           |

Skipping provider/inherited families is the entire point — most SharePoint
libraries on a hybrid system have hundreds of vendor docs the assessor
shouldn't burn time triaging. The CRM tells us which ones to ignore.

The CRM **narrative** field is also a fingerprint source: text like
"AWS Config rule …" or "GitLab role …" lets us boost candidates whose
filename/snippet contains those strings even when the workbook host
inventory misses them.

## File layout

```
backend/cybersecurity_assessor/
  evidence/
    sources/
      sharepoint.py               # existing — add sweep_for_boundary() method
      sweep.py                    # NEW — pure scoring logic, no Graph calls
  routes/
    sharepoint.py                 # add POST /api/sharepoint/sweep
  engine/
    crm_context.py                # existing — reuse build_crm_context()
ui/src/
  components/
    BrowseSharePointDialog.tsx    # existing — add "Sweep boundary" tab
    SweepTriageDialog.tsx         # NEW — candidate table + confirm flow
  lib/
    api.ts                        # add sweepSharePoint() helper
```

## Boundary fingerprint

Built once per sweep request from the workbook + CRM + catalog. Shape:

```python
@dataclass(frozen=True)
class BoundaryFingerprint:
    workbook_id: int
    host_tokens: set[str]          # normalized hostnames from HW/SW inventory
    control_families: set[str]     # {"AC", "AU", "SI", ...} of in-scope CCIs
    crm_skip_families: set[str]    # families where ALL CCIs are provider/inherited/NA
    crm_keywords: dict[str, set[str]]  # control_id -> tokens lifted from CRM narrative
    doc_number_prefixes: set[str]  # {"USD", "SDP", "Example System", ...} seen in workbook
```

Source order:
1. **host_tokens** — `Evidence.host_inventory` JSON across all evidence already
   ingested for this workbook, plus any hostname column the program control
   loader exposed (see `catalogs/program_controls_loader.py`).
2. **control_families** — distinct two-letter prefixes of in-scope CCIs from
   `BaselineObjective` (skip rows that resolved to NA via SDA Controls — see
   `feedback_verify_na_against_sda_controls.md`).
3. **crm_skip_families** — for each family, if `CrmContext.lookup(control_id)`
   returns `provider` / `inherited` / `not_applicable` for *every* CCI in
   the family, the family is skip-eligible. Conservative: a single
   customer/hybrid CCI keeps the whole family in scope.
4. **crm_keywords** — strip stopwords + 1-char tokens from `CrmEntry.narrative`;
   keep tokens ≥ 4 chars. Bounded to top 50 per control to keep the search
   matrix sane.
5. **doc_number_prefixes** — scrape `Evidence.doc_number` already in the DB;
   fall back to a hard-coded `{"USD"}` if the DB is empty (fresh workbook).

## Scoring

Each candidate file (already filtered to `_INGESTIBLE_SUFFIXES`) earns a
score from independent signals. Float, 0.0–1.0, additive cap at 1.0:

| Signal                                | Weight | Notes                                  |
|---------------------------------------|--------|----------------------------------------|
| Host token in name/path/snippet       | +0.40  | Cap once even if multi-hit             |
| CCI control-id in name/path/snippet   | +0.30  | e.g. "AC-2" literal                    |
| Family keyword from `tagger.py`       | +0.20  | Reuse `tagger._FAMILY_KEYWORDS`        |
| CRM narrative keyword hit             | +0.15  | Only if `crm_keywords` has matches     |
| Doc number prefix in filename         | +0.10  | "USD00050010_…"                        |
| In a family on `crm_skip_families`    | −∞     | Drop entirely                          |

`tagger.py` already has the filename/content heuristic table; the sweep
imports it directly rather than duplicating. The new bit is running it
against **Graph snippets** instead of the extracted-text body.

A candidate must score ≥ 0.30 to surface. Below that → almost certainly
not boundary-relevant; surfacing them retrains the user to ignore the
list, which kills the value of triage.

## Public API

### Backend module — `evidence/sources/sweep.py`

```python
@dataclass(frozen=True)
class SweepCandidate:
    name: str
    path: str               # relative to scan root (drive-relative inside library)
    web_url: str            # SharePoint UI URL for "open in browser" link
    size: int | None
    modified: str | None    # ISO-8601 string from Graph
    score: float            # 0.0–1.0
    matched_signals: list[str]   # ["host:server01", "family:AC", "crm-kw:gitlab"]
    proposed_ccis: list[str]     # OSCAL canonical, sorted, ≤ 8
    snippet: str | None     # Graph search hit excerpt, may be None
    download_url: str | None     # @microsoft.graph.downloadUrl captured at walk-time

@dataclass(frozen=True)
class SweepResult:
    scan_root: str          # the URI we swept
    workbook_id: int
    candidates: list[SweepCandidate]
    families_skipped_by_crm: list[str]   # for the UI "we ignored AU/AT/CP" badge
    truncated: bool         # true when we hit the candidate cap
    elapsed_ms: int

def build_boundary_fingerprint(
    workbook_id: int, session: Session
) -> BoundaryFingerprint: ...

def score_candidate(
    name: str,
    path: str,
    snippet: str | None,
    fingerprint: BoundaryFingerprint,
) -> tuple[float, list[str], list[str]]:
    """Returns (score, matched_signals, proposed_ccis). Pure function — no IO."""
```

### Method on `SharePointSource`

```python
def sweep_for_boundary(
    self,
    fingerprint: BoundaryFingerprint,
    *,
    max_candidates: int = 250,
    max_search_queries: int = 30,
) -> SweepResult:
    """Metadata-only enumeration + Graph search + scoring. No file bytes pulled.

    Caps:
    - max_search_queries bounds the /search round-trips (token budget control)
    - max_candidates bounds the returned list (UI sanity)

    Algorithm:
      1. BFS scan root via /children, capture {name, path, size, modified,
         webUrl, downloadUrl} for every ingestible file. Bounded depth = 4.
      2. For each token in fingerprint.host_tokens ∪ fingerprint.doc_number_prefixes
         ∪ (top-N control families), call /search(q=token) once and merge
         snippets into the candidate map by drive-item id.
      3. Score every candidate via sweep.score_candidate.
      4. Drop score < 0.30; sort desc; truncate to max_candidates.
    """
```

### Route — `routes/sharepoint.py`

```python
class SweepRequest(BaseModel):
    workbook_id: int
    max_candidates: int = 250

@router.post("/sweep")
def sweep_sharepoint(req: SweepRequest, s: Session = Depends(get_session)) -> dict:
    """Triage SharePoint for boundary-relevant evidence. Read-only — no Evidence
    rows are created. Caller proceeds with POST /api/sharepoint/ingest passing
    the confirmed file_paths subset.
    """
    # Build source from settings (same pattern as existing /search route)
    # Build fingerprint via sweep.build_boundary_fingerprint(workbook_id, s)
    # Call source.sweep_for_boundary(fingerprint, ...)
    # Return SweepResult.as_dict()
```

### UI — `SweepTriageDialog.tsx`

Triggered from the existing SharePoint dialog via a new tab/button "Sweep for
boundary…". Renders:

- Header: "N candidates from {scan_root}. Skipped {k} provider/inherited families:
  AU, AT, CP." (collapsible)
- Sortable table: checkbox | name | score (color-bar) | proposed CCIs (chips) |
  matched signals (gray chips) | snippet (truncated, tooltip-expand) |
  size | modified | open-in-SharePoint link
- Footer: "Ingest N selected →" button. Click hits the existing
  `POST /api/sharepoint/ingest` with `file_paths=[…]` — no new ingest path.

Pre-check rows scoring ≥ 0.60 by default so the common case is "review,
uncheck noise, click ingest".

## What NOT to do

- **Don't write Evidence rows from the sweep.** The whole point is no-download
  triage. Persisting candidates would fight the existing ingest dedupe and
  pollute the evidence inventory. Note: sweep DOES *read* `Evidence.path` to
  flag pre-credited candidates (so the UI can show an "In Evidence" badge and
  default-uncheck rows that already shipped) — that's a one-way read via the
  shared canonical URI (`sharepoint://host/<server-relative-url>`), not a
  write. See `sweep.normalize_sp_candidate_uri` and the batched lookup in
  `routes.sharepoint.sweep`. The Evidence ⇄ Sweep dependency stays strictly
  one-way: Sweep consumes Evidence; Evidence is unaware of Sweep.
- **Don't re-implement filename heuristics.** Import `tagger._FAMILY_KEYWORDS`
  (extract to a public name if needed) and reuse. Two copies will drift.
- **Don't trust Graph search snippets as evidence.** They're a hint for
  scoring, not extracted text. The real extractor runs at ingest after the
  user confirms.
- **Don't sweep recursively below depth 4.** SharePoint libraries with deep
  trees will balloon the search matrix. If a user has evidence deeper, they
  drill in via the existing browse dialog.
- **Don't surface candidates from CRM-skipped families with a "warning" badge.**
  That re-introduces the noise the CRM was supposed to eliminate. Hide them
  entirely; the "k families skipped" badge tells the user why.
- **Don't gate the sweep on "is CRM attached?"** When `CrmContext.empty()`,
  `crm_skip_families` is empty and the sweep just sweeps every family. CRM
  is a narrowing input, not a precondition.
- **Don't add a schema column for "swept_at".** Sweep state is ephemeral.
  If we ever want history, add it as a new table; don't taint Evidence.

## Test plan

- **Unit (sweep.py):** fingerprint construction from a synthetic session
  with one CRM overlay; assert `crm_skip_families` excludes families with any
  customer/hybrid CCI; assert `score_candidate` weights match the table.
- **Unit (SharePointSource.sweep_for_boundary):** monkeypatch `_list_children`
  and the `/search` endpoint; assert (a) no `.open()` is ever called on a
  returned `SharePointFile`, (b) `max_search_queries` is respected, (c)
  candidates from skip families are dropped before scoring.
- **Integration (route):** spin up the FastAPI app against a fake
  SharePointSource that returns a fixed candidate fixture; POST to /sweep;
  assert the response shape and that no `Evidence` rows exist after the call.
- **End-to-end (manual, against current Example System workbook):** run the
  sweep against the live SharePoint scan root; verify the candidate list is
  ≤ 100, includes the in-scope hostnames, excludes the provider-owned AU
  family, and that clicking "Ingest 30 selected" produces an IngestSummary
  with `ingested == 30`.

## Weight calibration (online SGD + batch reset)

The weights in the scoring table above (`_W_HOST = 0.40`, `_W_CONTROL_ID = 0.30`,
`_W_FAMILY = 0.20`, `_W_CRM_KEYWORD = 0.15`, `_W_DOC_PREFIX = 0.10`,
`_W_PRIORITY_LINK`) started life as "felt right". v0.2 ships the machinery to
drift them toward observed assessor behavior — every check/uncheck in
`SweepTriageDialog` is a labeled training example for "does this candidate
belong to the boundary?". The constants in `sweep.py` are now **fallback
defaults** consulted only when no `weights=` is passed (keeps unit tests
session-free); the live route loads a versioned row from `SweepWeights`.

### Data model

| Table             | Role                                                              |
|-------------------|-------------------------------------------------------------------|
| `SweepWeights`    | Versioned weight vector. `is_active=True` for the served row. `source ∈ {"manual","sgd_online","batch_lr"}`. `parent_weights_id` walks the lineage. `auc` populated for `batch_lr` rows. |
| `SweepDecision`   | One row per candidate shown in the triage dialog, with `included` reflecting the final checkbox state at Ingest click. Snapshots `signals_json`, `fingerprint_snapshot_json`, and `weights_version_id` so we can recompute features later even if the workbook changes. `consumed_for_training` flips true once the SGD path has trained against the row. |

`db.py` seeds a v1 `SweepWeights` row at init with `source="manual"`,
`is_active=True`, and the constants above.

### Live path — `engine/sweep_online.py::update_weights_online`

Triggered as a background task after `POST /sweep/decisions` persists a
triage session's worth of decision rows:

1. Pull all `SweepDecision` rows with `consumed_for_training=False`.
2. Refuse to fit if the batch is single-class — degenerate.
3. Warm-start `SGDClassifier(loss="log_loss")` from the currently-active
   weights vector (the active row's coefficients become `coef_init` /
   `intercept_init`).
4. `partial_fit` over the new batch.
5. Clip any negative coefficients to zero and log a warning — a negative
   weight on "host token matched" means the model wants to *demote*
   host-matched candidates, which is almost always overfitting on a
   small batch. Sign constraint matches the human-interpretable scoring
   table: weights are evidence, not penalties.
6. Write a new `SweepWeights` row with `source="sgd_online"`,
   `parent_weights_id=<current active>`, `is_active=False`.
7. Mark the consumed `SweepDecision` rows.

**Operator review before promotion** — auto-fitted rows always land
`is_active=False`. Operator spot-checks via the recalibration UI/script
and explicitly flips activation. Auto-activation is reserved for the
explicit `--activate` operator action; nothing the assessor does in
normal use flips the served weights.

`sklearn` loads lazily inside the background task — sidecar startup
stays sklearn-free for tests that don't exercise the live update path.

### Batch reset path — `scripts/recalibrate_sweep_weights.py`

Operator-invoked "reset to canonical" path; complements the online updater
when its drift has gone somewhere unwanted or the operator wants a
fresh fit from the full decision corpus.

| Exit | Reason                                                                  |
|------|-------------------------------------------------------------------------|
| 0    | Wrote a new `SweepWeights(source="batch_lr")` row                       |
| 1    | `--activate --dry-run` mutex violation; no DB work                      |
| 2    | Decision corpus below `MIN_DECISIONS_FOR_BATCH_FIT` (50) — too noisy   |
| 3    | Single-class corpus (all-included or all-excluded) — degenerate fit     |
| 5    | 5-fold CV AUC below `--min-auc` (default 0.70); override with `--min-auc 0` |

The script:

1. Pulls every `SweepDecision` row (regardless of `consumed_for_training`).
2. Fits scikit-learn `LogisticRegression` with the same negative-clip rule
   as the online path.
3. Runs 5-fold CV and records AUC on the new row.
4. Writes a new `SweepWeights` row with `source="batch_lr"`,
   `parent_weights_id=<current active>`, `is_active=False` by default.
5. `--activate` flips the swap atomically: new row goes `is_active=True`,
   the previously-active row goes `is_active=False`, in the same commit —
   exactly one active row at all times.
6. `--dry-run` exits 0 without persisting (used to eyeball the fit before
   committing).

### Reproducibility

Each `SweepDecision` row captures `weights_version_id` (which `SweepWeights`
row was live when the assessor made the decision) and
`fingerprint_snapshot_json` (the boundary fingerprint at decision time).
A future audit can re-derive the score the assessor saw and re-fit
against any historical weights vector without time-traveling the
workbook back.

## Open questions (defer; capture as TODOs in code)

1. **Graph search reliability** — Graph `/search(q=)` against drives is
   sometimes flaky for very recent uploads (indexing lag). Acceptable for
   v0.2; if it hurts users, fall back to filename-only matching when search
   returns < 3 hits.
2. **Cross-library sweep** — current design sweeps the configured scan root
   only. Multi-library boundaries are a v0.3 problem; mention in the empty
   state when no candidates surface.
3. **Cost ceiling** — `max_search_queries=30` × ~200ms = ~6s. If we ever add
   content-extraction at sweep time (which we shouldn't), the cost crosses
   into "needs a job" territory. Stay metadata-only.
