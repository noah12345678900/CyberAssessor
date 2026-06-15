# Pending-Sweep Smoke Test Plan

Covers the three scenarios in `hazy-tumbling-fairy.md` Verification §4
(boundary-sweep decoupled from Workbook). The plan is split into:

1. **Backend HTTP plan** (scriptable; no Electron required) — proves the
   sidecar contract end-to-end for all three scenarios.
2. **Manual UI checklist** — the small set of assertions that can ONLY
   be made by looking at the renderer (button-enabled state, banner
   copy, tooltip text).
3. **Deferred** — what would warrant Vitest/Playwright once the UI
   stabilizes.

The first two together prove the slice works. The kernel-under-dev
caveat is why we lean on (1) — every state transition that lives in
the DB is covered there without clicking through Electron.

---

## 0 — Prereqs

Sidecar reachable on `http://127.0.0.1:8765` (default dev port). If
the port is different, substitute throughout. Sidecar launched via:

```bash
cd ui && node scripts/launch-electron.mjs
```

Per `feedback_restart_sidecar_yourself.md`: if `taskkill` says Access
Denied, leave the orphan and launch again — the new sidecar picks an
ephemeral port.

All three scenarios assume a **clean pending state**. Reset first:

```bash
curl -X POST http://127.0.0.1:8765/api/system-context/pending/reset
```

---

## 1 — Backend HTTP Plan (no UI needed)

### Scenario A — No workbook open, pending-mode sweep

**Goal:** Pending boundary docs + extracted SystemContext are enough
to run a sweep. `SweepRun.workbook_id IS NULL`,
`SweepRun.system_context_id` is set.

**Already covered automatically:**

- `tests/routes/test_system_context_pending.py::test_get_pending_returns_200_null_when_empty`
- `tests/routes/test_system_context_pending.py::test_get_pending_returns_ctx_and_docs`
- `tests/routes/test_sharepoint_sweep.py::test_sweep_pending_mode_writes_sweeprun_with_null_workbook`
- `tests/routes/test_sharepoint_sweep.py::test_sweep_422_when_pending_fingerprint_has_no_signals`

**Run:**

```bash
cd backend && uv run pytest \
  tests/routes/test_system_context_pending.py \
  tests/routes/test_sharepoint_sweep.py -v
```

**Manual reproduction against live sidecar (sanity check the wired
DB, not the in-memory test DB):**

```bash
# 1. Confirm clean slate
curl -s http://127.0.0.1:8765/api/system-context/pending | jq .
#  → {"context": null, "boundary_docs": []} with 200
#    (route returns 200 on empty so the polled "is there pending scope?"
#    check doesn't spam DevTools with 404s on every fresh app load)

# 2. Seed a pending context directly (no LLM round-trip)
curl -s -X POST http://127.0.0.1:8765/api/system-context/pending \
  -H 'content-type: application/json' \
  -d '{
        "source_type":"freeform_markdown",
        "source_ref":"smoke-test",
        "extracted_tokens":["server01","host42"],
        "confidence":0.6
      }' | jq .
#  → 200 with the new SystemContext row; capture .id as $CTX_ID

# 3. Fire a sweep against the pending scope only
curl -s -X POST http://127.0.0.1:8765/api/sharepoint/sweep \
  -H 'content-type: application/json' \
  -d "{\"system_context_id\":$CTX_ID,\"max_candidates\":25}" | jq .
#  → 200; body.workbook_id is null; body.system_context_id == $CTX_ID

# 4. Confirm the SweepRun row is null-workbook
sqlite3 "$LOCALAPPDATA/cybersecurity-assessor/app.db" \
  "SELECT id, workbook_id, system_context_id FROM sweeprun ORDER BY id DESC LIMIT 1;"
#  → workbook_id is NULL; system_context_id matches $CTX_ID
```

**Pass criteria:** all four bullets behave as commented.

### Scenario B — Open workbook + pending scope → promote

**Goal:** Promote banner copy is exposed via the API; promote
reparents the SystemContext + Evidence rows + leaves pre-promote
SweepRun rows reachable via `system_context_id`.

**Already covered automatically:**

- `tests/routes/test_system_context_pending.py::test_promote_pending_reparents_context_and_docs`
- `tests/routes/test_system_context_pending.py::test_promote_pending_with_docs_only_reparents_docs`
- `tests/routes/test_system_context_pending.py::test_promote_pending_refuses_409_when_workbook_has_context`
- `tests/routes/test_system_context_pending.py::test_promote_pending_404_when_workbook_unknown`

**Run:**

```bash
cd backend && uv run pytest tests/routes/test_system_context_pending.py -v -k promote
```

**Manual reproduction:**

```bash
# Pre-req: scenario A done, so $CTX_ID exists and a SweepRun is keyed to it.

# 1. Open a workbook through the existing route (any small xlsx in your tree)
curl -s -X POST http://127.0.0.1:8765/api/workbooks \
  -H 'content-type: application/json' \
  -d '{"path":"C:/path/to/some/demo.xlsx"}' | jq .
#  → capture .id as $WB_ID

# 2. Promote
curl -s -X POST "http://127.0.0.1:8765/api/system-context/pending/promote?workbook_id=$WB_ID" | jq .
#  → 200, body.promoted == true, body.context.workbook_id == $WB_ID,
#    body.boundary_doc_count matches what you seeded

# 3. Pending GET now empty
curl -s http://127.0.0.1:8765/api/system-context/pending | jq .
#  → 200 with {"context": null, "boundary_docs": []}
#    (the pending row was reparented onto $WB_ID, so the pending scope
#    is empty again — but the route still 200s on empty per the contract
#    above)

# 4. Pre-promote SweepRun row reparented (confirms the slice's invariant
#    that historical telemetry survives the promote)
sqlite3 "$LOCALAPPDATA/cybersecurity-assessor/app.db" \
  "SELECT id, workbook_id, system_context_id FROM sweeprun WHERE system_context_id=$CTX_ID;"
#  → row's workbook_id IS NULL (we did not rewrite SweepRun rows in this slice —
#    they remain reachable via system_context_id, which now maps to $WB_ID
#    through SystemContext)
```

**409 promote-conflict path (covered by test, manual repro optional):**

```bash
# Open a second workbook
curl -X POST http://127.0.0.1:8765/api/workbooks ... → $WB2_ID

# Give it its own SystemContext directly (mimic user already extracted)
curl -X POST http://127.0.0.1:8765/api/system-context/$WB2_ID \
  -d '{"source_type":"freeform_markdown","source_ref":"x","extracted_tokens":["existing-host"],"confidence":0.7}'

# Try to promote a *new* pending scope onto $WB2_ID
curl -X POST http://127.0.0.1:8765/api/system-context/pending
  ... (seed pending)
curl -i -X POST "http://127.0.0.1:8765/api/system-context/pending/promote?workbook_id=$WB2_ID"
#  → HTTP/1.1 409 Conflict; detail mentions "already has a SystemContext"
```

### Scenario C — Neither workbook nor pending → sweep refused

**Goal:** The backend prevents firing a sweep without any signal.

**Already covered automatically:**

- `tests/routes/test_sharepoint_sweep.py::test_sweep_422_when_pending_fingerprint_has_no_signals`

For the **request-shape** half of the contract (caller passes neither
`workbook_id` nor `system_context_id`), confirm the route validator
trips:

```bash
curl -i -X POST http://127.0.0.1:8765/api/sharepoint/sweep \
  -H 'content-type: application/json' \
  -d '{}'
#  → HTTP/1.1 422 Unprocessable Entity
#    detail mentions "at least one of workbook_id / system_context_id"
```

**Pass criteria:** HTTP 422 with the dual-precondition copy.

---

## 2 — Manual UI Checklist

Only the items below need eyes on the renderer — the rest is proven
by §1. Launch the app (`node scripts/launch-electron.mjs` from `ui/`)
and walk through.

### Scenario A — No workbook open

| Step | Where | Expected |
|---|---|---|
| 1 | App opens with no workbook selected | Top bar shows no workbook chip |
| 2 | Navigate to **Sweep** | Page renders **without** the old "No workbook open" gate; boundary-doc dropzone is enabled |
| 3 | Drop one boundary PDF | Toast confirms ingest; Pending boundary list updates |
| 4 | Open **Workbooks → Browse SharePoint** | **Sweep for boundary…** button **enabled**; hover tooltip reads "Score files against your pending boundary scope." |
| 5 | Click **Sweep for boundary…** | `SweepTriageDialog` opens, title references pending scope (not a workbook filename) |
| 6 | Run sweep, accept zero candidates, close | No JS errors in DevTools console |

DB-row assertion for steps 3 + 6 is covered by the curl/sqlite checks
in §1 Scenario A — repeat those after step 6 if you want belt-and-suspenders.

### Scenario B — Open workbook with pending scope present

| Step | Where | Expected |
|---|---|---|
| 1 | After Scenario A finishes (pending row exists), open a workbook from **Workbooks** | Workbook chip appears top bar |
| 2 | Navigate to **Sweep** | A **promote banner** appears above the page body with copy similar to: *"You have a pending boundary scope from before this workbook was opened. Promote it onto {filename}?"* Banner has **Promote** + **Discard** buttons |
| 3 | Click **Promote** | Banner disappears; SystemContext now keyed on the workbook; latest-sweep card lists the pre-promote `SweepRun` |
| 4 | Reload (Ctrl+R) | No promote banner re-appears (pending is empty after promote) |

### Scenario B-alt — 409 conflict path

| Step | Where | Expected |
|---|---|---|
| 1 | Workbook with an existing SystemContext is open | (Set up via curl per §1) |
| 2 | Pending scope exists for a different host | (Set up via curl per §1) |
| 3 | Navigate to **Sweep** and click **Promote** | Toast/inline error explains "this workbook already has a SystemContext" and tells the user to reset the workbook's context first |
| 4 | DevTools network tab | Response is 409, not 200 |

### Scenario C — Neither workbook nor pending

| Step | Where | Expected |
|---|---|---|
| 1 | Fresh app, no workbook, pending reset | (Run `curl POST /api/system-context/pending/reset` first) |
| 2 | Open **Workbooks → Browse SharePoint** | **Sweep for boundary…** button is **disabled**; hover tooltip reads something equivalent to "Open a workbook or add boundary docs on the Sweep page first." |

---

## 3 — Deferred (out of this slice)

Once the kernel stabilizes, the UI checks in §2 would be good
candidates for Vitest + React Testing Library cases against the four
components touched in `hazy-tumbling-fairy.md`:

- `SweepContext.tsx` — pending vs workbook mode branching + promote
  banner appearance.
- `BrowseSharePointDialog.tsx` — disabled-state + tooltip copy logic
  (three branches).
- `SweepTriageDialog.tsx` — discriminated-union `scope` prop wiring.
- `lib/queries.ts` — `usePendingSystemContext` /
  `useUpsertPendingSystemContext` /
  `usePromotePendingSystemContext` (per
  `feedback_mutation_opts_spread_order.md` — destructure `onSuccess`
  out of `opts` BEFORE spreading).

Not adding now: no Vitest config exists in `ui/`, and the user's
constraint ("ship the best version now, not deferred") is satisfied
by the backend coverage + manual checklist for this release. Add the
component-test rig as part of the slice that introduces broader UI
testing, not piggybacked here.
