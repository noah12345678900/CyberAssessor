/**
 * ComplianceTargetPicker — picks the **framework / catalog binding** the
 * assessor uses to resolve CCI references in your program workbook.
 *
 * Mental model (corrected 2026-06-04 per
 * project_assessor_input_is_program_workbook.md and
 * feedback_fedramp_is_baseline.md):
 *
 *   - The **assessment target is the program workbook the user uploads** —
 *     output of RMF steps 1-3 (Categorize / Select / Implement). The
 *     workbook itself encodes scope: CCIs present = in-scope, absent =
 *     out-of-scope, flagged NA = NA.
 *   - This picker's job is **catalog binding only**: which published
 *     control catalog should the parser/lookup engine use when it sees
 *     a CCI like "CCI-000196" in the workbook?
 *   - It is NOT a "what are we assessing against" picker. That decision
 *     lives in the workbook the user uploads.
 *
 * UI grouping:
 *   - **Catalogs** — raw published frameworks (NIST 800-53 r4/r5). The
 *     primary thing the picker binds the workbook to.
 *   - **Workbook baselines** — selections materialized from a real
 *     assessment (CCIS-derived from a previously-opened workbook's
 *     column A scoping, CRM overlay, SSP, manual). Useful for
 *     filtering the Controls grid back to a known scope.
 *
 * OSCAL-profile "starter templates" (FedRAMP Low/Mod/High/20x) are
 * intentionally NOT surfaced here — they are stub-generation seeds for
 * a "New workbook from template" affordance on the Workbooks tab, not
 * assessment targets. Mixing them into the catalog/baselines picker was
 * the bug that prompted feedback_fedramp_is_baseline.md.
 *
 * The Workbooks screen also uses this picker as the *load* entry point —
 * sentinel values route to "Download NIST 800-53 Rev 4/5" and "Browse
 * local OSCAL JSON" actions. Read-only screens (Controls, Baseline
 * detail) hide those by passing `showAddActions=false`.
 *
 * Backend note: when a baseline is picked, callers that open a workbook
 * should still pass `frameworkId` to `openWorkbook`. The server
 * materializes baseline_id from the workbook's column A scoping (see
 * `routes/baselines.py`).
 */

import { useMemo } from "react";
import { Loader2 } from "lucide-react";

import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { hasNativeBridge } from "@/lib/api";
import type { Baseline, Framework } from "@/lib/api";
import {
  useBaselines,
  useFrameworks,
  useLoadFedramp,
  useLoadNist,
  useLoadNistR4,
} from "@/lib/queries";
import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";

export interface ComplianceTarget {
  frameworkId: number;
  /** Set when the user picked a baseline (FedRAMP profile, CCIS-derived, ...). */
  baselineId?: number;
}

export interface ComplianceTargetPickerProps {
  value: ComplianceTarget | undefined;
  onChange: (target: ComplianceTarget) => void;
  /**
   * Show the "Add framework" / "Browse local OSCAL" action items in the
   * dropdown. Read-only screens (Controls, baseline detail) should pass
   * `false`.
   *
   * Defaults to `true`.
   */
  showAddActions?: boolean;
  /**
   * Include baselines (FedRAMP profiles, CCIS-bound) as first-class entries
   * in the picker. Screens that only care about catalog scope can pass
   * `false` to suppress them.
   *
   * Defaults to `true`.
   */
  includeBaselines?: boolean;
  /**
   * Include frameworks (control catalogs like NIST 800-53) as first-class
   * entries in the picker. Pair with `includeBaselines={true}` and
   * `showAddActions={false}` to render a baselines-only picker.
   *
   * Defaults to `true`.
   */
  includeFrameworks?: boolean;
  className?: string;
  placeholder?: string;
  disabled?: boolean;
  /**
   * Optional width for the trigger button — default `w-[280px]` matches
   * the original Workbooks dropdown.
   */
  triggerClassName?: string;
}

// Sentinel-value prefixes. Real ids are serialized as numeric strings,
// sentinels are routed to mutation calls inside onValueChange. Keeping
// them as strings avoids a parallel "action menu" trigger and lets the
// Select stay the single keyboard-navigable surface.
const SENTINEL = {
  framework: "__fw:",
  baseline: "__bl:",
  loadR5: "__load:5",
  loadR4: "__load:4",
  browseR5: "__browse:5",
  browseR4: "__browse:4",
  loadFedrampHigh: "__load:fr-high",
} as const;

// FedRAMP profile detection — match against the canonical filename
// embedded in each child Framework's oscal_uri (mirrors how we detect
// rev4/rev5 by URL substring rather than catalog title/version).
//
// Only HIGH is surfaced in the picker: HIGH is a superset of MODERATE
// is a superset of LOW. Loading HIGH gives the assessor the full 410-
// control catalog and the program workbook (column A) scopes down per
// system. Adding MOD/LOW/LI-SaaS entries here would just be redundant
// loaders that produce smaller subsets of the same data. The loader +
// route still accept any level for direct API callers (tests cover
// this) — the UI just doesn't expose the affordance.
const FEDRAMP_HIGH_URI_FRAGMENT = "FedRAMP_rev5_HIGH-";

function encodeValue(target: ComplianceTarget | undefined): string {
  if (!target) return "";
  if (target.baselineId !== undefined) {
    return `${SENTINEL.baseline}${target.baselineId}`;
  }
  return `${SENTINEL.framework}${target.frameworkId}`;
}

export function ComplianceTargetPicker({
  value,
  onChange,
  showAddActions = true,
  includeBaselines = true,
  includeFrameworks = true,
  className,
  // Default placeholder reflects the corrected mental model: this picker
  // binds the framework used to resolve CCI refs in the workbook — it
  // does not pick the thing being assessed (that is the workbook itself).
  placeholder = "Pick a framework",
  disabled,
  triggerClassName = "w-[280px]",
}: ComplianceTargetPickerProps) {
  const frameworks = useFrameworks();
  const baselines = useBaselines();
  const nativeBridge = hasNativeBridge();

  const loadNist = useLoadNist({
    onSuccess: (fw) => {
      onChange({ frameworkId: fw.id });
      toast.success(
        "Framework loaded",
        `${fw.name} ${fw.version} — selected as active framework`,
      );
    },
    onError: (err) => toast.error("Framework load failed", humanize(err)),
  });
  const loadNistR4 = useLoadNistR4({
    onSuccess: (fw) => {
      onChange({ frameworkId: fw.id });
      toast.success(
        "Framework loaded",
        `${fw.name} ${fw.version} — selected as active framework`,
      );
    },
    onError: (err) => toast.error("Framework load failed", humanize(err)),
  });
  // FedRAMP loader — projects a profile (HIGH/MODERATE/LOW/LI-SAAS) as a
  // child Framework of rev5 with membership rows + FedRAMP-Additions
  // shadow Controls + ODP set-parameters overrides. Auto-selects the
  // newly-loaded child for visual consistency with the rev4/rev5
  // download buttons.
  const loadFedramp = useLoadFedramp({
    onSuccess: (fw) => {
      onChange({ frameworkId: fw.id });
      const bits = [
        `${fw.members_added} controls`,
        fw.controls_synthesized > 0
          ? `${fw.controls_synthesized} with Additions`
          : null,
        fw.parameters_loaded > 0
          ? `${fw.parameters_loaded} ODP overrides`
          : null,
      ].filter(Boolean);
      toast.success(
        "FedRAMP profile loaded",
        `${fw.name} — ${bits.join(", ")}`,
      );
    },
    onError: (err) => toast.error("FedRAMP load failed", humanize(err)),
  });
  const fws = frameworks.data ?? [];
  // All baselines are pickable as primary targets. CCIS-derived and any
  // legacy OSCAL-profile rows from older builds map cleanly to the same
  // workbook scoping.
  const allBaselines = includeBaselines ? (baselines.data ?? []) : [];

  // Workbook baselines = scoping materialized from an actual program
  // workbook the user uploaded (CCIS workbook, OSCAL SSP, hand-built
  // manual). Overlays (CRM, PROGRAM_CONTROLS/PSC, OTHER, ISO_SOA,
  // CIS_CSAT) are a different animal — they're informational lenses
  // applied *on top of* a workbook scope, not a scope themselves, and
  // surfacing them here as pickable assessment targets is a category
  // error. OSCAL-profile ("starter template") rows from older builds
  // are also excluded — they're stub-generation seeds, not scopes.
  //
  // Allow-list (not deny-list) on purpose: any new source_type added to
  // the enum defaults to *hidden* from the picker until it's been
  // classified, which is safer than silently leaking new overlay flavors.
  const WORKBOOK_SOURCE_TYPES = new Set<string>([
    "ccis_workbook",
    "oscal_ssp",
    "manual",
  ]);
  const workbookBaselines = allBaselines.filter((b) =>
    WORKBOOK_SOURCE_TYPES.has(b.source_type),
  );

  // Detect loaded revisions deterministically off the OSCAL source URL —
  // catalog title/version drift between releases (see Workbooks.tsx notes).
  const rev5 = useMemo(() => pickRev5(fws), [fws]);
  const rev4 = useMemo(() => fws.find((f) => (f.oscal_uri ?? "").includes("rev4")), [fws]);
  const hasR5 = !!rev5;
  const hasR4 = !!rev4;

  // FedRAMP HIGH presence — used to hide the "Download FedRAMP HIGH"
  // entry once the child Framework exists. Substring match on
  // oscal_uri is consistent with how we detect rev4/rev5; the loader
  // stamps the canonical GSA filename into oscal_uri at upsert time.
  const hasFedrampHigh = fws.some((f) =>
    (f.oscal_uri ?? "").includes(FEDRAMP_HIGH_URI_FRAGMENT),
  );
  const missingFedramp = hasR5 && !hasFedrampHigh;

  // Index frameworks for the baseline-label join. We display each baseline
  // as "<baseline.name> · <framework name short>" so the picker stays
  // self-describing even when several overlays exist on different rev
  // catalogs.
  const fwById = useMemo(() => {
    const m = new Map<number, Framework>();
    for (const f of fws) m.set(f.id, f);
    return m;
  }, [fws]);

  // v0.2 catalog refactor — group child Frameworks (e.g. FedRAMP)
  // directly beneath the root catalog they extend. We render the
  // list in [root, ...children, root, ...children] order so the visual
  // hierarchy in the dropdown matches the parent/child relationship.
  // Roots come back in their original load order; children are tacked on
  // immediately after their parent so the eye can follow the chain
  // without scanning the whole list. Orphaned children (parent_framework_id
  // points at a framework that's been deleted) fall back to root-level so
  // they're still pickable.
  const orderedFws = useMemo(() => {
    // Display/selection gate (migration 0012): only enabled frameworks are
    // pickable. The currently-selected framework is kept even if it was
    // disabled after selection, so the dropdown never silently drops the
    // active target out from under the user (the trigger label resolves it
    // via the full `fwById` map either way). Detection of loaded revs
    // (rev5/rev4/FedRAMP) above deliberately still scans the full `fws`.
    const pickable = fws.filter(
      (f) => f.enabled !== false || f.id === value?.frameworkId,
    );
    const roots: Framework[] = [];
    const childrenByParent = new Map<number, Framework[]>();
    for (const f of pickable) {
      if (f.parent_framework_id != null && fwById.has(f.parent_framework_id)) {
        const bucket = childrenByParent.get(f.parent_framework_id) ?? [];
        bucket.push(f);
        childrenByParent.set(f.parent_framework_id, bucket);
      } else {
        roots.push(f);
      }
    }
    const out: Framework[] = [];
    for (const r of roots) {
      out.push(r);
      const kids = childrenByParent.get(r.id) ?? [];
      for (const k of kids) out.push(k);
    }
    return out;
  }, [fws, fwById, value?.frameworkId]);

  const busy =
    loadNist.isPending || loadNistR4.isPending || loadFedramp.isPending;

  async function pickAndLoadCatalog(rev: "4" | "5") {
    if (!nativeBridge) return;
    const path = await window.ccis!.openFile([
      { name: "OSCAL Catalog", extensions: ["json"] },
    ]);
    if (!path) return;
    try {
      if (rev === "4") await loadNistR4.mutateAsync(path);
      else await loadNist.mutateAsync(path);
    } catch {
      // toast handled by onError
    }
  }

  function handleValueChange(v: string) {
    if (!v) return;

    if (v === SENTINEL.loadR5) {
      loadNist.mutate(undefined);
      return;
    }
    if (v === SENTINEL.loadR4) {
      loadNistR4.mutate(undefined);
      return;
    }
    if (v === SENTINEL.browseR5) {
      pickAndLoadCatalog("5");
      return;
    }
    if (v === SENTINEL.browseR4) {
      pickAndLoadCatalog("4");
      return;
    }
    if (v === SENTINEL.loadFedrampHigh) {
      loadFedramp.mutate({ level: "HIGH" });
      return;
    }

    if (v.startsWith(SENTINEL.baseline)) {
      const id = Number(v.slice(SENTINEL.baseline.length));
      const bl = allBaselines.find((b) => b.id === id);
      if (bl) onChange({ frameworkId: bl.framework_id, baselineId: bl.id });
      return;
    }

    if (v.startsWith(SENTINEL.framework)) {
      const id = Number(v.slice(SENTINEL.framework.length));
      onChange({ frameworkId: id });
      return;
    }
  }

  // Whether the "Add framework" group should render at all. The FedRAMP
  // HIGH entry only becomes eligible after rev5 is loaded (HIGH is a
  // child Framework of r5), so `missingFedramp` already encodes the r5
  // prerequisite.
  const showFrameworkLoaders =
    showAddActions && (!hasR5 || !hasR4 || missingFedramp);
  const showFrameworkBrowse = showAddActions && nativeBridge && (!hasR5 || !hasR4);

  return (
    <Select
      value={encodeValue(value)}
      onValueChange={handleValueChange}
      disabled={disabled || busy}
    >
      <SelectTrigger className={triggerClassName + (className ? ` ${className}` : "")}>
        {busy ? (
          <span className="inline-flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading…
          </span>
        ) : (
          <SelectValue placeholder={placeholder}>
            {renderTriggerLabel(value, fwById, allBaselines)}
          </SelectValue>
        )}
      </SelectTrigger>
      <SelectContent>
        {includeFrameworks && orderedFws.length > 0 && (
          <SelectGroup>
            <SelectLabel>Frameworks</SelectLabel>
            {orderedFws.map((f) => {
              const parent =
                f.parent_framework_id != null
                  ? fwById.get(f.parent_framework_id)
                  : undefined;
              return (
                <SelectItem
                  key={`fw-${f.id}`}
                  value={`${SENTINEL.framework}${f.id}`}
                  // Indent children one level so the parent/child
                  // relationship reads at a glance. The tail "(extends …)"
                  // tag below is the textual reinforcement.
                  className={parent ? "pl-8" : undefined}
                >
                  {f.name} {f.version}
                  {parent && (
                    <span className="text-muted-foreground">
                      {" "}
                      (extends {parent.name} {parent.version})
                    </span>
                  )}
                </SelectItem>
              );
            })}
          </SelectGroup>
        )}

        {workbookBaselines.length > 0 && (
          <>
            {includeFrameworks && orderedFws.length > 0 && <SelectSeparator />}
            <SelectGroup>
              <SelectLabel>Workbooks</SelectLabel>
              {workbookBaselines.map((b) => {
                const parent = fwById.get(b.framework_id);
                const tail = parent
                  ? `${parent.name.replace(/^NIST /, "")} ${parent.version}`
                  : `framework #${b.framework_id}`;
                return (
                  <SelectItem key={`bl-${b.id}`} value={`${SENTINEL.baseline}${b.id}`}>
                    {b.name}
                    <span className="text-muted-foreground"> · {tail}</span>
                  </SelectItem>
                );
              })}
            </SelectGroup>
          </>
        )}

        {showFrameworkLoaders && (
          <>
            {(fws.length > 0 || allBaselines.length > 0) && <SelectSeparator />}
            <SelectGroup>
              <SelectLabel>Add framework</SelectLabel>
              {!hasR5 && (
                <SelectItem value={SENTINEL.loadR5}>
                  Download NIST 800-53 Rev 5 (online)
                </SelectItem>
              )}
              {!hasR4 && (
                <SelectItem value={SENTINEL.loadR4}>
                  Download NIST 800-53 Rev 4 (online)
                </SelectItem>
              )}
              {hasR5 && !hasFedrampHigh && (
                <SelectItem value={SENTINEL.loadFedrampHigh}>
                  Download FedRAMP Rev 5 HIGH (online)
                </SelectItem>
              )}
            </SelectGroup>
          </>
        )}

        {showFrameworkBrowse && (
          <>
            <SelectSeparator />
            <SelectGroup>
              <SelectLabel>From disk</SelectLabel>
              {!hasR5 && (
                <SelectItem value={SENTINEL.browseR5}>
                  Browse local OSCAL JSON (Rev 5)…
                </SelectItem>
              )}
              {!hasR4 && (
                <SelectItem value={SENTINEL.browseR4}>
                  Browse local OSCAL JSON (Rev 4)…
                </SelectItem>
              )}
            </SelectGroup>
          </>
        )}

      </SelectContent>
    </Select>
  );
}

/**
 * Render the trigger label for a selected target. CCIS/SSP/manual
 * baseline picks include the parent framework after a dot so the user
 * can tell two baselines with the same name (on different revs) apart
 * at a glance. OSCAL-profile baselines (FedRAMP) drop the tail because
 * they're presented as standalone frameworks in the picker, not as a
 * tweak of 800-53 — the parent ref would be redundant noise there.
 */
function renderTriggerLabel(
  target: ComplianceTarget | undefined,
  fwById: Map<number, Framework>,
  bls: Baseline[],
): string | undefined {
  if (!target) return undefined;
  if (target.baselineId !== undefined) {
    const bl = bls.find((b) => b.id === target.baselineId);
    if (!bl) return `Baseline #${target.baselineId}`;
    if (bl.source_type === "oscal_profile") {
      return bl.name;
    }
    const parent = fwById.get(bl.framework_id);
    const tail = parent ? `${parent.name.replace(/^NIST /, "")} ${parent.version}` : "";
    return tail ? `${bl.name} · ${tail}` : bl.name;
  }
  const fw = fwById.get(target.frameworkId);
  return fw ? `${fw.name} ${fw.version}` : `Framework #${target.frameworkId}`;
}

function pickRev5(fws: Framework[] | undefined): Framework | undefined {
  return fws?.find((f) => (f.oscal_uri ?? "").includes("rev5"));
}
