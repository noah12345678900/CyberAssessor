/**
 * Application shell — sidebar nav + routed content panel.
 *
 * Sidebar order follows the assessor's natural workflow:
 *   1. Workflow   — overview / starting point
 *   2. Workbooks  — open the CCIS workbook
 *   3. Baselines  — pick framework + program overlay
 *   4. Evidence   — ingest evidence artifacts BEFORE assessing
 *   5. Controls   — assess CCIs (main work)
 *   6. POAMs      — track findings → remediation
 *   7. Runs       — review past assessment runs
 *   ── utilities ──
 *   8. Settings
 *   9. Help
 */

import { NavLink, Route, Routes, Navigate } from "react-router-dom";
import {
  BarChart3,
  FileSpreadsheet,
  ShieldCheck,
  ShieldAlert,
  FolderSearch,
  HelpCircle,
  History,
  ListChecks,
  Network,
  Settings as SettingsIcon,
  Telescope,
  Activity,
  Workflow as WorkflowIcon,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { useHealth, useSettings } from "@/lib/queries";
import {
  AssessBatchProgressStrip,
  AssessBatchProvider,
} from "@/contexts/AssessBatchContext";
import {
  IngestProgressStrip,
  IngestJobProvider,
} from "@/contexts/IngestJobContext";

import { WindowControls } from "@/components/WindowControls";
import { Workbooks } from "@/routes/Workbooks";
import { Baselines } from "@/routes/Baselines";
import { Controls } from "@/routes/Controls";
import { ControlDetail } from "@/routes/ControlDetail";
import { Evidence } from "@/routes/Evidence";
import { Help } from "@/routes/Help";
import { PreAssessment } from "@/routes/PreAssessment";
import { Poams } from "@/routes/Poams";
import { PoamDetail } from "@/routes/PoamDetail";
import { ReviewQueue } from "@/routes/ReviewQueue";
import { Metrics } from "@/routes/Metrics";
import { Runs } from "@/routes/Runs";
import { Settings } from "@/routes/Settings";
import { SweepContext } from "@/routes/SweepContext";
import { Workflow } from "@/routes/Workflow";

type NavItem = {
  to: string;
  label: string;
  icon: typeof WorkflowIcon;
  hint?: string;
  group?: "workflow" | "utility";
};

const NAV: NavItem[] = [
  { to: "/workflow",  label: "Workflow",  icon: WorkflowIcon,    hint: "Start here",                  group: "workflow" },
  { to: "/workbooks", label: "Catalogs", icon: FileSpreadsheet, hint: "Open an assessment workbook — the workbook is the catalog", group: "workflow" },
  // Sweep Context is reference material — boundary docs (SSP, network diagram,
  // ATO letter) that bias the SharePoint sweep. Optional sweep tuning, not a
  // required workflow step. Lives under Tools alongside Pre-Assessment so it
  // doesn't read as "step N of the assessor's loop". See
  // feedback_scoping_out_of_assessor.md. (Renamed from "System Description"
  // 2026-06-05 — the page is the assessor's hint sheet for the sweep, not a
  // place to author an SSP.)
  { to: "/sweep-context", label: "Sweep Context", icon: Telescope, hint: "Optional. Drop boundary docs (SSP, network diagram, ATO letter) to bias the SharePoint sweep.", group: "utility" },
  { to: "/baselines", label: "Baselines", icon: ListChecks,      hint: "Framework + program overlay", group: "workflow" },
  { to: "/evidence",  label: "Evidence",  icon: FolderSearch,    hint: "Ingest evidence artifacts",   group: "workflow" },
  { to: "/controls",  label: "Controls",  icon: ShieldCheck,     hint: "Assess controls",             group: "workflow" },
  { to: "/poams",     label: "POAMs",     icon: ShieldAlert,     hint: "Plans of action & milestones", group: "workflow" },
  { to: "/runs",      label: "Runs",      icon: History,         hint: "Past assessment runs",        group: "workflow" },
  // Metrics is reference/analytical material — accuracy/cost/time benchmarks
  // for tuning, not a step in the assessor's loop. Lives under Tools so it
  // doesn't read as "step N of the workflow". See
  // feedback_scoping_out_of_assessor.md.
  { to: "/metrics",   label: "Metrics",   icon: BarChart3,       hint: "Accuracy, cost, and time — Live vs reference benchmarks", group: "utility" },
  // Pre-Assessment is reference material — categorization + baseline-picking
  // guidance the system owner should have completed BEFORE the assessor opens
  // a workbook. Lives under Tools, not Workflow, so it doesn't read as "step 5
  // of 8" in the assessor's loop. See feedback_scoping_out_of_assessor.md.
  { to: "/pre-assessment", label: "Pre-Assessment", icon: Network, hint: "Pre-assessment scoping guide per framework (FIPS 199, CSF tier, SoA, IG, SAQ, TSC)", group: "utility" },
  { to: "/settings",  label: "Settings",  icon: SettingsIcon,                                        group: "utility" },
  { to: "/help",      label: "Help",      icon: HelpCircle,                                          group: "utility" },
];

export function App() {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background text-foreground">
      <DragStrip />
      <WindowControls />
      <Sidebar />
      {/*
        AssessBatchProvider wraps the routed content so the in-flight
        ``/assess-batch`` mutation + its 750 ms polling query survive route
        changes. Before this hoist, both lived inside the Controls route —
        navigating away mid-batch unmounted the progress strip AND killed
        the onSuccess auto-apply chain that writes column N. The progress
        strip is rendered as a sticky banner at the top of the main scroll
        area so it stays visible on every route while a batch is running.
      */}
      <main className="flex-1 overflow-auto animate-fade-in">
        <AssessBatchProvider>
          <IngestJobProvider>
          <AssessBatchProgressStrip />
          <IngestProgressStrip />
          <Routes>
            <Route path="/" element={<Navigate to="/workflow" replace />} />
            <Route path="/workflow" element={<Workflow />} />
            <Route path="/workbooks" element={<Workbooks />} />
            <Route path="/sweep-context" element={<SweepContext />} />
            {/* Old routes — keep so prior bookmarks / cached links don't 404. */}
            <Route path="/system-description" element={<Navigate to="/sweep-context" replace />} />
            <Route path="/system-context" element={<Navigate to="/sweep-context" replace />} />
            <Route path="/baselines" element={<Baselines />} />
            <Route path="/evidence" element={<Evidence />} />
            <Route path="/pre-assessment" element={<PreAssessment />} />
            <Route path="/controls" element={<Controls />} />
            <Route path="/controls/:controlId" element={<ControlDetail />} />
            <Route path="/review-queue" element={<ReviewQueue />} />
            <Route path="/poams" element={<Poams />} />
            <Route path="/poams/:poamId" element={<PoamDetail />} />
            <Route path="/runs" element={<Runs />} />
            <Route path="/metrics" element={<Metrics />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/help" element={<Help />} />
          </Routes>
          </IngestJobProvider>
        </AssessBatchProvider>
      </main>
    </div>
  );
}

/**
 * Invisible window-drag region overlaid across the top edge of the app.
 * Positioned `fixed` so it consumes zero layout space — content sits flush
 * to the top of the window as before. Stops 140px short of the right edge
 * to leave room for the custom <WindowControls /> cluster (132px wide +
 * 8px gap; see components/WindowControls.tsx).
 *
 * Why `top-1` (4px gap) and not `top-0`:
 *   Windows reserves the topmost row of pixels of a frameless window for
 *   the resize handle. A drag region anchored at top:0 covers that row and
 *   eats the resize cursor — the symptom is "can't grab the top edge to
 *   resize from the middle". Leaving 4px of clear pixels at the top lets
 *   the OS keep the resize grip while still giving us a wide drag area
 *   immediately below it.
 *
 * Why `h-8` (32px) and not `h-3` (12px):
 *   12px is hard to hit with the cursor — users have to aim carefully at
 *   what looks like blank space. 32px sits comfortably under the resize
 *   strip and matches the height of the custom WindowControls row, so the
 *   entire top band (minus the OS resize sliver and the right-edge buttons)
 *   is grabbable for moving the window.
 *
 * In browser-mode (VITE_ALLOW_BROWSER=1), the drag region is a no-op and
 * the strip is just invisible empty space.
 */
function DragStrip() {
  return (
    <div
      className="fixed left-0 right-[140px] top-1 z-50 h-8"
      style={{ WebkitAppRegion: "drag" } as React.CSSProperties}
      aria-hidden="true"
    />
  );
}

function Sidebar() {
  const health = useHealth();
  const ok = health.data?.status === "ok";
  // Hide SharePoint-only nav entries when the connector is disabled — Sweep
  // Context exists solely to bias the SP sweep (boundary docs → host_tokens
  // in the candidate scorer). With SP off, the page has nothing to act on,
  // so showing it in the sidebar would be a dead link. Toggle lives in
  // Settings → Connectors.
  //
  // NOTE: pending mode (drop boundary docs before opening a workbook) does
  // NOT relax this gate — the docs still exist to bias the SP sweep, so
  // without SP enabled there's still no consumer for them. Don't flip this
  // condition based on workbook presence.
  const settings = useSettings();
  const sharepointEnabled = settings.data?.features?.sharepoint ?? false;

  const visibleNav = NAV.filter(
    (n) => sharepointEnabled || n.to !== "/sweep-context",
  );
  const workflowItems = visibleNav.filter((n) => n.group !== "utility");
  const utilityItems  = visibleNav.filter((n) => n.group === "utility");

  return (
    <aside className="flex h-full w-64 shrink-0 flex-col border-r bg-card shadow-nuon-sm">
      {/* Brand block */}
      <div className="flex items-center gap-3 px-5 py-5 border-b">
        {/*
          In-app brand mark — bespoke shield in the nuon visual language.
          When the real nuon "powered by" mark lands, swap the <img src> below.
          See ui/LOGO_PLACEHOLDERS.md.
        */}
        {/*
          Public-dir asset referenced at runtime. Must go through BASE_URL:
          Vite only rewrites asset paths it controls (index.html, imports),
          not JSX string literals. A root-absolute "/brand-mark.svg" works on
          the dev server but resolves to the filesystem root under file:// in
          the packaged app — the classic broken brand mark. BASE_URL is "/" in
          dev and "./" in the build (see vite.config base), so this stays
          correct in both.
        */}
        <img
          src={`${import.meta.env.BASE_URL}brand-mark.svg`}
          alt=""
          aria-hidden="true"
          width={40}
          height={40}
          className="h-10 w-10 shrink-0 rounded-[10px] shadow-nuon-sm select-none"
          draggable={false}
        />
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold tracking-tight leading-tight">
            Cybersecurity Assessor
          </div>
          <div className="truncate text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
            Multi-framework
          </div>
        </div>
      </div>

      {/* Workflow nav */}
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        <SidebarGroupLabel>Workflow</SidebarGroupLabel>
        <ul className="mb-4 space-y-0.5">
          {workflowItems.map((item) => (
            <SidebarItem key={item.to} item={item} />
          ))}
        </ul>

        <SidebarGroupLabel>Tools</SidebarGroupLabel>
        <ul className="space-y-0.5">
          {utilityItems.map((item) => (
            <SidebarItem key={item.to} item={item} />
          ))}
        </ul>
      </nav>

      {/* Sidecar health footer */}
      <div className="flex items-center gap-2 border-t px-4 py-3 text-xs text-muted-foreground">
        <span
          className={cn(
            "inline-flex h-2 w-2 rounded-full",
            ok ? "bg-emerald-500 shadow-[0_0_0_3px_rgba(16,185,129,0.18)]" : "bg-amber-500 shadow-[0_0_0_3px_rgba(245,158,11,0.18)]",
          )}
        />
        <Activity className="h-3.5 w-3.5" />
        <span className="truncate">
          {ok ? `sidecar v${health.data?.version}` : "sidecar offline"}
        </span>
      </div>
    </aside>
  );
}

function SidebarGroupLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-3 pt-1 pb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground/80">
      {children}
    </div>
  );
}

function SidebarItem({ item }: { item: NavItem }) {
  const Icon = item.icon;
  return (
    <li>
      <NavLink
        to={item.to}
        title={item.hint}
        className={({ isActive }) =>
          cn(
            "group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors duration-150",
            isActive
              ? "nuon-nav-active font-medium"
              : "text-muted-foreground hover:bg-accent hover:text-foreground",
          )
        }
      >
        <Icon className="h-4 w-4 shrink-0" strokeWidth={2} />
        <span className="flex-1 truncate">{item.label}</span>
      </NavLink>
    </li>
  );
}
