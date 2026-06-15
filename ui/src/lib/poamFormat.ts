/**
 * Shared visual-language helpers for POAM screens.
 *
 * Both the list view (Poams.tsx) and the detail editor (PoamDetail.tsx) use
 * the same severity / status / date formatters — centralizing them here keeps
 * the colors honest as we tune them. Tailwind classes use opacity + dark:
 * variants so light/dark themes both read correctly.
 */

import type { PoamStatus, RiskLevel } from "@/lib/api";

/**
 * NIST SP 800-30r1 5-level qualitative severity → Tailwind classes.
 * Red (Very High) → Orange → Amber → Blue → Slate (Very Low). Falling off
 * either end with `null` returns the neutral muted style so an unscored
 * POAM still renders a badge without color noise.
 */
export function severityClasses(level: RiskLevel | null | undefined): string {
  switch (level) {
    case "Very High":
      return "bg-red-600/15 text-red-600 border-red-600/30 dark:text-red-400";
    case "High":
      return "bg-orange-500/15 text-orange-600 border-orange-500/30 dark:text-orange-400";
    case "Moderate":
      return "bg-amber-500/15 text-amber-700 border-amber-500/30 dark:text-amber-400";
    case "Low":
      return "bg-blue-500/15 text-blue-700 border-blue-500/30 dark:text-blue-400";
    case "Very Low":
      return "bg-slate-400/15 text-slate-600 border-slate-400/30 dark:text-slate-400";
    default:
      return "bg-muted text-muted-foreground border-border";
  }
}

/**
 * POAM lifecycle status → Tailwind classes. Mirrors the four-state model
 * defined by ``models.PoamStatus`` (Draft → Ongoing → Risk Accepted /
 * Completed terminal). Colors are intentionally distinct from the severity
 * palette so the eye can read both badges side-by-side without confusion.
 */
export function statusClasses(status: PoamStatus): string {
  switch (status) {
    case "Draft":
      return "bg-slate-400/15 text-slate-700 border-slate-400/30 dark:text-slate-300";
    case "Ongoing":
      return "bg-blue-500/15 text-blue-700 border-blue-500/30 dark:text-blue-400";
    case "Risk Accepted":
      return "bg-purple-500/15 text-purple-700 border-purple-500/30 dark:text-purple-400";
    case "Completed":
      return "bg-emerald-500/15 text-emerald-700 border-emerald-500/30 dark:text-emerald-400";
  }
}

/** Render an ISO timestamp as a YYYY-MM-DD calendar date (UTC slice). */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  // Backend serializes with `.isoformat()` (naive UTC). Slice off the time
  // portion — POAM dates are calendar dates in the eMASS template.
  return iso.slice(0, 10);
}

/** Render an ISO timestamp as a short locale datetime ("6/3/2026, 4:12 PM"). */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: "numeric",
      month: "numeric",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

/**
 * Convert an ISO timestamp to the ``YYYY-MM-DD`` value expected by
 * ``<input type="date">``. Empty string when the source is null so the
 * input renders blank instead of "Invalid Date".
 */
export function isoToDateInput(iso: string | null | undefined): string {
  if (!iso) return "";
  return iso.slice(0, 10);
}

/**
 * Convert a ``<input type="date">`` value back to an ISO datetime the
 * backend can parse with ``datetime.fromisoformat``. Empty string → null
 * so callers can pass the result straight into a PATCH body.
 */
export function dateInputToIso(value: string): string | null {
  if (!value) return null;
  // Append a midnight UTC time so the FastAPI Pydantic model coerces it
  // into a proper datetime without timezone ambiguity.
  return `${value}T00:00:00`;
}
