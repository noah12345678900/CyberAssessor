import type { ControlStatusRollup } from "./api";

export type RollupStatus = ControlStatusRollup["status"];
export type StatusFilter = "__all__" | "__unassessed__" | RollupStatus;

const ROLLUP_STATUSES: readonly RollupStatus[] = [
  "Compliant",
  "Non-Compliant",
  "Not Applicable",
  "Mixed",
  "Needs Review",
  "Partially Assessed",
];

export function normalizeControlStatusFilter(value: string): StatusFilter {
  if (value === "N/A") return "Not Applicable";
  if (value === "__all__" || value === "__unassessed__") return value;
  if (ROLLUP_STATUSES.includes(value as RollupStatus)) return value as RollupStatus;
  return "__all__";
}

export function matchesControlStatusFilter(
  status: RollupStatus | undefined,
  inferredNotApplicable: boolean,
  filter: StatusFilter,
): boolean {
  if (filter === "__all__") return true;
  const effectiveStatus = status ?? (inferredNotApplicable ? "Not Applicable" : undefined);
  if (filter === "__unassessed__") return effectiveStatus === undefined;
  return effectiveStatus === filter;
}

export function nextControlStatusFilter(
  current: StatusFilter,
  selected: RollupStatus,
): StatusFilter {
  return current === selected ? "__all__" : selected;
}
