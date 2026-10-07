import assert from "node:assert/strict";
import test from "node:test";

import {
  matchesControlStatusFilter,
  nextControlStatusFilter,
  normalizeControlStatusFilter,
  type RollupStatus,
} from "../src/lib/controlStatusFilter.ts";

const persistedStatuses: RollupStatus[] = [
  "Compliant",
  "Non-Compliant",
  "Not Applicable",
  "Mixed",
  "Needs Review",
  "Partially Assessed",
];

test("each persisted rollup status matches its canonical filter", () => {
  for (const status of persistedStatuses) {
    assert.equal(matchesControlStatusFilter(status, false, status), true);
    assert.equal(matchesControlStatusFilter(status, false, "__unassessed__"), false);
  }
});

test("legacy N/A input is normalized to Not Applicable", () => {
  assert.equal(normalizeControlStatusFilter("N/A"), "Not Applicable");
  assert.equal(normalizeControlStatusFilter("Mixed"), "Mixed");
  assert.equal(normalizeControlStatusFilter("unexpected"), "__all__");
});

test("workbook-inferred N/A is filterable and is not unassessed", () => {
  assert.equal(matchesControlStatusFilter(undefined, true, "Not Applicable"), true);
  assert.equal(matchesControlStatusFilter(undefined, true, "__unassessed__"), false);
});

test("a control without a rollup or workbook N/A remains unassessed", () => {
  assert.equal(matchesControlStatusFilter(undefined, false, "__unassessed__"), true);
  assert.equal(matchesControlStatusFilter(undefined, false, "Not Applicable"), false);
});

test("clicking an active chip clears it and another chip replaces it", () => {
  assert.equal(nextControlStatusFilter("Mixed", "Mixed"), "__all__");
  assert.equal(nextControlStatusFilter("Mixed", "Not Applicable"), "Not Applicable");
});
