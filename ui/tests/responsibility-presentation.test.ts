import assert from "node:assert/strict";
import test from "node:test";

import {
  isNotApplicableImplementationStatus,
  responsibilityDescription,
  responsibilityLabel,
} from "../src/lib/responsibilityPresentation.ts";

test("responsibility labels use assessor-facing language", () => {
  assert.equal(responsibilityLabel("assess"), "Local");
  assert.equal(responsibilityLabel("escalate"), "Source missing");
  assert.equal(
    responsibilityLabel("inherited", "DoW Enterprise"),
    "Inherited · DoW Enterprise",
  );
  assert.equal(responsibilityLabel("na"), "—");
});

test("not-applicable responsibility is explained without another N/A chip", () => {
  assert.equal(
    responsibilityDescription("na"),
    "Not applicable per Column D; responsibility does not apply.",
  );
  assert.equal(isNotApplicableImplementationStatus(" Not Applicable "), true);
  assert.equal(isNotApplicableImplementationStatus("n/a"), true);
  assert.equal(isNotApplicableImplementationStatus("Planned"), false);
});
