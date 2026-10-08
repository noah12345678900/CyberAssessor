export type ResponsibilityOutcome = "inherited" | "assess" | "escalate" | "na";

const NA_VALUES = new Set(["not applicable", "n/a", "na"]);

export function isNotApplicableImplementationStatus(
  value: string | null | undefined,
): boolean {
  return NA_VALUES.has((value ?? "").trim().toLowerCase());
}

export function responsibilityLabel(
  outcome: ResponsibilityOutcome,
  source?: string | null,
): string {
  if (outcome === "na") return "—";
  if (outcome === "assess") return "Local";
  if (outcome === "escalate") return "Source missing";
  const namedSource = (source ?? "").trim();
  return namedSource ? `Inherited · ${namedSource}` : "Inherited";
}

export function responsibilityDescription(
  outcome: ResponsibilityOutcome,
  source?: string | null,
): string {
  if (outcome === "na") {
    return "Not applicable per Column D; responsibility does not apply.";
  }
  if (outcome === "assess") {
    return "This CCI is locally owned and requires assessment.";
  }
  if (outcome === "escalate") {
    return "Marked inherited, but no source is named in Column M.";
  }
  const namedSource = (source ?? "").trim();
  return namedSource
    ? `Implementation is inherited from ${namedSource}.`
    : "Implementation is inherited from a named upstream source.";
}
