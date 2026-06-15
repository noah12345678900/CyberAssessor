"""Auto-status detection (SKILL.md Rule #8).

Ported verbatim from the nist-assessor plugin's ``SKILL.md`` rule #8
(a/b/c). Operates **deterministically on CCIS row data alone** — no LLM,
no external evidence required. If this returns a confident verdict, the
LLM never sees the row; if it returns ``UNCLEAR``, the row goes to the
LLM with the unclear classification attached so the LLM knows to ask
rather than guess.

The rule split:

- **8a — Compliant via inheritance.** Cols K/J/L cite inheritance from an
  internal/DoD source we leverage or operate, OR col Q/U documents that the
  control is implemented by a CSP/provider we inherit from. Per doctrine,
  inherited/CSP-provided controls are COMPLIANT (the control IS satisfied,
  just not by us directly). Status: Compliant.
- **8b — Not Applicable via documented scope exclusion.** Col Q (results) /
  col U (previous_results) carries an explicit human-authored decision that
  the control does NOT apply (system scoping, SSAA, SDA-control, GOCO, or
  cloud-environment exclusion). NA is reserved for genuine non-applicability,
  never for inheritance. Status: Not Applicable.
- **8c — When in doubt, ASK.** Phrases like "inherited from" without
  enough context to distinguish 8a from 8b → return UNCLEAR.

Column note: the assessor's findings, CSP attribution, and scope-exclusion
rationale live in **col Q / col U**, not the generic DISA template text in
K/J. The Q/U recognizer is what recovers the human-reviewed NA verdicts;
a K/J-only filter is effectively inert in production.

This file is one of the patent-supporting components: a deterministic
pre-filter that catches the high-confidence rows the LLM would otherwise
spend tokens on, AND prevents the LLM from making the 8a-vs-8b call on
its own (where it has historically gotten it wrong by defaulting to one
side).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from ..excel.ccis_reader import CcisRow
from ..models import ComplianceStatus

# ---------------------------------------------------------------------------
# Trigger phrases (case-insensitive substring match)
# ---------------------------------------------------------------------------

# Rule 8a — Compliant via internal inheritance. These triggers indicate the
# control is satisfied by something WE leverage internally (DoD, parent
# system, sibling org, enterprise service).
_R8A_TRIGGERS: tuple[str, ...] = (
    "automatically compliant",
    "covered at the dod level",
    "dod-level cci",
    "at the dod level",
    "no system-level test",
    "no system-level assessment",
    "no test required",
)

# 8a inheritance-source triggers — phrases that NAME an internal source.
# "inherited from" alone is ambiguous (could be 8a or 8b); these qualified
# forms are not.
_R8A_INHERITANCE_INTERNAL: tuple[str, ...] = (
    "inherited from dow",
    "inherited from the dow",
    "inherited from dod",
    "inherited from the dod",
    "inherited from the enterprise",
    "inherited from enterprise",
    "inherited from parent",
    "inherited from the parent system",
)

# Rule 8b — Not Applicable via EXPLICIT scope exclusion documented by the
# assessor in col Q (results) / col U (previous_results). The generic DISA
# template text in K/J never carries these; the human-authored rationale in
# Q/U does. NA is reserved for genuine non-applicability — a documented
# scope/SSAA/SDA decision that the control does not apply.
_R8B_NA_SCOPE_PHRASES: tuple[str, ...] = (
    "not applicable per sda control",
    "per system scoping, this cci is not applicable",
    "per system scoping this cci is not applicable",
    "not required per ssaa",
    "per ssaa scope",
    "not required for goco",
    "n/a in cloud environment",
)

# Rule 8a (CSP/external-inheritance lane) — these phrases in col Q/U mean the
# control IS implemented, just by a provider we inherit from. Per doctrine,
# inherited/CSP-provided controls are COMPLIANT, NOT Not Applicable.
_R8A_CSP_INHERIT_PHRASES: tuple[str, ...] = (
    "implemented by aws",
    "implemented by azure",
    "implemented by gcp",
    "implemented by the cloud service provider",
    "implemented by the csp",
    "provided by the csp",
    "provided by aws",
    "provided by azure",
    "provided by gcp",
    "inherited from the csp",
    "inherited from the cloud service provider",
)

# Negative guard for the NA lane: an explicit compliance claim in the same
# Q/U rationale means the human ruled it Compliant (program/contract level),
# not NA. If this fires, the scope-exclusion NA phrases are suppressed.
_COMPLIANCE_GUARD = re.compile(
    r"compliance is satisfied|is compliant|are compliant", re.IGNORECASE
)

# Bare "inherited from" — ambiguous; needs source classification before
# we can decide 8a vs 8b. If found without a qualifier above, that's 8c.
_BARE_INHERITED_FROM = re.compile(r"\binherited from\b", re.IGNORECASE)

# Col L values that indicate INTERNAL inheritance (rule 8a structural trigger).
# "Local" means we own it locally → not auto-anything. Anything else with
# a value is treated as internal inheritance unless the cell explicitly
# names an external CSP (rare in practice).
_COL_L_EXTERNAL_HINTS: tuple[str, ...] = ("aws", "azure", "gcp", "csp", "cloud service provider")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class AutoStatusVerdict(str, Enum):
    """What the rules engine decided for one CCI row."""

    COMPLIANT_8A = "compliant_8a"  # internal inheritance
    NOT_APPLICABLE_8B = "not_applicable_8b"  # external CSP, zero local responsibility
    UNCLEAR_8C = "unclear_8c"  # ambiguous — escalate to user / LLM
    NO_AUTO_RULE = "no_auto_rule"  # row needs a normal assessment


@dataclass
class AutoStatusResult:
    """Result of running rule #8 against one CCI row.

    ``narrative`` is the suggested col Q text if a verdict was reached,
    formatted per the plugin's exact templates. It is None for UNCLEAR_8C
    and NO_AUTO_RULE — those go to the LLM (with ``trigger_phrase`` and
    ``rule`` carried as corrective context if applicable).
    """

    verdict: AutoStatusVerdict
    status: ComplianceStatus | None
    narrative: str | None
    rule: str | None  # "8a" / "8b" / "8c" / None
    trigger_phrase: str | None  # the verbatim phrase that fired the rule
    trigger_column: str | None  # "J", "K", "L", "Q", or "U"
    reason: str | None = None  # human-readable note (e.g. for UNCLEAR_8C)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def classify_row(row: CcisRow) -> AutoStatusResult:
    """Apply rule #8 to a single CCI row. Pure function, no DB, no LLM.

    Order of checks:
        1. Rule 8a explicit phrases in cols K then J (Compliant). Runs FIRST
           so col-K-authoritative DoD-auto rows are claimed Compliant before
           any NA recognizer can see them.
        2. Rule 8a qualified "inherited from <internal source>" in cols K/J.
        3. Col Q/U documented-rationale recognizer:
             3a. explicit scope-exclusion phrases (COMPLIANCE_GUARD-gated) → NA.
             3b. CSP / external-inheritance phrases → Compliant.
        4. Rule 8a structural — col L non-empty, not "Local", not naming a CSP.
        5. Rule 8c — bare "inherited from" with no qualifier (UNCLEAR).
        6. NO_AUTO_RULE — row goes to normal assessment.
    """

    # --- 1. Rule 8a explicit phrases (col-K authoritative; runs first) ---
    for col_name, text in (("K", row.procedures), ("J", row.guidance)):
        hit = _find_first_trigger(text, _R8A_TRIGGERS)
        if hit is not None:
            return AutoStatusResult(
                verdict=AutoStatusVerdict.COMPLIANT_8A,
                status=ComplianceStatus.COMPLIANT,
                narrative=_format_8a_text_narrative(hit, col_name, text),
                rule="8a",
                trigger_phrase=hit,
                trigger_column=col_name,
            )

    # --- 2. Rule 8a qualified "inherited from <internal>" ---------------
    for col_name, text in (("K", row.procedures), ("J", row.guidance)):
        hit = _find_first_trigger(text, _R8A_INHERITANCE_INTERNAL)
        if hit is not None:
            return AutoStatusResult(
                verdict=AutoStatusVerdict.COMPLIANT_8A,
                status=ComplianceStatus.COMPLIANT,
                narrative=_format_8a_text_narrative(hit, col_name, text),
                rule="8a",
                trigger_phrase=hit,
                trigger_column=col_name,
            )

    # --- 3. Col Q / U documented-rationale recognizer -------------------
    # The assessor's scope-exclusion and CSP-attribution rationale lives here,
    # NOT in the generic DISA template text of K/J. This is the mechanism that
    # recovers the human-reviewed NA verdicts.
    q_text, u_text = row.results, row.previous_results
    blob = f"{q_text or ''}\n{u_text or ''}"
    compliance_claimed = bool(_COMPLIANCE_GUARD.search(blob))

    # 3a. explicit scope exclusion → Not Applicable (unless compliance claimed
    #     in the same rationale, which means the human ruled it Compliant).
    if not compliance_claimed:
        for col_name, text in (("Q", q_text), ("U", u_text)):
            hit = _find_first_trigger(text, _R8B_NA_SCOPE_PHRASES)
            if hit is not None:
                return AutoStatusResult(
                    verdict=AutoStatusVerdict.NOT_APPLICABLE_8B,
                    status=ComplianceStatus.NOT_APPLICABLE,
                    narrative=_format_na_scope_narrative(hit, col_name, text),
                    rule="8b",
                    trigger_phrase=hit,
                    trigger_column=col_name,
                )

    # 3b. CSP / external-provider inheritance → Compliant (inherited != NA).
    for col_name, text in (("Q", q_text), ("U", u_text)):
        hit = _find_first_trigger(text, _R8A_CSP_INHERIT_PHRASES)
        if hit is not None:
            return AutoStatusResult(
                verdict=AutoStatusVerdict.COMPLIANT_8A,
                status=ComplianceStatus.COMPLIANT,
                narrative=_format_csp_compliant_narrative(hit, col_name),
                rule="8a",
                trigger_phrase=hit,
                trigger_column=col_name,
            )

    # --- 4. Rule 8a structural — col L names an internal inheritance source
    col_l = (row.inherited or "").strip()
    if col_l and col_l.lower() != "local":
        if not _value_names_external_csp(col_l):
            return AutoStatusResult(
                verdict=AutoStatusVerdict.COMPLIANT_8A,
                status=ComplianceStatus.COMPLIANT,
                narrative=_format_8a_structural_narrative(col_l),
                rule="8a",
                trigger_phrase=col_l,
                trigger_column="L",
            )
        # Col L names a CSP-ish source — that's an 8b structural signal, but
        # the plugin requires text triggers in K/J for 8b; if we got here
        # without one, fall through to 8c.

    # --- 5. Rule 8c — bare "inherited from" w/ no qualifier -------------
    for col_name, text in (("K", row.procedures), ("J", row.guidance)):
        if text and _BARE_INHERITED_FROM.search(text):
            return AutoStatusResult(
                verdict=AutoStatusVerdict.UNCLEAR_8C,
                status=None,
                narrative=None,
                rule="8c",
                trigger_phrase="inherited from",
                trigger_column=col_name,
                reason=(
                    f'Col {col_name} says "inherited from" but does not name the source. '
                    "Cannot distinguish internal (8a → Compliant) from external CSP "
                    "(8b → Not Applicable). Escalate to assessor."
                ),
            )

    # --- 6. Nothing fired — normal LLM-driven assessment ----------------
    return AutoStatusResult(
        verdict=AutoStatusVerdict.NO_AUTO_RULE,
        status=None,
        narrative=None,
        rule=None,
        trigger_phrase=None,
        trigger_column=None,
    )


# ---------------------------------------------------------------------------
# Narrative formatters (verbatim from plugin)
# ---------------------------------------------------------------------------


def _original_case(text: str | None, trigger: str) -> str:
    """Recover the substring of ``text`` that matched ``trigger``.

    ``_find_first_trigger`` matches against a lowercased haystack and returns
    the canonical (lowercase) trigger, which is the right stable identifier for
    ``trigger_phrase`` and the decision cache. But quoting that lowercase form
    verbatim in a user-facing narrative reads wrong (e.g. an all-caps acronym
    like "GOCO" lands as "goco"). This recovers the original casing from the
    source cell for display. Falls back to ``trigger`` if the span can't be
    located (defensive; callers only pass text that already matched).
    """
    if text:
        idx = text.lower().find(trigger)
        if idx != -1:
            return text[idx : idx + len(trigger)]
    return trigger


def _format_8a_text_narrative(
    trigger: str, col_name: str, source_text: str | None = None
) -> str:
    col_label = {
        "J": "Implementation Guidance (col J)",
        "K": "Assessment Procedures (col K)",
    }.get(col_name, f"col {col_name}")
    quoted = _original_case(source_text, trigger)
    return f'Automatically compliant per {col_label}: "{quoted}".'


def _format_8a_structural_narrative(col_l_value: str) -> str:
    return f'Automatically compliant per Inheritance (col L = "{col_l_value}").'


def _format_na_scope_narrative(
    trigger: str, col_name: str, source_text: str | None = None
) -> str:
    col_label = {
        "Q": "Assessment Results (col Q)",
        "U": "Previous Results (col U)",
    }.get(col_name, f"col {col_name}")
    quoted = _original_case(source_text, trigger)
    return (
        f"Not applicable — {col_label} documents an explicit scope exclusion: "
        f'"{quoted}".'
    )


def _format_csp_compliant_narrative(trigger: str, col_name: str) -> str:
    # Paraphrase the provider rather than quoting the trigger verbatim: the
    # raw "implemented by aws" string is an NA-class phrase in the validator,
    # so quoting it would make a Compliant narrative read as ambiguous.
    provider = _infer_external_provider(trigger)
    col_label = {
        "Q": "Assessment Results (col Q)",
        "U": "Previous Results (col U)",
    }.get(col_name, f"col {col_name}")
    return (
        f"Compliant — control is satisfied through inherited provider "
        f"implementation ({provider}); confirmed via {col_label}."
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _find_first_trigger(text: str | None, triggers: tuple[str, ...]) -> str | None:
    """Return the first trigger (verbatim, lowercased) found in ``text``,
    or None. Triggers are checked in the order given so callers can prefer
    more specific phrases first.
    """
    if not text:
        return None
    haystack = text.lower()
    for t in triggers:
        if t in haystack:
            return t
    return None


def _value_names_external_csp(value: str) -> bool:
    v = value.lower()
    return any(hint in v for hint in _COL_L_EXTERNAL_HINTS)


def _infer_external_provider(trigger: str) -> str:
    """Pull the provider name out of an 8b trigger phrase for the narrative."""
    t = trigger.lower()
    if "aws" in t:
        return "AWS"
    if "azure" in t:
        return "Azure"
    if "gcp" in t:
        return "GCP"
    if "csp" in t or "cloud service provider" in t:
        return "the cloud service provider (CSP)"
    return "an external service provider"
