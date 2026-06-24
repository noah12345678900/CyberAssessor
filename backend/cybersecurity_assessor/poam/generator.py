"""Cluster Non-Compliant assessments into draft POAMs.

Grouping policy — per feedback_poam_scoping.md:
  1. Start from NC assessments in the target workbook.
  2. Default cluster = base control + its (N) enhancements
     (e.g. SI-3 + SI-3(1) + SI-3(2) → one POAM).
  3. If a whole family's failures share one remediation owner / root cause /
     milestone set, fold them into one POAM. This isn't auto-detected here —
     the generator emits per-base-control clusters; the UI provides a merge
     action when the assessor sees that pattern.
  4. Conversely, if two CCIs under one control need distinct fixes, the UI
     provides a split action.

What this module DOES:
  - Reads NC assessments for a workbook.
  - Joins assessment → objective → control to learn the base control id.
  - Groups by base control id (regex strip the (N) suffix).
  - Builds one Poam + N PoamObjective rows per cluster.
  - Seeds defaults (status=Draft, likelihood=Moderate, impact=Moderate).

What this module does NOT do:
  - Boundary reasoning. The workbook already represents one system boundary;
    NC findings in it are already scoped — per the user, don't re-cluster on
    boundary.
  - LLM-driven family-level merging. The assessor owns that judgment in the
    UI.
  - Idempotence beyond "skip clusters that already have a Poam row for this
    workbook + cluster id". Re-running the generator after the assessor has
    edited a POAM will NOT overwrite their work.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select

from sqlmodel import delete

from ..engine.crm_context import CrmContext, CrmEntry, build_crm_context
from ..engine.finding_corroboration import (
    _SEVERITY_RANK,
    _severity_sort_key,
    affected_hosts as _shared_affected_hosts,
    corroborating_findings as _shared_corroborating_findings,
    format_finding_citation,
)
from ..excel.ccis_reader import _ccis_to_oscal_control_id, _normalize_control
from ..models import (
    Assessment,
    AssessmentImplementation,
    ComplianceStatus,
    Control,
    Objective,
    Poam,
    PoamEvidence,
    PoamMilestone,
    PoamObjective,
    PoamStatus,
    RiskLevel,
    StigFinding,
)
from .risk import (
    DEFAULT_IMPACT,
    DEFAULT_LIKELIHOOD,
    compute_risk,
    record_risk_change,
    seed_impact_from_stig,
)

# CRM responsibilities that suppress POAM generation entirely. An NC
# assessment for any of these is treated as stale (e.g. assessed before
# the CRM overlay was attached) — the kernel would short-circuit the
# same control to COMPLIANT (inherited) or NOT_APPLICABLE
# (provider / not_applicable) on the next run, so emitting a POAM for it
# would create a draft that the next assessment cycle invalidates.
_CRM_SKIP_RESPONSIBILITIES = frozenset({"provider", "inherited", "not_applicable"})

# "AC-2(3)" → "AC-2". Matches NIST 800-53 enhancement notation.
_ENHANCEMENT_RE = re.compile(r"^([A-Z]{2}-\d+)(\(\d+\))?$")


def base_control_id(control_id: str) -> str:
    """Strip (N) enhancement suffix to get the base control id.

    AC-2     → AC-2
    AC-2(3)  → AC-2
    SI-3(12) → SI-3
    Anything we don't recognize is returned unchanged so unusual IDs don't
    silently get merged.
    """
    m = _ENHANCEMENT_RE.match(control_id.strip())
    return m.group(1) if m else control_id


# v0.2 multi-impl cluster key separator. The POAM clusterer keys on
# ``"{base_control}|{scope_label}"`` so an Assessment whose impls split
# across (AWS GovCloud, Azure Government) fans out to two distinct POAMs —
# each remediable on its own schedule by its own owner. Round-trips through
# ``existing_poams_by_cluster`` on re-run for idempotence. Legacy (no impl
# rows) assessments stay keyed on the bare base_control_id so pre-v0.2
# POAMs don't get orphaned.
_CLUSTER_KEY_SEP = "|"


def _encode_cluster_key(base: str, scope_label: str | None) -> str:
    """Build the POAM cluster key. ``None``/empty scope → bare base id.

    Pinned shape: ``"AC-2"`` (single-impl) or ``"AC-2|AWS GovCloud"``
    (per-scope). See ``tests/engine/test_multi_impl_cascade.py`` for the
    literal expectation.
    """
    if not scope_label:
        return base
    return f"{base}{_CLUSTER_KEY_SEP}{scope_label}"


def _default_scheduled_date() -> datetime:
    """Default POAM scheduled completion = 90 days from generation.

    Conservative — gives the system owner a quarter to close common findings.
    Assessor adjusts in the UI before exporting to eMASS. Retained for any
    callers that don't have STIG-finding context; new POAM creation goes
    through ``_remediation_completion_date`` which is severity-aware.
    """
    return datetime.now(timezone.utc) + timedelta(days=90)


# DISA-aligned remediation horizons. CAT-I findings are expected to close in
# 30 days, CAT-II in 90, CAT-III in a year — picking the highest-severity
# finding's bucket for the whole cluster keeps eMASS dates defensible without
# slowing assessor review (still editable in the UI before export).
_SEVERITY_REMEDIATION_DAYS: dict[str, int] = {
    "high": 30,
    "cat i": 30,
    "medium": 90,
    "cat ii": 90,
    "low": 365,
    "cat iii": 365,
}
_DEFAULT_REMEDIATION_DAYS = 90

# When no STIG findings corroborate the cluster, fall back to the computed
# cluster RiskLevel. Moderate (the assess-time default) maps to the same
# 90-day horizon the old single-path logic always used — keeps behavior
# stable on no-evidence rows.
_RISK_LEVEL_TO_SEVERITY: dict[RiskLevel, str] = {
    RiskLevel.VERY_HIGH: "high",
    RiskLevel.HIGH: "high",
    RiskLevel.MODERATE: "medium",
    RiskLevel.LOW: "low",
    RiskLevel.VERY_LOW: "low",
}


def _derive_remediation_severity(
    stig_findings: list[tuple[StigFinding, str]],
    fallback: RiskLevel,
) -> str:
    """Pick the severity key that drives ``_SEVERITY_REMEDIATION_DAYS``.

    Highest-severity STIG finding wins — the shared corroboration query has
    already severity-sorted the list, so the first VALID entry is the worst.
    "Valid" means a non-empty severity string that resolves to a known
    remediation tier (high/medium/low/informational). If the top entry's
    severity is None or an unknown string like "unknown", walk further into
    the list rather than falling all the way back to the cluster-level
    RiskLevel — a second high-severity finding shouldn't be lost just
    because the corroboration sort put a None-severity row at index 0.
    When the cluster has no STIG findings at all, fall back to the
    cluster's computed ``RiskLevel`` mapped through ``_RISK_LEVEL_TO_SEVERITY``.
    Returns a lowercase key safe to look up in ``_SEVERITY_REMEDIATION_DAYS``.
    """
    for finding, _label in stig_findings:
        sev = finding.severity
        if not sev:
            continue
        key = sev.strip().lower()
        if key in _SEVERITY_REMEDIATION_DAYS:
            return key
    return _RISK_LEVEL_TO_SEVERITY.get(fallback, "medium")


def _remediation_completion_date(severity_key: str) -> datetime:
    """Translate a severity key into an absolute completion date."""
    days = _SEVERITY_REMEDIATION_DAYS.get(severity_key, _DEFAULT_REMEDIATION_DAYS)
    return datetime.now(timezone.utc) + timedelta(days=days)


def _grounded_remediation_text(
    cluster_id: str,
    items: list[tuple[Assessment, Objective, Control]],
) -> str:
    """Build a remediation milestone grounded in the control's own requirement.

    Used for the lead "develop and implement" milestone. When the cluster has
    no STIG/scan fix-text to source from, the remediation plan would otherwise
    be a content-free placeholder ("Develop and implement remediation plan for
    AC-2."). Per the project's grounding rule, remediation text may be
    auto-filled ONLY when derived from real inputs — so we anchor it to what
    the control actually demands, sourced (in priority order) from the
    ``Control.statement`` requirement text, then ``Control.title``, then the
    failing ``Objective.text``. We never invent a vendor/product-specific
    procedure here — the phrasing is explicitly "controls satisfying <the
    requirement>", which is true regardless of how the system owner closes it.

    Returns the bare generic milestone string when no requirement text exists
    on any contributing control (defensive — keeps eMASS's >=1-milestone
    invariant intact rather than emitting an empty description).
    """
    generic = f"Develop and implement remediation plan for {cluster_id}."
    if not items:
        return generic

    # Prefer the base control's requirement statement; fall back to title, then
    # to the first failing objective's text. Take the first non-empty source so
    # one well-populated control grounds the whole cluster.
    requirement = ""
    for _a, _o, c in items:
        stmt = (c.statement or "").strip()
        if stmt:
            requirement = stmt
            break
    if not requirement:
        for _a, _o, c in items:
            title = (c.title or "").strip()
            if title:
                requirement = title
                break
    if not requirement:
        for _a, o, _c in items:
            otext = (o.text or "").strip()
            if otext:
                requirement = otext
                break
    if not requirement:
        return generic

    summary = _first_sentence(requirement, 240)
    if not summary:
        return generic
    return (
        f"Develop and implement controls satisfying the {cluster_id} "
        f"requirement: {summary}"
    )


def _build_mitigations_text(
    cluster_id: str,
    stig_findings: list[tuple[StigFinding, str]],
    items: list[tuple[Assessment, Objective, Control]],
) -> str:
    """Draft the POAM 'Mitigations' field, grounded in verbatim remediation text.

    eMASS expects a description of the corrective action / interim mitigation.
    Per the project grounding rule (remediation text is auto-filled ONLY from
    real inputs), we quote the cluster's contributing STIG ``fix_text``
    VERBATIM — that DISA/vendor-authored fix is the most defensible mitigation
    statement and is exactly what a 3PAO expects to read. Up to the top 3
    unique rules (severity order from the pre-sorted finding list, deduped by
    ``rule_id``) are listed in full; we do NOT truncate the fix text, since the
    whole point is auditable verbatim guidance. When the cluster has no STIG
    fix text to quote, fall back to the requirement-anchored remediation
    sentence (same source priority as the lead milestone) so the field is
    never blank — but we never invent a product-specific procedure.
    """
    lines: list[str] = []
    seen: set[str] = set()
    for finding, _label in stig_findings:
        if len(seen) >= 3:
            break
        fix = (finding.fix_text or "").strip()
        rule_id = (finding.rule_id or "").strip()
        if not fix or not rule_id or rule_id in seen:
            continue
        seen.add(rule_id)
        lines.append(f"- {rule_id}: {fix}")
    if lines:
        header = (
            "Apply the following DISA/vendor-authored corrective actions for "
            f"{cluster_id} (verbatim STIG fix text):"
        )
        return header + "\n" + "\n".join(lines)
    # No STIG fix text in this cluster — anchor to the control requirement so
    # the field still carries grounded content rather than rendering blank.
    return _grounded_remediation_text(cluster_id, items)


def _build_resources_required_text(cluster_id: str) -> str:
    """Draft the POAM 'Resources required' field as an honest starting estimate.

    Unlike Mitigations (grounded in verbatim STIG fix text), resourcing has no
    verbatim source to derive from, so this is an explicitly-labeled starting
    estimate rather than a costed figure: the labor needed to implement and
    validate the cited corrective action. Phrased as "pending assessor cost
    analysis" so it never masquerades as a final number — the assessor owns the
    dollar/effort estimate before eMASS submission. Populated (not left blank)
    because an empty Resources field reads as "not yet analyzed" in eMASS
    review, and the field is part of a complete POA&M line.
    """
    return (
        "System administrator and ISSO labor to implement, document, and "
        f"validate the corrective action for {cluster_id}. Estimated level of "
        "effort and any funding / hardware / software needs pending assessor "
        "cost analysis."
    )


def _seed_milestones(
    poam_id: int,
    cluster_id: str,
    stig_findings: list[tuple[StigFinding, str]],
    completion_date: datetime,
    items: list[tuple[Assessment, Objective, Control]] | None = None,
) -> list[PoamMilestone]:
    """Build the initial milestone set for a freshly created POAM.

    Always emits one lead "Develop and implement ..." milestone (eMASS requires
    at least one). When ``items`` (the cluster's NC assessment/objective/control
    tuples) are supplied, that lead milestone is GROUNDED in the control's own
    requirement text via :func:`_grounded_remediation_text` — so even a cluster
    with no STIG fix-text to source from gets a remediation plan derived from
    what the control demands, not a content-free placeholder. When the cluster
    has tagged STIG findings, additionally emits one milestone per unique rule
    (top 3 by severity, deduped by ``rule_id``) so the eMASS export carries
    actionable remediation tasks. All milestones share the cluster's
    severity-derived completion date — assessor adjusts in the UI before export.
    """
    lead_desc = (
        _grounded_remediation_text(cluster_id, items)
        if items
        else f"Develop and implement remediation plan for {cluster_id}."
    )
    milestones: list[PoamMilestone] = [
        PoamMilestone(
            poam_id=poam_id,
            description=lead_desc,
            scheduled_date=completion_date,
        )
    ]
    seen_rules: set[str] = set()
    for finding, _label in stig_findings:
        if len(seen_rules) >= 3:
            break
        rule_id = (finding.rule_id or "").strip()
        # Whitespace-only rule_ids ARE truthy in Python — guard explicitly
        # so we don't emit "Remediate    : bad config" in milestone text.
        if not rule_id or rule_id in seen_rules:
            continue
        seen_rules.add(rule_id)
        detail = _first_sentence(finding.finding_details, 160)
        if detail:
            desc = f"Remediate {rule_id}: {detail}"
        else:
            desc = f"Remediate {rule_id}."
        milestones.append(
            PoamMilestone(
                poam_id=poam_id,
                description=desc,
                scheduled_date=completion_date,
            )
        )
    return milestones


def _format_controls_aps(control_ids: list[str], cci_ids: list[str]) -> str:
    """eMASS column D (Controls / APs) formatting.

    Existing template entries look like 'AC-2(3).1, AC-2(3).2, IA-4.8' —
    control id + dot + assessment-procedure number. We emit one entry per
    CCI: '<ctl_id>.<cci_tail>'. If we can't parse a CCI tail (CCI-000213
    style), fall back to just the CCI id.
    """
    parts = []
    for ctl, cci in zip(control_ids, cci_ids):
        # AC-2.1 style CCIs already include the AP suffix
        if cci.startswith(ctl + ".") or cci.startswith(ctl + "("):
            parts.append(cci)
        else:
            parts.append(f"{ctl} ({cci})")
    return ", ".join(parts)


def _format_security_control_number(control_ids: set[str]) -> str:
    """eMASS-friendly list of control IDs covered, sorted.

    SI-3 + SI-3(1) + SI-3(2) → 'SI-3, SI-3(1), SI-3(2)'
    """

    def _key(c: str):
        m = _ENHANCEMENT_RE.match(c)
        if not m:
            return (c, 0)
        return (m.group(1), int(m.group(2)[1:-1]) if m.group(2) else 0)

    return ", ".join(sorted(control_ids, key=_key))


def _resolve_crm_entry(control_id: str | None, crm: CrmContext) -> CrmEntry | None:
    """Look up CRM responsibility for a Control row's id.

    Mirrors :meth:`Assessor._lookup_crm`: ``CrmContext`` keys on OSCAL
    canonical control_id ("ac-2.1"), and ``Control.control_id`` is also
    stored in OSCAL canonical form by the catalog loader. The two
    normalizer calls are idempotent and exist only to be defensive
    against future loaders that store the CCIS form ("AC-2(1)") instead.
    """
    if not control_id:
        return None
    norm = _normalize_control(control_id)
    if not norm:
        return None
    return crm.lookup(_ccis_to_oscal_control_id(norm))


def _render_crm_hybrid_block(entries: list[CrmEntry]) -> str:
    """Format CRM-hybrid citations for prepend to the vulnerability text.

    POAMs for hybrid controls remediate the **customer half** only — the
    provider portion is the CSP's responsibility. The block lists each
    affected control with its CRM narrative so reviewers can trace why
    the scope was trimmed without re-opening the CRM workbook.
    """
    lines = [
        "## Responsibility split (from CRM overlay)",
        (
            "The following control(s) are HYBRID per the attached Customer "
            "Responsibility Matrix. This POAM addresses the customer portion "
            "only; the provider portion is the CSP's responsibility."
        ),
    ]
    for e in entries:
        snippet = (e.narrative or "").strip()
        if snippet:
            lines.append(f"- {e.control_id}: {snippet}")
        else:
            lines.append(
                f"- {e.control_id}: hybrid responsibility per CRM overlay "
                f"(no narrative supplied)."
            )
    return "\n".join(lines)


def _collect_cite_refresh_pairs(
    items: list[tuple[Assessment, Objective, Control]],
) -> list[tuple[str, str, str]]:
    """Pull (control_id, legacy, current) triples from rewrite_requested rows.

    v0.2 citation-hygiene contract: a row with ``rewrite_requested=True``
    landed on a trusted verdict, but the narrative still references a
    legacy doc name that supersession (or NA-reconsideration) flagged for
    refresh. The pair list is JSON-encoded on
    ``Assessment.rewrite_requested_refs`` as ``[[legacy, current], ...]``.

    Returns an empty list when no row in the cluster carries a refresh
    request, or when every flagged row has refs=NULL (older rows where
    supersession couldn't reconstruct the pair — the exporter then falls
    back to a generic note in the caller).
    """
    pairs: list[tuple[str, str, str]] = []
    for a, _, c in items:
        if not getattr(a, "rewrite_requested", False):
            continue
        raw = getattr(a, "rewrite_requested_refs", None)
        if not raw:
            continue
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if not isinstance(decoded, list):
            continue
        for entry in decoded:
            if (
                isinstance(entry, (list, tuple))
                and len(entry) >= 2
                and entry[0]
                and entry[1]
            ):
                pairs.append((c.control_id, str(entry[0]), str(entry[1])))
    return pairs


def _has_generic_cite_refresh(
    items: list[tuple[Assessment, Objective, Control]],
) -> bool:
    """True when at least one row asked for a refresh but had no refs decoded.

    Lets the caller emit the generic "cite refresh requested" footer even
    when the structured pair list is empty (legacy rows from before the
    rewrite_requested_refs column was populated).
    """
    for a, _, _ in items:
        if not getattr(a, "rewrite_requested", False):
            continue
        raw = getattr(a, "rewrite_requested_refs", None)
        if not raw:
            return True
    return False


def _render_cite_refresh_block(
    pairs: list[tuple[str, str, str]], generic: bool
) -> str:
    """Format a 'cite refresh requested' callout for the vulnerability text.

    Stale-reference and NA-reconsideration rows still ship with a trusted
    verdict (per the v0.2 design — they're citation hygiene, not abstain).
    POAMs for the affected controls carry this banner so the assessor's
    next narrative pass knows which doc cites to swap. Mirrors
    :func:`_render_crm_hybrid_block` in shape so reviewers see a consistent
    callout pattern.
    """
    lines = ["## Cite refresh requested"]
    if pairs:
        lines.append(
            "The narratives for the following control(s) cite a legacy "
            "document name that has been superseded. The verdict still "
            "stands — update the citation in the next narrative pass."
        )
        for ctl, legacy, current in pairs:
            lines.append(f"- {ctl}: '{legacy}' \u2192 '{current}'")
    elif generic:
        lines.append(
            "One or more narratives in this cluster were flagged for a "
            "citation refresh, but the specific legacy/current pair could "
            "not be reconstructed. Re-run assess after updating the "
            "narrative to clear the flag."
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Vulnerability description builder
# ---------------------------------------------------------------------------
#
# Sections are conditional — a cluster with no STIG findings, no host inventory,
# and no assessor narrative excerpts will get just the summary line + CCI list,
# rather than empty headers with "n/a" rows under them. This is the precision-
# over-recall rule applied to the narrative surface: never imply we located
# evidence we didn't actually find.

# Cap for the rendered text. eMASS column D has no hard char limit, but Excel
# itself caps a single cell at 32,767 characters — exceed that and openpyxl
# raises / the cell is silently lost. We sit just under that hard ceiling so the
# vulnerability description keeps its full content (assessor excerpts, host
# lists, findings) instead of being trimmed for cosmetics. The prior 4000 was a
# COSMETIC soft cap ("renders awkwardly in the cell preview") that was dropping
# real evidence detail — completeness/defensibility wins over preview tidiness.
# The priority-trim ladder below now only fires for genuinely enormous
# descriptions approaching Excel's limit, as a last-resort safety net.
_EXCEL_CELL_HARD_LIMIT = 32767
_VULN_DESC_CAP = 32000

# _SEVERITY_RANK and _severity_sort_key now live in engine.finding_corroboration
# (canonical home — shared by the assessor evidence bundle). Imported above and
# re-exported here so existing callers keep working.


def _first_sentence(text: str | None, max_chars: int) -> str:
    """First sentence (or first ``max_chars`` of text) with trailing ellipsis if cut.

    Cheap heuristic — splits on `. ` / `! ` / `? ` and keeps the first piece.
    Falls back to a hard char cap when no sentence terminator appears. We
    don't pull in nltk for this; POAM narrative text is already short and we
    only need a stable summary, not perfect tokenization.
    """
    if not text:
        return ""
    t = text.strip()
    if not t:
        return ""
    for sep in (". ", "! ", "? ", ".\n", "!\n", "?\n"):
        idx = t.find(sep)
        if 0 < idx <= max_chars:
            return t[: idx + 1].strip()
    if len(t) <= max_chars:
        return t
    return t[: max_chars - 1].rstrip() + "\u2026"


def _collect_stig_findings_for_cluster(
    objective_ids: list[int],
    cci_ids_in_cluster: set[str],
    s: Session,
) -> list[tuple[StigFinding, str]]:
    """Thin wrapper preserving the historical name; the real query lives in
    engine.finding_corroboration so the assessor evidence bundle can call the
    same code path (no narrative/status drift)."""
    return _shared_corroborating_findings(objective_ids, cci_ids_in_cluster, s)


def _collect_affected_hosts(
    objective_ids: list[int], s: Session
) -> list[str]:
    """Thin wrapper preserving the historical name; the real query lives in
    engine.finding_corroboration. See the shared module for behavior contract."""
    return _shared_affected_hosts(objective_ids, s)


def _build_vuln_description(
    items: list[tuple[Assessment, Objective, Control]],
    cluster_id: str,
    hybrid_entries: list[CrmEntry],
    cite_pairs: list[tuple[str, str, str]],
    cite_generic: bool,
    s: Session,
    stig_findings: list[tuple[StigFinding, str]] | None = None,
) -> str:
    """Compose the sectioned vulnerability narrative for a POAM cluster.

    Layered top→bottom: callout blocks (CRM-hybrid, cite refresh), summary
    line, failing-CCI enumeration, corroborating scan findings, affected
    hosts, and per-CCI assessor-narrative excerpts. Each section is
    independently conditional. The composed text is soft-capped at
    ``_VULN_DESC_CAP``; over-cap we trim assessor excerpts first, then hosts,
    then findings (keeping the high-signal CCI list and summary intact).
    """
    control_ids = sorted({c.control_id for _, _, c in items})
    cci_ids_in_cluster = {o.objective_id for _, o, _ in items}
    objective_ids = [o.id for _, o, _ in items if o.id is not None]

    # --- Top callouts (kept verbatim — already exercised by the prior flow)
    callouts: list[str] = []
    if hybrid_entries:
        callouts.append(_render_crm_hybrid_block(hybrid_entries))
    if cite_pairs or cite_generic:
        callouts.append(_render_cite_refresh_block(cite_pairs, cite_generic))

    # --- Summary line
    if len(items) == 1:
        summary = (
            f"{cluster_id}: 1 assessment objective non-compliant "
            f"(control {control_ids[0]})."
        )
    else:
        summary = (
            f"{cluster_id}: {len(items)} assessment objectives non-compliant "
            f"across controls {', '.join(control_ids)}."
        )

    # --- Failing CCI enumeration
    cci_lines: list[str] = ["**Failing assessment objectives:**"]
    for _, o, _ in items:
        cci_lines.append(f"- {o.objective_id}: {_first_sentence(o.text, 220)}")
    cci_section = "\n".join(cci_lines)

    # --- Corroborating STIG findings (top 5 by severity)
    # Accept a pre-fetched list from the caller (the POAM creation path
    # computes it once and reuses for milestone seeding) to avoid a second
    # round-trip to the StigFinding table; otherwise fetch here.
    findings = (
        stig_findings
        if stig_findings is not None
        else _collect_stig_findings_for_cluster(objective_ids, cci_ids_in_cluster, s)
    )
    findings_section = ""
    if findings:
        findings.sort(key=lambda pair: _severity_sort_key(pair[0].severity))
        top = findings[:5]
        f_lines = ["**Corroborating scan/STIG findings:**"]
        for f, label in top:
            sev = f.severity or "unrated"
            citation = format_finding_citation(f, label)
            detail = _first_sentence(f.finding_details, 160) or "(no details)"
            f_lines.append(f"- {citation} ({sev}): {detail}")
            # Append check/fix text when present so a reviewer can correlate
            # the POAM line item directly to the STIG Viewer rule.
            if f.check_text:
                f_lines.append(
                    f"  check: {_first_sentence(f.check_text, 120) or f.check_text[:120]}"
                )
            if f.fix_text:
                f_lines.append(
                    f"  fix: {_first_sentence(f.fix_text, 120) or f.fix_text[:120]}"
                )
        if len(findings) > 5:
            f_lines.append(f"- (+{len(findings) - 5} additional finding(s) not shown)")
        findings_section = "\n".join(f_lines)

    # --- Affected hosts
    hosts = _collect_affected_hosts(objective_ids, s)
    hosts_section = ""
    if hosts:
        shown = hosts[:20]
        suffix = f" (+{len(hosts) - 20} more)" if len(hosts) > 20 else ""
        hosts_section = (
            f"**Affected hosts ({len(hosts)}):** " + ", ".join(shown) + suffix
        )

    # --- Assessor narrative excerpts (per-CCI first sentence)
    excerpt_lines: list[str] = []
    for a, o, _ in items:
        if not a.narrative_q:
            continue
        snippet = _first_sentence(a.narrative_q, 240)
        if snippet:
            excerpt_lines.append(f"> {o.objective_id}: {snippet}")
    excerpt_section = ""
    if excerpt_lines:
        excerpt_section = "**Assessor narrative excerpts:**\n" + "\n".join(excerpt_lines)

    # --- Compose with cap-aware trimming. Order from highest to lowest
    # priority; if the final string exceeds the cap, drop the lowest-priority
    # sections one at a time until it fits.
    def _join(sections: list[str]) -> str:
        return "\n\n".join(s for s in sections if s)

    body_sections = [summary, cci_section]
    if findings_section:
        body_sections.append(findings_section)
    if hosts_section:
        body_sections.append(hosts_section)
    if excerpt_section:
        body_sections.append(excerpt_section)

    # Cap: trim from lowest-priority end (excerpts → hosts → findings → cci → summary).
    # Callouts always stay; they're hygiene-critical (CRM scope split, cite
    # refresh request) and tiny.
    while True:
        composed = _join(callouts + body_sections)
        if len(composed) <= _VULN_DESC_CAP:
            return composed
        # Trim, in order: excerpts, hosts, findings. Never drop CCI list /
        # summary — those are the irreducible identity of the POAM.
        if excerpt_section and body_sections[-1] is excerpt_section:
            body_sections.pop()
            excerpt_section = ""
            continue
        if hosts_section and body_sections[-1] is hosts_section:
            body_sections.pop()
            hosts_section = ""
            continue
        if findings_section and body_sections[-1] is findings_section:
            body_sections.pop()
            findings_section = ""
            continue
        # Only summary + CCI list left and still over cap → hard-truncate the
        # CCI section. Rare path; keeps us from ever returning > cap.
        if len(body_sections) >= 2 and body_sections[1] is cci_section:
            body_sections[1] = cci_section[: _VULN_DESC_CAP - len(summary) - 8].rstrip() + "\u2026"
        return _join(callouts + body_sections)


def _prune_stale_poam_links(workbook_id: int, s: Session) -> int:
    """Drop PoamObjective rows whose objective is no longer Non-Compliant.

    Run before generation so re-running /generate also heals POAMs left over
    from earlier sessions (e.g. an objective got remediated and reassessed
    Compliant, but the POAM lingered because the assessment was edited
    against an older sidecar that didn't auto-prune).

    Empty POAMs that result are deleted along with their milestones and
    evidence links — auto-generated rows have no manual edits worth keeping.
    Returns the number of POAMs deleted (caller commits).
    """
    # Stale = link points to an objective whose current assessment in this
    # workbook is anything other than NC (or has no assessment at all).
    stale_links = s.exec(
        select(PoamObjective)
        .join(Poam, Poam.id == PoamObjective.poam_id)
        .where(Poam.workbook_id == workbook_id)
    ).all()

    obj_status: dict[int, ComplianceStatus | None] = {}
    for po in stale_links:
        if po.objective_id in obj_status:
            continue
        a = s.exec(
            select(Assessment)
            .where(Assessment.workbook_id == workbook_id)
            .where(Assessment.objective_id == po.objective_id)
        ).first()
        # v0.2 precision-over-recall: a needs_review NC is an abstention,
        # not a trusted finding — treat it as stale so the POAM gets
        # pruned. If/when the reviewer clears the abstain, /generate will
        # rebuild the POAM from the trusted verdict.
        if a is None or a.needs_review:
            obj_status[po.objective_id] = None
        else:
            obj_status[po.objective_id] = a.status

    to_delete = [
        po for po in stale_links
        if obj_status.get(po.objective_id) != ComplianceStatus.NON_COMPLIANT
    ]
    if not to_delete:
        return 0

    affected_poams = {po.poam_id for po in to_delete}
    for po in to_delete:
        s.delete(po)
    s.flush()

    deleted = 0
    for pid in affected_poams:
        remaining = s.exec(
            select(PoamObjective).where(PoamObjective.poam_id == pid)
        ).first()
        if remaining is not None:
            continue
        s.exec(delete(PoamMilestone).where(PoamMilestone.poam_id == pid))
        s.exec(delete(PoamEvidence).where(PoamEvidence.poam_id == pid))
        p = s.get(Poam, pid)
        if p is not None:
            s.delete(p)
            deleted += 1
    return deleted


@dataclass
class GenerateResult:
    """Per-bucket Poam rows from one ``generate_for_workbook`` run.

    The route layer turns counts into the user-facing toast; tests assert on
    the lists directly. Keeping the bucketing here (rather than re-deriving
    it in the route) means a single source of truth for "what happened this
    run" — important because regenerate is the assessor's most-pressed
    button and the prior list-only return shape made non-creating runs look
    like silent failures.

    Buckets:
      created             — brand-new Poam rows (NC cluster had none).
      rewritten           — existing DRAFT + unlocked Poam whose enriched
                            description changed this run.
      unchanged           — existing DRAFT + unlocked Poam whose enriched
                            description matched the existing text (a no-op,
                            but counted so the UI can say "all caught up").
      locked_skipped      — Poam with ``narrative_locked=True`` (assessor
                            edited the description via the UI). Skipped to
                            preserve assessor narrative.
      non_draft_skipped   — Poam not in DRAFT status (ONGOING, COMPLETED,
                            RISK_ACCEPTED). Skipped to preserve workflow
                            audit trail.
    """

    created: list[Poam] = field(default_factory=list)
    rewritten: list[Poam] = field(default_factory=list)
    unchanged: list[Poam] = field(default_factory=list)
    locked_skipped: list[Poam] = field(default_factory=list)
    non_draft_skipped: list[Poam] = field(default_factory=list)


def generate_for_workbook(workbook_id: int, s: Session) -> GenerateResult:
    """Build draft POAMs for every NC cluster in a workbook.

    Heals first, then generates:
      0. Drop PoamObjective links whose current assessment is no longer NC,
         and delete any POAMs left empty by that pruning.
      1. Cluster NC assessments → draft POAMs for new clusters; for clusters
         that already have a POAM, rewrite the enriched vulnerability
         description in place when (a) the POAM is still in DRAFT and
         (b) ``narrative_locked`` is False. Non-draft POAMs and any POAM the
         assessor has edited through the UI are skipped — the lock flips
         True on the first PATCH that includes ``vulnerability_description``.

    Returns a :class:`GenerateResult` partitioning every touched Poam into
    one of five buckets (created / rewritten / unchanged / locked_skipped /
    non_draft_skipped). Caller is responsible for s.commit().
    """
    _prune_stale_poam_links(workbook_id, s)

    # CRM overlay snapshot (latest-wins on duplicate control_id, same
    # rules as the kernel uses during assess). Empty when no CRM is
    # attached to the workbook — controls then fall through with
    # ``lookup() -> None`` and contribute to POAMs normally per the
    # overlay-default-local rule.
    crm = build_crm_context(workbook_id, s)

    # 1. All NC assessments in this workbook, with their objective + control.
    # v0.2 precision-over-recall gate: needs_review NCs are abstentions —
    # the LLM's proposed status isn't trusted yet, so emitting a POAM for
    # one would bake a triage-pending verdict into the remediation plan.
    # Filter them out here; once the reviewer resolves the abstain
    # (manually editing the row clears needs_review), re-running generate
    # picks the cluster up normally.
    stmt = (
        select(Assessment, Objective, Control)
        .join(Objective, Objective.id == Assessment.objective_id)
        .join(Control, Control.id == Objective.control_id_fk)
        .where(Assessment.workbook_id == workbook_id)
        .where(Assessment.status == ComplianceStatus.NON_COMPLIANT)
        .where(Assessment.needs_review == False)  # noqa: E712 — SQLModel needs ==, not `is`
    )
    rows = s.exec(stmt).all()
    if not rows:
        return GenerateResult()

    # v0.2 multi-impl pre-load: batch-fetch every per-scope implementation
    # for the NC assessments so the cluster loop can fan out per scope_label
    # without N+1 queries. Empty list for a parent assessment ID = pre-v0.2
    # single-impl row; cluster key falls back to bare base_control_id.
    nc_assessment_ids = [a.id for a, _, _ in rows if a.id is not None]
    impls_by_assessment: dict[int, list[AssessmentImplementation]] = defaultdict(list)
    if nc_assessment_ids:
        for impl in s.exec(
            select(AssessmentImplementation).where(
                AssessmentImplementation.assessment_id.in_(nc_assessment_ids)  # type: ignore[attr-defined]
            )
        ).all():
            impls_by_assessment[impl.assessment_id].append(impl)

    # 2. Cluster by (base control id, scope_label). When a parent NC
    # assessment has per-scope impls, fan out one cluster entry per NC impl
    # so AWS-side and Azure-side findings remediate independently — a 3PAO
    # reading the POAM workbook can close one platform without waiting on
    # the other. Compliant/NA impls under a NC parent are skipped (those
    # scopes don't have a finding to track). Parents with no impl rows fall
    # back to the legacy single-cluster shape so pre-v0.2 POAMs keep their
    # existing control_cluster keys and round-trip cleanly through
    # ``existing_poams_by_cluster`` for idempotence.
    clusters: dict[str, list[tuple[Assessment, Objective, Control]]] = defaultdict(list)
    cluster_scope_label: dict[str, str | None] = {}
    for a, o, c in rows:
        base = base_control_id(c.control_id)
        impls = impls_by_assessment.get(a.id, []) if a.id is not None else []
        nc_impls = [
            i for i in impls if i.status == ComplianceStatus.NON_COMPLIANT
        ]
        if nc_impls:
            for impl in nc_impls:
                key = _encode_cluster_key(base, impl.scope_label)
                clusters[key].append((a, o, c))
                cluster_scope_label[key] = impl.scope_label
        else:
            key = _encode_cluster_key(base, None)
            clusters[key].append((a, o, c))
            cluster_scope_label.setdefault(key, None)

    # 3. Index existing POAMs by cluster id so we can either skip-or-rewrite
    # rather than blindly skipping. Rewrite-in-place lets the descriptions
    # benefit from new evidence (scan ingest, host inventory, narrative
    # edits on the source assessment) on each /generate run without
    # clobbering manual narrative edits — the narrative_locked flag is
    # set by the POAM PATCH endpoint the first time the assessor saves a
    # vulnerability_description from the UI.
    existing_poams_by_cluster: dict[str, Poam] = {
        p.control_cluster: p
        for p in s.exec(select(Poam).where(Poam.workbook_id == workbook_id)).all()
    }

    result = GenerateResult()
    for cluster_id, all_items in sorted(clusters.items()):
        # Per-item CRM filter. Provider / inherited / not_applicable get
        # dropped entirely — those are CSP-owned or out-of-boundary, no
        # POAM warranted. Hybrid items stay in the cluster but are
        # tracked separately so the narrative can cite the CRM row.
        items: list[tuple[Assessment, Objective, Control]] = []
        hybrid_entries: list[CrmEntry] = []
        seen_hybrid_controls: set[str] = set()
        for a, o, c in all_items:
            entry = _resolve_crm_entry(c.control_id, crm)
            if entry is not None and entry.responsibility in _CRM_SKIP_RESPONSIBILITIES:
                continue
            if entry is not None and entry.responsibility == "hybrid":
                if entry.control_id not in seen_hybrid_controls:
                    seen_hybrid_controls.add(entry.control_id)
                    hybrid_entries.append(entry)
            items.append((a, o, c))

        # Whole cluster was CSP-owned / inherited → nothing to remediate
        # locally. Skip silently; the next assess run will reconcile the
        # NC findings to COMPLIANT/NA via the kernel short-circuit.
        if not items:
            continue

        control_ids = sorted({c.control_id for _, _, c in items})

        # Pre-fetch corroborating STIG findings once per cluster — both the
        # narrative builder (top-5 render) and the milestone seeder (top-3
        # rule milestones + severity-derived completion date) consume it.
        # Compute even on the rewrite path so narrative refreshes stay in
        # sync with newly-tagged evidence, but only use it for milestones
        # on the brand-new POAM path (rewrite leaves milestones alone).
        objective_ids_for_cluster = [
            o.id for _, o, _ in items if o.id is not None
        ]
        cci_ids_in_cluster = {o.objective_id for _, o, _ in items}
        cluster_stig_findings = _collect_stig_findings_for_cluster(
            objective_ids_for_cluster, cci_ids_in_cluster, s
        )

        # Build the enriched, sectioned narrative. Shared by new POAM
        # creation and the rewrite-existing-draft path so both surfaces
        # always emit the same text for the same cluster + evidence state.
        cite_pairs = _collect_cite_refresh_pairs(items)
        cite_generic = _has_generic_cite_refresh(items)
        vuln = _build_vuln_description(
            items=items,
            cluster_id=cluster_id,
            hybrid_entries=hybrid_entries,
            cite_pairs=cite_pairs,
            cite_generic=cite_generic,
            s=s,
            stig_findings=cluster_stig_findings,
        )

        # Mitigations (verbatim STIG fix text, grounded) and Resources required
        # (labeled starting estimate). Computed once here so the create path and
        # the rewrite-in-place backfill below share identical text for the same
        # cluster + evidence state — the same invariant the narrative holds.
        mitigations_text = _build_mitigations_text(
            cluster_id, cluster_stig_findings, items
        )
        resources_text = _build_resources_required_text(cluster_id)

        existing = existing_poams_by_cluster.get(cluster_id)
        if existing is not None:
            # Rewrite-in-place gate: only when the row is still DRAFT and
            # the narrative hasn't been manually owned by the assessor.
            # ONGOING/COMPLETED/RISK_ACCEPTED POAMs are off-limits — their
            # text is part of the workflow record and rewriting it would
            # invalidate audit trail.
            if existing.status != PoamStatus.DRAFT:
                result.non_draft_skipped.append(existing)
            elif existing.narrative_locked:
                result.locked_skipped.append(existing)
            else:
                # Backfill blank Mitigations / Resources without clobbering
                # assessor edits: only fill when the field is empty. A
                # previously-generated POAM (pre-fix) has these as NULL/blank,
                # so this populates them on the next generate pass; a POAM the
                # assessor has already written into keeps its text. Tracked
                # alongside the vuln refresh so any change marks the row
                # "rewritten" (not "unchanged").
                changed = False
                if existing.vulnerability_description != vuln:
                    existing.vulnerability_description = vuln
                    changed = True
                if not (existing.mitigations or "").strip():
                    existing.mitigations = mitigations_text
                    changed = True
                if not (existing.resources_required or "").strip():
                    existing.resources_required = resources_text
                    changed = True
                if changed:
                    existing.updated_at = datetime.now(timezone.utc)
                    s.add(existing)
                    result.rewritten.append(existing)
                else:
                    result.unchanged.append(existing)
            continue

        # ── Severity-aware completion date (unchanged) ────────────────────
        # Highest-severity STIG finding in the cluster picks the DISA
        # horizon (CAT-I=30d / CAT-II=90d / CAT-III=365d). No findings →
        # fall back to the cluster RiskLevel (Moderate default → 90d,
        # matching the old behavior). We compute it against the eventual
        # raw_severity below; ``_derive_remediation_severity`` takes a
        # RiskLevel fallback that's only consulted when STIG findings are
        # absent, so passing DEFAULT_LIKELIHOOD × DEFAULT_IMPACT here is
        # safe — it never overrides a real STIG severity.
        severity_key = _derive_remediation_severity(
            cluster_stig_findings, compute_risk(DEFAULT_LIKELIHOOD, DEFAULT_IMPACT)
        )
        completion = _remediation_completion_date(severity_key)

        # ── Risk seeding (alembic 0008 provenance) ────────────────────────
        # ``impact`` seeds from the highest-severity contributing STIG
        # finding when one exists (CAT I → HIGH, CAT II → MODERATE,
        # CAT III → LOW), badged source="auto". When no STIG finding
        # grounds it, impact AND likelihood fall back to the documented
        # MODERATE baseline default, badged source="default" — a POAM must
        # carry risk information for the assessor and eMASS export, and the
        # "default" badge keeps the provenance honest (it is plainly an
        # un-owned starting value, not a STIG-derived call, so it does not
        # masquerade as evidence per feedback_precision_over_recall). The
        # matrix computes ``raw_severity`` from these for the UI list-sort.
        # Locate the top contributing STIG finding (highest severity) for
        # provenance. Gate seeding on the PRESENCE OF A REAL FINDING — the
        # ``severity_key`` fallback above intentionally returns "medium"
        # when no findings exist so the horizon math still works, but that
        # fallback must NOT propagate into ``impact_source = "auto"`` (an
        # "auto" badge with no STIG citation behind it is exactly the
        # kind of unjustified default ``feedback_precision_over_recall``
        # forbids — and exactly what a 3PAO would flag at audit).
        top_finding_rule_id: str | None = None
        top_finding_severity: str | None = None
        for finding, _label in cluster_stig_findings:
            sev = (finding.severity or "").strip().lower()
            if sev in {"high", "medium", "low"}:
                top_finding_rule_id = finding.rule_id
                top_finding_severity = sev
                break

        if top_finding_severity is not None:
            seeded_impact = seed_impact_from_stig(top_finding_severity)
        else:
            seeded_impact = None

        # The visible ``*_rationale`` columns drive the POAM detail "why"
        # fields. For un-owned baseline defaults those columns are left NULL:
        # a "Baseline default (MODERATE) pending review" sentence on every
        # field was noise the assessor explicitly didn't want — the source
        # badge ("default") already says it's un-owned. We keep a substantive
        # rationale visible ONLY when it carries real signal (STIG-grounded
        # "auto" impact). The descriptive literal still flows to the
        # PoamRiskHistory audit row (``*_audit_rationale``) so the 3PAO
        # "where did this value come from?" trail stays intact.
        if seeded_impact is not None:
            impact: RiskLevel | None = seeded_impact
            impact_source: str | None = "auto"
            impact_rationale: str | None = (
                f"Seeded from highest-severity contributing finding "
                f"({top_finding_rule_id}, severity={top_finding_severity})"
            )
            impact_audit_rationale = impact_rationale
        else:
            # No STIG finding to ground impact — seed the documented baseline
            # default (MODERATE), badge source="default", but leave the
            # visible rationale NULL (the badge says enough; the literal lives
            # only in the audit trail).
            impact = DEFAULT_IMPACT
            impact_source = "default"
            impact_rationale = None
            impact_audit_rationale = (
                "Baseline default (MODERATE) pending assessor review — "
                "no STIG CAT severity available to ground this value."
            )

        # Likelihood has no STIG/CVSS/KEV signal to derive from, so it always
        # takes the baseline default. Badge source="default"; visible rationale
        # NULL; descriptive literal preserved in the audit trail only.
        likelihood: RiskLevel | None = DEFAULT_LIKELIHOOD
        likelihood_source: str | None = "default"
        likelihood_rationale: str | None = None
        likelihood_audit_rationale = (
            "Baseline default (MODERATE) pending assessor review — "
            "no CVSS/CVE/KEV/EPSS signal available to ground this value."
        )

        raw = compute_risk(
            likelihood or DEFAULT_LIKELIHOOD,
            impact or DEFAULT_IMPACT,
        )

        poam = Poam(
            workbook_id=workbook_id,
            control_cluster=cluster_id,
            vulnerability_description=vuln,
            security_control_number=_format_security_control_number(set(control_ids)),
            status=PoamStatus.DRAFT,
            scheduled_completion_date=completion,
            mitigations=mitigations_text,
            resources_required=resources_text,
            likelihood=likelihood,
            impact=impact,
            raw_severity=raw,
            residual_risk=raw,
            likelihood_source=likelihood_source,
            likelihood_rationale=likelihood_rationale,
            impact_source=impact_source,
            impact_rationale=impact_rationale,
            # residual_risk starts unowned — it equals raw_severity until the
            # assessor (or the LLM advisor) revises it. Leaving source NULL
            # tells the UI not to show a badge so the assessor knows this is
            # still the raw computation, not a deliberate residual call.
            residual_risk_source=None,
            residual_risk_rationale=None,
        )
        s.add(poam)
        s.flush()  # populate poam.id for FK use below

        # Audit trail for every seeded field so the 3PAO question "where
        # did this HIGH come from?" has an answer even on an unedited POAM.
        # likelihood + impact are now always seeded (STIG-grounded "auto"
        # or baseline "default"), so both always get a row.
        if likelihood is not None:
            record_risk_change(
                s,
                poam_id=poam.id,
                field="likelihood",
                prev_value=None,
                new_value=likelihood,
                actor="system:generator",
                new_rationale=likelihood_audit_rationale,
                new_source=likelihood_source,
            )
        if impact is not None:
            record_risk_change(
                s,
                poam_id=poam.id,
                field="impact",
                prev_value=None,
                new_value=impact,
                actor="system:generator",
                new_rationale=impact_audit_rationale,
                new_source=impact_source,
            )
        record_risk_change(
            s,
            poam_id=poam.id,
            field="raw_severity",
            prev_value=None,
            new_value=raw,
            actor="system:generator",
            new_rationale=(
                "Computed from "
                f"likelihood={likelihood.value if likelihood else 'DEFAULT_MODERATE'} × "
                f"impact={impact.value if impact else 'DEFAULT_MODERATE'} via 800-30r1 Table I-2"
            ),
            new_source="auto",
        )
        record_risk_change(
            s,
            poam_id=poam.id,
            field="residual_risk",
            prev_value=None,
            new_value=raw,
            actor="system:generator",
            new_rationale=(
                "Initialized to raw_severity pending assessor or residual-advisor review"
            ),
            new_source=None,
        )

        for a, o, _ in items:
            s.add(
                PoamObjective(
                    poam_id=poam.id,
                    objective_id=o.id,
                    status_at_creation=a.status,
                )
            )

        # Seed milestones — always the generic one (eMASS requires ≥1) plus a
        # per-rule milestone for up to the top 3 corroborating STIG findings.
        # Only on POAM creation: the rewrite-in-place branch above intentionally
        # leaves milestones alone so assessor edits via the UI survive.
        for ms in _seed_milestones(
            poam.id, cluster_id, cluster_stig_findings, completion, items=items
        ):
            s.add(ms)

        result.created.append(poam)

    return result
