"""Deterministic system-boundary brief woven into the assessment prompt.

This is the load-bearing half of the boundary-context guarantee: every
control narrative the assessor produces MUST carry the system boundary as
a first-class part of the verdict story, not a bolt-on. The kernel cannot
write a boundary-situated narrative if it never sees the boundary, so the
route layer builds this brief once per assess request and threads it into
the LLM user message (after the corrective-context block, before the row)
and into the decision-cache fingerprint.

Two responsibilities, one brief
-------------------------------
1. **Locate the verdict.** Name the authorization boundary, the technology
   inventory, the operators, and the declared requirements so a 3PAO/JAB
   reviewer can see exactly *which* system the evidence and verdict apply
   to. In a multi-boundary program (a cloud CSP slice + an on-prem slice)
   an unsituated narrative is ambiguous about what was assessed and can
   misattribute evidence across boundaries.

2. **Find the gaps at the responsibility seam.** A cloud (CSP) scope
   covers only what the provider operates up to the edge of its offering;
   the on-prem scope covers everything the customer deploys, configures,
   and operates above that line. The brief tells the kernel *where cloud
   responsibility ends and customer responsibility begins* and instructs
   it to derive the customer-side gaps that live at that seam — a control
   the CSP only partially satisfies that still requires customer action on
   the on-prem footprint to be fully met. This is the responsibility-split
   reasoning the per-control CRM ``responsibility`` / ``responsibility_onprem``
   fields encode at the row level, lifted to the system level so the
   narrative reasons about the demarcation explicitly rather than treating
   "customer" vs "provider" as an opaque label.

Pure formatter + route loader
------------------------------
:func:`format_boundary_brief` is pure (no DB, no I/O) and unit-testable in
isolation. :func:`build_boundary_brief` is the session-aware route helper
that loads the per-workbook :class:`SystemContext` and renders the brief —
mirroring ``build_crm_context(workbook_id, session)`` so the kernel stays
session-free past the parameter boundary.

Returns ``None`` (not an empty string) when there is no boundary signal at
all, so the prompt builder can cleanly omit the ``## System boundary``
block. Per the overlay-default-local rule, the absence of a boundary brief
does not weaken the assessment — the kernel still runs the full LLM path on
the located evidence; it just cannot prefix a boundary it was never given.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlmodel import Session, select

from ..baselines.scope_labels import ON_PREM_LABEL, is_on_prem
from ..models import SystemContext


def _clean(value: str | None) -> str:
    """Trim surrounding whitespace; treat blank-only prose as absent."""
    if value is None:
        return ""
    return value.strip()


def _dedupe_preserve_order(labels: Sequence[str]) -> list[str]:
    """De-dupe scope labels case-insensitively, preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in labels:
        label = (raw or "").strip()
        if not label:
            continue
        key = label.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(label)
    return out


def _render_responsibility_demarcation(scope_labels: Sequence[str]) -> str | None:
    """Render the cloud/on-prem responsibility-seam instruction.

    Returns ``None`` when there is no cloud scope to demarcate against —
    a single on-prem-only system has no CSP seam, so emitting the
    boilerplate would only dilute the prompt. When at least one cloud
    scope is present (alongside or without an explicit on-prem slice),
    name the scopes concretely so the kernel reasons about the actual
    platforms, not a generic "cloud vs on-prem".
    """
    labels = _dedupe_preserve_order(scope_labels)
    if not labels:
        return None

    cloud = [lbl for lbl in labels if not is_on_prem(lbl)]
    if not cloud:
        # On-prem-only (or only the synthesized on-prem slice). No CSP
        # boundary to reason about — the whole system is customer-owned,
        # which the overlay-default-local path already assumes.
        return None

    has_onprem = any(is_on_prem(lbl) for lbl in labels)
    cloud_str = ", ".join(cloud)

    lines = [
        "Responsibility demarcation (assess the gaps at this seam):",
        (
            f"- Cloud (CSP) scope(s): {cloud_str}. The provider is "
            "responsible ONLY up to the edge of its service offering — the "
            "infrastructure, platform, and inherited controls it operates "
            "and attests to."
        ),
        (
            f"- {ON_PREM_LABEL} scope: everything the customer deploys, "
            "configures, and operates ABOVE that line — the residual "
            "implementation the CSP does not cover."
        )
        if has_onprem
        else (
            f"- {ON_PREM_LABEL} scope (residual): everything the customer "
            "deploys, configures, and operates above the CSP line, even "
            "though no separate on-prem implementation was declared."
        ),
        (
            "For each control, determine WHERE cloud-provider responsibility "
            "ends and customer/on-prem responsibility begins. Assess the "
            "customer-side implementation against the located evidence, and "
            "report any gap that arises at this seam — a control the CSP only "
            "partially satisfies that still requires customer action on the "
            f"on-prem footprint to be fully met — as a finding scoped to the "
            f"{ON_PREM_LABEL} slice. Do NOT mark a control compliant on the "
            "strength of CSP-inherited coverage alone when customer-side work "
            "remains."
        ),
    ]
    return "\n".join(lines)


def format_boundary_brief(
    *,
    boundary: str | None,
    stakeholders: str | None,
    tech_inventory: str | None,
    requirement_hints: str | None,
    scope_labels: Sequence[str] = (),
) -> str | None:
    """Render the deterministic boundary brief, or ``None`` if no signal.

    Pure — no DB, no I/O. The route loader :func:`build_boundary_brief`
    supplies the field values from the per-workbook :class:`SystemContext`
    and the CRM-derived ``scope_labels``.

    The brief is intentionally instruction-bearing, not just descriptive:
    it tells the kernel to situate the verdict in the boundary AND to
    derive the customer-side gaps at the cloud/on-prem responsibility seam
    (see module docstring). The ``## System boundary`` header is added by
    the prompt builder, not here, so this string can also be embedded in
    other surfaces (audit panel, brief preview) without a stray header.
    """
    boundary_t = _clean(boundary)
    stakeholders_t = _clean(stakeholders)
    tech_t = _clean(tech_inventory)
    requirements_t = _clean(requirement_hints)
    demarcation = _render_responsibility_demarcation(scope_labels)

    # Nothing to say → no block. The prompt builder omits the section.
    if not any(
        [boundary_t, stakeholders_t, tech_t, requirements_t, demarcation]
    ):
        return None

    sections: list[str] = [
        "This assessment applies to the authorization boundary described "
        "below. Situate every verdict and narrative in this boundary and "
        "name it explicitly so a reviewer can see which system the evidence "
        "and verdict apply to. When responsibility is split across scopes, "
        "write a narrative per scope."
    ]

    if boundary_t:
        sections.append(f"Authorization boundary:\n{boundary_t}")
    if tech_t:
        sections.append(f"Technology inventory:\n{tech_t}")
    if stakeholders_t:
        sections.append(f"Stakeholders / operators:\n{stakeholders_t}")
    if requirements_t:
        sections.append(f"Declared requirements / standards:\n{requirements_t}")
    if demarcation:
        sections.append(demarcation)

    return "\n\n".join(sections)


def build_boundary_brief(
    workbook_id: int,
    session: Session,
    *,
    scope_labels: Sequence[str] = (),
) -> str | None:
    """Load the per-workbook :class:`SystemContext` and render its brief.

    Session-aware route helper mirroring ``build_crm_context``: the route
    handler calls this, the kernel consumes the returned opaque string.
    Returns ``None`` when the workbook has no SystemContext row, or when
    that row carries no boundary signal — the prompt then omits the
    ``## System boundary`` block entirely.

    ``scope_labels`` is the list of CRM scope labels attached to the
    workbook (typically derived from the already-built
    :class:`CrmContext`). Passing them lets the brief name the concrete
    cloud platforms at the responsibility seam instead of a generic
    "cloud vs on-prem". The on-prem slice is synthesized by the CRM layer,
    so it may already be present in the list.
    """
    ctx = session.exec(
        select(SystemContext).where(SystemContext.workbook_id == workbook_id)
    ).first()
    if ctx is None:
        # No per-workbook context. Still emit the responsibility seam if
        # CRM scope labels exist, so multi-boundary programs without a
        # written boundary doc keep their cloud/on-prem gap reasoning.
        return format_boundary_brief(
            boundary=None,
            stakeholders=None,
            tech_inventory=None,
            requirement_hints=None,
            scope_labels=scope_labels,
        )

    return format_boundary_brief(
        boundary=ctx.boundary,
        stakeholders=ctx.stakeholders,
        tech_inventory=ctx.tech_inventory,
        requirement_hints=ctx.requirement_hints,
        scope_labels=scope_labels,
    )
