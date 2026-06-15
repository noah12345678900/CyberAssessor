"""ODP placeholder resolution at *render time*.

This module exists because :class:`~cybersecurity_assessor.models.Control`
statements are stored as templates — never str.replace'd at ingest. The
three principles in ``memory/project_odp_architecture.md`` require it:

  1. Templates stay templates. The statement column never carries
     program-specific values.
  2. Provenance over inference. Multiple overlays (workbook, CRM,
     SSP-doc) can coexist for the same ODP; the row's ``assigned_from``
     identifies which one applies. No "stricter wins" algorithm.
  3. Cross-framework crosswalks are a JOIN through
     :class:`~cybersecurity_assessor.models.FrameworkEquivalence`,
     not an in-code translation function.

Three placeholder syntaxes are recognized in the same template:

  * Rev 4: ``{$N$}`` — eMASS CCIS workbook ODP IDs (Rev 4 catalogs).
  * Rev 5: ``ac-XX_odp.NN`` (and similar) — OSCAL/NIST 800-53 Rev 5
    bare-token form.
  * OSCAL wrapper: ``{{ insert: param, ac-2_prm_1 }}`` — the canonical
    OSCAL prose form, present in both Rev 4 and Rev 5 catalog JSONs.
    Resolved by a *two-tier* lookup:

      1. Fast path: the ``oscal_param_id`` bridge column on
         :class:`OdpAssignment`, populated at workbook ingest by
         positional alignment against the catalog's then-current
         statement. O(1).
      2. Catalog-agnostic re-bridge: when (1) misses, fall back to
         :class:`OdpAssignment.slot_index` (the row's invariant slot
         position in the originating workbook). The render layer
         re-extracts OSCAL param ids from the *current* template,
         looks up ``oscal_params[slot_index]``, and substitutes — but
         only when total slot count matches total param count. This
         is what makes the bridge survive catalog reloads, FedRAMP
         shadow synthesis, and Rev 4↔Rev 5 naming-convention swaps
         within the same revision family.

    When both tiers miss (e.g. Rev 4 workbook against Rev 5 catalog —
    genuine cross-revision mismatch), the placeholder is left in place
    and the bare OSCAL id is returned in ``unresolved``. That genuine
    cross-revision case is what v0.3's :class:`FrameworkEquivalence`
    cures by JOIN, not by inference.

Render policy when multiple :class:`OdpAssignment` rows match the same
``(framework_version, control_id, odp_id)`` (rare — happens when a
workbook stacks overlays in v0.1, common in v0.2 once CRM rows land):
the most recent ``ingested_at`` wins. Deterministic, no precedence
inference. The user's mental model (see plan notes): CRMs slot
different controls than program-specific ones, so within v0.1 a single
program workbook is unlikely to produce duplicates.

Never mutates ``Control.statement``. Operates on the template string
passed in and returns ``(rendered_text, unresolved_odp_ids)``.
"""

from __future__ import annotations

import re
from typing import Literal

from sqlmodel import Session, select

from ..models import OdpAssignment, OdpAuditLog

# Output formats for highlighting substituted values. Default keeps the
# raw value (back-compat with the v0.1 render path and the existing test
# suite). "markdown" wraps in ``**...**`` for the UI (ControlDetail.tsx
# parses this into <strong>). "html" wraps in ``<b>...</b>`` for the SAR
# DOCX path (ReportLab Paragraph interprets the tag). Only RESOLVED
# values get wrapped — unresolved placeholders stay verbatim so the
# existing unresolved-odps badge still fires.
BoldFormat = Literal["markdown", "html"]

# Combined tokenizer for all three placeholder syntaxes. The Rev 4
# form is the eMASS CCIS literal ``{$37$}`` (always digits between
# braces and dollar signs). The Rev 5 bare form is OSCAL's
# ``<family>-<number>_odp[.NN]`` — the trailing ``.NN`` is optional
# because some controls expose a single unnamed ODP. The OSCAL wrapper
# form is ``{{ insert: param, <id> }}`` and is what the catalog actually
# ships in ``Control.statement`` (both Rev 4 and Rev 5). We keep all
# three patterns in one regex so a single pass covers mixed templates
# (FedRAMP profiles overlay a Rev 4 base; Rev 5 statements mix bare and
# wrapped forms).
#
# Group order matters: ``oscal`` is FIRST so the wrapper form wins over
# the bare ``rev5`` form when both could match (e.g. the bare id sitting
# inside the wrapper). Capturing groups: ``oscal_id`` is the param id
# inside the wrapper, used as the OSCAL bridge lookup key.
_ODP_PATTERN = re.compile(
    r"(?P<oscal>\{\{\s*insert\s*:\s*param\s*,\s*(?P<oscal_id>[a-z0-9_().\-]+?)\s*\}\})"  # {{ insert: param, ac-2_prm_1 }}
    r"|"
    r"(?P<rev4>\{\$\d+\$\})"  # {$37$}
    r"|"
    r"(?P<rev5>[a-z]{2}-\d{1,2}(?:\(\d+\))?_odp(?:\.\d+)?)",  # ac-02_odp.03
    re.IGNORECASE,
)

# Param-id extractor for the catalog-agnostic re-bridge fallback. Mirrors
# the regex used by ``ccis_workbook._extract_oscal_param_ids`` at ingest
# so the two ends of the bridge agree on what "first occurrence" means.
# Kept private here (instead of importing the ingest helper) so the
# render layer has no cross-package dependency on baselines/ — keeps the
# import graph one-way: routes → controls → models.
_OSCAL_PARAM_REF_RE = re.compile(
    r"\{\{\s*insert\s*:\s*param\s*,\s*([a-z0-9_().\-]+?)\s*\}\}",
    re.IGNORECASE,
)


def _extract_template_oscal_param_ids(template: str) -> list[str]:
    """First-occurrence OSCAL param ids from a control statement template.

    Used at render time to re-derive the OSCAL bridge when the cached
    ``oscal_param_id`` column is NULL or stale (e.g. after a catalog
    reload renamed the params). Dedupes so a param referenced twice
    doesn't shift positions — matches ingest-side semantics exactly.
    """
    seen: set[str] = set()
    out: list[str] = []
    for m in _OSCAL_PARAM_REF_RE.finditer(template):
        pid = m.group(1)
        if pid not in seen:
            seen.add(pid)
            out.append(pid)
    return out


def _pick_assignment(rows: list[OdpAssignment]) -> OdpAssignment:
    """Most-recent-wins. Deterministic, no precedence inference.

    ``ingested_at`` is monotonic per ingest, and SQLite-naive datetimes
    round-trip as comparable; falling back to the row's PK string when
    ``ingested_at`` ties keeps the sort total.
    """
    return max(
        rows,
        key=lambda r: (r.ingested_at, r.assigned_from),
    )


def resolve_odps(
    session: Session,
    framework_version: str,
    control_id: str,
    template: str,
    bold_format: BoldFormat | None = None,
) -> tuple[str, list[str]]:
    """Substitute ODP placeholders in ``template`` with stored values.

    Parameters
    ----------
    session:
        Active SQLModel session. The function issues a single
        ``SELECT`` on the ``odp_assignment`` table per call.
    framework_version:
        Canonical ``Framework.framework_id`` string the ODP was
        ingested under (e.g. ``"NIST-800-53r4"``). Cross-framework
        rendering will land in v0.3 via an optional
        ``target_framework_version`` parameter that JOINs through
        :class:`FrameworkEquivalence`; v0.1 uses the source framework
        directly.
    control_id:
        Control identifier as stored on :class:`OdpAssignment`
        (e.g. ``"AC-2"`` or ``"AC-2(1)"``). Casing must match the
        ingest path; the CCIS workbook normalizes to upper case.
    template:
        The control statement (or any text) containing one or more
        ODP placeholders.

    Returns
    -------
    (rendered, unresolved):
        ``rendered`` is ``template`` with every recognized placeholder
        replaced by its stored value when a row exists. Placeholders
        with no matching row are left in place verbatim so the UI can
        badge them.
        ``unresolved`` is the deduplicated list of ``odp_id`` strings
        that had no stored value (preserving the order they first
        appeared in the template).
    """
    if not template:
        return template, []

    # Cheap pre-check: skip the query when no placeholder is present.
    matches = list(_ODP_PATTERN.finditer(template))
    if not matches:
        return template, []

    # Single round-trip: pull every ODP for this (framework, control).
    # The ``ix_odpassignment_fw_control`` index covers this access path.
    all_rows = session.exec(
        select(OdpAssignment).where(
            OdpAssignment.framework_version == framework_version,
            OdpAssignment.control_id == control_id,
        )
    ).all()

    # Group by odp_id for {$N$}/bare-Rev5 lookup, AND by oscal_param_id
    # for the OSCAL wrapper lookup. Both views built from one query.
    # Same odp_id may have multiple ``assigned_from`` rows;
    # _pick_assignment collapses to one deterministically. ``by_slot``
    # indexes the catalog-agnostic re-bridge fallback (see below).
    by_odp: dict[str, list[OdpAssignment]] = {}
    by_oscal: dict[str, list[OdpAssignment]] = {}
    by_slot: dict[int, list[OdpAssignment]] = {}
    # Authoritative declared slot count for this control, taken from the
    # ingest-time stamp on any row (all rows for the same control share
    # the value — see ccis_workbook.py Step 6). We use this instead of
    # ``len(by_slot)`` so a SPARSE workbook (declared 4 slots but only
    # filled 2) doesn't mis-reject the positional fallback against the
    # catalog's 4 params. NULL when no row had a declared slot list at
    # ingest time (then the count check abstains, same as before).
    workbook_slot_total: int | None = None
    for row in all_rows:
        by_odp.setdefault(row.odp_id, []).append(row)
        if row.oscal_param_id:
            by_oscal.setdefault(row.oscal_param_id, []).append(row)
        if row.slot_index is not None:
            by_slot.setdefault(row.slot_index, []).append(row)
        if workbook_slot_total is None and row.slot_total is not None:
            workbook_slot_total = row.slot_total

    # Re-derive the OSCAL param order from the CURRENT template once per
    # call. The ingest-time cache (``oscal_param_id``) was computed
    # against whatever the catalog said at workbook-load time; the
    # catalog may have been reloaded or replaced since (Rev 4 → Rev 5
    # swap, FedRAMP profile re-synthesis, manual reload). Recomputing
    # here keeps render correct even when the cache is stale. Lazy — we
    # only need ``template_oscal_params`` if a wrapper lookup misses on
    # the fast path; computing it once up front is cheap (single regex
    # scan, same template we're already iterating) and avoids per-match
    # recomputation.
    template_oscal_params: list[str] | None = None

    unresolved: list[str] = []
    unresolved_seen: set[str] = set()

    def _record_unresolved(token: str) -> None:
        if token not in unresolved_seen:
            unresolved_seen.add(token)
            unresolved.append(token)

    def _emit(value: str) -> str:
        """Wrap a resolved value per ``bold_format``. No-op when off."""
        if bold_format == "markdown":
            return f"**{value}**"
        if bold_format == "html":
            return f"<b>{value}</b>"
        return value

    def _substitute(match: re.Match[str]) -> str:
        # OSCAL wrapper {{ insert: param, X }} — look up via the bridge
        # column populated at ingest. The bare param id is the unresolved
        # token (not the whole wrapper) so the UI badge is concise and
        # matches what the assessor sees in the workbook trace.
        nonlocal template_oscal_params
        oscal_id = match.group("oscal_id") if match.group("oscal") else None
        if oscal_id:
            rows = by_oscal.get(oscal_id)
            if not rows:
                # Case-insensitive fallback — OSCAL param ids are lower
                # case in the catalog but workbook ingest paths could
                # vary across overlays.
                for stored_id, stored_rows in by_oscal.items():
                    if stored_id.lower() == oscal_id.lower():
                        rows = stored_rows
                        break
            if rows:
                picked = _pick_assignment(rows)
                # Empty value = slot exists in the workbook but the
                # program hasn't assigned a value yet. Treat as unresolved
                # so the placeholder stays visible (don't silently render
                # "Requires approvals by  for..."). The slot identity is
                # what made positional alignment possible at ingest — see
                # ccis_workbook.py Step 6b.
                if picked.value:
                    return _emit(picked.value)
                _record_unresolved(oscal_id)
                return match.group(0)

            # Cache miss on ``oscal_param_id``. Try the catalog-agnostic
            # re-bridge via slot_index. This catches three real-world
            # cases the at-ingest cache cannot cover:
            #
            #   1. Catalog was reloaded after ingest and the OSCAL
            #      ``Control.statement`` was rewritten (oscal_loader.py
            #      line ~286 overwrites in place). The cached param ids
            #      are now stale strings; the slot positions still hold.
            #   2. FedRAMP shadow Controls embed the parent's verbatim
            #      statement via synthesize_statement() — when the parent
            #      catalog is reloaded the shadow regenerates with the
            #      new param ids while ingested rows still point at the
            #      old ones.
            #   3. Workbook was ingested before this column existed
            #      (v0.1 → v0.x upgrade) — slot_index was backfilled on
            #      the next re-ingest, oscal_param_id may still be NULL.
            #
            # We re-extract the CURRENT template's param order and look
            # up by position. Count-match guard: if the workbook DECLARED
            # N slots but the catalog now declares M params, positional
            # alignment is unsafe and we abstain (same rule as ingest-side
            # Step 6b). That genuine cross-revision case is what v0.3's
            # FrameworkEquivalence cures.
            #
            # Uses ``workbook_slot_total`` (the declared count stamped at
            # ingest) rather than ``len(by_slot)`` (the FILLED count). A
            # workbook that declared 4 slots but only filled 2 has
            # ``len(by_slot)==2`` yet the catalog still has 4 params — the
            # bridge is sound, the two filled values still land on the
            # right positions, the other two stay unresolved. The DB-level
            # filter on ``framework_version`` (the SELECT above) already
            # bounds this to the right revision family — no separate
            # framework_version check is needed in the fallback.
            if by_slot and workbook_slot_total is not None:
                if template_oscal_params is None:
                    template_oscal_params = _extract_template_oscal_param_ids(template)
                if (
                    template_oscal_params
                    and len(template_oscal_params) == workbook_slot_total
                    and oscal_id in template_oscal_params
                ):
                    target_slot = template_oscal_params.index(oscal_id)
                    fallback_rows = by_slot.get(target_slot)
                    if fallback_rows:
                        picked = _pick_assignment(fallback_rows)
                        if picked.value:
                            return _emit(picked.value)
            _record_unresolved(oscal_id)
            return match.group(0)

        # Bare Rev 4 ({$N$}) or Rev 5 (ac-XX_odp.NN) token.
        token = match.group(0)
        rows = by_odp.get(token)
        if rows:
            picked = _pick_assignment(rows)
            if picked.value:
                return _emit(picked.value)
            _record_unresolved(token)
            return token
        # Case-insensitive fallback for Rev 5 (workbook may store lower
        # case while template carries the canonical OSCAL casing).
        for stored_id, stored_rows in by_odp.items():
            if stored_id.lower() == token.lower():
                picked = _pick_assignment(stored_rows)
                if picked.value:
                    return _emit(picked.value)
                _record_unresolved(token)
                return token
        _record_unresolved(token)
        return token

    rendered = _ODP_PATTERN.sub(_substitute, template)
    return rendered, unresolved


def fetch_odp_history(
    session: Session,
    framework_version: str,
    control_id: str,
) -> list[dict]:
    """Return every :class:`OdpAuditLog` row for one control, grouped per ODP.

    The audit log is written by :func:`ccis_workbook.apply` (and future
    overlay ingests) whenever an existing :class:`OdpAssignment.value`
    changes during re-ingest. Nothing else writes it; nothing else used to
    read it -- this helper is the read surface that the UI Control Detail
    card and the SAR Appendix H share.

    Aggregation rule (locked by user decision, see plan): *all* rows,
    grouped per ``odp_id``. Multi-overlay provenance demands the full
    trace -- when CRM, workbook, and user-edit have all touched the same
    ODP, the assessor must be able to see every step in order, not the
    collapsed latest value. Latest-per-ODP is already visible in the
    rendered statement via :func:`resolve_odps`; this surface complements
    it with history, not a duplicate of the current value.

    Output shape (one entry per ``odp_id`` present in the audit log,
    ordered by ``odp_id`` ascending for stable display; events within
    each group ordered by ``when`` descending so most-recent reads
    first)::

        [
            {
                "odp_id": "{$37$}",
                "events": [
                    {
                        "when": "2026-06-01T14:33:00Z",
                        "who": "CCIS-workbook-ingest:CCIS_Rev_C.xlsx",
                        "assigned_from": "AC-2",
                        "prev_value": "ISSM",
                        "new_value": "ISSM/ISSO",
                    },
                    ...
                ],
            },
            ...
        ]

    Returns an empty list when no audit rows exist (the typical first-
    ingest case). The UI hides its card on empty; the SAR omits its
    appendix on empty -- no "(none)" placeholders, no empty cards.

    Single round-trip on the ``ix_odpauditlog_fw_control_when`` index
    that was added with the table -- the SELECT is on-index by
    construction. In-memory regroup matches the SAR pattern at
    ``_appendix_crm_short_circuits`` (single sort + ``defaultdict``).
    """
    rows = session.exec(
        select(OdpAuditLog).where(
            OdpAuditLog.framework_version == framework_version,
            OdpAuditLog.control_id == control_id,
        )
    ).all()

    if not rows:
        return []

    # Regroup by odp_id. Events within each group are ordered by when
    # descending; build the lists by sorting the whole result set once
    # and relying on a stable group walk so the secondary order falls
    # out for free.
    rows_sorted = sorted(rows, key=lambda r: r.when, reverse=True)

    grouped: dict[str, list[dict]] = {}
    for r in rows_sorted:
        grouped.setdefault(r.odp_id, []).append(
            {
                # ISO 8601 with the explicit ``Z`` suffix so the UI can
                # parse without ambiguity. ``_utcnow`` (models.py) stamps
                # naive UTC; isoformat() omits the tz designator on a
                # naive datetime, so we append ``Z`` ourselves to keep
                # the round-trip lossless.
                "when": r.when.isoformat() + "Z",
                "who": r.who,
                "assigned_from": r.assigned_from,
                "prev_value": r.prev_value,
                "new_value": r.new_value,
            }
        )

    return [
        {"odp_id": odp_id, "events": grouped[odp_id]}
        for odp_id in sorted(grouped.keys())
    ]
