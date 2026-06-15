"""CCIS workbook → Baseline adapter.

The DoD eMASS CCIS .xlsx is *both* a catalog enrichment source (it
carries CCI definitions, implementation guidance, and assessment
procedures that OSCAL does not publish) and a baseline source (column A
"Required for assessment?" tells you which CCIs apply to *this* system).

This adapter does both in one ``apply()`` so opening a workbook is a
single round-trip:

  1. Parse the workbook (read-only, openpyxl).
  2. Upsert ``Objective`` rows from CCI cells — calls the existing
     ``populate_objectives`` helper unchanged.
  3. Upsert one ``Baseline`` per workbook path.
  4. Upsert one ``BaselineControl`` per Control/Enhancement referenced
     by the workbook. **A control is in-scope iff *any* of its CCIs are
     marked required in column A** — the tailoring decision is per
     control, not per CCI.
  5. Upsert one ``BaselineObjective`` per CCI row for source_row
     tracking only (no in_scope on the row anymore).

Re-running ``apply`` on the same workbook is idempotent: the Baseline
row is found by ``(source_type, source_ref)``, BaselineControls by
``(baseline_id, control_id)``, BaselineObjectives by
``(baseline_id, objective_id)``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from sqlmodel import Session, select

# OSCAL parameter reference in Control.statement prose. Matches both
# Rev 4 ("ac-2_prm_1") and Rev 5 ("ac-02_odp.01") param ids. We capture
# the bare id so the bridge column stores the same string the render
# layer will look up. First-occurrence order is preserved by walking the
# statement with finditer + a dedup set — that order is the OSCAL
# canonical param order for the control, which is what we need to zip
# positionally against the workbook's eMASS ODPs.
_OSCAL_PARAM_REF_RE = re.compile(
    r"\{\{\s*insert\s*:\s*param\s*,\s*([a-z0-9_().\-]+?)\s*\}\}",
    re.IGNORECASE,
)


def _extract_oscal_param_ids(statement: str | None) -> list[str]:
    """Return OSCAL param ids referenced in a control statement, in first-occurrence order.

    Dedups so a param referenced twice (rare but legal in OSCAL) doesn't
    inflate the count and break positional alignment.
    """
    if not statement:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _OSCAL_PARAM_REF_RE.finditer(statement):
        pid = m.group(1)
        if pid not in seen:
            seen.add(pid)
            out.append(pid)
    return out

from ..excel.ccis_reader import (
    _ccis_to_oscal_control_id,
    populate_objectives,
    read_assignment_values,
    read_workbook_index,
)
from ..models import (
    Baseline,
    BaselineControl,
    BaselineObjective,
    BaselineSourceType,
    Control,
    Framework,
    Objective,
    OdpAssignment,
    OdpAuditLog,
)
from .base import BaselineApplyResult


class CcisWorkbookBaselineSource:
    """Apply a CCIS workbook as both catalog enrichment and baseline."""

    source_type = BaselineSourceType.CCIS_WORKBOOK

    def __init__(
        self,
        workbook_path: str | Path,
        *,
        name: str | None = None,
        system_id: int | None = None,
    ) -> None:
        self.workbook_path = Path(workbook_path)
        self.name = name or self.workbook_path.stem
        self.system_id = system_id

    def apply(self, session: Session, *, framework_id: int) -> BaselineApplyResult:
        framework = session.get(Framework, framework_id)
        if framework is None:
            raise ValueError(f"Framework id={framework_id} does not exist")

        index = read_workbook_index(self.workbook_path)

        # Step 1+2: enrich catalog Objective rows with CCI text from this
        # workbook. Idempotent — returns its own counts which we keep for
        # diagnostics but don't surface in BaselineApplyResult (those are
        # baseline-level, not catalog-level).
        catalog_counts = populate_objectives(
            session, framework_id=framework_id, index=index
        )

        # Step 3: upsert the Baseline row, keyed by (source_type, source_ref).
        source_ref = str(self.workbook_path)
        baseline = session.exec(
            select(Baseline).where(
                Baseline.source_type == self.source_type,
                Baseline.source_ref == source_ref,
            )
        ).first()
        if baseline is None:
            baseline = Baseline(
                framework_id=framework_id,
                system_id=self.system_id,
                name=self.name,
                source_type=self.source_type,
                source_ref=source_ref,
            )
            session.add(baseline)
            session.commit()
            session.refresh(baseline)
        else:
            baseline.framework_id = framework_id  # allow rev re-detection
            if self.system_id is not None:
                baseline.system_id = self.system_id
            baseline.refreshed_at = datetime.now(timezone.utc)
            session.add(baseline)
            session.commit()
            session.refresh(baseline)

        # Step 4+5: upsert BaselineControl + BaselineObjective rows. Need
        # lookups from control_id -> Control.id and (control_id, cci_id)
        # -> Objective.id so we can join workbook rows to the catalog
        # without re-querying inside the loop.
        from ..excel.ccis_reader import _ccis_to_oscal_control_id  # local-only helper

        control_pk_by_id: dict[str, int] = {}
        control_ids: dict[int, str] = {}
        for c in session.exec(
            select(Control).where(Control.framework_id == framework_id)
        ).all():
            if c.id is None:
                continue
            control_pk_by_id[c.control_id] = c.id
            control_ids[c.id] = c.control_id

        objective_lookup: dict[tuple[str, str], int] = {}
        objective_to_control_pk: dict[int, int] = {}
        for o in session.exec(
            select(Objective).where(
                Objective.control_id_fk.in_(list(control_ids.keys()))  # type: ignore[attr-defined]
            )
        ).all():
            ctl = control_ids.get(o.control_id_fk)
            if ctl and o.id is not None:
                objective_lookup[(ctl, o.objective_id)] = o.id
                objective_to_control_pk[o.id] = o.control_id_fk

        existing_baseline_objs = {
            bo.objective_id: bo
            for bo in session.exec(
                select(BaselineObjective).where(BaselineObjective.baseline_id == baseline.id)
            ).all()
        }
        existing_baseline_ctls = {
            bc.control_id: bc
            for bc in session.exec(
                select(BaselineControl).where(BaselineControl.baseline_id == baseline.id)
            ).all()
        }

        # First pass: walk the workbook and build (a) objective writes and
        # (b) per-control aggregation. A control is in-scope iff ANY of
        # its CCIs are marked required — eMASS serializes one row per CCI
        # but tailoring is a control-level decision (see model docstrings).
        objectives_unknown = 0
        controls_unknown_ids: set[str] = set()
        seen_objective_ids: set[int] = set()
        control_required: dict[int, bool] = {}  # control_pk -> any-CCI-required

        for row in index.rows:
            if not row.cci_id:
                continue
            oscal_ctl_id = _ccis_to_oscal_control_id(row.control_id)
            obj_pk = objective_lookup.get((oscal_ctl_id, row.cci_id))
            if obj_pk is None:
                objectives_unknown += 1
                if oscal_ctl_id not in control_pk_by_id:
                    controls_unknown_ids.add(oscal_ctl_id)
                continue
            seen_objective_ids.add(obj_pk)

            ctl_pk = objective_to_control_pk.get(obj_pk)
            if ctl_pk is not None:
                # OR-aggregate: control stays in-scope if any CCI is required.
                control_required[ctl_pk] = control_required.get(ctl_pk, False) or row.required

            bo = existing_baseline_objs.get(obj_pk)
            if bo is None:
                session.add(
                    BaselineObjective(
                        baseline_id=baseline.id,  # type: ignore[arg-type]
                        objective_id=obj_pk,
                        source_row=str(row.excel_row),
                        is_deprecated=False,
                    )
                )
            else:
                bo.source_row = str(row.excel_row)
                # Re-surface a previously-deprecated row when the workbook
                # carries the CCI again (e.g. user re-adds a row to col A).
                bo.is_deprecated = False
                # Leave bo.tailoring_reason alone — assessor may set it
                # on individual CCIs for explanatory text; we don't own it.
                session.add(bo)

        # Second pass: upsert BaselineControl rows from the aggregation.
        controls_in_scope = 0
        controls_out_of_scope = 0
        seen_control_pks: set[int] = set()

        for ctl_pk, in_scope in control_required.items():
            seen_control_pks.add(ctl_pk)
            tailoring = (
                None
                if in_scope
                else "All CCIs under this control marked not required in workbook col A"
            )
            bc = existing_baseline_ctls.get(ctl_pk)
            if bc is None:
                session.add(
                    BaselineControl(
                        baseline_id=baseline.id,  # type: ignore[arg-type]
                        control_id=ctl_pk,
                        in_scope=in_scope,
                        tailoring_reason=tailoring,
                    )
                )
            else:
                bc.in_scope = in_scope
                bc.tailoring_reason = tailoring
                session.add(bc)
            if in_scope:
                controls_in_scope += 1
            else:
                controls_out_of_scope += 1

        # Clean up rows the workbook no longer references — keeps the
        # baseline truthful when the workbook is regenerated with a
        # tighter overlay. Safe because Baseline* tables are metadata;
        # the catalog Objective/Control rows stay put.
        #
        # BaselineObjective uses soft-delete (is_deprecated=True) instead
        # of hard delete: ``_resolve_excel_row`` in routes/controls.py
        # joins BaselineObjective.source_row when saving Compliance
        # statuses, and the DISA CCI catalog loader may mark an Objective
        # row source="CCI-deprecated" independently of the workbook
        # roster. Hard-deleting orphans the source_row pointer and breaks
        # save with "No BaselineObjective row for objective_id=… in
        # baseline …" — see feedback memory on the 002124 incident. The
        # row stays in place; the column flips on/off as the workbook
        # adds or drops the CCI on re-import.
        for obj_pk, bo in existing_baseline_objs.items():
            if obj_pk not in seen_objective_ids:
                if not bo.is_deprecated:
                    bo.is_deprecated = True
                    session.add(bo)
        for ctl_pk, bc in existing_baseline_ctls.items():
            if ctl_pk not in seen_control_pks:
                session.delete(bc)

        session.commit()

        # Step 6: ingest ODP (Organization-Defined Parameter) values from
        # the Assignment Values tab into the framework-scoped
        # ``odp_assignment`` table. Statements stay parameterized in
        # ``Control.statement``; the render layer resolves placeholders at
        # read time. See memory/project_odp_architecture.md for the locked
        # design and the three principles (templates not baked, provenance
        # over inference, JOIN for cross-framework). Audit-log diff fires
        # only when an existing row's value actually changes, so
        # re-importing an unchanged workbook is a no-op for the log.
        # ``slot_orders`` is the authoritative per-control slot list
        # extracted from the parameterized control statement column. We
        # use it (not the value-bearing rows) for the OSCAL positional
        # bridge in Step 6b — see read_assignment_values docstring for
        # the sparse-workbook rationale. ``assignment_rows`` carries the
        # value-bearing rows the audit-log + storage path needs.
        assignment_rows, slot_orders_raw = read_assignment_values(self.workbook_path)
        # Translate slot_orders keys from workbook form ("AC-2") to OSCAL
        # canonical ("ac-2") to match the canonical control_id we store
        # on OdpAssignment in Step 6, so Step 6b can look up by the same
        # key it iterates over.
        slot_orders: dict[str, list[str]] = {
            _ccis_to_oscal_control_id(k): v for k, v in slot_orders_raw.items()
        }
        odp_inserted = 0
        odp_updated = 0
        if assignment_rows:
            existing_odps = {
                (a.framework_version, a.control_id, a.odp_id, a.assigned_from): a
                for a in session.exec(
                    select(OdpAssignment).where(
                        OdpAssignment.framework_version == framework.framework_id
                    )
                ).all()
            }
            who = f"CCIS-workbook-ingest:{self.workbook_path.name}"
            for row in assignment_rows:
                # Translate workbook form ("AC-2") → OSCAL canonical
                # ("ac-2") so OdpAssignment.control_id joins cleanly to
                # Control.control_id at render time. Doing it at ingest
                # keeps the render path a single equality predicate
                # (covered by ix_odpassignment_fw_control) instead of a
                # case/translation function that would defeat the index.
                ctl_id = _ccis_to_oscal_control_id(row.control_id)
                # Catalog-agnostic anchor for the OSCAL bridge: the
                # row's position in the workbook's declared slot list.
                # ``slot_orders`` is the authoritative per-control slot
                # list derived from the parameterized statement column
                # (NOT from value-bearing rows — sparse controls would
                # mis-count). When the workbook's slot list is missing
                # entirely or the odp_id isn't in it, slot_index stays
                # NULL and render falls back to odp_id lookup. See
                # models.OdpAssignment.slot_index for the full rationale.
                ctl_slots = slot_orders.get(ctl_id, [])
                slot_index = (
                    ctl_slots.index(row.odp_id)
                    if row.odp_id in ctl_slots
                    else None
                )
                # ``slot_total`` is the workbook's DECLARED slot count for
                # the control (every row for this control gets the same
                # value). Render uses it instead of ``len(by_slot)`` so a
                # sparse workbook — 4 declared slots but only 2 filled —
                # doesn't mis-reject the positional bridge against a
                # 4-param catalog. NULL when the workbook had no slot
                # list for this control (then render abstains on count).
                slot_total = len(ctl_slots) if ctl_slots else None
                key = (
                    framework.framework_id,
                    ctl_id,
                    row.odp_id,
                    row.assigned_from,
                )
                existing = existing_odps.get(key)
                if existing is not None:
                    if existing.value != row.value:
                        # Audit insert MUST precede the field mutation —
                        # the prev_value snapshot needs the unmodified row.
                        session.add(
                            OdpAuditLog(
                                framework_version=framework.framework_id,
                                control_id=ctl_id,
                                odp_id=row.odp_id,
                                assigned_from=row.assigned_from,
                                prev_value=existing.value,
                                new_value=row.value,
                                who=who,
                            )
                        )
                        existing.value = row.value
                        existing.ingested_at = datetime.now(timezone.utc)
                        odp_updated += 1
                    # Refresh slot_index and slot_total on every existing
                    # row so a workbook that reordered/inserted slots, or
                    # one whose total slot count grew, updates the anchor
                    # even when the value is unchanged. Cheap and
                    # idempotent — re-imports of an unchanged workbook
                    # write the same integers.
                    if existing.slot_index != slot_index:
                        existing.slot_index = slot_index
                    if existing.slot_total != slot_total:
                        existing.slot_total = slot_total
                    session.add(existing)
                else:
                    session.add(
                        OdpAssignment(
                            framework_version=framework.framework_id,
                            control_id=ctl_id,
                            odp_id=row.odp_id,
                            assigned_from=row.assigned_from,
                            value=row.value,
                            source_ingest="CCIS-workbook",
                            slot_index=slot_index,
                            slot_total=slot_total,
                        )
                    )
                    odp_inserted += 1
            session.commit()

        # Step 6b: bridge eMASS ODP ids ({$N$}) → OSCAL param ids
        # (ac-2_prm_1) by positional alignment within each control.
        #
        # Why this exists: Control.statement carries OSCAL placeholders
        # ({{ insert: param, ac-2_prm_1 }}) while OdpAssignment.odp_id
        # carries the workbook's eMASS token ({$37$}). The render layer
        # needs to translate at lookup time without baking values into
        # the template. The bridge is data, not code (see locked
        # architecture rule: "translation is data, not code").
        #
        # Alignment rule: for each control, OSCAL declares params in a
        # fixed order, and the workbook's parameterized control statement
        # column enumerates eMASS ODP slots in the same order — including
        # slots that have no assigned value. We use that authoritative
        # slot list (from ``slot_orders``) instead of deriving slots from
        # value-bearing rows because sparse controls (AC-2: 4 declared,
        # 2 filled) would otherwise mis-count and abstain unnecessarily.
        # When counts match, zip positionally. When they don't, ABSTAIN —
        # leave oscal_param_id NULL on every row for that control. NULL
        # is correct (not "wrong"); the render layer already handles
        # unresolved placeholders by leaving them in place and surfacing
        # the odp_id in `unresolved`. Spurious mappings would silently
        # substitute the wrong value, which is worse than a visible
        # placeholder.
        odp_mapped = 0
        odp_mapping_abstained = 0
        # ``odp_value_rows_without_slot`` counts value-bearing rows whose
        # ``odp_id`` is absent from the parameterized statement column's
        # declared slot list for the same control. Observed in the wild
        # (Example System workbook, May 2026) on AC-7, SI-5, CM-3, SA-19,
        # SI-3 — the two columns disagree about which ODP ids exist.
        # We don't guess a bridge for these (precision over recall); they
        # stay ``oscal_param_id=NULL`` so the render layer surfaces them
        # as visible unresolved placeholders. The count exists so the
        # ingest result can warn the assessor about data-quality drift
        # without forcing them to query the DB.
        odp_value_rows_without_slot = 0
        controls_with_orphan_values: list[str] = []
        if assignment_rows:
            # Pull every OdpAssignment row we just touched plus any
            # previously-ingested rows for this framework — the mapping
            # is a function of (control_id, position) so we re-derive
            # for all rows on every ingest. Idempotent: same workbook
            # produces same alignment, so the UPDATE is a no-op when
            # values haven't shifted.
            all_rows = session.exec(
                select(OdpAssignment).where(
                    OdpAssignment.framework_version == framework.framework_id
                )
            ).all()
            # Group workbook-sourced rows by control_id for positional
            # zip. Non-workbook sources (CRM overlay, user-edit) carry
            # their own oscal_param_id from their respective ingest path
            # and shouldn't be re-mapped here.
            rows_by_ctl: dict[str, list[OdpAssignment]] = {}
            for r in all_rows:
                if r.source_ingest != "CCIS-workbook":
                    continue
                rows_by_ctl.setdefault(r.control_id, []).append(r)

            # Iterate by authoritative slot_orders keys, not by
            # value-bearing rows_by_ctl keys — a control may declare
            # slots in the parameterized statement but have zero values
            # assigned, and we still want to register the (controlled)
            # abstain rather than silently skipping. Union the two key
            # sets so we don't miss controls whose slot_orders entry
            # came from the value-bearing fallback path.
            for oscal_ctl_id in set(rows_by_ctl) | set(slot_orders):
                rows = rows_by_ctl.get(oscal_ctl_id, [])
                # oscal_ctl_id is already canonical OSCAL form because
                # Step 6 translated at ingest and slot_orders was
                # translated above. No second translation here.
                control = session.exec(
                    select(Control).where(
                        Control.framework_id == framework_id,
                        Control.control_id == oscal_ctl_id,
                    )
                ).first()
                if control is None:
                    # Control not in catalog (e.g. workbook references a
                    # withdrawn enhancement). Abstain on all rows.
                    for r in rows:
                        if r.oscal_param_id is not None:
                            r.oscal_param_id = None
                            session.add(r)
                    odp_mapping_abstained += len(rows)
                    continue

                oscal_params = _extract_oscal_param_ids(control.statement)

                # Authoritative slot order from the parameterized
                # statement column. Includes unfilled slots so the count
                # matches OSCAL even when the workbook only fills a
                # subset.
                slots = slot_orders.get(oscal_ctl_id, [])

                # Index rows by odp_id so we can stamp each row whose
                # slot has a value. A workbook may emit multiple rows
                # for the same odp_id (overlay stacking, e.g. {$39$}
                # appearing under both DoW Enterprise and FedRAMP HBL);
                # they all represent the same OSCAL param.
                rows_by_slot: dict[str, list[OdpAssignment]] = {}
                for r in rows:
                    rows_by_slot.setdefault(r.odp_id, []).append(r)

                if not slots:
                    # No slot order discoverable for this control (no
                    # parameterized statement column and no value rows).
                    # Nothing to do.
                    continue

                if len(oscal_params) != len(slots) or not oscal_params:
                    # Count mismatch (or control has no params in OSCAL
                    # statement). Abstain — clear any stale bridge from
                    # a prior ingest where the alignment did match.
                    for r in rows:
                        if r.oscal_param_id is not None:
                            r.oscal_param_id = None
                            session.add(r)
                    odp_mapping_abstained += len(rows)
                    continue

                for pid, slot_id in zip(oscal_params, slots, strict=True):
                    # Slots with no value-bearing row have nothing to
                    # stamp — the bridge exists conceptually but there's
                    # no DB row, and render will leave the OSCAL wrapper
                    # unresolved naturally. This is exactly the desired
                    # behavior for unfilled slots like AC-2 {$36$}/{$38$}.
                    for r in rows_by_slot.get(slot_id, []):
                        if r.oscal_param_id != pid:
                            r.oscal_param_id = pid
                            session.add(r)
                        odp_mapped += 1

                # Count value-bearing rows whose odp_id is NOT in the
                # declared slot list — they have no bridge target and
                # will stay NULL. Also clear any stale bridge they may
                # carry from a prior ingest where the slot list differed.
                slot_set = set(slots)
                orphan_rows = [r for r in rows if r.odp_id not in slot_set]
                if orphan_rows:
                    for r in orphan_rows:
                        if r.oscal_param_id is not None:
                            r.oscal_param_id = None
                            session.add(r)
                    odp_value_rows_without_slot += len(orphan_rows)
                    controls_with_orphan_values.append(oscal_ctl_id)

            session.commit()

        return BaselineApplyResult(
            baseline=baseline,
            controls_in_scope=controls_in_scope,
            controls_out_of_scope=controls_out_of_scope,
            controls_unknown=len(controls_unknown_ids),
            objectives_seen=len(seen_objective_ids),
            objectives_unknown=objectives_unknown,
            notes={
                "catalog_enrichment": catalog_counts,
                "odp_assignments": {
                    "inserted": odp_inserted,
                    "updated": odp_updated,
                    "rows_parsed": len(assignment_rows),
                    "oscal_mapped": odp_mapped,
                    "oscal_mapping_abstained": odp_mapping_abstained,
                    "value_rows_without_slot": odp_value_rows_without_slot,
                    "controls_with_orphan_values": sorted(
                        controls_with_orphan_values
                    ),
                },
            },
        )
