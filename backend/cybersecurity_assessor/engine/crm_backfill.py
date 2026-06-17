"""Attach-time CRM backfill — write Assessment rows the instant a CRM is attached.

Without this, a fresh CRM overlay sits inert until the user clicks Assess —
the relational ``WorkbookOverlay`` link is the only state change. The
assess pipeline already short-circuits provider / inherited / not_applicable
through :func:`engine.assessor.Assessor._finalize_crm_decision`, so we reuse
that same code path here at attach time. Same Decision shape, same status
mapping, same narrative defaults, same supersession rewrite — the only
difference is we never call the LLM (hybrid + customer are deliberately
deferred to assess time so the user can review the LLM proposals).

Skips any (workbook, objective) that already has an Assessment row.
Backfill is additive and idempotent; it never stomps prior assessments
(user edits, prior LLM runs, prior backfill from a different overlay).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlmodel import Session, select

from ..excel.ccis_reader import read_workbook_index
from ..models import (
    Assessment,
    Baseline,
    BaselineControl,
    BaselineObjective,
    Control,
    Objective,
    Workbook,
)
from .assessor import Assessor
from .crm_context import build_crm_context
from .impl_persistence import persist_assessment_with_impls

# Responsibilities the engine can decide without an LLM call. Hybrid +
# customer still need the LLM (hybrid prepends a scoping block, customer
# is a no-op short-circuit), so they're skipped at backfill.
_DETERMINISTIC = {"provider", "inherited", "not_applicable"}


@dataclass(frozen=True)
class BackfillResult:
    applied: int
    skipped_existing: int
    skipped_no_crm_entry: int
    skipped_non_deterministic: int
    skipped_no_workbook_row: int

    def as_dict(self) -> dict[str, int]:
        return {
            "applied": self.applied,
            "skipped_existing": self.skipped_existing,
            "skipped_no_crm_entry": self.skipped_no_crm_entry,
            "skipped_non_deterministic": self.skipped_non_deterministic,
            "skipped_no_workbook_row": self.skipped_no_workbook_row,
        }


def backfill_workbook_crm(
    workbook_id: int,
    session: Session,
    *,
    tester: str = "system",
) -> BackfillResult:
    """Write Assessment rows for every in-scope CCI whose CRM entry is deterministic.

    Returns counts so the route handler can surface them in the attach
    response. Caller is responsible for ``session.commit()`` — we stage
    writes via ``session.add()`` so the attach handler can commit them
    in the same transaction as the ``WorkbookOverlay`` insert.

    Returns an all-zeros result (no error) when the workbook has no
    primary baseline yet — fresh workbooks without a framework binding
    can still receive overlay attachments; the backfill simply has
    nothing to iterate.
    """
    wb = session.get(Workbook, workbook_id)
    if wb is None or wb.baseline_id is None:
        return BackfillResult(0, 0, 0, 0, 0)

    primary = session.get(Baseline, wb.baseline_id)
    if primary is None:
        return BackfillResult(0, 0, 0, 0, 0)

    wb_path = Path(wb.path)
    if not wb_path.exists():
        # File moved/deleted — nothing to backfill against. The attach
        # itself still succeeds; the user will get a clearer error when
        # they try to open or assess.
        return BackfillResult(0, 0, 0, 0, 0)

    try:
        index = read_workbook_index(wb_path)
    except (ValueError, FileNotFoundError):
        # Workbook present but unreadable (corrupted, schema changed).
        # Same reasoning as missing file — don't fail the attach over it.
        return BackfillResult(0, 0, 0, 0, 0)
    cci_to_row = index.by_cci()

    # In-scope CCI pairs, mirrored from routes/controls.py batch_assess
    # so backfill and assess agree on which objectives are in play.
    pairs: list[tuple[BaselineObjective, Objective]] = list(
        session.exec(
            select(BaselineObjective, Objective)
            .join(Control, Control.id == Objective.control_id_fk)
            .join(BaselineControl, BaselineControl.control_id == Control.id)
            .where(
                BaselineObjective.baseline_id == primary.id,
                # Skip soft-deleted CCIs — the workbook no longer
                # references them; CRM-driven backfill on a dropped row
                # would write Assessments to deprecated objectives.
                BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
                BaselineObjective.objective_id == Objective.id,
                BaselineControl.baseline_id == primary.id,
                BaselineControl.in_scope.is_(True),  # type: ignore[union-attr]
            )
        ).all()
    )
    if not pairs:
        return BackfillResult(0, 0, 0, 0, 0)

    # Existing assessments in one query, not N — never stomp prior writes.
    existing_obj_ids: set[int] = set(
        session.exec(
            select(Assessment.objective_id).where(
                Assessment.workbook_id == workbook_id
            )
        ).all()
    )

    crm_context = build_crm_context(workbook_id, session)
    if not crm_context.by_control:
        # No CRM overlays on this workbook (or the freshly-attached one
        # has no responsibility-tagged controls). Nothing to backfill.
        return BackfillResult(0, 0, 0, 0, 0)

    # Genuine multi-tenant signal: how many DISTINCT tenant scope_labels are in
    # play (e.g. "AWS GovCloud" + "Azure Government"), excluding the synthesized
    # On-Premises slice. With 2+ real tenants, a control whose per-scope slices
    # come back EMPTY means scope attribution is missing/unreliable for that
    # control — so the single latest-attach-wins ``entry.responsibility`` must
    # NOT be trusted to short-circuit (it would silently mark the control
    # COMPLIANT-by-inheritance with no LLM, masking the other tenant's
    # customer-side work). Counting LABELS, not baselines, avoids a false
    # positive when one logical CRM is split across several unlabeled baselines
    # (a test/import convenience that is not multi-tenant). See empty-slices
    # branch below.
    multi_tenant = crm_context.distinct_scope_label_count >= 2

    # Reuse the same Decision-builder the assess pipeline uses. llm=None
    # is fine: _finalize_crm_decision never touches the client.
    assessor = Assessor(llm=None)

    applied = 0
    skipped_existing = 0
    skipped_no_entry = 0
    skipped_non_det = 0
    skipped_no_row = 0
    when = datetime.now(timezone.utc)

    for _, obj in pairs:
        row = cci_to_row.get(obj.objective_id)
        if row is None:
            skipped_no_row += 1
            continue
        entry = assessor._lookup_crm(row, crm_context)
        if entry is None:
            skipped_no_entry += 1
            continue
        # Multi-scope_label masking guard: ``entry`` is the latest-attach-wins
        # single row, so a deterministic latest attach (e.g. Azure
        # "inherited") can hide an earlier customer/hybrid scope (e.g. AWS
        # GovCloud "customer") on the SAME control. The per-scope slices
        # preserve every scope plus the synthesized On-Premises customer
        # slice. Backfill only writes when EVERY slice is deterministic;
        # any customer/hybrid slice defers the whole control to the LLM at
        # assess time so the customer-side work is never silently set
        # COMPLIANT-by-inheritance without evidence.
        slices = assessor._lookup_crm_slices(row, crm_context)
        if slices:
            slice_resps = [s.responsibility for s in slices if s.responsibility]
            deterministic = bool(slice_resps) and all(
                r in _DETERMINISTIC for r in slice_resps
            )
        elif multi_tenant:
            # Multi-tenant workbook but NO per-scope slices for this control —
            # scope attribution is missing/unreliable here (e.g. a CRM lacked a
            # scope_label, or only one tenant's row parsed). Trusting the single
            # latest-attach-wins ``entry`` would re-open the masking hole the
            # slice guard above closes: an "inherited" latest attach would mark
            # the control COMPLIANT with no LLM, hiding the other tenant's
            # customer-side obligation. Defer to the LLM at assess time instead.
            deterministic = False
        else:
            # Single-CRM (or zero scope-labeled) workbook: the legacy
            # single-entry short-circuit is safe — there is no second tenant to
            # mask. Preserves the original deterministic backfill behavior.
            deterministic = entry.responsibility in _DETERMINISTIC
        if not deterministic:
            # Hybrid / customer (on any scope) — leave for the LLM at
            # assess time.
            skipped_non_det += 1
            continue
        if obj.id in existing_obj_ids:
            skipped_existing += 1
            continue

        decision = assessor._finalize_crm_decision(
            row, row.cci_id or row.control_id, entry, outcome=None,
            slices=slices,
        )
        if not decision.accepted or decision.status is None or not decision.narrative:
            # _finalize_crm_decision always accepts, but guard the
            # invariant defensively rather than write a partial row.
            continue

        new_row = Assessment(
            workbook_id=workbook_id,
            objective_id=obj.id,
            excel_row=decision.excel_row,
            status=decision.status,
            tester=tester,
            narrative_q=decision.narrative,
            narrative_on_prem=decision.narrative_on_prem,
            narrative_cloud=decision.narrative_cloud,
            narrative_class=decision.narrative_class,
            inheritance_rule=decision.rule,
            date_tested=when,
        )
        # v0.2 multi-impl: deterministic backfill goes through the same
        # shared helper as /assess and /assess-batch so a CRM-driven
        # inheritance write also lands the per-scope
        # AssessmentImplementation rows. Caller still owns the commit
        # (helper only flushes), so this stays in the attach handler's
        # transaction.
        persist_assessment_with_impls(
            session,
            assessment=new_row,
            decision=decision,
            crm_context=crm_context,
            control_id=row.control_id,
            is_new=True,
        )
        applied += 1
        # Track in-memory so two attached CRMs in the same call don't
        # double-write the same objective (latest-wins is already enforced
        # by build_crm_context, but we keep the set consistent).
        existing_obj_ids.add(obj.id)

    return BackfillResult(
        applied=applied,
        skipped_existing=skipped_existing,
        skipped_no_crm_entry=skipped_no_entry,
        skipped_non_deterministic=skipped_non_det,
        skipped_no_workbook_row=skipped_no_row,
    )
