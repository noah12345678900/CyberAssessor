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

from sqlmodel import Session, delete, select

from ..excel.ccis_reader import read_workbook_index
from ..models import (
    Assessment,
    AssessmentImplementation,
    Baseline,
    BaselineControl,
    BaselineObjective,
    ComplianceStatus,
    Control,
    Objective,
    VerdictSource,
    Workbook,
)
from ..baselines.scope_labels import ON_PREM_LABEL
from . import rules
from .assessor import Assessor, decision_to_verdict_source
from .crm_context import CrmContext, build_crm_context
from .impl_persistence import persist_assessment_with_impls

# Responsibilities the engine can decide without an LLM call. Hybrid +
# customer still need the LLM (hybrid prepends a scoping block, customer
# is a no-op short-circuit), so they're skipped at backfill.
_DETERMINISTIC = {"provider", "inherited", "not_applicable"}

# verdict_source values that mark a row as written by the SYSTEM (attach/open
# backfill), i.e. safe for the self-healing backfill to overwrite or delete
# when the CRM picture changes. A row whose verdict_source is LLM/abstain/
# imported, or whose tester is a human, was produced or touched by a user or
# the assess pipeline and must NEVER be stomped by backfill.
_SYSTEM_VERDICT_SOURCES = {
    VerdictSource.CRM_PROVIDER,
    VerdictSource.CRM_INHERITED,
    VerdictSource.CRM_NOT_APPLICABLE,
    VerdictSource.CRM_HYBRID_MIXED,
    VerdictSource.RULE_8A,
    VerdictSource.RULE_8B,
    VerdictSource.RULE_8C,
}
# CRM-DERIVED subset: rows the CRM backfill itself authored from CRM overlays.
# These are the ONLY rows the CRM self-heal may delete/overwrite when the CRM
# picture changes. RULE_* verdicts are workbook-INTRINSIC attestations (col-N
# Not Applicable → 8b, col-M named inheritance → 8a) — written by
# backfill_workbook_rules from the eMASS workbook itself, not from any CRM. A
# CRM attach must NEVER delete or clobber a workbook attestation (PE-10 bug:
# attaching a CRM whose flex slice resolves col-L ASSESS judged the control
# "non-deterministic" and the self-heal deleted the valid rule_8b NA row). The
# workbook fact stands regardless of CRM coverage; only re-derive/heal rows the
# CRM owns. (RULE_8C is never written by backfill — only the deterministic
# COMPLIANT_8A/NOT_APPLICABLE_8B verdicts are — but it's listed for symmetry.)
_CRM_DERIVED_VERDICT_SOURCES = {
    VerdictSource.CRM_PROVIDER,
    VerdictSource.CRM_INHERITED,
    VerdictSource.CRM_NOT_APPLICABLE,
    VerdictSource.CRM_HYBRID_MIXED,
}
_SYSTEM_TESTER = "system"


def _is_crm_derived(assessment: Assessment) -> bool:
    """True when the row was written by the CRM backfill from a CRM overlay.

    Narrower than :func:`_is_system_written`: a CRM-derived row is one the CRM
    self-heal may delete (stale inheritance) or re-derive in place (slice set
    grew). A RULE_8A/8B verdict is system-written but NOT CRM-derived — it is a
    workbook attestation the CRM must never touch. Requires both the CRM
    verdict_source AND the backfill tester sentinel (a human/LLM never gets
    healed).
    """
    vs = assessment.verdict_source
    if vs is None or vs not in _CRM_DERIVED_VERDICT_SOURCES:
        return False
    if assessment.tester and assessment.tester != _SYSTEM_TESTER:
        return False
    return True


def _is_system_written(assessment: Assessment) -> bool:
    """True when the row was written by attach/open backfill (safe to heal).

    Guards the self-heal delete/rewrite: a row counts as system-written when
    it carries a deterministic CRM/rule ``verdict_source`` AND its tester is
    the backfill sentinel. User edits (human tester) or LLM/abstain rows are
    excluded so the backfill never clobbers reviewer work.
    """
    vs = assessment.verdict_source
    if vs is not None and vs not in _SYSTEM_VERDICT_SOURCES:
        return False
    if assessment.tester and assessment.tester != _SYSTEM_TESTER:
        return False
    return True


@dataclass(frozen=True)
class BackfillResult:
    applied: int
    skipped_existing: int
    skipped_no_crm_entry: int
    skipped_non_deterministic: int
    skipped_no_workbook_row: int
    # Self-heal: stale system-written deterministic rows deleted because the
    # control became customer/hybrid after a later CRM attach (defers to LLM).
    healed_deleted: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "applied": self.applied,
            "skipped_existing": self.skipped_existing,
            "skipped_no_crm_entry": self.skipped_no_crm_entry,
            "skipped_non_deterministic": self.skipped_non_deterministic,
            "skipped_no_workbook_row": self.skipped_no_workbook_row,
            "healed_deleted": self.healed_deleted,
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

    # Existing assessments in one query, not N. Keyed by objective_id so the
    # self-healing path can READ the prior row (to decide overwrite vs delete
    # vs leave-alone), not just detect presence. One Assessment per
    # (workbook, objective) is now enforced by uq_assessment_workbook_objective.
    existing_assessments = list(
        session.exec(
            select(Assessment).where(Assessment.workbook_id == workbook_id)
        ).all()
    )
    existing_by_obj: dict[int, Assessment] = {
        a.objective_id: a for a in existing_assessments
    }
    # Per-assessment persisted impl-row count, so the self-heal rewrite only
    # fires when the CRM slice set GREW since the last backfill (e.g. PE-3 went
    # from 1 cloud to 2). An unchanged re-run (slice count == persisted impl
    # count) skips as ``skipped_existing`` — preserves idempotency, avoids
    # rewriting identical rows on every attach.
    existing_impl_count: dict[int, int] = {}
    aids = [a.id for a in existing_assessments if a.id is not None]
    if aids:
        for im in session.exec(
            select(AssessmentImplementation).where(
                AssessmentImplementation.assessment_id.in_(aids)
            )
        ).all():
            existing_impl_count[im.assessment_id] = (
                existing_impl_count.get(im.assessment_id, 0) + 1
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
    healed_deleted = 0
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
        # Flex (On-Premises/workbook) slice handling (pie-slice model). The
        # synthesized flex slice carries responsibility="customer" as its ROUTING
        # label, but its STATUS comes from the workbook's Column L, not the CRM.
        # So "customer" on the flex slice must NOT, by itself, defer the control
        # to the LLM. Resolve Column L: INHERITED → the flex slice is
        # deterministically Compliant (write it now via flex_statuses); ASSESS or
        # ESCALATE → the flex outcome depends on assess-time evidence retrieval
        # (NC-on-no-evidence / abstain), which backfill runs BEFORE — so defer
        # those to the LLM/assess path rather than writing a premature verdict.
        flex_slice = next(
            (
                s
                for s in slices
                if s.scope_label == ON_PREM_LABEL and s.source_baseline_id is None
            ),
            None,
        )
        flex_statuses: dict[str, str] | None = None
        if flex_slice is not None:
            flex_outcome = rules.resolve_col_l_flex_status(
                row.inherited, row.remote_inheritance
            )
            if flex_outcome is rules.ColLFlexOutcome.INHERITED:
                flex_statuses = {ON_PREM_LABEL: ComplianceStatus.COMPLIANT.value}
        if slices:
            # The flex slice's routing "customer" label is excluded from the
            # cloud determinism check; its determinism is decided by Column L
            # above (flex_statuses set ⟺ col L INHERITED ⟺ deterministic).
            cloud_resps = [
                s.responsibility
                for s in slices
                if s.responsibility
                and not (
                    s.scope_label == ON_PREM_LABEL and s.source_baseline_id is None
                )
            ]
            clouds_deterministic = bool(cloud_resps) and all(
                r in _DETERMINISTIC for r in cloud_resps
            )
            if flex_slice is not None:
                # Flex-bearing control: deterministic only when the clouds are
                # all inheritable AND Column L resolved the flex slice to
                # INHERITED (flex_statuses set). Otherwise defer to assess time.
                deterministic = clouds_deterministic and flex_statuses is not None
            else:
                deterministic = clouds_deterministic
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
        existing = existing_by_obj.get(obj.id)

        if not deterministic:
            # Hybrid / customer (on any scope) — this control needs the LLM at
            # assess time. SELF-HEAL: if a PRIOR backfill (run when only one
            # CRM was attached and the control looked all-inheritable) already
            # wrote a CRM-DERIVED deterministic row, it is now STALE — a later
            # CRM made the control customer/hybrid. Delete that CRM row + its
            # impl rows so the control defers cleanly to the LLM instead of
            # showing a frozen single-scope COMPLIANT. Never touch a user- or
            # LLM-authored row. This is the AC-17 fix (Azure attached first →
            # deterministic row; AWS attached second → now customer/hybrid).
            #
            # GUARD (PE-10 fix): only delete CRM-DERIVED rows. A RULE_8A/8B
            # verdict is a workbook attestation (col-N Not Applicable / col-M
            # named inheritance), NOT a CRM guess — a CRM attach must never
            # delete it. Before this guard the predicate was _is_system_written,
            # which includes RULE_*, so attaching a CRM whose flex slice
            # resolved col-L ASSESS judged the control non-deterministic and
            # deleted the valid rule_8b NA row (PE-10 vanished from the count).
            if existing is not None and _is_crm_derived(existing):
                session.exec(
                    delete(AssessmentImplementation).where(
                        AssessmentImplementation.assessment_id == existing.id
                    )
                )
                session.delete(existing)
                existing_by_obj.pop(obj.id, None)
                healed_deleted += 1
            else:
                # Either a user/LLM row OR a workbook RULE_* attestation — both
                # are preserved. The control still defers to the LLM at assess
                # time, but the existing authoritative row stays put.
                skipped_non_det += 1
            continue

        # Deterministic control. If a user/LLM row OR a workbook RULE_*
        # attestation already owns it, leave it. Only a CRM-derived row may be
        # re-derived in place below (the PE-3 slice-enrichment case). A col-N
        # rule_8b NA row must survive a later CRM marking the control
        # inherited/provider — the workbook attestation is authoritative.
        if existing is not None and not _is_crm_derived(existing):
            skipped_existing += 1
            continue

        # Idempotency: a system-written deterministic row whose persisted impl
        # set already covers the current slice count is up-to-date — skip the
        # rewrite. Only re-derive when the slice set GREW (a later CRM added a
        # scope), which is the PE-3 enrichment case. ``slices`` may be empty
        # (single-CRM legacy path) → expected 0 impl rows → matches, skip.
        if existing is not None and existing.id is not None:
            if existing_impl_count.get(existing.id, 0) >= len(slices):
                skipped_existing += 1
                continue

        decision = assessor._finalize_crm_decision(
            row, row.cci_id or row.control_id, entry, outcome=None,
            slices=slices,
            flex_statuses=flex_statuses,
        )
        if not decision.accepted or decision.status is None or not decision.narrative:
            # _finalize_crm_decision always accepts, but guard the
            # invariant defensively rather than write a partial row.
            continue

        verdict_src = decision_to_verdict_source(decision)

        if existing is not None:
            # SELF-HEAL / re-derive: a prior system-written deterministic row
            # exists, but the CRM slice set may have GROWN since (e.g. PE-3
            # had only AWS when first backfilled, now has AWS + Azure). Rewrite
            # it in place (is_new=False replaces the impl rows) so every cloud
            # persists instead of freezing the first-attach snapshot.
            existing.excel_row = decision.excel_row
            existing.status = decision.status
            existing.tester = tester
            existing.narrative_q = decision.narrative
            existing.narrative_on_prem = decision.narrative_on_prem
            existing.narrative_cloud = decision.narrative_cloud
            existing.narrative_class = decision.narrative_class
            existing.inheritance_rule = decision.rule
            existing.verdict_source = verdict_src
            existing.date_tested = when
            persist_assessment_with_impls(
                session,
                assessment=existing,
                decision=decision,
                crm_context=crm_context,
                control_id=row.control_id,
                is_new=False,
            )
            applied += 1
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
            verdict_source=verdict_src,
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
        # Track in-memory so two pairs for the same objective in this pass
        # (join fan-out) don't double-write — the second sees the row.
        existing_by_obj[obj.id] = new_row

    return BackfillResult(
        applied=applied,
        skipped_existing=skipped_existing,
        skipped_no_crm_entry=skipped_no_entry,
        skipped_non_deterministic=skipped_non_det,
        skipped_no_workbook_row=skipped_no_row,
        healed_deleted=healed_deleted,
    )


@dataclass(frozen=True)
class RuleBackfillResult:
    """Counts for the deterministic-RULE backfill (rules.classify_row)."""

    applied: int
    skipped_existing: int
    skipped_no_rule: int
    skipped_no_workbook_row: int

    def as_dict(self) -> dict[str, int]:
        return {
            "applied": self.applied,
            "skipped_existing": self.skipped_existing,
            "skipped_no_rule": self.skipped_no_rule,
            "skipped_no_workbook_row": self.skipped_no_workbook_row,
        }


def backfill_workbook_rules(
    workbook_id: int,
    session: Session,
    *,
    tester: str = "system",
) -> RuleBackfillResult:
    """Write Assessment rows for in-scope CCIs that rule #8 decides deterministically.

    Sibling of :func:`backfill_workbook_crm`. Where CRM backfill front-loads
    the CRM-overlay short-circuit, this front-loads the *rule* short-circuit
    (``engine.rules.classify_row``) so workbook-intrinsic deterministic
    verdicts surface in the Controls grid the moment a workbook is opened or a
    CRM is attached — without waiting for the user to click Assess. The
    motivating case: a control marked **Not Applicable** in workbook col N (with
    a scope-exclusion rationale) classifies as ``NOT_APPLICABLE_8B`` but had no
    auto-writer, so AC-18 showed a blank "—" chip until manually assessed.

    Only the unambiguous verdicts are written: ``COMPLIANT_8A`` and
    ``NOT_APPLICABLE_8B``. ``UNCLEAR_8C`` and ``NO_AUTO_RULE`` need the LLM, so
    they are deferred to assess time exactly as before. CRM-covered controls are
    skipped here — CRM backfill owns them (and rule #8 wins over CRM only inside
    the assess pipeline, which the user can still run). These rows carry no CRM
    slices, so ``persist_assessment_with_impls`` writes a parent-only row (the
    grid rollup reads ``Assessment.status`` directly).

    Idempotent and non-stomping: skips any objective that already has an
    Assessment (CRM-backfilled, rule-backfilled, user-edited, or LLM-assessed).
    Caller owns the commit.
    """
    wb = session.get(Workbook, workbook_id)
    if wb is None or wb.baseline_id is None:
        return RuleBackfillResult(0, 0, 0, 0)
    primary = session.get(Baseline, wb.baseline_id)
    if primary is None:
        return RuleBackfillResult(0, 0, 0, 0)
    wb_path = Path(wb.path)
    if not wb_path.exists():
        return RuleBackfillResult(0, 0, 0, 0)
    try:
        index = read_workbook_index(wb_path)
    except (ValueError, FileNotFoundError):
        return RuleBackfillResult(0, 0, 0, 0)
    cci_to_row = index.by_cci()

    pairs: list[tuple[BaselineObjective, Objective]] = list(
        session.exec(
            select(BaselineObjective, Objective)
            .join(Control, Control.id == Objective.control_id_fk)
            .join(BaselineControl, BaselineControl.control_id == Control.id)
            .where(
                BaselineObjective.baseline_id == primary.id,
                BaselineObjective.is_deprecated.is_(False),  # type: ignore[union-attr]
                BaselineObjective.objective_id == Objective.id,
                BaselineControl.baseline_id == primary.id,
                BaselineControl.in_scope.is_(True),  # type: ignore[union-attr]
            )
        ).all()
    )
    if not pairs:
        return RuleBackfillResult(0, 0, 0, 0)

    existing_obj_ids: set[int] = set(
        session.exec(
            select(Assessment.objective_id).where(
                Assessment.workbook_id == workbook_id
            )
        ).all()
    )

    # Empty CRM context: this path writes parent-only rows (no per-scope slices).
    empty_crm = CrmContext.empty()
    assessor = Assessor(llm=None)

    applied = 0
    skipped_existing = 0
    skipped_no_rule = 0
    skipped_no_row = 0
    when = datetime.now(timezone.utc)

    _DETERMINISTIC_RULE_VERDICTS = {
        rules.AutoStatusVerdict.COMPLIANT_8A,
        rules.AutoStatusVerdict.NOT_APPLICABLE_8B,
    }

    for _, obj in pairs:
        row = cci_to_row.get(obj.objective_id)
        if row is None:
            skipped_no_row += 1
            continue
        if obj.id in existing_obj_ids:
            skipped_existing += 1
            continue
        auto = rules.classify_row(row)
        if auto.verdict not in _DETERMINISTIC_RULE_VERDICTS:
            skipped_no_rule += 1
            continue

        source = "rule_8a" if auto.verdict == rules.AutoStatusVerdict.COMPLIANT_8A else "rule_8b"
        decision = assessor._finalize_rule_decision(
            row, row.cci_id or row.control_id, auto, source=source, outcome=None,
        )
        if not decision.accepted or decision.status is None or not decision.narrative:
            skipped_no_rule += 1
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
            verdict_source=decision_to_verdict_source(decision),
            date_tested=when,
        )
        persist_assessment_with_impls(
            session,
            assessment=new_row,
            decision=decision,
            crm_context=empty_crm,
            control_id=row.control_id,
            is_new=True,
        )
        applied += 1
        existing_obj_ids.add(obj.id)

    return RuleBackfillResult(
        applied=applied,
        skipped_existing=skipped_existing,
        skipped_no_rule=skipped_no_rule,
        skipped_no_workbook_row=skipped_no_row,
    )
