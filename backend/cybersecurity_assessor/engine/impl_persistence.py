"""Shared persistence helper — write an Assessment plus its impl rows in one go.

Centralizes the v0.2 multi-implementation write path so every Decision-
producing site (single ``/assess``, batched ``/assess-batch``, the
deterministic CRM backfill in :mod:`engine.crm_backfill`) emits the same
``Assessment`` + N x ``AssessmentImplementation`` tuple in the same
transaction.

Layering
--------
Engine-layer placement (not ``routes/controls.py`` as the original plan
suggested) so the deterministic backfill in :mod:`engine.crm_backfill`
can import the same helper without a routes→engine import. The helper
takes a SQLModel ``Session`` and never opens or commits one itself —
``session.flush()`` materializes the parent PK without ending the
transaction, which keeps both single-CCI commit-per-row and batched
commit-in-finally call sites happy.

Replace, don't append
---------------------
On update the helper deletes every prior ``AssessmentImplementation``
row for the parent ``assessment_id`` before inserting the new plan set.
The impl set is always a fresh snapshot of the latest assess decision —
no historical impl rows are preserved (audit history lives on
``CciOutcomeRow`` / ``RunRecord``).

Abstain handling
----------------
When ``decision.status is None`` (hard abstain — validator exhausted,
parse error, dual-pass disagreement) the parent ``Assessment.status``
and ``narrative_q`` have already been coerced to ``NON_COMPLIANT`` +
the standard placeholder by ``_coerce_abstain_persistence_fields`` in
the route layer, AND ``needs_review`` is set on the parent. The helper
explicitly leaves those fields alone in that case — overwriting with a
rollup from deterministic impl rows (provider/inherited CRMs) would
flip the parent to COMPLIANT and hide the abstain from the reviewer
queue, which violates ``feedback_precision_over_recall.md``.
Deterministic impl rows still get written; they record the inheritance
facts an auditor needs alongside the parent's reviewer flag.
"""

from __future__ import annotations

from sqlmodel import Session, delete

from ..excel.ccis_reader import _ccis_to_oscal_control_id, _normalize_control
from ..models import Assessment, AssessmentImplementation
from .assessor import (
    Decision,
    compose_rolled_narrative,
    compute_rollup_status,
    plan_implementations,
)
from .crm_context import CrmContext


def persist_assessment_with_impls(
    session: Session,
    *,
    assessment: Assessment,
    decision: Decision,
    crm_context: CrmContext,
    control_id: str,
    is_new: bool,
) -> int:
    """Persist *assessment* and its per-impl children in the current transaction.

    Parameters
    ----------
    session
        Active SQLModel session. The helper calls ``session.add`` and
        ``session.flush`` but never ``commit`` — the caller owns the
        transaction boundary.
    assessment
        Either a freshly-constructed (unsaved) row or a row already
        attached to *session* and mutated in-place by the route handler.
        Either way it must already carry its audit fields (``status``,
        ``narrative_q``, ``needs_review`` etc.); the helper only
        overwrites ``status`` + ``narrative_q`` when a non-abstain rollup
        is available.
    decision
        Kernel Decision for the CCI; drives both the rollup gate
        (``decision.status is None`` means abstain — skip rollup) and
        the customer-side mirror inside :func:`plan_implementations`.
    crm_context
        Per-workbook CRM snapshot built by
        :func:`engine.crm_context.build_crm_context`. The helper reads
        :meth:`CrmContext.implementations` keyed on *control_id*.
    control_id
        Control identifier for the row — accepts EITHER the workbook
        display form (``"AC-2(1)"``, ``"PE-3"``) or the OSCAL canonical
        form (``"ac-2.1"``, ``"pe-3"``). It is normalized to OSCAL here
        before the ``CrmContext.implementations`` lookup, so callers can
        safely pass ``row.control_id`` (display form) without each having
        to remember the normalization. NOT the CCI identifier.
    is_new
        ``True`` for INSERT, ``False`` for UPDATE. UPDATE deletes the
        prior impl rows before writing the new set (replace, not
        append). INSERT skips that delete to save one round-trip.

    Returns
    -------
    The persisted ``Assessment.id``. Always non-None after the flush.
    """
    # Normalize to the OSCAL canonical id the CRM context keys on. Every
    # route/backfill caller passes ``row.control_id`` (workbook DISPLAY form
    # like "PE-3" / "AC-2(1)"), but ``build_crm_context`` keys
    # ``by_control_impls`` on the OSCAL form ("pe-3" / "ac-2.1"). Without this
    # the lookup silently missed for every real caller — ``slices`` came back
    # empty, NO AssessmentImplementation rows were ever written, and a
    # fully-inherited control's parent narrative_q kept only the single
    # latest-attach short-circuit text (one cloud's narrative) instead of the
    # composed per-scope breakdown. Idempotent if already OSCAL.
    oscal_control_id = _ccis_to_oscal_control_id(_normalize_control(control_id))
    slices = crm_context.implementations(oscal_control_id)
    plans = plan_implementations(decision, slices)

    # Only override the parent's status/narrative when we have a real
    # multi-impl rollup AND the decision wasn't a hard abstain. See the
    # module docstring for why abstain rows must keep their coerced
    # parent fields.
    if plans and decision.status is not None:
        assessment.status = compute_rollup_status([p.status for p in plans])
        # FIXME(impl-persistence-audit): compose_rolled_narrative can return
        # "" when every plan narrative is blank/whitespace. Assigning that
        # empty string silently destroys the parent narrative_q and may
        # trip the POST-time validator (column Q non-null + template-phrase
        # gate). Only overwrite when the composition produced real text.
        rolled = compose_rolled_narrative(plans)
        if rolled:
            assessment.narrative_q = rolled

    session.add(assessment)
    session.flush()  # materializes assessment.id without ending the txn
    assert assessment.id is not None  # post-flush invariant

    if plans:
        if not is_new:
            session.exec(
                delete(AssessmentImplementation).where(
                    AssessmentImplementation.assessment_id == assessment.id
                )
            )
        for plan in plans:
            session.add(
                AssessmentImplementation(
                    assessment_id=assessment.id,
                    scope_label=plan.scope_label,
                    source_baseline_id=plan.source_baseline_id,
                    responsibility=plan.responsibility,
                    status=plan.status,
                    narrative=plan.narrative,
                    evidence_refs=plan.evidence_refs,
                )
            )

    return assessment.id


def preview_rolled_narrative(
    decision: Decision,
    crm_context: CrmContext,
    control_id: str,
) -> str | None:
    """Compute the column-Q text a SAVE would persist — for the proposal preview.

    The assess/propose endpoints show the user a diff of the proposed column-Q
    against the existing assessment before they save. Previously the preview
    used ``stitch_scope_narrative(decision.narratives_by_scope)``, which only
    stitches CUSTOMER-OWNED scopes (``narratives_by_scope`` is populated by
    ``narratives_by_scope_from_proposal`` for customer/hybrid slices only).
    Inherited/provider scopes — whose narrative comes from the CRM's verbatim
    text in ``plan_implementations`` — were therefore ABSENT from the preview,
    even though ``persist_assessment_with_impls`` writes them via
    ``compose_rolled_narrative`` over EVERY plan row. The diff then showed the
    inherited (e.g. Azure) scope as "removed" on re-assess, alarming the user,
    when in fact the save re-adds it.

    This helper reproduces the persist path's column-Q derivation exactly —
    ``plan_implementations`` over the same OSCAL-normalized slices, then
    ``compose_rolled_narrative`` — so the preview shows the same scope set the
    save will land. Returns ``None`` when there are no per-scope plans (single-
    boundary control) so callers fall back to the plain ``decision.narrative``,
    matching the persist path's "only override when rolled is truthy" gate.
    Pure/read-only: no session, no writes.
    """
    oscal_control_id = _ccis_to_oscal_control_id(_normalize_control(control_id))
    slices = crm_context.implementations(oscal_control_id)
    plans = plan_implementations(decision, slices)
    if not plans or decision.status is None:
        return None
    rolled = compose_rolled_narrative(plans)
    return rolled or None
