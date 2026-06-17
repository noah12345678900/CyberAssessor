"""Per-workbook CRM lookup snapshot, built once per assess request.

Mirrors the ``tagged_evidence`` and family-gated asset cross-check patterns:
the route handler builds this object from the session, the kernel consumes
it. Keeps the engine session-free and testable in isolation, and avoids
re-querying overlay tables for every CCI in a batch assess.

Only ``WorkbookOverlay`` rows whose baseline is ``source_type=CRM`` and
whose ``BaselineControl.responsibility`` is set contribute entries. Per
the overlay-default-local rule, a control with no CRM entry yields
``lookup() -> None`` and the assessor runs the full LLM path.

Latest overlay wins on duplicate ``control_id`` (sort by
``WorkbookOverlay.attached_at`` desc) so re-uploading a corrected CRM
takes effect without detaching the older one.

Multi-implementation enumeration (v0.2)
---------------------------------------
``implementations(control_id)`` returns one :class:`ImplementationSlice`
per attached CRM ``scope_label`` — the data input that the route layer
turns into N ``AssessmentImplementation`` rows. Within a single
``scope_label`` the same latest-wins rule applies (re-uploading the
AWS-Gov CRM updates only the AWS-Gov slice). An ``"On-Premises"`` slice
is synthesized whenever any cloud slice carries a customer or hybrid
verdict — the customer-side work has to be assessed on the on-prem
footprint too, and on-prem is never a CRM upload by contract (see
``baselines/scope_labels.py``).

Legacy CRMs (uploaded before the scope_label migration; ``scope_label IS
NULL``) contribute to ``lookup()`` exactly as before but contribute *no*
implementation slices — the assessor falls through to the single-result
legacy path for those workbooks, preserving pre-migration behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import or_
from sqlmodel import Session, select

from ..baselines.scope_labels import ON_PREM_LABEL
from ..models import (
    Baseline,
    BaselineControl,
    BaselineSourceType,
    Control,
    WorkbookOverlay,
)


@dataclass(frozen=True)
class CrmEntry:
    """One CRM row, resolved to its canonical catalog control_id string.

    ``responsibility`` is the CLOUD-scope verdict (matches every CSP-issued
    CRM template — AWS GovCloud, Azure, GCP). ``responsibility_onprem`` is
    the separately-tracked verdict for the on-prem footprint of the same
    control, for mixed cloud + on-prem systems. Either may be None on a
    given entry, but the WHERE filter in ``build_crm_context`` guarantees
    at least one is set (otherwise the row contributes no signal and
    silently dropping it would mask CRM data-quality issues).
    """

    control_id: str  # OSCAL canonical form, e.g. "ac-2.1"
    responsibility: str | None  # cloud scope; one of customer/provider/hybrid/inherited/not_applicable
    narrative: str | None  # cloud-scope narrative
    source_baseline_id: int
    responsibility_onprem: str | None = None
    narrative_onprem: str | None = None


@dataclass(frozen=True)
class ImplementationSlice:
    """One implementation slice — the data input for an ``AssessmentImplementation`` row.

    Carries the per-scope verdict (responsibility), narrative, and the
    originating ``source_baseline_id`` so the persistence layer can wire
    the impl row's FK back to the CRM that produced it. The synthesized
    on-prem slice carries ``source_baseline_id=None`` and
    ``narrative=None`` (no CRM authored it; the assessor decides the
    on-prem side from local evidence).
    """

    scope_label: str  # e.g. "AWS GovCloud" or ON_PREM_LABEL
    responsibility: str | None  # customer/provider/hybrid/inherited/not_applicable
    narrative: str | None  # narrative from the CRM; None for synthesized on-prem
    source_baseline_id: int | None  # FK to Baseline; None for synthesized on-prem


# Responsibility values that mean "customer has to do work on this control".
# Drives on-prem-slice synthesis: if any cloud slice is in this set, the
# customer's work shows up on the on-prem footprint too.
_CUSTOMER_OWNED_RESPONSIBILITIES = frozenset({"customer", "hybrid"})


@dataclass(frozen=True)
class CrmContext:
    """Per-workbook CRM lookup snapshot.

    ``by_control`` is the legacy latest-wins map driving deterministic
    short-circuits (rule_crm_*). ``by_control_impls`` is the per-scope
    expansion driving the v0.2 multi-implementation persistence layer.

    Empty contexts are cheap and lookup-safe; the route handler always
    passes *some* CrmContext (possibly empty) so the kernel can stay
    null-check free past the parameter boundary.
    """

    by_control: dict[str, CrmEntry] = field(default_factory=dict)
    by_control_impls: dict[str, list[ImplementationSlice]] = field(
        default_factory=dict
    )

    @property
    def distinct_scope_label_count(self) -> int:
        """Number of distinct tenant scope_labels across all per-scope slices.

        This is the genuine multi-tenant signal. A scope_label is what
        distinguishes one cloud tenant's CRM from another (e.g. "AWS GovCloud"
        vs "Azure Government"); the synthesized ``On-Premises`` slice is
        excluded so it can't, by itself, make a single-cloud workbook look
        multi-tenant.

        ``>= 2`` means two or more real tenants are in play. Crucially this is
        derived from slices that DID populate — so a control whose own slices
        are empty can still be recognized as living in a multi-tenant workbook
        (other controls' slices reveal the tenant labels) and therefore must
        NOT short-circuit on the single latest-attach-wins entry, which would
        mask one tenant's customer-side work.

        Note we count *labels*, not baselines: splitting one logical CRM across
        several unlabeled baselines (a test/import convenience) does NOT look
        multi-tenant, because unlabeled baselines contribute no scope_label and
        no slices. Only deliberately scope-labeled CRMs count.
        """
        from ..baselines.scope_labels import ON_PREM_LABEL

        labels: set[str] = set()
        for slices in self.by_control_impls.values():
            for sl in slices:
                if sl.scope_label and sl.scope_label != ON_PREM_LABEL:
                    labels.add(sl.scope_label.casefold())
        return len(labels)

    @classmethod
    def empty(cls) -> CrmContext:
        return cls(by_control={}, by_control_impls={})

    def lookup(self, control_id: str) -> CrmEntry | None:
        return self.by_control.get(control_id)

    def implementations(self, control_id: str) -> list[ImplementationSlice]:
        """Return per-scope implementation slices for *control_id*.

        Empty list means: no CRM with a non-null scope_label covers this
        control. Callers (the assessor + persistence layer) treat that
        as "fall through to the legacy single-result path" — no impl
        rows are written, the parent Assessment's status/narrative_q
        carry the verdict on their own.
        """
        return self.by_control_impls.get(control_id, [])

    def scope_labels(self) -> list[str]:
        """Deduped scope labels across every control's impl slices.

        Feeds :func:`system_context.brief.build_boundary_brief` so the
        boundary brief names the concrete cloud platforms at the
        responsibility seam instead of a generic "cloud vs on-prem".
        First-seen order is preserved (cloud platforms first, the
        synthesized On-Premises slice last, matching the UI/exporter
        ordering). Empty when no scope-bearing CRM is attached — the
        brief then omits the responsibility-demarcation block.
        """
        seen: set[str] = set()
        out: list[str] = []
        for slices in self.by_control_impls.values():
            for sl in slices:
                key = sl.scope_label.casefold()
                if key in seen:
                    continue
                seen.add(key)
                out.append(sl.scope_label)
        return out


def build_crm_context(workbook_id: int, session: Session) -> CrmContext:
    """Join ``WorkbookOverlay`` -> ``Baseline`` (CRM) -> ``BaselineControl`` -> ``Control``.

    Returns the latest-wins map of ``control_id`` -> :class:`CrmEntry`
    AND the per-scope :class:`ImplementationSlice` groups used by the
    multi-impl persistence layer. Returns :meth:`CrmContext.empty` when
    the workbook has no CRM overlays — defensive against callers that
    always build a context even when no CRM is attached.
    """
    rows = session.exec(
        select(BaselineControl, Control, WorkbookOverlay, Baseline)
        .join(Baseline, Baseline.id == BaselineControl.baseline_id)  # type: ignore[arg-type]
        .join(Control, Control.id == BaselineControl.control_id)  # type: ignore[arg-type]
        .join(WorkbookOverlay, WorkbookOverlay.baseline_id == Baseline.id)  # type: ignore[arg-type]
        .where(WorkbookOverlay.workbook_id == workbook_id)
        .where(Baseline.source_type == BaselineSourceType.CRM)
        # Include rows where EITHER scope is specified — a CRM that only
        # carries on-prem verdicts (rare but valid) still contributes
        # short-circuit signal for the on-prem-only assets.
        .where(
            or_(
                BaselineControl.responsibility.is_not(None),  # type: ignore[union-attr]
                BaselineControl.responsibility_onprem.is_not(None),  # type: ignore[union-attr]
            )
        )
        .order_by(WorkbookOverlay.attached_at.desc())  # type: ignore[attr-defined]
    ).all()

    by_control: dict[str, CrmEntry] = {}
    by_control_impls: dict[str, list[ImplementationSlice]] = {}
    # Track (control_id, scope_label) to enforce latest-wins WITHIN a
    # scope when two CRMs share the same label (edge case — replace
    # semantics in the route layer normally prevent this, but a legacy
    # workbook may have stale attachments).
    seen_impls: set[tuple[str, str]] = set()

    for bc, ctrl, overlay, baseline in rows:
        # Legacy latest-wins map — unchanged behavior for the kernel's
        # existing rule_crm_* short-circuits.
        # FIXME(crm-audit): latest-wins on by_control is order-dependent
        # across CRMs with different scope_labels — e.g. AWS-Gov
        # "customer" attached first + Azure "inherited" attached second
        # will short-circuit COMPLIANT-by-inheritance via _lookup_crm,
        # silently dropping the AWS customer-side work. by_control_impls
        # preserves both, but assessor._run + crm_backfill consult only
        # by_control. Fix: pick most-restrictive responsibility across
        # all scope_labels for the same control_id, OR teach the
        # short-circuit path to consult by_control_impls. See
        # tests/engine/test_crm_context_edges.py::
        # test_multi_scope_label_latest_wins_in_by_control_can_drop_customer_verdict.
        if ctrl.control_id not in by_control:
            by_control[ctrl.control_id] = CrmEntry(
                control_id=ctrl.control_id,
                responsibility=bc.responsibility,
                narrative=bc.responsibility_narrative,
                source_baseline_id=overlay.baseline_id,
                responsibility_onprem=bc.responsibility_onprem,
                narrative_onprem=bc.responsibility_onprem_narrative,
            )

        # Per-scope impl group. Only Baselines that carry a scope_label
        # (i.e. v0.2-era CRM uploads) contribute slices; legacy CRMs
        # without a scope_label keep their lookup() behavior but don't
        # synthesize impl rows.
        if baseline.scope_label is None or bc.responsibility is None:
            continue
        key = (ctrl.control_id, baseline.scope_label)
        if key in seen_impls:
            continue
        seen_impls.add(key)
        by_control_impls.setdefault(ctrl.control_id, []).append(
            ImplementationSlice(
                scope_label=baseline.scope_label,
                responsibility=bc.responsibility,
                narrative=bc.responsibility_narrative,
                source_baseline_id=overlay.baseline_id,
            )
        )

    # Synthesize the On-Premises slice for any control whose cloud slices
    # leave customer-side work to do. Appended last so the UI/exporter
    # renders cloud platforms first, on-prem last — stable ordering keyed
    # to the user's mental model.
    for ctrl_id, slices in by_control_impls.items():
        already_has_onprem = any(s.scope_label == ON_PREM_LABEL for s in slices)
        if already_has_onprem:
            continue
        if any(
            s.responsibility in _CUSTOMER_OWNED_RESPONSIBILITIES for s in slices
        ):
            slices.append(
                ImplementationSlice(
                    scope_label=ON_PREM_LABEL,
                    responsibility="customer",
                    narrative=None,
                    source_baseline_id=None,
                )
            )

    return CrmContext(by_control=by_control, by_control_impls=by_control_impls)
