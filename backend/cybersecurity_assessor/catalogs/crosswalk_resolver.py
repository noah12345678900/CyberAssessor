"""Cross-framework lookup helpers over Crosswalk + ControlCrosswalk.

The :class:`Crosswalk` (objective-level) and :class:`ControlCrosswalk`
(control-level) tables shipped empty with the v0.1 schema. The v0.3 plan
needs them populated with real cross-framework data; this module provides
the read-side resolver so the rest of the app (Evidence-list filter,
SAR multi-framework rendering, future cross-framework assess) can ask
"what's the 800-53 equivalent of this FedRAMP control?" without re-deriving
the graph walk in every caller.

All three functions are **symmetric** — a Crosswalk row from A→B is treated
as equivalent to B→A. The underlying tables were designed direction-agnostic
(the ``from_``/``to_`` field names reflect insertion order, not semantic
direction), and any real-world mapping a vendor publishes is meant to be
bidirectional. Filtering by target framework happens after the walk.

Single-hop only — A→B→C does not resolve to A→C. Transitive resolution is
a v0.4 concern (it requires confidence multiplication and cycle detection)
and right now we have no data populated to exercise it anyway.
"""

from __future__ import annotations

from sqlmodel import Session, or_, select

from ..models import Control, ControlCrosswalk, Crosswalk, Objective


def resolve_equivalent_controls(
    session: Session,
    control_id: int,
    target_framework_id: int,
) -> list[Control]:
    """Return controls in ``target_framework_id`` equivalent to ``control_id``.

    Walks :class:`ControlCrosswalk` in both directions and filters the
    other-side controls to those owned by the target Framework. Empty list
    when no mapping exists or when the only mappings point at frameworks
    other than the target. The source control itself is **not** included —
    callers that want "the source plus its equivalents" should union the
    result with ``[session.get(Control, control_id)]``.
    """
    crosswalk_rows = session.exec(
        select(ControlCrosswalk).where(
            or_(
                ControlCrosswalk.from_control_id == control_id,
                ControlCrosswalk.to_control_id == control_id,
            )
        )
    ).all()

    if not crosswalk_rows:
        return []

    # Pick the "other side" of each row — whichever end isn't the source.
    other_ids: set[int] = set()
    for row in crosswalk_rows:
        other = row.to_control_id if row.from_control_id == control_id else row.from_control_id
        if other != control_id:  # guard against self-loops in the data
            other_ids.add(other)

    if not other_ids:
        return []

    return session.exec(
        select(Control)
        .where(Control.id.in_(other_ids))
        .where(Control.framework_id == target_framework_id)
    ).all()


def resolve_equivalent_objectives(
    session: Session,
    objective_id: int,
    target_framework_id: int,
) -> list[Objective]:
    """Return objectives in ``target_framework_id`` equivalent to ``objective_id``.

    Same single-hop, direction-symmetric semantics as
    :func:`resolve_equivalent_controls` but walking :class:`Crosswalk`.
    Filters by ``target_framework_id`` via a join through the objective's
    parent control.
    """
    crosswalk_rows = session.exec(
        select(Crosswalk).where(
            or_(
                Crosswalk.from_objective_id == objective_id,
                Crosswalk.to_objective_id == objective_id,
            )
        )
    ).all()

    if not crosswalk_rows:
        return []

    other_ids: set[int] = set()
    for row in crosswalk_rows:
        other = (
            row.to_objective_id
            if row.from_objective_id == objective_id
            else row.from_objective_id
        )
        if other != objective_id:
            other_ids.add(other)

    if not other_ids:
        return []

    # Join Objective → Control to filter by framework. Two-step query keeps
    # the SQL readable and lets SQLite use the existing indexes on both
    # objective.control_id_fk and control.framework_id.
    return session.exec(
        select(Objective)
        .join(Control, Control.id == Objective.control_id_fk)
        .where(Objective.id.in_(other_ids))
        .where(Control.framework_id == target_framework_id)
    ).all()


def objectives_visible_in_framework(
    session: Session,
    framework_id: int,
) -> set[int]:
    """Set of objective IDs visible when the active lens is ``framework_id``.

    Visible = directly owned by one of the framework's controls **or**
    crosswalk-equivalent (objective-level OR control-level) to one of them.
    Used by the Evidence-list filter to answer "which evidence is in scope
    when the user picks this framework?" — an Evidence row tagged on any
    objective in the returned set should appear.

    Returns a plain Python set so the caller can pass it straight into a
    ``WHERE Evidence.... IN (...)``-style subquery. SQLite handles large
    IN clauses fine (rowid lookup); the typical framework has well under
    10k objectives so we don't bother chunking.
    """
    # Step 1: direct objectives — those whose parent control sits on the
    # target framework.
    direct = set(
        session.exec(
            select(Objective.id)
            .join(Control, Control.id == Objective.control_id_fk)
            .where(Control.framework_id == framework_id)
        ).all()
    )

    if not direct:
        return set()

    visible: set[int] = set(direct)

    # Step 2: objective-level crosswalk — any objective whose Crosswalk
    # partner is in the direct set. Symmetric: a crosswalk row from external
    # objective X to a direct objective D means X is also visible.
    objective_crosswalks = session.exec(
        select(Crosswalk).where(
            or_(
                Crosswalk.from_objective_id.in_(direct),
                Crosswalk.to_objective_id.in_(direct),
            )
        )
    ).all()
    for row in objective_crosswalks:
        if row.from_objective_id in direct:
            visible.add(row.to_objective_id)
        if row.to_objective_id in direct:
            visible.add(row.from_objective_id)

    # Step 3: control-level crosswalk — any objective whose parent control
    # is crosswalk-equivalent to a direct control. Picks up the case where
    # a mapping was published at control granularity (CIS↔800-53, ISO↔800-53)
    # without per-objective crosswalk rows.
    direct_control_ids = set(
        session.exec(
            select(Control.id).where(Control.framework_id == framework_id)
        ).all()
    )
    if direct_control_ids:
        control_crosswalks = session.exec(
            select(ControlCrosswalk).where(
                or_(
                    ControlCrosswalk.from_control_id.in_(direct_control_ids),
                    ControlCrosswalk.to_control_id.in_(direct_control_ids),
                )
            )
        ).all()
        equivalent_control_ids: set[int] = set()
        for row in control_crosswalks:
            if row.from_control_id in direct_control_ids:
                equivalent_control_ids.add(row.to_control_id)
            if row.to_control_id in direct_control_ids:
                equivalent_control_ids.add(row.from_control_id)
        equivalent_control_ids -= direct_control_ids
        if equivalent_control_ids:
            equiv_objectives = session.exec(
                select(Objective.id).where(
                    Objective.control_id_fk.in_(equivalent_control_ids)
                )
            ).all()
            visible.update(equiv_objectives)

    return visible
