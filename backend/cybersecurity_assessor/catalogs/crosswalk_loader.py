"""Cross-framework / cross-revision control crosswalk loaders.

Today this just auto-builds the NIST 800-53 rev4 ↔ rev5 mapping by control_id
match. Most controls are 1:1 across revs (AC-2(1) r4 → AC-2(1) r5). Rev5
added a few new controls (PT family, SR family, etc.) and withdrew a handful
from rev4; those show up as unmapped on either side and are returned in
the result for review.

The same table (:class:`ControlCrosswalk`) will later host published
mappings for CIS Controls → 800-53 and ISO 27002 → 800-53 (v0.5/v0.6).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlmodel import Session, select

from ..models import Control, ControlCrosswalk, Framework


@dataclass
class CrosswalkLoadResult:
    """Counts from a single auto-crosswalk run."""

    from_framework_id: int
    to_framework_id: int
    pairs_created: int = 0
    pairs_already_present: int = 0
    unmapped_from: list[str] = field(default_factory=list)  # control_ids only in `from`
    unmapped_to: list[str] = field(default_factory=list)  # control_ids only in `to`


def _resolve_framework(session: Session, framework_id: int) -> Framework:
    fw = session.get(Framework, framework_id)
    if fw is None:
        raise ValueError(f"Framework id={framework_id} not found")
    return fw


def load_id_match_crosswalk(
    session: Session,
    *,
    from_framework_id: int,
    to_framework_id: int,
    source_label: str = "auto-id-match",
    confidence: float = 1.0,
) -> CrosswalkLoadResult:
    """Auto-create :class:`ControlCrosswalk` rows by matching ``control_id``.

    Idempotent — re-running won't duplicate pairs. The directional pair
    ``(from → to)`` is recorded; if you want the reverse, call again with the
    framework ids swapped.

    Args:
        session: active SQLModel session.
        from_framework_id: source framework (e.g. rev4 Framework.id).
        to_framework_id: target framework (e.g. rev5 Framework.id).
        source_label: stored on each new row; defaults to ``auto-id-match``.
            Use ``"NIST-rev-mapping"`` if seeding from NIST's official
            transition spreadsheet later.
        confidence: stored on each new row. 1.0 for ID-match, lower for
            heuristic / NLP mappings.
    """
    if from_framework_id == to_framework_id:
        raise ValueError("from_framework_id and to_framework_id must differ")

    _resolve_framework(session, from_framework_id)
    _resolve_framework(session, to_framework_id)

    from_rows = session.exec(
        select(Control).where(Control.framework_id == from_framework_id)
    ).all()
    to_rows = session.exec(
        select(Control).where(Control.framework_id == to_framework_id)
    ).all()

    to_by_id = {c.control_id: c for c in to_rows}
    from_ids = {c.control_id for c in from_rows}

    # Existing pairs in this direction (so the run is idempotent)
    existing_pairs = {
        (r.from_control_id, r.to_control_id)
        for r in session.exec(select(ControlCrosswalk)).all()
    }

    result = CrosswalkLoadResult(
        from_framework_id=from_framework_id,
        to_framework_id=to_framework_id,
    )

    for from_ctrl in from_rows:
        to_ctrl = to_by_id.get(from_ctrl.control_id)
        if to_ctrl is None:
            result.unmapped_from.append(from_ctrl.control_id)
            continue
        # We already validated both rows exist, so both IDs are populated
        pair = (from_ctrl.id, to_ctrl.id)
        if pair in existing_pairs:
            result.pairs_already_present += 1
            continue
        session.add(
            ControlCrosswalk(
                from_control_id=from_ctrl.id,  # type: ignore[arg-type]
                to_control_id=to_ctrl.id,  # type: ignore[arg-type]
                source=source_label,
                confidence=confidence,
            )
        )
        result.pairs_created += 1

    result.unmapped_to = sorted(
        cid for cid in to_by_id.keys() if cid not in from_ids
    )
    result.unmapped_from.sort()
    session.commit()
    return result
