"""Inert ("Other") overlay loader.

When the unified overlay-import classifier (:mod:`overlay_classifier`)
can't recognize a file as either a CRM or a PSC overlay, we still want
to accept it: the user dropped it in for a reason. The fix is to
register a :class:`Baseline` row with ``source_type=OTHER`` so the file
shows up in the Workbooks page attach UI, but emit *zero*
``BaselineControl`` / ``RequirementSource`` / ``RequirementMap`` rows.
No resolver runs against an OTHER overlay during assessment — it's
inert metadata until someone programs a resolver for the file's
shape (see the engine OTHER-passthrough branches that log+skip).

Why not copy the file into a cache dir
--------------------------------------
The CRM loader stores the original path in ``Baseline.source_ref`` and
doesn't copy. We match that convention — re-import is idempotent
because we upsert on ``(source_type, source_ref)`` where source_ref is
the absolute path. If the user moves the source file later, the
overlay row stays valid (the file is never re-read by the engine
anyway, since no resolver consumes it).

Why a Baseline row at all if there's no resolver
------------------------------------------------
The Workbooks page's overlay attach UI joins
``WorkbookOverlay → Baseline``. Without a Baseline row, the file is
invisible to the user — they couldn't see "yes the system ingested
the file I dropped in." The inert Baseline row is the receipt.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlmodel import Session, select

from ..models import Baseline, BaselineSourceType, Framework
from .base import BaselineApplyResult


class OtherXlsxBaselineSource:
    """BaselineSource adapter for unclassified ("Other") overlay xlsx files.

    Apply is a metadata-only upsert — no rows materialize on
    ``BaselineControl``, ``RequirementSource``, or ``RequirementMap``.
    """

    source_type = BaselineSourceType.OTHER

    def __init__(
        self,
        workbook_path: str | Path,
        *,
        name: str | None = None,
        system_id: int | None = None,
    ) -> None:
        self.workbook_path = Path(workbook_path)
        # Default name: stem of the file so the Settings → Overlays chip
        # reads sensibly without forcing the user to type a label.
        # Caller can override with a real label at import time.
        self.name = name or f"Other: {self.workbook_path.stem}"
        self.system_id = system_id

    def _upsert_baseline(self, session: Session, framework_id: int) -> Baseline:
        """Upsert on ``(source_type, source_ref)``.

        Matches the CRM loader convention — re-importing the same file
        finds the existing row and bumps ``refreshed_at`` instead of
        creating a duplicate.
        """
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
            baseline.framework_id = framework_id
            if self.system_id is not None:
                baseline.system_id = self.system_id
            # Let a re-import update the user-visible label without
            # making the user delete-and-recreate.
            baseline.name = self.name
            baseline.refreshed_at = datetime.now(timezone.utc)
            session.add(baseline)
            session.commit()
            session.refresh(baseline)
        return baseline

    def apply(self, session: Session, *, framework_id: int) -> BaselineApplyResult:
        """Register the file as an inert Baseline. Emits no child rows.

        Raises ``ValueError`` if ``framework_id`` doesn't exist or if
        the source file is missing — both are bugs in the caller, not
        soft warnings.
        """
        framework = session.get(Framework, framework_id)
        if framework is None:
            raise ValueError(f"Framework id={framework_id} does not exist")
        if not self.workbook_path.exists():
            raise ValueError(
                f"Other-overlay file not found: {self.workbook_path}"
            )

        baseline = self._upsert_baseline(session, framework_id)
        return BaselineApplyResult(
            baseline=baseline,
            notes={
                "kind": "other",
                "resolver": None,
                "message": (
                    "Overlay imported as OTHER — no resolver is registered "
                    "for this shape, so it will not influence assessment "
                    "until one is programmed."
                ),
            },
        )
