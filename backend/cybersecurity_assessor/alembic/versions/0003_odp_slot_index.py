"""Add ``slot_index`` + ``slot_total`` columns for catalog-agnostic OSCAL bridge.

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-06

Why these columns exist
-----------------------
``oscal_param_id`` is a *cache* of the OSCAL bridge — derived at ingest by
positional alignment of the workbook's ODP slots against the catalog's
declared OSCAL params. It works the moment the workbook is loaded, but
the catalog state can shift independently:

* A catalog reload overwrites ``Control.statement`` (see
  ``catalogs/oscal_loader.py:286``), which can change param ids when a
  source catalog revision drifts.
* FedRAMP shadow Controls synthesize a statement embedding the parent's
  param ids verbatim; if the parent framework is re-loaded, the shadow's
  statement is regenerated on the next profile load.
* Rev 4 vs Rev 5 catalogs use different param id conventions
  (``ac-2_prm_1`` vs ``ac-02_odp.01``) for the SAME slot position.

``slot_index`` is the catalog-agnostic anchor: the row's 0-based position
in the workbook's declared slot list. Slot 0 is slot 0 forever,
regardless of what the catalog later decides to name it. The render
layer re-derives the current OSCAL id at lookup time against whatever
the catalog statement says today.

``slot_total`` records how many slots the workbook DECLARED for the
control — not how many are filled. Stored on every row (all rows for the
same control share the value) so the render-time count-match safety
check ("workbook slot count == catalog param count → positional mapping
is safe") survives the sparse case: a workbook that declared 4 slots but
only filled 2 leaves ``len(by_slot) == 2``, which would incorrectly
abstain. ``slot_total == len(template_oscal_params)`` is the correct
guard. Without this, the sparse case silently falls through to
"unresolved" even when the bridge is logically sound.

Both columns are nullable because pre-existing rows ingested under v0.1
(before these columns existed) have no recorded position; the ingest
path will backfill them on the next ``apply()`` of the originating
workbook. Render falls through to ``odp_id`` lookup for any row still
NULL on either column, which preserves v0.1 behavior end-to-end.

Idempotency
-----------
Wrapped in ``batch_alter_table`` so SQLite gets a clean table rebuild
without losing data. Each ``add_column`` is independently guarded with
an introspection check so re-running this migration against a DB that
already has one or both columns (dev boxes that ran 0001 with the
updated model definition already in place) does not error. The guards
also let us add ``slot_total`` to a DB that already had ``slot_index``
applied — no need to chain a fresh 0004 for what is the same logical
change (the OSCAL slot-bridge column set).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def _has_column(bind: sa.engine.Connection, table: str, column: str) -> bool:
    inspector = sa.inspect(bind)
    if table not in inspector.get_table_names():
        return False
    return any(c["name"] == column for c in inspector.get_columns(table))


def upgrade() -> None:
    bind = op.get_bind()
    need_slot_index = not _has_column(bind, "odpassignment", "slot_index")
    need_slot_total = not _has_column(bind, "odpassignment", "slot_total")
    if not need_slot_index and not need_slot_total:
        return
    with op.batch_alter_table("odpassignment", schema=None) as batch_op:
        if need_slot_index:
            batch_op.add_column(sa.Column("slot_index", sa.Integer(), nullable=True))
        if need_slot_total:
            batch_op.add_column(sa.Column("slot_total", sa.Integer(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    have_slot_index = _has_column(bind, "odpassignment", "slot_index")
    have_slot_total = _has_column(bind, "odpassignment", "slot_total")
    if not have_slot_index and not have_slot_total:
        return
    with op.batch_alter_table("odpassignment", schema=None) as batch_op:
        if have_slot_total:
            batch_op.drop_column("slot_total")
        if have_slot_index:
            batch_op.drop_column("slot_index")
