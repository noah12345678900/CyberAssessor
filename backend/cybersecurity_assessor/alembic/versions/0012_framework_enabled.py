"""Framework enable/disable gate — ``framework.enabled`` column + index.

Revision ID: 0012
Revises: 0010
Create Date: 2026-06-08

Why this migration exists
-------------------------
The catalog is growing from two frameworks (NIST 800-53 r5 + FedRAMP) to
the full bundle (CSF 2.0, 800-171, ISO, CIS, PCI, SOC 2/3). Not every
program assesses against every framework, so each framework needs to be
independently enable/disable-able. A disabled framework disappears from the
active Catalog section and from the assess/baseline pickers, but stays
listed in Settings (as the toggle row) so it can be re-enabled.

Disabling is **presentation/selection-only**. It does NOT tear down the
parent→child inheritance that ``list_controls`` and ``catalog_status`` rely
on: a disabled parent's Control rows are still merged into any enabled
child framework. The column is purely a display gate read by the API
serializers and filtered client-side by the UI.

Schema changes
--------------
* ``framework`` — one new column:
    - ``enabled`` BOOLEAN NOT NULL, ``server_default`` true. Backfills every
      legacy row to enabled so nothing silently vanishes from the catalog
      on upgrade. Indexed because picker/catalog queries filter on it.

Numbering note
--------------
Head at authoring time is ``0010`` (chain: 0008 → 0011 → 0009 → 0010), so
``down_revision = "0010"``. This is the next sequential revision after the
parallel 0009/0010 evidence-scope branch merged behind 0011.

Idempotency
-----------
``_has_column`` / ``_has_index`` guards match the pattern in
``0008_poam_risk_provenance.py``. Safe to re-run against a DB that already
saw ``SQLModel.metadata.create_all`` (which creates the column directly).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0012"
down_revision = "0010"
branch_labels = None
depends_on = None


def _has_table(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _has_column(bind: sa.engine.Connection, table: str, column: str) -> bool:
    inspector = sa.inspect(bind)
    if table not in inspector.get_table_names():
        return False
    return any(c["name"] == column for c in inspector.get_columns(table))


def _has_index(bind: sa.engine.Connection, table: str, index: str) -> bool:
    if not _has_table(bind, table):
        return False
    return any(ix["name"] == index for ix in sa.inspect(bind).get_indexes(table))


def upgrade() -> None:
    bind = op.get_bind()

    # Self-heal a leftover batch temp table from an older revision of this
    # migration. The first cut used ``batch_alter_table`` (table copy + swap),
    # which on an interrupted run left ``_alembic_tmp_framework`` behind and
    # broke every subsequent startup. We no longer use batch mode here, but a
    # DB that hit the old path still needs the orphan dropped.
    if _has_table(bind, "_alembic_tmp_framework"):
        op.execute("DROP TABLE _alembic_tmp_framework")

    # Adding a NOT NULL column with a constant server_default is a native
    # ``ALTER TABLE ADD COLUMN`` on SQLite — no table rebuild required. The
    # earlier batch_alter_table approach forced a copy-and-DROP of
    # ``framework``, which fails under ``PRAGMA foreign_keys=ON`` (our default)
    # because child tables hold FK references to it. ``op.add_column`` avoids
    # the drop entirely.
    if _has_table(bind, "framework") and not _has_column(bind, "framework", "enabled"):
        op.add_column(
            "framework",
            sa.Column(
                "enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
        )

    if not _has_index(bind, "framework", "ix_framework_enabled"):
        op.create_index("ix_framework_enabled", "framework", ["enabled"])


def downgrade() -> None:
    bind = op.get_bind()

    if _has_index(bind, "framework", "ix_framework_enabled"):
        op.drop_index("ix_framework_enabled", table_name="framework")

    if _has_table(bind, "framework") and _has_column(bind, "framework", "enabled"):
        with op.batch_alter_table("framework", schema=None) as batch_op:
            batch_op.drop_column("enabled")
