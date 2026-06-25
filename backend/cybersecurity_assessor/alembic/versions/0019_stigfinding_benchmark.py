"""Checklist benchmark key — ``stigfinding.benchmark`` column.

Revision ID: 0019
Revises: 0018
Create Date: 2026-06-25

Why this migration exists
-------------------------
A DISA STIG assessment of a system arrives as TWO spreadsheet reports — a
MANUAL STIG-Viewer review (``STIG_Manual_report.xlsx``) and an AUTOMATED
OpenSCAP scan (``STIG_OSCAP_report.xlsx``) — each with one sheet per benchmark
and one column per host. The checklist-coverage unit is one benchmark assessed
on one host (e.g. "RHEL8 on paas-vdi-01"); a manual review PLUS an automated
scan of that same benchmark on that same host is ONE checklist assessed two
ways, not two checklists.

The two reports name the same benchmark differently in the per-rule columns
(Manual carries the STIG id ``RHEL-08-010030``; OSCAP carries a CCI token
``CCI-000366``), so the old counter — which derived the benchmark from
``rule_version`` — could not union them and double-counted (78 + 64 = 142
instead of the true union 78). The SHEET NAME, however, is byte-identical
across both files (both have sheets literally named ``RHEL8`` / ``FIREFOX``).
This column stores that sheet name as a stable, shared benchmark key so the
asset-coverage counter unions ``(boundary, benchmark, host)`` correctly.

It is a SEPARATE column rather than overloading ``rule_version`` because
``routes/stig.py`` exposes ``rule_version`` in its API and the per-rule STIG id
(``RHEL-08-010030``) is load-bearing there — overwriting it would lose that id.

Schema changes
--------------
* ``stigfinding`` — one new column:
    - ``benchmark`` VARCHAR NULL — canonical benchmark key (STIG-report sheet
      name). NULL for non-xlsx findings (.ckl/.cklb/XCCDF/Nessus), whose
      benchmark is still derived from ``rule_version``, and for legacy rows
      ingested before this column existed.

Idempotency
-----------
``_has_column`` guard mirrors ``0018``. Adding a NULLable column is a native
``ALTER TABLE ADD COLUMN`` on SQLite — no table rebuild, FKs untouched. Safe to
re-run against a DB already built by ``SQLModel.metadata.create_all``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

_TABLE = "stigfinding"
_COLUMN = "benchmark"


def _has_table(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _has_column(bind: sa.engine.Connection, table: str, column: str) -> bool:
    inspector = sa.inspect(bind)
    if table not in inspector.get_table_names():
        return False
    return any(c["name"] == column for c in inspector.get_columns(table))


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, _TABLE):
        # Fresh DB built via create_all before any migration ran — the model
        # already declares the column. Nothing to do.
        return
    if not _has_column(bind, _TABLE, _COLUMN):
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.String(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, _TABLE):
        return
    if _has_column(bind, _TABLE, _COLUMN):
        with op.batch_alter_table(_TABLE, schema=None) as batch_op:
            batch_op.drop_column(_COLUMN)
