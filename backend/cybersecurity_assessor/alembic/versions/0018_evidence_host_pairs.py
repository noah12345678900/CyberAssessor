"""Device-identity pairs — ``evidence.host_pairs`` sibling column.

Revision ID: 0018
Revises: 0017
Create Date: 2026-06-22

Why this migration exists
-------------------------
Asset reconciliation is device-centric: a credentialed ACAS/Nessus scan
reports BOTH the IP and the OS-resolved FQDN/netbios for the same live box
under ``<HostProperties>``. Capturing that ``(ip, fqdn)`` pairing is what
lets the asset cross-check collapse several scanned IPs under ONE device
(hostname) — assess/STIG once per device, IPs are attributes — instead of
counting each IP as a separate host (which produced the misleading
"Scanned 86 / Checklisted 0").

The pairs CANNOT ride in ``evidence.host_inventory``: that column is a flat
JSON ``list[str]`` of bare hostnames read by ``engine.evidence_bundle``,
``engine.finding_corroboration``, and ``evidence.sources.sweep``. Changing
its shape would break all three. So this adds a SIBLING column that carries
the structured ``[{"ip": ..., "fqdn": ...}, ...]`` list without touching the
existing contract.

Schema changes
--------------
* ``evidence`` — one new column:
    - ``host_pairs`` VARCHAR NULL — JSON list of ``{"ip","fqdn"}`` dicts.
      NULL for uncredentialed scans (IP only), single-host formats with no
      IP, and legacy rows ingested before this column existed.

Idempotency
-----------
``_has_column`` guard mirrors ``0013``. Adding a NULLable column is a native
``ALTER TABLE ADD COLUMN`` on SQLite — no table rebuild, FKs untouched. Safe
to re-run against a DB already built by ``SQLModel.metadata.create_all``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

_TABLE = "evidence"
_COLUMN = "host_pairs"


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
    # SQLite drop_column needs batch mode (table rebuild). The rebuild copies
    # forward every FK that references evidence.id.
    if _has_column(bind, _TABLE, _COLUMN):
        with op.batch_alter_table(_TABLE, schema=None) as batch_op:
            batch_op.drop_column(_COLUMN)
