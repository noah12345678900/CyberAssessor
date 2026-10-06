"""Data-preserving migration coverage for ODP workbook ownership."""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import command
from sqlalchemy import inspect, text
from sqlmodel import Session, create_engine, select

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.migrations import _alembic_config  # noqa: E402
from cybersecurity_assessor.models import OdpAssignment  # noqa: E402


def _upgrade(engine, revision: str) -> None:
    with engine.begin() as connection:
        command.upgrade(_alembic_config(connection=connection), revision)


def _downgrade(engine, revision: str) -> None:
    with engine.begin() as connection:
        command.downgrade(_alembic_config(connection=connection), revision)


def test_migration_preserves_legacy_odp_as_global_fallback(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'odp-migration.sqlite'}")
    _upgrade(engine, "0019")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO odpassignment (
                    framework_version, control_id, odp_id, assigned_from,
                    value, source_ingest, ingested_at, oscal_param_id,
                    slot_index, slot_total
                ) VALUES (
                    'NIST-800-53r4', 'ac-2', '{$37$}', 'DoW Enterprise',
                    'legacy value', 'CCIS-workbook', '2026-10-06 00:00:00',
                    'ac-2_prm_1', 0, 1
                )
                """
            )
        )

    _upgrade(engine, "head")

    with Session(engine) as session:
        rows = session.exec(select(OdpAssignment)).all()
        assert len(rows) == 1
        assert rows[0].id is not None
        assert rows[0].workbook_id is None
        assert rows[0].value == "legacy value"

    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("odpassignment")}
    assert {"id", "workbook_id"}.issubset(columns)
    assert inspector.get_pk_constraint("odpassignment")["constrained_columns"] == ["id"]
    engine.dispose()


def test_downgrade_collapses_scoped_duplicates_deterministically(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'odp-downgrade.sqlite'}")
    _upgrade(engine, "head")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO odpassignment (
                    workbook_id, framework_version, control_id, odp_id,
                    assigned_from, value, source_ingest, ingested_at
                ) VALUES
                    (1, 'NIST-800-53r4', 'ac-2', '{$37$}',
                     'DoW Enterprise', 'older', 'CCIS-workbook',
                     '2026-10-05 00:00:00'),
                    (2, 'NIST-800-53r4', 'ac-2', '{$37$}',
                     'DoW Enterprise', 'newer', 'CCIS-workbook',
                     '2026-10-06 00:00:00')
                """
            )
        )

    _downgrade(engine, "0019")
    with engine.connect() as connection:
        rows = connection.execute(text("SELECT value FROM odpassignment")).fetchall()
    assert rows == [("newer",)]
    columns = {column["name"] for column in inspect(engine).get_columns("odpassignment")}
    assert "id" not in columns
    assert "workbook_id" not in columns
    engine.dispose()
