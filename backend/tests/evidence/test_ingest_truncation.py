"""Tests for per-file text-truncation in the ingest pipeline.

MAX_FILE_BYTES / IngestSummary.truncated / "[...TRUNCATED...]" marker.

We monkeypatch ingest.MAX_FILE_BYTES to a small value so the tests are
fast and deterministic without fabricating a 25 MB file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401 -- registers tables
from cybersecurity_assessor.evidence import ingest as ingest_mod
from cybersecurity_assessor.evidence.ingest import ingest_folder
from cybersecurity_assessor.models import Evidence, Workbook


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def workbook_id(session) -> int:
    """A minimal Workbook row; ingest_source requires workbook_id (PR 2)."""
    wb = Workbook(path="/tmp/trunc_test.xlsx", filename="trunc_test.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb.id


@pytest.fixture(autouse=True)
def small_cap(monkeypatch):
    """Reduce MAX_FILE_BYTES to 200 bytes so a tiny .txt triggers truncation."""
    monkeypatch.setattr(ingest_mod, "MAX_FILE_BYTES", 200)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _extracted_text(session: Session, path_fragment: str) -> str | None:
    """Load the stored extracted text for an evidence row by path substring."""
    rows = session.exec(select(Evidence)).all()
    for ev in rows:
        if path_fragment in ev.path:
            if ev.extracted_text_path:
                p = Path(ev.extracted_text_path)
                if p.exists():
                    return p.read_text(encoding="utf-8", errors="replace")
            return None
    return None


# ---------------------------------------------------------------------------
# Test: oversize file is truncated, Evidence row still created, summary.truncated == 1
# ---------------------------------------------------------------------------


def test_oversize_text_file_is_truncated(session, tmp_path, workbook_id):
    """A .txt file exceeding the cap gets a truncated evidence row with marker."""
    big = tmp_path / "big_log.txt"
    # Write 500 bytes of data — well over the 200-byte cap
    content = "A" * 500
    big.write_text(content, encoding="utf-8")

    summary = ingest_folder(session, tmp_path, workbook_id=workbook_id)

    assert summary.ingested == 1, "Evidence row must be created even when truncated"
    assert summary.truncated == 1, "summary.truncated must be incremented"
    assert summary.errors == [], "Truncation must not be an error"

    evs = session.exec(select(Evidence)).all()
    assert len(evs) == 1

    ev = evs[0]
    assert ev.extracted_text_path is not None, "Extracted text path must be recorded"
    stored = Path(ev.extracted_text_path).read_text(encoding="utf-8", errors="replace")
    assert "[...TRUNCATED" in stored, "Truncation marker must appear in stored text"
    assert len(stored.encode("utf-8")) < 500, "Stored text must be shorter than original"


# ---------------------------------------------------------------------------
# Test: under-cap file is NOT truncated
# ---------------------------------------------------------------------------


def test_undersized_file_not_truncated(session, tmp_path, workbook_id):
    """A file under the cap passes through without truncation."""
    small = tmp_path / "small_note.txt"
    small.write_text("hello world", encoding="utf-8")

    summary = ingest_folder(session, tmp_path, workbook_id=workbook_id)

    assert summary.ingested == 1
    assert summary.truncated == 0
    assert summary.errors == []

    evs = session.exec(select(Evidence)).all()
    assert len(evs) == 1
    if evs[0].extracted_text_path:
        stored = Path(evs[0].extracted_text_path).read_text(encoding="utf-8", errors="replace")
        assert "TRUNCATED" not in stored


# ---------------------------------------------------------------------------
# Test: mixed batch — only the oversize file increments truncated
# ---------------------------------------------------------------------------


def test_mixed_batch_only_large_increments_truncated(session, tmp_path, workbook_id):
    small = tmp_path / "a.txt"
    small.write_text("short text", encoding="utf-8")

    big = tmp_path / "b.txt"
    big.write_text("X" * 500, encoding="utf-8")

    summary = ingest_folder(session, tmp_path, workbook_id=workbook_id)

    assert summary.ingested == 2
    assert summary.truncated == 1
    assert summary.errors == []
