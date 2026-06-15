"""Pin the two hardening guards on the working-copy directory layer.

The lazy-create flow in ``excel/working_copy.py`` is mostly forgiving —
``Path.mkdir(exist_ok=True)`` handles the "already exists" case, the
copy-forward branch handles a wiped working_copies tree, the
fresh-timestamp naming dodges Excel's exclusive lock — but two edge
cases needed explicit handling so they don't fail loudly mid-Apply:

  1. A FILE happens to occupy the per-workbook directory slot (e.g.
     the user pasted ``7`` into ``~/Downloads/CyberAssessor/`` without
     realising it was about to clash). ``mkdir(exist_ok=True)`` raises
     a bare ``FileExistsError`` here, which is opaque to the assessor.
     ``_assert_parent_is_directory`` upgrades that to an actionable
     ``RuntimeError``.

  2. The SQLite DB was wiped between sessions but
     ``~/Downloads/CyberAssessor/`` was left in place. The new
     ``Workbook`` row gets the same auto-increment id as a prior one,
     and the copy-forward branch would have happily picked up the
     previous tenant's file as if it were our own — silent data
     corruption. ``_quarantine_foreign_working_copies`` moves any file
     whose stem doesn't match the current workbook into an
     ``_orphans_<ts>`` subdirectory and logs a WARNING.

These tests pin both behaviours so a refactor that drops them surfaces
here instead of via a confused assessor staring at someone else's
narratives in their workbook.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.excel import working_copy  # noqa: E402
from cybersecurity_assessor.excel.working_copy import (  # noqa: E402
    WORKING_SUFFIX,
    _assert_parent_is_directory,
    _quarantine_foreign_working_copies,
    get_or_create_working_copy,
)
from cybersecurity_assessor.models import Framework, Workbook  # noqa: E402


@pytest.fixture
def session():
    """Fresh in-memory SQLite per test; isolation is the whole point here."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def patched_working_dir(tmp_path, monkeypatch):
    """Redirect ``working_copies_dir()`` into pytest's tmp_path.

    The production helper lives at ``~/Downloads/CyberAssessor/`` and
    we absolutely do not want the test suite littering the user's real
    Downloads folder. Patch the module-local reference so every call
    site inside ``working_copy.py`` sees the tmp path.
    """
    target = tmp_path / "working_copies"
    target.mkdir()
    monkeypatch.setattr(working_copy, "working_copies_dir", lambda: target)
    return target


def _make_workbook(session: Session, source: Path) -> Workbook:
    """Persist a minimal Workbook row pointing at ``source``."""
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    wb = Workbook(path=str(source), filename=source.name, framework_id=fw.id)
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


# ---------------------------------------------------------------------------
# Guard 1: parent path occupied by a file, not a directory
# ---------------------------------------------------------------------------


def test_assert_parent_is_directory_raises_when_file_occupies_slot(tmp_path):
    """A regular file at the parent path → RuntimeError with guidance.

    The raw ``mkdir(exist_ok=True)`` raises FileExistsError here, which
    surfaces to the user as a 500 with no hint about what to fix. The
    guard converts it into a message naming the offending path.
    """
    slot = tmp_path / "7"
    slot.write_bytes(b"i am a file pretending to be a directory")

    with pytest.raises(RuntimeError, match="exists as a file, not a directory"):
        _assert_parent_is_directory(slot)


def test_assert_parent_is_directory_noop_when_dir_exists(tmp_path):
    """Pre-existing directory must not raise — that's the happy path."""
    slot = tmp_path / "7"
    slot.mkdir()
    _assert_parent_is_directory(slot)  # no raise


def test_assert_parent_is_directory_noop_when_path_missing(tmp_path):
    """Missing path is fine — mkdir will create it."""
    slot = tmp_path / "does_not_exist_yet"
    _assert_parent_is_directory(slot)  # no raise


def test_get_or_create_working_copy_surfaces_file_in_slot_clearly(
    tmp_path, patched_working_dir, session
):
    """End-to-end: a file blocking the per-wb_id slot yields a clean error.

    Without the guard the user sees ``FileExistsError: [WinError 183]``
    or similar with no actionable text; with the guard they see the
    path of the offending file and the instruction to move it.
    """
    src = tmp_path / "Foo.xlsx"
    src.write_bytes(b"x" * 16)
    wb = _make_workbook(session, src)

    # Pre-create a regular file at the slot the working copy wants.
    blocker = patched_working_dir / str(wb.id)
    blocker.write_bytes(b"misplaced file")

    with pytest.raises(RuntimeError, match="exists as a file, not a directory"):
        get_or_create_working_copy(wb, session)


# ---------------------------------------------------------------------------
# Guard 2: orphan working copies from a previous wb_id tenant
# ---------------------------------------------------------------------------


def test_quarantine_moves_foreign_files_into_orphans_subdir(tmp_path, caplog):
    """Files not matching the expected stem prefix get sequestered.

    Two files in the slot — one belongs to the new workbook (matches
    the expected prefix), one is leftover from the prior DB lifetime.
    After the call the foreign one lives under ``_orphans_<ts>/`` and
    the matching one is untouched.
    """
    slot = tmp_path / "7"
    slot.mkdir()
    ours = slot / f"NewWorkbook{WORKING_SUFFIX}_20260606T120000.xlsx"
    ours.write_bytes(b"new")
    foreign = slot / f"OldWorkbook{WORKING_SUFFIX}_20250101T000000.xlsx"
    foreign.write_bytes(b"old")

    with caplog.at_level("WARNING"):
        _quarantine_foreign_working_copies(slot, "NewWorkbook")

    assert ours.exists(), "matching file must not be touched"
    assert not foreign.exists(), "foreign file must be moved out of the slot"

    # Find the quarantine subdir (timestamped — match by prefix).
    orphan_dirs = [p for p in slot.iterdir() if p.is_dir() and p.name.startswith("_orphans_")]
    assert len(orphan_dirs) == 1, "exactly one quarantine subdir expected"
    moved = orphan_dirs[0] / foreign.name
    assert moved.exists(), "foreign file should now live inside the quarantine subdir"
    assert moved.read_bytes() == b"old", "quarantined file content preserved"

    # The warning is the operator's only signal that this happened.
    assert any("Quarantined" in r.message for r in caplog.records)


def test_quarantine_is_noop_when_only_matching_files_present(tmp_path, caplog):
    """No foreign files → no quarantine subdir, no warning.

    The fresh-row scan runs on every first Apply; it must stay silent
    in the common case where the slot is empty or contains only our
    own working copies.
    """
    slot = tmp_path / "7"
    slot.mkdir()
    ours = slot / f"NewWorkbook{WORKING_SUFFIX}_20260606T120000.xlsx"
    ours.write_bytes(b"new")

    with caplog.at_level("WARNING"):
        _quarantine_foreign_working_copies(slot, "NewWorkbook")

    assert ours.exists()
    assert not any(p.is_dir() and p.name.startswith("_orphans_") for p in slot.iterdir())
    assert not any("Quarantined" in r.message for r in caplog.records)


def test_quarantine_is_noop_when_slot_missing(tmp_path):
    """Quarantine on a non-existent slot is a no-op — first Apply ever."""
    _quarantine_foreign_working_copies(tmp_path / "never_created", "Anything")
    # No raise = pass.


def test_get_or_create_working_copy_quarantines_on_first_apply_only(
    tmp_path, patched_working_dir, session, caplog
):
    """The quarantine scan runs only when ``wb.working_path`` is None.

    First Apply on a re-created DB row: slot has a leftover file → we
    quarantine and log. Second Apply on the same row: ``working_path``
    is now set, so even if a foreign file were dropped into the slot
    we don't scan it (we already know which file is ours via the DB).
    """
    src = tmp_path / "Foo.xlsx"
    src.write_bytes(b"x" * 16)
    wb = _make_workbook(session, src)

    # Pre-seed the slot with a leftover from a "prior tenant".
    slot = patched_working_dir / str(wb.id)
    slot.mkdir()
    leftover = slot / f"OldStem{WORKING_SUFFIX}_20250101T000000.xlsx"
    leftover.write_bytes(b"prior tenant data")

    with caplog.at_level("WARNING"):
        first = get_or_create_working_copy(wb, session)

    assert first.exists()
    assert first.name.startswith(f"Foo{WORKING_SUFFIX}_")
    assert not leftover.exists(), "leftover must be quarantined on first Apply"
    assert any("Quarantined" in r.message for r in caplog.records)

    # Drop another foreign file and run Apply again — wb.working_path
    # is set now, so the scan should NOT happen.
    intruder = slot / "another_foreign_file.xlsx"
    intruder.write_bytes(b"should be ignored")
    caplog.clear()

    with caplog.at_level("WARNING"):
        second = get_or_create_working_copy(wb, session)

    assert second.exists()
    assert second != first, "second Apply must produce a fresh timestamped file"
    assert intruder.exists(), "second Apply must not quarantine (working_path is set)"
    assert not any("Quarantined" in r.message for r in caplog.records)
