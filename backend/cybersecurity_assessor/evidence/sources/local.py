"""Local-folder source.

Treats any local directory tree as a flat file repository — same
shape whether the root is on the workstation's C: drive, an NFS
mount, a OneDrive sync folder, or a UNC share. Zip archives
encountered during the walk are transparently descended into via
:class:`~.zip_source.ZipMemberSource`; the zip itself is not yielded
as a file, only its members are.

Hidden files (``.foo``) and Office lock files (``~$report.docx``) are
skipped to keep the evidence list clean.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator
from urllib.parse import quote

from .base import Source, SourceFile

# Same set the previous ingest module used. Kept here so the local
# walker can decide quickly whether to descend (.zip) or yield (.pdf
# etc.) without consulting the dispatcher's registry.
_INGESTIBLE_SUFFIXES = {
    ".pdf",
    ".docx",
    ".pptx",
    ".xlsx",
    ".xlsm",
    ".ckl",
    ".cklb",
    ".xml",
    ".arf",
    ".nessus",
    ".txt",
    ".md",
    ".log",
    ".csv",
    # Images (no OCR — filename/metadata tagging) + vector diagrams
    # (.vsdx/.svg shape text extracted). Admitted so screenshots and
    # network/boundary diagrams become visible evidence instead of being
    # silently dropped at the file walk.
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".tif",
    ".tiff",
    ".vsdx",
    ".svg",
}


def path_to_uri(path: Path) -> str:
    """Render an absolute path as a ``file://`` URI.

    Windows paths get the canonical ``file:///C:/...`` form so URIs
    compare equal across runs regardless of how the path was typed.
    Spaces and unicode chars are percent-encoded so the URI is safe
    to embed in JSON / logs.
    """
    abs_path = path.resolve()
    posix = abs_path.as_posix()
    # On Windows ``C:/foo`` → ``file:///C:/foo`` (three slashes).
    # On POSIX ``/foo`` → ``file:///foo`` (also three; the leading
    # slash of the path supplies one).
    if posix.startswith("/"):
        return "file://" + quote(posix, safe="/:")
    return "file:///" + quote(posix, safe="/:")


@dataclass
class LocalFile:
    """Concrete :class:`SourceFile` backed by a path on the local FS."""

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    _path: Path

    def open(self) -> BinaryIO:
        return self._path.open("rb")


class LocalFolderSource:
    """Walk a local directory tree and yield every ingestible file.

    Pass ``recursive=False`` to limit to the immediate folder (rarely
    useful in practice — evidence trees are nested). Zip archives are
    always descended regardless of ``recursive`` because the archive
    itself counts as one folder-step.
    """

    def __init__(self, root: Path | str, *, recursive: bool = True) -> None:
        self.root = Path(root)
        self.recursive = recursive
        self.uri = path_to_uri(self.root)

    def iter_files(self) -> Iterator[SourceFile]:
        if not self.root.exists() or not self.root.is_dir():
            return

        walker = self.root.rglob("*") if self.recursive else self.root.glob("*")
        for p in walker:
            if not p.is_file():
                continue
            name = p.name
            if name.startswith("~$") or name.startswith("."):
                continue
            suffix = p.suffix.lower()

            if suffix == ".zip":
                # Lazy import: ZipMemberSource pulls stdlib only, but
                # keeping the dependency chain shallow makes the
                # module graph easier to reason about.
                import zipfile

                from .zip_source import ZipMemberSource

                # Corrupt or partially-downloaded archives crop up in
                # real evidence trees (interrupted OneDrive sync, half-
                # written ACAS exports). Treat them like any other
                # unreadable noise: skip silently rather than poisoning
                # the whole walk. The orchestrator already records
                # per-file errors for archives that open but yield bad
                # members.
                try:
                    yield from ZipMemberSource(p).iter_files()
                except zipfile.BadZipFile:
                    pass
                continue

            if suffix not in _INGESTIBLE_SUFFIXES:
                continue

            try:
                size = p.stat().st_size
            except OSError:
                size = None

            yield LocalFile(
                uri=path_to_uri(p),
                name=name,
                size=size,
                # archive_uri is reserved for archive members (zip, tar, etc.)
                # — plain folder files have no holding archive, per the
                # API contract documented on Evidence.archive_uri.
                container_uri=None,
                _path=p,
            )

    def estimated_total(self) -> int:
        """Cheap pre-count of the files :meth:`iter_files` will yield.

        Duck-typed metadata the ingest-job registry calls (via ``getattr``)
        to give the UI a real progress bar + ETA instead of an indeterminate
        sweep. Reuses the exact same filter — suffix allow-list, lock/dotfile
        skip, zip descent — so the count matches the ``scanned`` counter the
        job reports, but skips the per-file ``stat``/URI work since only the
        tally matters. Returns 0 for a missing/empty root. Best-effort: a
        corrupt zip contributes 0 members rather than aborting the count.

        Streaming sources (e.g. SharePoint) deliberately do NOT implement this
        — pre-counting would mean a second network walk — so they fall back to
        the indeterminate bar.
        """
        if not self.root.exists() or not self.root.is_dir():
            return 0

        walker = self.root.rglob("*") if self.recursive else self.root.glob("*")
        total = 0
        for p in walker:
            if not p.is_file():
                continue
            name = p.name
            if name.startswith("~$") or name.startswith("."):
                continue
            suffix = p.suffix.lower()

            if suffix == ".zip":
                import zipfile

                from .zip_source import ZipMemberSource

                # Count members exactly as iter_files yields them so the ETA
                # denominator stays in lockstep with the scanned counter.
                try:
                    total += sum(1 for _ in ZipMemberSource(p).iter_files())
                except zipfile.BadZipFile:
                    pass
                continue

            if suffix not in _INGESTIBLE_SUFFIXES:
                continue

            total += 1
        return total


class SingleLocalFileSource:
    """Yield exactly one local file as a :class:`SourceFile`.

    Companion to :class:`LocalFolderSource` for callers that need to
    push a specific file through the orchestrator without walking a
    directory — the boundary-doc upload route is the motivating case:
    the user picks one SSP via the Electron file picker, and we want
    the same hash + extract + tag pipeline that a folder ingest gets.

    Zip files are not auto-descended here (unlike LocalFolderSource) —
    if the user explicitly picked an archive we treat it as a single
    blob; the boundary-doc UX is about docs, not archive trees. Lock
    files / dotfiles aren't filtered either; if you pointed at one,
    you meant it.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.uri = path_to_uri(self.path)

    def iter_files(self) -> Iterator[SourceFile]:
        p = self.path
        if not p.exists() or not p.is_file():
            return
        try:
            size = p.stat().st_size
        except OSError:
            size = None
        yield LocalFile(
            uri=path_to_uri(p),
            name=p.name,
            size=size,
            container_uri=None,
            _path=p,
        )
