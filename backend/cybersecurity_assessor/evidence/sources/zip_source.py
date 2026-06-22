"""Zip-archive source.

Streams members out of a zip without ever extracting them to disk.
Members carry a ``zip://`` URI of the form::

    zip:///C:/path/to/archive.zip!/inner/dir/file.pdf

The ``!`` separator matches the JAR / Spring Boot convention so a
human reading a log can split archive path from member path by eye.

The archive itself remains the unit of provenance — every member's
``container_uri`` points back to the archive, and the
:class:`LocalFolderSource` walker descends into a zip rather than
yielding it, which means the zip never gets indexed as evidence in
its own right.

Nested zips are handled recursively: an inner ``.zip`` member opens
into another :class:`ZipMemberSource` over an in-memory buffer.

Heavy hardening (zip-bombs, path traversal) is deliberately left to a
future pass — current evidence comes from internal sources, not
adversarial uploads. If we ever expose ingest to untrusted input,
this is where to add `compressed_size` ratio checks and member-name
normalization.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterator
from urllib.parse import quote

from .base import Source, SourceFile
from .local import path_to_uri

# Mirror LocalFolderSource so a zip yields the same file set a folder
# would. Kept local to this module to avoid a cross-module constant
# import cycle if the suffix list ever diverges.
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
    ".json",
    # Packet captures — summary-digest extractor (stdlib, dependency-free).
    ".pcap",
    ".pcapng",
    ".cap",
    # Images + vector diagrams (see local.py for rationale).
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


def zip_member_uri(archive_uri: str, member_name: str) -> str:
    """Build a ``zip://`` URI for a member inside an archive.

    ``archive_uri`` is expected to be a ``file://`` URI for the
    archive on disk; we swap the scheme to ``zip://`` and append
    ``!/`` plus the percent-encoded inner path.
    """
    base = archive_uri.replace("file://", "zip://", 1)
    return f"{base}!/{quote(member_name, safe='/')}"


@dataclass
class ZipMemberFile:
    """Concrete :class:`SourceFile` backed by bytes inside a zip archive.

    Holds the parent ``ZipFile`` so successive ``open()`` calls don't
    re-read the central directory. The orchestrator opens-and-reads
    each member once, so contention is non-existent in practice.
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    _archive: zipfile.ZipFile
    _member: str

    def open(self) -> BinaryIO:
        # ZipFile.open returns a ZipExtFile, which is a binary stream
        # but is not seekable. Most extractors only need ``.read()``;
        # the few that wrap the stream with a library that wants seek
        # (``openpyxl`` in read-only mode is fine; ``pdfplumber`` is
        # fine) handle non-seekable inputs by buffering internally.
        return self._archive.open(self._member, "r")


class ZipMemberSource:
    """Iterate members of a zip archive as :class:`SourceFile` objects.

    Nested zips are recursed into — a member ending in ``.zip`` opens
    into a sub-source over an in-memory buffer (no temp file). All
    members keep their ``container_uri`` pointing at the *outer*
    archive so provenance grouping stays useful.
    """

    def __init__(self, archive: Path | str) -> None:
        self.archive_path = Path(archive)
        self.uri = path_to_uri(self.archive_path).replace(
            "file://", "zip://", 1
        ) + "!/"
        self._zf = zipfile.ZipFile(self.archive_path, "r")
        self._archive_file_uri = path_to_uri(self.archive_path)

    def iter_files(self) -> Iterator[SourceFile]:
        for info in self._zf.infolist():
            if info.is_dir():
                continue
            member_name = info.filename
            leaf = PurePosixPath(member_name).name
            if not leaf:
                continue
            if leaf.startswith("~$") or leaf.startswith("."):
                continue
            suffix = PurePosixPath(leaf).suffix.lower()

            if suffix == ".zip":
                # Read the nested zip into memory and recurse. Nested
                # archives are rare; loading the whole inner zip is
                # fine for evidence-sized payloads.
                with self._zf.open(info, "r") as inner:
                    buf = io.BytesIO(inner.read())
                # Sub-source needs a stable URI; use the outer archive
                # path plus the inner member as a synthetic one.
                inner_archive_uri = zip_member_uri(
                    self._archive_file_uri, member_name
                )
                yield from _InMemoryZipSource(buf, inner_archive_uri).iter_files()
                continue

            if suffix not in _INGESTIBLE_SUFFIXES:
                continue

            yield ZipMemberFile(
                uri=zip_member_uri(self._archive_file_uri, member_name),
                name=leaf,
                size=info.file_size,
                container_uri=self._archive_file_uri,
                _archive=self._zf,
                _member=member_name,
            )


class _InMemoryZipSource:
    """Walk a zip whose bytes already live in memory.

    Used for nested zips so we don't have to round-trip through the
    filesystem. The synthetic URI is ``zip://outer!/inner!/`` so the
    nesting is visible in logs.
    """

    def __init__(self, buf: io.BytesIO, archive_uri: str) -> None:
        self._buf = buf
        self.uri = archive_uri + "!/"
        self._zf = zipfile.ZipFile(buf, "r")
        self._archive_uri = archive_uri

    def iter_files(self) -> Iterator[SourceFile]:
        for info in self._zf.infolist():
            if info.is_dir():
                continue
            member_name = info.filename
            leaf = PurePosixPath(member_name).name
            if not leaf or leaf.startswith("~$") or leaf.startswith("."):
                continue
            suffix = PurePosixPath(leaf).suffix.lower()
            if suffix not in _INGESTIBLE_SUFFIXES:
                # Deliberately do NOT recurse further; two-deep zips
                # are already exotic.
                continue
            yield ZipMemberFile(
                uri=f"{self._archive_uri}!/{quote(member_name, safe='/')}",
                name=leaf,
                size=info.file_size,
                container_uri=self._archive_uri,
                _archive=self._zf,
                _member=member_name,
            )
