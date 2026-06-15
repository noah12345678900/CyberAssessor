"""Source / SourceFile protocols.

Kept in their own module so concrete implementations (local folder,
zip member, cloud blob) can import them without circular imports.

The protocols are deliberately tiny — anything more couples the ingest
loop to a particular backend. If a backend needs richer metadata
(e.g. S3 ETag for short-circuit dedupe), it puts the extra fields on
its concrete ``SourceFile`` subclass and the orchestrator inspects
them via ``getattr`` rather than expanding the protocol.
"""

from __future__ import annotations

from typing import BinaryIO, Iterable, Iterator, Protocol, runtime_checkable


@runtime_checkable
class SourceFile(Protocol):
    """One addressable byte payload from a :class:`Source`.

    Attributes:
        uri: Canonical URI (see ``sources/__init__.py`` for scheme
            conventions). Stable across re-ingest runs; used as the
            primary key in ``Evidence.path``.
        name: Leaf filename without path components — drives the
            extractor's extension lookup and feeds the filename
            heuristics in the doc-number / family tagger.
        size: Byte size if cheaply available, else ``None``. Pure
            metadata — never required to be correct, never the basis
            for dedupe.
        container_uri: URI of the holding folder / archive / bucket.
            Used for provenance grouping in the evidence list ("all
            files ingested from this folder").
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None

    def open(self) -> BinaryIO:
        """Return a readable binary stream. Caller is responsible for closing."""
        ...


@runtime_checkable
class Source(Protocol):
    """A producer of :class:`SourceFile` objects.

    Implementations decide their own walk semantics — local folder
    recurses by default, zip member source streams archive entries in
    archive order, cloud sources may page through a bucket prefix.

    The ingest orchestrator only consumes the iterator; it never
    inspects a source's type. New backends slot in by implementing
    this protocol — no orchestrator changes required.
    """

    uri: str
    """Top-level URI describing the source itself — e.g.
    ``file:///C:/Users/Noah/Downloads/`` for a folder. Recorded on
    ``IngestSummary`` so the UI can show which root was just walked."""

    def iter_files(self) -> Iterator[SourceFile]:
        """Yield every ingestible file under this source.

        Implementations should skip noise (hidden files, Office lock
        files, unsupported extensions) themselves — the orchestrator
        treats whatever the iterator yields as worth attempting.
        """
        ...


# Helper for backends that want to expose a one-liner factory while
# still letting tests inject a custom iterable.
def static_source(uri: str, files: Iterable[SourceFile]) -> Source:
    """Wrap an iterable of ``SourceFile`` as a :class:`Source`.

    Used in tests and in cases where the file list is pre-computed
    elsewhere (e.g. a SharePoint search result that we want to feed
    through the same ingest pipeline).
    """

    class _StaticSource:
        def __init__(self) -> None:
            self.uri = uri
            self._files = list(files)

        def iter_files(self) -> Iterator[SourceFile]:
            yield from self._files

    return _StaticSource()
