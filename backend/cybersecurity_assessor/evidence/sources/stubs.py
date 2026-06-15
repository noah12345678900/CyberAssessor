"""Cloud-backed source stubs.

Placeholders for v0.2+ backends. They conform to the :class:`Source`
protocol so the orchestrator and UI can already pass instances around
(e.g. construct one from a Settings page form) without the wiring
crashing — calling :meth:`iter_files` is what raises.

The URI schemes these will produce are documented in
``sources/__init__.py``; concrete implementations should set
``container_uri`` on every emitted :class:`SourceFile` to the bucket /
library URI so evidence-list "ingested from" grouping keeps working
across backends.
"""

from __future__ import annotations

from typing import BinaryIO, Iterator

from .base import SourceFile


class _NotYetImplemented:
    """Common base — keeps the NotImplementedError message uniform."""

    _milestone: str = "v0.2"
    _scheme: str = ""

    def iter_files(self) -> Iterator[SourceFile]:  # pragma: no cover - stub
        raise NotImplementedError(
            f"{type(self).__name__} ({self._scheme}://) is planned for "
            f"cybersecurity-assessor {self._milestone}. Use LocalFolderSource for "
            "v0.1 ingest."
        )


class S3Source(_NotYetImplemented):
    """S3 bucket-prefix source. Planned: v0.2.

    Constructor will take ``bucket``, ``prefix``, and an optional
    boto3-style client/credentials handle. ``iter_files()`` will page
    through ``list_objects_v2`` and emit one :class:`SourceFile` per
    key whose suffix is in the ingestible set. ETag will be exposed
    via an extra attribute so the orchestrator can short-circuit
    re-ingest cheaply.
    """

    _scheme = "s3"

    def __init__(self, bucket: str, prefix: str = "") -> None:
        self.bucket = bucket
        self.prefix = prefix.lstrip("/")
        self.uri = f"s3://{bucket}/{self.prefix}"


class AzureBlobSource(_NotYetImplemented):
    """Azure Blob container source. Planned: v0.2.

    Constructor will take ``account``, ``container``, ``prefix``, and
    a credential (DefaultAzureCredential or SAS). Mirrors the S3
    shape; ContentMD5 is the ETag analogue.
    """

    _scheme = "azblob"

    def __init__(
        self, account: str, container: str, prefix: str = ""
    ) -> None:
        self.account = account
        self.container = container
        self.prefix = prefix.lstrip("/")
        self.uri = f"azblob://{account}/{container}/{self.prefix}"


# SharePointSource has moved to .sharepoint (real implementation, no longer a stub).
