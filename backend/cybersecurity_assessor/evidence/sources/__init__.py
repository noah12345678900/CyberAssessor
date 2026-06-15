"""Evidence source abstraction.

A :class:`Source` is anything that yields :class:`SourceFile` objects —
addressable byte payloads identified by URI. The ingest orchestrator
walks a source uniformly without caring whether the bytes live in a
local folder, an NFS mount, a zip archive, an S3 bucket, or a
SharePoint document library.

URI scheme convention
---------------------

Every ``SourceFile`` carries a canonical URI used as its primary
identifier in the evidence index (``Evidence.path``):

* ``file:///C:/Users/Noah/Downloads/foo.pdf`` — local file (or NFS
  mount mapped to a drive letter; same scheme either way).
* ``zip:///C:/path/to/archive.zip!/inner/foo.pdf`` — member inside a
  zip archive. The ``!`` separator follows the JAR/JDK convention so
  human readers can split the URI mentally.
* ``s3://bucket/key`` — S3 object (stub for v0.2+).
* ``azblob://account/container/key`` — Azure Blob (stub for v0.2+).
* ``sharepoint://host/sites/.../library/path/to/file.pdf`` — SharePoint
  document. Active implementation uses MSAL device-code flow against
  the configured tenant (GovCloud by default) and streams bytes via
  Office365-REST-Python-Client.
* ``tenable://host/scan/<scan_id>/<run_id>`` — Tenable.sc (on-prem) or
  Tenable.io (``host=cloud.tenable.com``) completed scan run. v0.4
  connector; gated behind a constructor feature flag. Bytes are the
  ``.nessus`` XML export for the run; ``run_id`` is the per-execution
  history id so re-ingest yields stable URIs across walks.
* ``snow-grc://<instance-host>/<table>/<sys_id>`` — ServiceNow GRC row
  (v0.4, feature-flagged). One Now Table row per :class:`SourceFile`;
  the payload is a JSON serialization of the row so the JSON extractor
  picks it up downstream.
* ``gitlab://host/group/subgroup/project@<commit_sha>/path/to/file.ckl`` —
  GitLab repository file pinned to a specific commit SHA. Re-ingesting at
  the same SHA hashes identically (orchestrator dedupe short-circuits);
  a new SHA materializes as fresh evidence. Active implementation uses
  the ``python-gitlab`` v4 REST client with a personal-access-token
  (env ``GITLAB_TOKEN`` first, then OS keychain per-host slot).
* ``confluence://host/page/<id>@<version>`` — Confluence Data Center
  page body, with a ``/attachment/<att_id>@<att_version>`` suffix for
  individual attachments. Version suffix is load-bearing for dedupe
  vs. update detection. Gated behind two feature flags
  (``connectors.v04`` + ``connectors.confluence_upcoming_gated``).

``container_uri`` is the URI of whatever holds the file — the archive
for zip members, the folder for local files, the bucket for S3. The
ingest orchestrator uses it to group children for "ingest source"
provenance.
"""

from __future__ import annotations

from .archer import (
    ArcherApplicationQuery,
    ArcherConfig,
    ArcherSource,
    feature_enabled as archer_feature_enabled,
)
from .base import Source, SourceFile, static_source
from .gitlab import GitLabSource
from .confluence import (
    ConfluenceFile,
    ConfluenceGatedError,
    ConfluenceSource,
    confluence_enabled,
)
from .jira import (
    JiraConfig,
    JiraConnectorDisabledError,
    JiraIssueFile,
    JiraSource,
    is_jira_connector_enabled,
    jira_issue_uri,
)
from .emass import EmassConnectorGatedError, EmassSource, emass_uri
from .local import LocalFolderSource, SingleLocalFileSource, path_to_uri
from .servicenow_grc import ServiceNowGrcSource
from .sharepoint import SharePointSource
from .splunk import SplunkResultFile, SplunkSource

# v0.4 boundary-discovery connector — feature-gated. Import is safe
# regardless of the flag; instantiation raises BoundarySweepDisabledError
# when the env flag is off so v0.1/v0.2/v0.3 builds can list it in the
# public API without accidentally activating it.
from .sp_boundary_sweep import (
    BoundaryLocation,
    BoundarySweepCaps,
    BoundarySweepDisabledError,
    SharePointBoundarySweepSource,
    is_enabled as boundary_sweep_enabled,
)
from .stubs import AzureBlobSource, S3Source
from .tenable import TenableScanFile, TenableSource
from .zip_source import ZipMemberSource, zip_member_uri

__all__ = [
    "Source",
    "SourceFile",
    "LocalFolderSource",
    "SingleLocalFileSource",
    "ZipMemberSource",
    "S3Source",
    "AzureBlobSource",
    "SharePointSource",
    "TenableSource",
    "TenableScanFile",
    "ServiceNowGrcSource",
    "ArcherSource",
    "ArcherConfig",
    "ArcherApplicationQuery",
    "archer_feature_enabled",
    "SplunkSource",
    "SplunkResultFile",
    # v0.4 boundary sweep — gated, see boundary_sweep_enabled()
    "BoundaryLocation",
    "BoundarySweepCaps",
    "BoundarySweepDisabledError",
    "SharePointBoundarySweepSource",
    "boundary_sweep_enabled",
    "GitLabSource",
    "ConfluenceSource",
    "ConfluenceFile",
    "ConfluenceGatedError",
    "confluence_enabled",
    # Jira connector (gated v0.4+)
    "JiraSource",
    "JiraIssueFile",
    "JiraConfig",
    "JiraConnectorDisabledError",
    "is_jira_connector_enabled",
    "jira_issue_uri",
    "EmassSource",
    "EmassConnectorGatedError",
    "emass_uri",
    "path_to_uri",
    "zip_member_uri",
    "static_source",
]
