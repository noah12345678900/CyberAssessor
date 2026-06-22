"""Evidence ingest + browse endpoints.

The ingest body is a discriminated union on ``source.type`` so the UI
can pick whichever backend matches the user's intent — local folder
today, cloud / SharePoint as they come online — without growing
parallel endpoints. The orchestrator does the actual work uniformly
via the :class:`Source` protocol.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Union
from urllib.parse import unquote, urlparse

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlmodel import Session, delete, select

from ..catalogs.crosswalk_resolver import (
    objectives_visible_in_framework,
    resolve_equivalent_controls,
)
from ..db import chunked, get_session
from ..engine.invalidation import invalidate_assessments_for_objectives
from ..evidence.asset_crosscheck import summarize_asset_coverage
from ..evidence.extractors import ExtractorError, ExtractorSkip, extract_stream
from ..evidence.ingest import (
    _build_tagger_llm,
    _framework_id_for_workbook,
    ingest_single_local_file,
)
from ..evidence.jobs import registry as ingest_jobs
from ..evidence.tagger import tag_evidence
from ..evidence.sources import (
    AzureBlobSource,
    LocalFolderSource,
    S3Source,
    SharePointSource,
)
from ..models import (
    AssessmentCitation,
    AssessmentEvidenceShown,
    Asset,
    BoundarySegment,
    BoundaryTokenSource,
    Component,
    Control,
    Evidence,
    EvidenceAsset,
    EvidenceBoundary,
    EvidenceComponent,
    EvidenceTag,
    Objective,
    PoamEvidence,
    ScopeLinkSource,
    StigFinding,
    iso_utc,
)

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


# ---------------------------------------------------------------------------
# URI rendering helpers
# ---------------------------------------------------------------------------


def _display_path(uri: str) -> str:
    """Render a canonical URI in a form a human wants to see.

    file:///C:/Users/foo/bar.pdf     → C:/Users/foo/bar.pdf
    zip:///C:/foo.zip!/inner/a.pdf   → C:/foo.zip!/inner/a.pdf
    s3://bucket/key                  → s3://bucket/key   (kept as-is — it IS the address)
    sharepoint://host/lib/a.pdf      → sharepoint://host/lib/a.pdf
    /legacy/bare/path                → /legacy/bare/path
    """
    if uri.startswith("file:///"):
        return unquote(uri[len("file:///"):])
    if uri.startswith("zip:///"):
        return unquote(uri[len("zip:///"):])
    return uri


def _leaf_name(uri: str) -> str:
    """Filename component of any URI we mint, for display purposes.

    For zip member URIs the leaf is the last path segment of the
    inner-member portion (after ``!/``); for plain file/cloud URIs it
    is the last path segment.
    """
    # Zip URI: split on the "!/" separator and take the inner tail.
    if "!/" in uri:
        inner = uri.rsplit("!/", 1)[-1]
        return PurePosixPath(unquote(inner)).name or inner
    # Strip scheme + netloc.
    try:
        parsed = urlparse(uri)
        path = parsed.path or uri
    except ValueError:
        path = uri
    return PurePosixPath(unquote(path)).name or uri


def _serialize(e: Evidence) -> dict:
    return {
        "id": e.id,
        "path": e.path,                       # canonical URI
        "display_path": _display_path(e.path),
        "filename": _leaf_name(e.path),
        "archive_uri": e.archive_uri,
        "title": e.title,
        "doc_number": e.doc_number,
        "kind": e.kind,
        "sha256": e.sha256,
        "size_bytes": e.size_bytes,
        "ingested_at": iso_utc(e.ingested_at),
        "extracted_text_path": e.extracted_text_path,
        "is_asset_list": e.is_asset_list,
        "asset_list_label": e.asset_list_label,
        "is_boundary_doc": e.is_boundary_doc,
        "boundary_doc_kind": e.boundary_doc_kind,
        "workbook_id": e.workbook_id,
        # v0.3-ready: connector telemetry. Nullable because pre-migration
        # rows have no source_kind stamped — the UI renders "unknown" then.
        "source_kind": e.source_kind,
    }


# ---------------------------------------------------------------------------
# Discriminated-union request body
# ---------------------------------------------------------------------------


class FolderSourceSpec(BaseModel):
    """Local filesystem path. UNC paths and NFS mounts work transparently."""

    type: Literal["folder"] = "folder"
    path: str
    recursive: bool = True


class S3SourceSpec(BaseModel):
    """v0.2+: orchestrator will raise NotImplementedError cleanly."""

    type: Literal["s3"] = "s3"
    bucket: str
    prefix: str = ""


class AzureBlobSourceSpec(BaseModel):
    """v0.2+: orchestrator will raise NotImplementedError cleanly."""

    type: Literal["azblob"] = "azblob"
    account: str
    container: str
    prefix: str = ""


class SharePointSourceSpec(BaseModel):
    """v0.2+: routes via the Python SharePoint MCP.

    ``file_paths``, when present, switches the walker out of "walk this
    folder" mode and into "fetch exactly these scan-root-relative paths"
    mode — used by the Browse dialog's filename-search results so the
    assessor can cherry-pick matched files instead of ingesting a whole
    subtree.
    """

    type: Literal["sharepoint"] = "sharepoint"
    site_url: str
    library: str = ""
    folder_path: str = ""
    file_paths: list[str] | None = None


SourceSpec = Annotated[
    Union[
        FolderSourceSpec,
        S3SourceSpec,
        AzureBlobSourceSpec,
        SharePointSourceSpec,
    ],
    Field(discriminator="type"),
]


class IngestRequest(BaseModel):
    """Body for ``POST /api/evidence/ingest``.

    The ``source`` discriminated union picks which backend to walk.
    Legacy callers can still POST ``{"folder": "...", "recursive": true}``
    via the deprecated top-level fields — see the route shim below.
    """

    source: SourceSpec | None = None
    # Deprecated, kept for one release so the UI can migrate.
    folder: str | None = None
    recursive: bool = True
    # v0.3-ready: the active workbook when the user kicked off the ingest.
    # Threaded through to :func:`ingest_source` so auto-tags get stamped
    # with the workbook's framework lens. None preserves the framework-
    # agnostic legacy behavior (no workbook context).
    workbook_id: int | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/ingest")
def ingest(body: IngestRequest) -> dict:
    """Kick off an ingest run; return a ``job_id`` for polling.

    Used to be synchronous and blocked the FastAPI worker for the entire
    walk (minutes on SharePoint). Now we spawn a daemon thread inside the
    :class:`JobRegistry` and the UI polls ``GET /ingest/jobs/{id}`` for
    progress. Idempotency is unchanged — the orchestrator still dedupes
    on URI and content hash, errors still surface per-file in the final
    summary blob.
    """
    if body.workbook_id is None:
        # Hard-binding contract: evidence is bound to the workbook open at
        # ingest time. Without a workbook there is no system under assessment
        # to attach the rows to, so refuse here rather than letting the daemon
        # thread raise ValueError and surface it only as a failed job. Mirrors
        # the 400 the synchronous /ingest-file route already returns.
        raise HTTPException(
            status_code=400,
            detail="workbook_id is required for ingest — open a workbook first.",
        )

    spec: SourceSpec | None = body.source
    if spec is None:
        # Legacy shape — synthesize a FolderSourceSpec from top-level fields.
        if not body.folder:
            raise HTTPException(
                status_code=400,
                detail="Request must include either 'source' or legacy 'folder'.",
            )
        spec = FolderSourceSpec(path=body.folder, recursive=body.recursive)

    if isinstance(spec, FolderSourceSpec):
        root = Path(spec.path)
        if not root.exists() or not root.is_dir():
            raise HTTPException(
                status_code=400, detail=f"Folder not found: {root}"
            )
        source = LocalFolderSource(root, recursive=spec.recursive)
    elif isinstance(spec, S3SourceSpec):
        source = S3Source(spec.bucket, spec.prefix)
    elif isinstance(spec, AzureBlobSourceSpec):
        source = AzureBlobSource(spec.account, spec.container, spec.prefix)
    elif isinstance(spec, SharePointSourceSpec):
        source = SharePointSource(
            spec.site_url,
            spec.library,
            spec.folder_path,
            file_paths=spec.file_paths,
        )
    else:  # pragma: no cover - exhaustively handled above
        raise HTTPException(status_code=400, detail=f"Unknown source type: {spec}")

    try:
        job_id = ingest_jobs.start_ingest_job(source, workbook_id=body.workbook_id)
    except RuntimeError as exc:
        # Another ingest is already in flight — surface 409 so the UI can
        # show "wait for the current run to finish" instead of starting
        # two threads that fight over the same Evidence rows.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"job_id": job_id}


@router.get("/ingest/jobs/active")
def get_active_ingest_job() -> dict | None:
    """Return the running job (if any) so a UI refresh can reattach.

    Registered BEFORE ``/ingest/jobs/{job_id}`` so FastAPI matches the
    literal path first and doesn't try to parse ``"active"`` as a job id.
    Returns ``null`` when idle — the UI uses that to hide the progress strip.
    """
    job = ingest_jobs.get_active_job()
    return job.as_dict() if job else None


@router.get("/ingest/jobs/{job_id}")
def get_ingest_job(job_id: str) -> dict:
    """Polling endpoint — live counters while running, full summary on done."""
    job = ingest_jobs.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
    return job.as_dict()


@router.get("")
def list_evidence(
    kind: str | None = None,
    archive_uri: str | None = None,
    workbook_id: int | None = None,
    framework_id: int | None = None,
    control_id: int | None = None,
    component_id: int | None = None,
    asset_id: int | None = None,
    boundary_id: int | None = None,
    limit: int = 3000,
    offset: int = 0,
    response: Response = None,  # type: ignore[assignment]  # injected by FastAPI
    s: Session = Depends(get_session),
) -> list[dict]:
    """List recently ingested evidence.

    Pagination (added for the Evidence page, which previously showed only a
    truncated window): ``offset`` + ``limit`` page the ``ingested_at DESC``
    ordering. The TOTAL matching-row count (pre-limit) is returned in the
    ``X-Total-Count`` response header so the UI can render "page N of M"
    without changing the bare-list response shape every existing consumer
    expects. Same total semantics on both query paths (simple + id-filter).

    ``archive_uri`` filters to members of one zip / container so the UI
    can render the disclosure-triangle expansion.

    v0.3-ready filter set:

    * ``workbook_id`` — narrow to a single workbook's Evidence PLUS
      framework-agnostic rows (``Evidence.workbook_id IS NULL``). NULL
      means "not workbook-specific" (folder ingests done outside any
      workbook context — policies, scans, CKLs); those artifacts are
      valid against any workbook, so the workbook view must include
      them or the list looks empty after a fresh CCIS-workbook open.
      Stays independent of framework_id so a workbook's full corpus
      can be shown even when "All catalogs" is selected.
    * ``framework_id`` — narrow to Evidence with at least one
      :class:`EvidenceTag` against an objective visible under that
      framework (direct ownership OR crosswalk-equivalent). The
      "catalog-aware Evidence list" the planning doc calls for. When
      both ``workbook_id`` and ``framework_id`` are passed they AND.
    * ``control_id`` — narrow to Evidence tagged against any objective
      under that control OR a crosswalk-equivalent control. The
      "drill-down from a control card" path.
    * ``component_id`` / ``asset_id`` / ``boundary_id`` — narrow via
      the three M2M scope link tables. AND across all three when more
      than one is provided.

    All scope/catalog filters short-circuit to ``[]`` if the resolver
    returns nothing (e.g. framework with zero direct/crosswalked
    objectives) instead of returning the whole table. That's the
    distinction the UI needs to render "no rows match this filter"
    rather than "filter ignored, showing everything."
    """
    stmt = select(Evidence)
    if kind:
        stmt = stmt.where(Evidence.kind == kind)
    if archive_uri:
        stmt = stmt.where(Evidence.archive_uri == archive_uri)
    if workbook_id is not None:
        # Strict hard-binding: evidence is bound to whatever workbook was open
        # at ingest time, and a workbook view shows ONLY that workbook's rows.
        # No NULL/global leak — legacy rows with workbook_id IS NULL (e.g. from
        # a pre-binding ingest or a workbook delete that nulled the FK) are
        # intentionally invisible here; they belong to no system under
        # assessment and must not bleed across boundaries.
        stmt = stmt.where(Evidence.workbook_id == workbook_id)

    # Catalog/scope filters intersect in Python rather than ANDing several
    # ``Evidence.id.in_(...)`` clauses into one statement. On a 10k-host
    # enterprise any one of these id-sets can exceed SQLITE_MAX_VARIABLES
    # (32766); a single un-chunked IN would raise "too many SQL variables".
    # Accumulating the intersection here lets the final query chunk ONE id
    # set instead of trying to bind several oversized lists at once.
    # ``id_filter is None`` means "no id-based filter applied yet"; an empty
    # set means "a filter ran and matched nothing" → short-circuit to [].
    id_filter: set[int] | None = None

    def _intersect(current: set[int] | None, new: set[int]) -> set[int]:
        return new if current is None else (current & new)

    # framework_id — union of objectives visible under the lens (direct +
    # crosswalked), then narrow Evidence to rows with at least one matching
    # EvidenceTag.
    if framework_id is not None:
        visible_obj_ids = objectives_visible_in_framework(s, framework_id)
        if not visible_obj_ids:
            return []
        evidence_ids_for_framework = set(
            s.exec(
                select(EvidenceTag.evidence_id).where(
                    EvidenceTag.objective_id.in_(visible_obj_ids)
                )
            ).all()
        )
        if not evidence_ids_for_framework:
            return []
        id_filter = _intersect(id_filter, evidence_ids_for_framework)

    # control_id — direct objectives + crosswalk-equivalent controls'
    # objectives. We resolve equivalents under the framework_id lens when
    # one was passed (so "AC-2 under FedRAMP" doesn't pull 800-53 AC-2's
    # CIS partner), otherwise we resolve across all frameworks.
    if control_id is not None:
        ctrl = s.get(Control, control_id)
        if ctrl is None:
            return []
        control_ids_in_scope: set[int] = {control_id}
        # When framework_id is set, only walk crosswalk pairs inside that
        # framework; without it we don't have a useful filter target, so
        # we accept all equivalents (single-hop, symmetric).
        if framework_id is not None:
            for equiv in resolve_equivalent_controls(s, control_id, framework_id):
                if equiv.id is not None:
                    control_ids_in_scope.add(equiv.id)
        obj_ids_for_control = set(
            s.exec(
                select(Objective.id).where(
                    Objective.control_id_fk.in_(control_ids_in_scope)
                )
            ).all()
        )
        if not obj_ids_for_control:
            return []
        evidence_ids_for_control = set(
            s.exec(
                select(EvidenceTag.evidence_id).where(
                    EvidenceTag.objective_id.in_(obj_ids_for_control)
                )
            ).all()
        )
        if not evidence_ids_for_control:
            return []
        id_filter = _intersect(id_filter, evidence_ids_for_control)

    # Scope filters (component / asset / boundary) — each is an independent
    # AND. Per-filter subquery instead of triple-JOIN keeps the SQL readable
    # and avoids row-duplication when an Evidence has multiple links of one
    # kind (a multi-host Asset would otherwise duplicate it once per host).
    if component_id is not None:
        component_evidence_ids = set(
            s.exec(
                select(EvidenceComponent.evidence_id).where(
                    EvidenceComponent.component_id == component_id
                )
            ).all()
        )
        if not component_evidence_ids:
            return []
        id_filter = _intersect(id_filter, component_evidence_ids)

    if asset_id is not None:
        asset_evidence_ids = set(
            s.exec(
                select(EvidenceAsset.evidence_id).where(
                    EvidenceAsset.asset_id == asset_id
                )
            ).all()
        )
        if not asset_evidence_ids:
            return []
        id_filter = _intersect(id_filter, asset_evidence_ids)

    if boundary_id is not None:
        boundary_evidence_ids = set(
            s.exec(
                select(EvidenceBoundary.evidence_id).where(
                    EvidenceBoundary.boundary_segment_id == boundary_id
                )
            ).all()
        )
        if not boundary_evidence_ids:
            return []
        id_filter = _intersect(id_filter, boundary_evidence_ids)

    stmt = stmt.order_by(Evidence.ingested_at.desc())

    def _set_total(n: int) -> None:
        if response is not None:
            response.headers["X-Total-Count"] = str(n)

    # No id-based filter → the kind/archive/workbook predicates are bounded,
    # so a single limited query is safe. Count the full match set (pre-limit)
    # for the pagination header via SQL COUNT(*) — NOT by materializing every
    # id into Python (a perf cliff on a 100k-row enterprise DB) — then page
    # with offset+limit. The count reuses the same WHERE predicates by wrapping
    # the built statement (minus ordering) in a subquery.
    if id_filter is None:
        count_stmt = select(func.count()).select_from(
            stmt.order_by(None).subquery()
        )
        total = s.exec(count_stmt).one()
        _set_total(int(total))
        rows = s.exec(stmt.offset(offset).limit(limit)).all()
        return [_serialize(e) for e in rows]

    # An id filter ran and matched nothing (the intersection emptied out).
    if not id_filter:
        _set_total(0)
        return []

    # Chunk the id IN-clause: the intersected set can still exceed
    # SQLITE_MAX_VARIABLES on a large enterprise. Each batch carries the
    # same kind/archive/workbook predicates and ordering; we union the rows,
    # then re-apply ordering + limit in Python so the result is identical to
    # the un-chunked query. Dedup by id because batches are disjoint by
    # construction but _serialize must not double-count.
    seen_ids: set[int] = set()
    collected: list[Evidence] = []
    for batch in chunked(list(id_filter)):
        for e in s.exec(stmt.where(Evidence.id.in_(batch))).all():  # type: ignore[attr-defined]
            if e.id is not None and e.id not in seen_ids:
                seen_ids.add(e.id)
                collected.append(e)
    collected.sort(
        key=lambda e: (e.ingested_at is not None, e.ingested_at),
        reverse=True,
    )
    _set_total(len(collected))
    return [_serialize(e) for e in collected[offset : offset + limit]]


@router.delete("")
def clear_evidence(
    purge_text: bool = True, s: Session = Depends(get_session)
) -> dict:
    """Nuke the evidence index.

    Wipes ``Evidence`` and every row that FK-references an evidence id:
    ``EvidenceTag``, ``StigFinding``, ``PoamEvidence``, the scope-link M2M
    tables (``EvidenceComponent`` / ``EvidenceAsset`` / ``EvidenceBoundary``),
    the sweep-token provenance (``BoundaryTokenSource``), and the per-assessment
    evidence-shown audit rows (``AssessmentEvidenceShown`` and its
    ``AssessmentCitation`` children). Optionally deletes the extracted-text
    cache files on disk too (default on — there's no point keeping orphaned
    .txt blobs after the rows are gone).

    The catalog, workbooks, baselines, superseded chains, and the Assessment
    rows themselves (verdicts + narratives) are NOT touched — only the artifact
    index and the evidence-derived audit pointers. Every affected assessment is
    flagged for re-review below, so the now-stale evidence-shown records (which
    point at artifacts that no longer exist) are deleted rather than left
    dangling; they regenerate on the next assess. Re-ingest the source folder
    to repopulate.

    Why this enumerates ALL FK children where :func:`delete_one_evidence` does
    not: SQLite runs with ``PRAGMA foreign_keys=ON`` (see db.py), so a bulk
    ``delete(Evidence)`` raises ``IntegrityError`` the moment ANY child row
    still points at an evidence id. ``AssessmentEvidenceShown`` is the row that
    bites in practice — once the user has run an assess-all over an ingested
    set, those audit rows exist and block the clear.

    Returns the row counts removed so the UI can show a confirmation toast.
    """
    text_paths: list[Path] = []
    if purge_text:
        # sqlmodel.Session.exec() on a single-column select returns scalars,
        # not 1-tuples — iterate directly, no destructuring.
        for p in s.exec(select(Evidence.extracted_text_path)).all():
            if p:
                text_paths.append(Path(p))

    # Order matters — FK constraints on EvidenceTag.evidence_id /
    # StigFinding.evidence_id mean Evidence has to go last.
    tag_count = len(s.exec(select(EvidenceTag.id)).all())
    finding_count = len(s.exec(select(StigFinding.id)).all())
    evidence_count = len(s.exec(select(Evidence.id)).all())

    # Snapshot every objective that had a tag BEFORE the wipe — once the
    # rows are gone we can't reconstruct the set, and we need to flag the
    # downstream Assessment rows for re-review (otherwise verdicts the
    # engine computed against the pre-wipe evidence picture silently
    # persist). See engine/invalidation.py for the contract.
    affected_objective_ids = set(
        s.exec(select(EvidenceTag.objective_id).distinct()).all()
    )

    # Per-assessment evidence-shown audit rows reference evidence ids and must
    # go before Evidence. AssessmentCitation hangs off AssessmentEvidenceShown
    # (FK evidence_shown_id), so it has to be cleared first — otherwise the
    # AssessmentEvidenceShown delete trips its own child FK. The parent
    # Assessment rows are left intact and flagged for re-review below.
    s.exec(delete(AssessmentCitation))
    s.exec(delete(AssessmentEvidenceShown))

    s.exec(delete(EvidenceTag))
    s.exec(delete(StigFinding))
    s.exec(delete(PoamEvidence))
    # Scope-link M2M tables (Component / Asset / BoundarySegment) all carry an
    # evidence_id FK with no ondelete; backfill may have populated them, so they
    # must be cleared explicitly or the final delete(Evidence) fails under
    # foreign_keys=ON.
    s.exec(delete(EvidenceComponent))
    s.exec(delete(EvidenceAsset))
    s.exec(delete(EvidenceBoundary))
    # Wipe sweep-token provenance too — a full evidence clear must leave no
    # tokens behind pointing at now-deleted artifacts (see delete_one_evidence
    # for the per-row rationale).
    s.exec(
        delete(BoundaryTokenSource).where(
            BoundaryTokenSource.source_evidence_id.is_not(None)
        )
    )
    # Null the self-FK before bulk-delete so SQLite doesn't trip on the
    # superseded_by_id chain mid-delete.
    s.exec(
        Evidence.__table__.update().values(superseded_by_id=None)  # type: ignore[attr-defined]
    )
    s.exec(delete(Evidence))
    invalidated = invalidate_assessments_for_objectives(s, affected_objective_ids)
    s.commit()

    files_removed = 0
    if purge_text:
        for p in text_paths:
            try:
                if p.exists():
                    p.unlink()
                    files_removed += 1
            except OSError:
                # Best-effort — locked file on Windows is a known nuisance,
                # not worth failing the whole clear over.
                pass

    return {
        "ok": True,
        "evidence_removed": evidence_count,
        "tags_removed": tag_count,
        "findings_removed": finding_count,
        "text_files_removed": files_removed,
        "assessments_flagged_for_review": invalidated,
    }


class AssetListPatch(BaseModel):
    """Body for ``PATCH /api/evidence/{id}/asset-list``.

    ``asset_list_label`` is only meaningful when ``is_asset_list`` is true;
    the route nulls it out when the flag is being unset so a re-flagged
    artifact starts from a clean label rather than inheriting a stale one.
    """

    is_asset_list: bool
    asset_list_label: str | None = None


class BoundaryDocPatch(BaseModel):
    """Body for ``PATCH /api/evidence/{id}/boundary-doc``.

    Flags an existing :class:`Evidence` row as a boundary-defining document
    (SSP / SSPP / ATO letter / network diagram) and binds it to a workbook
    so :func:`BoundaryDocsContextSource.apply` can pull just this workbook's
    boundary docs at extraction time. ``boundary_doc_kind`` is free text —
    we don't enum it so future doc shapes don't need a schema change.

    Nulling rules mirror the asset-list patch: when ``is_boundary_doc`` is
    being unset, ``boundary_doc_kind`` is forced to ``None`` so a future
    re-flag starts with a clean label. ``workbook_id`` is left untouched
    on unset — the artifact may still belong to that workbook for other
    purposes (manual tagging, future per-workbook scoping).
    """

    is_boundary_doc: bool
    boundary_doc_kind: str | None = None
    workbook_id: int | None = None


class IngestFileRequest(BaseModel):
    """Body for ``POST /api/evidence/ingest-file`` — sync single-file ingest.

    Companion to the async job-based ``/ingest`` endpoint for the
    boundary-doc upload UX, where the assessor picks one file in the
    Electron file dialog and expects to see the Evidence row + boundary-
    doc flags applied immediately (no progress strip, no polling).

    The boundary fields are optional so this same endpoint can serve any
    future "upload one thing right now" UX without needing a new route.
    """

    path: str
    is_boundary_doc: bool = False
    boundary_doc_kind: str | None = None
    workbook_id: int | None = None


@router.get("/crosscheck")
def get_crosscheck(workbook_id: int, s: Session = Depends(get_session)) -> dict:
    """Per-workbook asset-coverage cross-check (auto-derived).

    Mirrors what the kernel injects into CM-8 / CA-3 / PM-5 / RA-5 / CA-7
    prompts so the assessor can see — and sanity-check — the same gap
    analysis the LLM is reading. The asset universe is computed from
    every ACAS scan + STIG checklist + assessor-declared inventory, with
    hostnames normalized to bare lowercase short form for cross-source
    matching. See ``evidence/asset_crosscheck.py`` for the source rules.

    Response shape:
      sources[]       — one row per contributing artifact (scan / CKL /
                        declared inventory) with its category + host count
      hosts[]         — one row per host with per-source attribution +
                        list of STIGs applied + a coverage tag
      gaps{}          — hostnames bucketed by gap class (keys mirror
                        HostRecord.coverage so the UI can render a tab
                        per class)
      totals{}        — set-cardinality summary the UI shows up top

    Returns ``sources: []`` (and empty hosts/gaps) when nothing in the DB
    qualifies as scan/checklist/declared — the UI uses that as the cue
    to collapse the panel.

    Registered BEFORE the ``/{evidence_id}`` catch-all on purpose: FastAPI
    matches routes in declaration order and would otherwise try to parse
    ``"crosscheck"`` as an int and 422.
    """
    report = summarize_asset_coverage(workbook_id, s)
    return {
        "sources": [
            {
                "evidence_id": src.evidence_id,
                "label": src.label,
                "kind": src.kind,
                "category": src.category,
                "host_count": src.host_count,
            }
            for src in report.sources
        ],
        "hosts": [
            {
                "hostname": h.hostname,
                "coverage": h.coverage,
                "scanned_in": [
                    {"evidence_id": r.evidence_id, "label": r.label, "kind": r.kind}
                    for r in h.scanned_in
                ],
                "checklisted_in": [
                    {"evidence_id": r.evidence_id, "label": r.label, "kind": r.kind}
                    for r in h.checklisted_in
                ],
                "declared_in": [
                    {"evidence_id": r.evidence_id, "label": r.label, "kind": r.kind}
                    for r in h.declared_in
                ],
                "stigs_applied": h.stigs_applied,
            }
            for h in report.hosts
        ],
        "gaps": report.gaps,
        "totals": {
            "scanned": len(report.scanned_set),
            "checklisted": len(report.checklisted_set),
            "declared": len(report.declared_set),
            "union": len(
                report.scanned_set | report.checklisted_set | report.declared_set
            ),
        },
    }


@router.patch("/{evidence_id}/asset-list")
def set_asset_list(
    evidence_id: int,
    body: AssetListPatch,
    s: Session = Depends(get_session),
) -> dict:
    """Flip the manual asset-list flag (and optional label) on one artifact.

    Clears ``asset_list_label`` when ``is_asset_list`` is being unset so
    the next toggle-on starts blank. Returns the refreshed row so the UI
    can update without a follow-up GET.
    """
    ev = s.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    # Declared inventories only come via spreadsheet. A vendor parts catalog and
    # an HW/SW inventory are indistinguishable by column shape, so the assessor
    # flags one manually — but the flag is only meaningful on a spreadsheet
    # (any Excel format plus CSV). Reject the toggle on any other artifact rather
    # than silently accepting a flag the asset cross-check can never parse.
    if body.is_asset_list:
        leaf = _leaf_name(ev.path)
        ext = PurePosixPath(leaf).suffix.lower()
        if ext not in {".xlsx", ".xlsm", ".xls", ".csv"}:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Declared inventories must be spreadsheets "
                    f"(.xlsx/.xlsm/.xls/.csv); '{leaf}' is not."
                ),
            )
    ev.is_asset_list = body.is_asset_list
    ev.asset_list_label = body.asset_list_label if body.is_asset_list else None
    s.add(ev)
    s.commit()
    s.refresh(ev)
    return _serialize(ev)


@router.patch("/{evidence_id}/boundary-doc")
def set_boundary_doc(
    evidence_id: int,
    body: BoundaryDocPatch,
    s: Session = Depends(get_session),
) -> dict:
    """Flag (or unflag) an existing artifact as a boundary-defining document.

    Mirrors :func:`set_asset_list`. Used by the Sweep Context page's
    row-level "Remove from boundary" action and any future "mark this
    Evidence row as a boundary doc retroactively" affordance.

    Registered BEFORE the ``/{evidence_id}`` catch-all on purpose — FastAPI
    matches routes in declaration order.
    """
    ev = s.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    ev.is_boundary_doc = body.is_boundary_doc
    ev.boundary_doc_kind = body.boundary_doc_kind if body.is_boundary_doc else None
    if body.workbook_id is not None:
        ev.workbook_id = body.workbook_id
    s.add(ev)
    s.commit()
    s.refresh(ev)
    return _serialize(ev)


@router.delete("/{evidence_id}")
def delete_one_evidence(
    evidence_id: int,
    purge_text: bool = True,
    s: Session = Depends(get_session),
) -> dict:
    """Surgically remove one Evidence row and its dependents.

    Mirrors :func:`clear_evidence` for a single id. FK cascade order matters
    — ``EvidenceTag`` / ``StigFinding`` / ``PoamEvidence`` first, then null
    any ``superseded_by_id`` back-pointers, then the Evidence row itself.
    Optionally unlinks the cached ``.txt`` extraction so we don't leak
    orphaned blobs on disk (default on, matching the bulk-clear default).

    Registered AFTER the literal ``/crosscheck`` and PATCH ``/{evidence_id}/{op}``
    routes on purpose — FastAPI matches routes in declaration order and would
    otherwise try ``"crosscheck"`` against this int path-param and 422.

    Cascade parity: this and :func:`clear_evidence` now clear the same set of
    FK children (tags, findings, POAM links, scope-link M2M rows, sweep tokens,
    and the per-assessment evidence-shown audit rows + their citations). Both
    must, because SQLite runs with ``PRAGMA foreign_keys=ON`` and a dangling
    child row raises ``IntegrityError`` on the Evidence delete.
    """
    ev = s.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    # Snapshot the cache-file path before delete — once the ORM evicts the
    # row, attribute access on the detached instance would lazy-load and
    # blow up.
    text_path = Path(ev.extracted_text_path) if ev.extracted_text_path else None

    tag_count = len(
        s.exec(select(EvidenceTag.id).where(EvidenceTag.evidence_id == evidence_id)).all()
    )
    finding_count = len(
        s.exec(select(StigFinding.id).where(StigFinding.evidence_id == evidence_id)).all()
    )
    poam_link_count = len(
        s.exec(
            select(PoamEvidence.poam_id).where(PoamEvidence.evidence_id == evidence_id)
        ).all()
    )
    # Snapshot the affected objectives BEFORE deleting their tags; the
    # post-delete invalidation flips downstream Assessment rows so the
    # reviewer sees that the evidence picture changed. See clear_evidence
    # above and engine/invalidation.py for the shared contract.
    affected_objective_ids = set(
        s.exec(
            select(EvidenceTag.objective_id)
            .where(EvidenceTag.evidence_id == evidence_id)
            .distinct()
        ).all()
    )

    # Per-assessment evidence-shown audit rows reference this evidence id and
    # must go before the Evidence row (FK, no ondelete). AssessmentCitation
    # hangs off AssessmentEvidenceShown, so clear the citations for THIS
    # evidence's shown-rows first, then the shown-rows themselves.
    shown_ids = [
        sid
        for sid in s.exec(
            select(AssessmentEvidenceShown.id).where(
                AssessmentEvidenceShown.evidence_id == evidence_id
            )
        ).all()
    ]
    for batch in chunked(shown_ids):
        s.exec(
            delete(AssessmentCitation).where(
                AssessmentCitation.evidence_shown_id.in_(batch)
            )
        )
    s.exec(
        delete(AssessmentEvidenceShown).where(
            AssessmentEvidenceShown.evidence_id == evidence_id
        )
    )

    s.exec(delete(EvidenceTag).where(EvidenceTag.evidence_id == evidence_id))
    s.exec(delete(StigFinding).where(StigFinding.evidence_id == evidence_id))
    s.exec(delete(PoamEvidence).where(PoamEvidence.evidence_id == evidence_id))
    # Scope-link M2M tables — same evidence_id FK, same no-ondelete; clear the
    # rows for this artifact so the Evidence delete doesn't trip foreign_keys=ON.
    s.exec(delete(EvidenceComponent).where(EvidenceComponent.evidence_id == evidence_id))
    s.exec(delete(EvidenceAsset).where(EvidenceAsset.evidence_id == evidence_id))
    s.exec(delete(EvidenceBoundary).where(EvidenceBoundary.evidence_id == evidence_id))
    # Drop the sweep tokens this evidence contributed. The FK is declared
    # SET NULL (degrade-to-unattributed), but the user expects a deleted
    # document's tokens to disappear from the boundary fingerprint, not
    # linger as orphaned provenance — so remove them outright here. Done in
    # the app layer because the on-disk SQLite table predates the ondelete
    # DDL and ``info``-carried ondelete never reaches the constraint anyway.
    s.exec(
        delete(BoundaryTokenSource).where(
            BoundaryTokenSource.source_evidence_id == evidence_id
        )
    )
    # Null any rows that point at this id via the supersession self-FK so
    # the delete itself doesn't trip the constraint.
    s.exec(
        Evidence.__table__.update()  # type: ignore[attr-defined]
        .where(Evidence.superseded_by_id == evidence_id)
        .values(superseded_by_id=None)
    )
    s.delete(ev)
    invalidated = invalidate_assessments_for_objectives(s, affected_objective_ids)
    s.commit()

    text_file_removed = False
    if purge_text and text_path is not None:
        try:
            if text_path.exists():
                text_path.unlink()
                text_file_removed = True
        except OSError:
            # Best-effort — locked file on Windows is a known nuisance, not
            # worth failing the delete over.
            pass

    return {
        "ok": True,
        "evidence_id": evidence_id,
        "tags_removed": tag_count,
        "findings_removed": finding_count,
        "poam_links_removed": poam_link_count,
        "text_file_removed": text_file_removed,
        "assessments_flagged_for_review": invalidated,
    }


@router.post("/ingest-file")
def ingest_file(
    body: IngestFileRequest,
    s: Session = Depends(get_session),
) -> dict:
    """Synchronous single-file ingest + optional boundary-doc tagging.

    The async ``POST /ingest`` route can't cleanly thread per-file metadata
    through :class:`IngestSummary` / :class:`JobRegistry`, so the boundary-
    doc upload flow uses this sync endpoint instead: pick one file in the
    Electron picker, post path + flags, get back the Evidence row in the
    same response. No polling, no progress strip.

    Returns the serialized Evidence row. 404 if the file isn't readable
    or the orchestrator dropped it (e.g. an unsupported extension).
    """
    # PR 2: per-workbook hard-scoping. Reject up front with a 400 (not a
    # 500 from the deep ``ValueError`` in ``ingest_single_local_file``) so
    # the assessor sees a clean "open a workbook first" message instead of
    # an opaque server error. Pinning the 400 specifically — rather than
    # 422 from Pydantic — keeps the contract stable for the UI even if
    # the request body schema evolves.
    if body.workbook_id is None:
        raise HTTPException(
            status_code=400,
            detail="workbook_id is required — open a workbook before "
                   "ingesting evidence",
        )

    p = Path(body.path)
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=400, detail=f"File not found: {p}")

    # Serialise through the same writer mutex as batch ingest so a
    # boundary-doc upload can't race a connector pull (or another upload)
    # and corrupt the per-workbook evidence set. claim_single_file raises
    # RuntimeError when the registry is busy — surface that as 409, exactly
    # like the async ``/ingest`` route above, so the UI shows "try again"
    # rather than an opaque 500.
    try:
        with ingest_jobs.claim_single_file():
            ev = ingest_single_local_file(s, p, workbook_id=body.workbook_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if ev is None:
        raise HTTPException(
            status_code=400,
            detail=f"Ingest produced no Evidence row for {p} "
                   f"(unsupported extension or read error)",
        )

    # Stamp the boundary-doc fields if requested — even on a dedupe-hit
    # (existing row returned), so the assessor can promote a previously-
    # ingested file to boundary-doc status with one upload click.
    #
    # Use ``model_fields_set`` to distinguish "client omitted the field"
    # from "client explicitly sent null". SweepContext.tsx submits only
    # ``{path, is_boundary_doc, workbook_id}`` (no ``boundary_doc_kind``),
    # and a naive overwrite would clobber an existing row's kind to NULL
    # on every re-add. Preserve what's already there unless the client
    # actually sent a new value.
    sent = body.model_fields_set
    touched = False
    if body.is_boundary_doc:
        ev.is_boundary_doc = True
        if "boundary_doc_kind" in sent:
            ev.boundary_doc_kind = body.boundary_doc_kind
        touched = True
    if "workbook_id" in sent and body.workbook_id is not None:
        ev.workbook_id = body.workbook_id
        touched = True
    if touched:
        s.add(ev)
        s.commit()
        s.refresh(ev)
    return _serialize(ev)


# ---------------------------------------------------------------------------
# Retag — re-run the deterministic tagger over already-ingested evidence
# ---------------------------------------------------------------------------
#
# Why this exists: the tagger evolves (catalog-spray guard, content-shape
# classification, semantic backstop) but tags are written once, at ingest.
# An assessor who improved the tagger — or who hit a tagging bug like the
# account/roles matrix that produced ZERO tags (BUG B, evidence id 85) —
# needs a way to re-derive tags for the existing corpus WITHOUT deleting and
# re-ingesting every file (which would lose manual tags, supersession links,
# POAM evidence links, and the ingest job audit trail).
#
# The crux: ``evidence_type`` (e.g. "account_matrix" → AC-2/AC-6/IA-2) and
# ``_stig_findings`` (→ CCI-direct Tier 2) are NOT persisted on the Evidence
# row — they're produced by the extractor at ingest and handed straight to
# the tagger. A text-only retag (reading the cached .txt) therefore can't
# reproduce Tiers 2 & 4. So when the original file is locally reachable we
# RE-EXTRACT it, reproducing every tier. Connector-only URIs fall back to
# cached text (Tiers 1/3/5 only) — still better than the stale tags we drop.


class RetagBody(BaseModel):
    """Optional filter for the bulk retag — restrict to one workbook's lens."""

    workbook_id: int | None = Field(
        default=None,
        description="If set, only retag evidence whose workbook_id matches.",
    )


def _reopen_stream(uri: str) -> io.BytesIO | None:
    """Re-open the original artifact's bytes for re-extraction, if reachable.

    Returns a seekable :class:`io.BytesIO` for ``file:///`` and
    ``zip:///…!/…`` URIs. Returns ``None`` for connector URIs
    (sharepoint://, s3://, azure://) — they need a live connector session
    and the caller falls back to cached extracted text.

    The zip member is read fully into memory because ``ZipFile.open`` yields
    a non-seekable stream, and several extractors (openpyxl read-only,
    pdfplumber) seek — BytesIO is the safe, uniform shape.
    """
    if uri.startswith("file:///"):
        p = Path(unquote(uri[len("file:///"):]))
        if not p.exists():
            return None
        try:
            return io.BytesIO(p.read_bytes())
        except OSError:
            return None
    if uri.startswith("zip:///") and "!/" in uri:
        archive_part, member_part = uri[len("zip:///"):].rsplit("!/", 1)
        archive_path = Path(unquote(archive_part))
        member = unquote(member_part)
        if not archive_path.exists():
            return None
        try:
            with zipfile.ZipFile(archive_path) as zf:
                return io.BytesIO(zf.read(member))
        except (KeyError, zipfile.BadZipFile, OSError):
            return None
    return None


def _retag_one(
    ev: Evidence,
    s: Session,
    *,
    client: Any | None = None,
    judge_model: str | None = None,
) -> dict:
    """Regenerate one artifact's auto tags from a fresh extraction.

    Drops the artifact's ``auto`` / ``auto_review`` :class:`EvidenceTag`
    rows, then re-runs :func:`tag_evidence`. Manual / LLM-confirmed tags
    (any other ``source``) are left untouched, and ``tag_evidence`` skips
    objective ids already tagged so they're never duplicated.

    ``client`` / ``judge_model`` are the optional Tier 5-LLM "smart
    backstop" — passed straight through to :func:`tag_evidence` so a retag
    gets the same AI-assisted tagging as a fresh ingest. Callers build the
    client ONCE (via :func:`_build_tagger_llm`) and hand it in, so a
    whole-corpus retag resolves the provider/key once, not per file.

    Invalidation has two halves:
      * objectives that LOST a tag (e.g. a de-sprayed catalog/index doc,
        BUG A) — flagged here from the deleted snapshot.
      * objectives that GAINED a tag — :func:`tag_evidence` flags those
        itself at the end of its run.
    """
    assert ev.id is not None

    # Snapshot objectives whose auto tags we're about to drop so they get
    # re-reviewed even if the fresh pass doesn't re-tag them (the de-spray
    # case: an index doc that used to spray 200 controls and now tags none).
    deleted_objective_ids = set(
        s.exec(
            select(EvidenceTag.objective_id)
            .where(EvidenceTag.evidence_id == ev.id)
            .where(EvidenceTag.source.in_(("auto", "auto_review")))
            .distinct()
        ).all()
    )
    s.exec(
        delete(EvidenceTag)
        .where(EvidenceTag.evidence_id == ev.id)
        .where(EvidenceTag.source.in_(("auto", "auto_review")))
    )

    framework_id = _framework_id_for_workbook(s, ev.workbook_id)

    result = None
    reextracted = False
    stream = _reopen_stream(ev.path)
    if stream is not None:
        try:
            doc = extract_stream(stream, _leaf_name(ev.path))
            reextracted = True
        except (ExtractorError, ExtractorSkip):
            doc = None
        finally:
            stream.close()
        if doc is not None:
            result = tag_evidence(
                s,
                ev,
                doc.text,
                stig_findings=doc.metadata.get("_stig_findings") or None,
                evidence_type=doc.metadata.get("evidence_type"),
                evidence_type_signals=doc.metadata.get("evidence_type_signals"),
                framework_id=framework_id,
                client=client,
                judge_model=judge_model,
            )

    if result is None:
        # Fallback: connector URI, missing file, or re-extract failed. Retag
        # from cached text — Tiers 1/3/5 still fire; Tiers 2 & 4 are lost
        # (no _stig_findings / evidence_type without the original bytes).
        text = ""
        if ev.extracted_text_path:
            tp = Path(ev.extracted_text_path)
            if tp.exists():
                try:
                    text = tp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
        result = tag_evidence(
            s,
            ev,
            text,
            framework_id=framework_id,
            client=client,
            judge_model=judge_model,
        )

    # Flag the objectives that LOST a tag. tag_evidence already flagged the
    # ones that GAINED a tag during its run.
    invalidate_assessments_for_objectives(s, deleted_objective_ids)

    return {
        "evidence_id": ev.id,
        "reextracted": reextracted,
        "tags_created": result.tags_created,
        "objectives_invalidated": len(deleted_objective_ids),
    }


@router.post("/retag")
def retag_all_evidence(
    body: RetagBody | None = None,
    s: Session = Depends(get_session),
) -> dict:
    """Re-run the tagger over every ingested artifact (optionally one workbook).

    Registered BEFORE ``/{evidence_id}`` so FastAPI's declaration-order
    matcher doesn't try to coerce the literal ``"retag"`` into the int path
    param. One commit at the end so the whole corpus retag is atomic — a
    mid-run failure leaves the prior tags in place rather than a half-retagged
    set.
    """
    workbook_id = body.workbook_id if body else None
    q = select(Evidence)
    if workbook_id is not None:
        q = q.where(Evidence.workbook_id == workbook_id)
    rows = s.exec(q).all()

    # Build the Tier 5-LLM "smart backstop" client ONCE for the whole corpus
    # retag (one provider/key resolution, not one per file). None when the
    # kill-switch is off or no provider is configured — retag degrades to the
    # deterministic TF-IDF Tier 5, exactly like a fresh ingest.
    tagger_client, tagger_judge_model = _build_tagger_llm()

    per_file: list[dict] = []
    total_created = 0
    reextracted_count = 0
    for ev in rows:
        r = _retag_one(ev, s, client=tagger_client, judge_model=tagger_judge_model)
        per_file.append(r)
        total_created += r["tags_created"]
        reextracted_count += 1 if r["reextracted"] else 0
    s.commit()

    return {
        "ok": True,
        "evidence_retagged": len(rows),
        "reextracted": reextracted_count,
        "tags_created": total_created,
        "per_file": per_file,
    }


@router.post("/{evidence_id}/retag")
def retag_one_evidence(
    evidence_id: int, s: Session = Depends(get_session)
) -> dict:
    """Re-run the tagger over a single artifact. See :func:`_retag_one`."""
    ev = s.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    tagger_client, tagger_judge_model = _build_tagger_llm()
    result = _retag_one(ev, s, client=tagger_client, judge_model=tagger_judge_model)
    s.commit()
    return {"ok": True, **result}


@router.get("/{evidence_id}")
def get_evidence(evidence_id: int, s: Session = Depends(get_session)) -> dict:
    e = s.get(Evidence, evidence_id)
    if not e:
        raise HTTPException(status_code=404, detail="Evidence not found")
    tags = s.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == evidence_id)).all()
    out = _serialize(e)
    out["tags"] = [
        {
            "objective_id": t.objective_id,
            "relevance": t.relevance,
            "confidence": t.confidence,
            "source": t.source,
            "rationale": t.rationale,
        }
        for t in tags
    ]
    return out


@router.get("/by-objective/{objective_id}")
def list_evidence_for_objective(
    objective_id: int,
    workbook_id: int | None = None,
    s: Session = Depends(get_session),
) -> list[dict]:
    """Evidence linked to one objective, one row per distinct artifact.

    Storage allows multiple :class:`EvidenceTag` rows for the same
    (evidence_id, objective_id) pair on purpose — an auto-tag from the
    family/keyword pass can coexist with a manual or LLM-confirmed tag —
    so a naive iteration would render the same file two or three times
    in the UI. We collapse here instead of upstream so each tag's
    provenance (auto / manual / llm) survives in the response as a list
    while the visible row count matches the distinct-artifact count.

    Workbook scoping (defense-in-depth): when ``workbook_id`` is given, only
    evidence belonging to THAT workbook is returned. Evidence is 1:1 with a
    workbook by design, but two live workbooks can tag the same shared CCI —
    without this filter, workbook A's artifacts would surface on workbook B's
    control for that CCI. The control detail always passes the active
    workbook, so the panel shows only in-scope evidence.

    Result ordering: highest aggregated relevance first, then by
    filename — gives a stable, intuitive top-to-bottom read in the UI.
    """
    tags = s.exec(
        select(EvidenceTag).where(EvidenceTag.objective_id == objective_id)
    ).all()

    # Group by evidence_id. For relevance/confidence we keep the max
    # across tags — the most confident assertion that this artifact
    # supports the objective is the one the UI should show.
    grouped: dict[int, dict] = {}
    for t in tags:
        row = grouped.get(t.evidence_id)
        if row is None:
            grouped[t.evidence_id] = {
                "evidence_id": t.evidence_id,
                "relevance": t.relevance,
                "confidence": t.confidence,
                "sources": [t.source] if t.source else [],
                "rationales": [t.rationale] if t.rationale else [],
                "tag_count": 1,
            }
            continue
        row["relevance"] = max(row["relevance"], t.relevance)
        row["confidence"] = max(row["confidence"], t.confidence)
        if t.source and t.source not in row["sources"]:
            row["sources"].append(t.source)
        if t.rationale and t.rationale not in row["rationales"]:
            row["rationales"].append(t.rationale)
        row["tag_count"] += 1

    out: list[dict] = []
    for evidence_id, row in grouped.items():
        e = s.get(Evidence, evidence_id)
        if not e:
            continue
        # Workbook scoping: skip evidence that belongs to another workbook (or
        # is orphaned, workbook_id=None) when a workbook filter is supplied.
        if workbook_id is not None and e.workbook_id != workbook_id:
            continue
        # "source" / "rationale" kept as singular fields for back-compat
        # with the UI's existing column accessors; the new list-shaped
        # "sources" / "rationales" let callers show provenance badges
        # when multiple taggers agreed independently.
        out.append(
            {
                "evidence_id": e.id,
                "filename": _leaf_name(e.path),
                "display_path": _display_path(e.path),
                "title": e.title,
                "kind": e.kind,
                "relevance": row["relevance"],
                "confidence": row["confidence"],
                "source": ", ".join(row["sources"]) if row["sources"] else None,
                "rationale": "\n".join(row["rationales"]) if row["rationales"] else None,
                "sources": row["sources"],
                "rationales": row["rationales"],
                "tag_count": row["tag_count"],
            }
        )
    out.sort(key=lambda r: (-r["relevance"], r["filename"].lower()))
    return out


# ---------------------------------------------------------------------------
# v0.3 scope-link endpoints
#
# Three near-identical M2M attach/detach families (Component, Asset,
# BoundarySegment). Each follows the same shape so the UI's filter-chip
# drag-drop behaves uniformly:
#
#   GET    /api/evidence/{id}/{kind}            list current links
#   POST   /api/evidence/{id}/{kind}            attach (idempotent)
#   DELETE /api/evidence/{id}/{kind}/{link_id}  detach one link
#
# Idempotency is important — the UI sometimes re-submits the full chip
# set on save, and double-attaching would otherwise insert a duplicate
# (composite PK would actually raise, but we'd rather no-op). The POST
# bodies accept a list so a single round-trip can replace the chip set.
# ---------------------------------------------------------------------------


class ScopeAttachRequest(BaseModel):
    """Body for the three POST /api/evidence/{id}/{component|asset|boundary-segment} endpoints.

    ``ids`` is the full set the UI wants this Evidence linked to; the
    route diffs against existing links and inserts the missing pairs.
    Existing links not in the list are LEFT IN PLACE — caller uses
    DELETE to remove. This is the "additive attach" semantics the chip
    UI needs; a "replace all" gesture would need a separate flag.
    """

    ids: list[int]


def _attach_scope_links(
    s: Session,
    evidence_id: int,
    requested_ids: list[int],
    link_model: type,
    fk_field: str,
) -> list[int]:
    """Generic attach helper shared by the three scope endpoint families.

    Inserts ``link_model(evidence_id=..., {fk_field}=...)`` rows for any
    requested id not already linked. Returns the list of newly-created
    fk values so the response can tell the UI what actually changed.

    Composite PK means a duplicate insert raises IntegrityError — we
    pre-filter against the existing set instead of catching to keep the
    transaction clean.
    """
    existing = set(
        s.exec(
            select(getattr(link_model, fk_field)).where(
                link_model.evidence_id == evidence_id
            )
        ).all()
    )
    new_ids = [i for i in requested_ids if i not in existing]
    for fk in new_ids:
        s.add(
            link_model(
                **{
                    "evidence_id": evidence_id,
                    fk_field: fk,
                    "source": ScopeLinkSource.MANUAL,
                }
            )
        )
    if new_ids:
        s.commit()
    return new_ids


# ---- Components --------------------------------------------------------------


@router.get("/{evidence_id}/components")
def list_evidence_components(
    evidence_id: int, s: Session = Depends(get_session)
) -> list[dict]:
    """List Component links for one Evidence row.

    Returns the resolved Component (name + kind) joined with link metadata
    (confidence + source) so the UI chip can show both — the chip label
    comes from the Component, the chip badge / tooltip from the link.
    """
    if s.get(Evidence, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    links = s.exec(
        select(EvidenceComponent, Component)
        .join(Component, Component.id == EvidenceComponent.component_id)
        .where(EvidenceComponent.evidence_id == evidence_id)
    ).all()
    return [
        {
            "component_id": comp.id,
            "name": comp.name,
            "kind": comp.kind,
            "confidence": link.confidence,
            "source": link.source,
        }
        for link, comp in links
    ]


@router.post("/{evidence_id}/components")
def attach_evidence_components(
    evidence_id: int,
    body: ScopeAttachRequest,
    s: Session = Depends(get_session),
) -> dict:
    """Attach one or more Components to an Evidence row (idempotent)."""
    if s.get(Evidence, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    created = _attach_scope_links(
        s, evidence_id, body.ids, EvidenceComponent, "component_id"
    )
    return {"ok": True, "created": created}


@router.delete("/{evidence_id}/components/{component_id}")
def detach_evidence_component(
    evidence_id: int,
    component_id: int,
    s: Session = Depends(get_session),
) -> dict:
    """Remove one Component link from an Evidence row.

    No-op if the link didn't exist — the UI's chip-remove gesture
    shouldn't 404 just because two clicks raced.
    """
    s.exec(
        delete(EvidenceComponent)
        .where(EvidenceComponent.evidence_id == evidence_id)
        .where(EvidenceComponent.component_id == component_id)
    )
    s.commit()
    return {"ok": True}


# ---- Assets ------------------------------------------------------------------


@router.get("/{evidence_id}/assets")
def list_evidence_assets(
    evidence_id: int, s: Session = Depends(get_session)
) -> list[dict]:
    """List Asset links for one Evidence row."""
    if s.get(Evidence, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    links = s.exec(
        select(EvidenceAsset, Asset)
        .join(Asset, Asset.id == EvidenceAsset.asset_id)
        .where(EvidenceAsset.evidence_id == evidence_id)
    ).all()
    return [
        {
            "asset_id": asset.id,
            "hostname": asset.hostname,
            "fqdn": asset.fqdn,
            "ip_address": asset.ip_address,
            "asset_class": asset.asset_class,
            "asset_source": asset.source,
            "confidence": link.confidence,
            "link_source": link.source,
        }
        for link, asset in links
    ]


@router.post("/{evidence_id}/assets")
def attach_evidence_assets(
    evidence_id: int,
    body: ScopeAttachRequest,
    s: Session = Depends(get_session),
) -> dict:
    """Attach one or more Assets to an Evidence row (idempotent)."""
    if s.get(Evidence, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    created = _attach_scope_links(
        s, evidence_id, body.ids, EvidenceAsset, "asset_id"
    )
    return {"ok": True, "created": created}


@router.delete("/{evidence_id}/assets/{asset_id}")
def detach_evidence_asset(
    evidence_id: int,
    asset_id: int,
    s: Session = Depends(get_session),
) -> dict:
    """Remove one Asset link from an Evidence row."""
    s.exec(
        delete(EvidenceAsset)
        .where(EvidenceAsset.evidence_id == evidence_id)
        .where(EvidenceAsset.asset_id == asset_id)
    )
    s.commit()
    return {"ok": True}


# ---- Boundary segments -------------------------------------------------------


@router.get("/{evidence_id}/boundary-segments")
def list_evidence_boundary_segments(
    evidence_id: int, s: Session = Depends(get_session)
) -> list[dict]:
    """List BoundarySegment links for one Evidence row."""
    if s.get(Evidence, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    links = s.exec(
        select(EvidenceBoundary, BoundarySegment)
        .join(BoundarySegment, BoundarySegment.id == EvidenceBoundary.boundary_segment_id)
        .where(EvidenceBoundary.evidence_id == evidence_id)
    ).all()
    return [
        {
            "boundary_segment_id": seg.id,
            "name": seg.name,
            "kind": seg.kind,
            "confidence": link.confidence,
            "source": link.source,
        }
        for link, seg in links
    ]


@router.post("/{evidence_id}/boundary-segments")
def attach_evidence_boundary_segments(
    evidence_id: int,
    body: ScopeAttachRequest,
    s: Session = Depends(get_session),
) -> dict:
    """Attach one or more BoundarySegments to an Evidence row (idempotent)."""
    if s.get(Evidence, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    created = _attach_scope_links(
        s, evidence_id, body.ids, EvidenceBoundary, "boundary_segment_id"
    )
    return {"ok": True, "created": created}


@router.delete("/{evidence_id}/boundary-segments/{boundary_segment_id}")
def detach_evidence_boundary_segment(
    evidence_id: int,
    boundary_segment_id: int,
    s: Session = Depends(get_session),
) -> dict:
    """Remove one BoundarySegment link from an Evidence row."""
    s.exec(
        delete(EvidenceBoundary)
        .where(EvidenceBoundary.evidence_id == evidence_id)
        .where(EvidenceBoundary.boundary_segment_id == boundary_segment_id)
    )
    s.commit()
    return {"ok": True}
