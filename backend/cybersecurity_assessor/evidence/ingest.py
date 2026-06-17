"""Source-walk orchestrator: hash → extract → persist → tag.

This is the single entry point the API and the CLI both call. It is
intentionally idempotent: re-running over the same source is cheap
because we dedupe on ``sha256`` (content) and on the canonical URI
(``Evidence.path`` unique constraint). If a file's content has
changed, the new sha256 produces a new ``Evidence`` row; the old one
stays in the index so prior assessments still resolve their citations.

The orchestrator only knows :class:`Source` and :class:`SourceFile` —
it does not care whether the bytes live on the local FS, an NFS mount,
inside a zip, in S3, or in SharePoint. New backends slot in by
implementing the Source protocol; no changes here.

Failure modes are recorded, not raised. One unreadable PDF should
never abort an ingest run — the orchestrator captures the error per
file in :class:`IngestSummary.errors` and continues.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from sqlmodel import Session, select

from ..config import extracted_text_dir, load_config
from ..models import Evidence, EvidenceKind, EvidenceSourceKind, StigFinding, Workbook
from .extractors import ExtractedDoc, ExtractorError, ExtractorSkip, extract_stream, infer_kind
from .extractors._stig_common import StigFindingRow
from .sources import LocalFolderSource, SingleLocalFileSource, Source, SourceFile
from .sources.local import path_to_uri
from .supersession_tracker import apply_supersession_at_ingest
from .tagger import tag_evidence

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-file text-extraction byte budget
#
# A massive log file is less valuable to the LLM than a Splunk insight query
# result, but truncated text beats nothing — the assessor can still see what
# kind of artifact it is and match it to controls. We truncate (with a clear
# marker) rather than skip, so the artifact still lands in the evidence index.
#
# 25 MB is sized so that a typical CKL (< 5 MB), a large PDF (< 20 MB), and
# even a verbose Nessus scan (< 25 MB extracted) pass through uncut, while a
# 200 MB application log doesn't flood the LLM context window or the
# extracted_text directory with an unreadable blob.
#
# Override per-deployment via AppConfig.max_file_bytes in config.toml.
# ---------------------------------------------------------------------------
MAX_FILE_BYTES: int = 25_000_000


@dataclass
class IngestSummary:
    """High-level result of one source-walk run.

    Surfaced verbatim by the ``POST /api/evidence/ingest`` route so the
    UI can show "scanned 412, ingested 309, 11 errors, 1234 tags".

    ``source_uri`` is the top-level URI describing the source (e.g.
    ``file:///C:/Users/.../Downloads/``). Kept as ``folder`` in the
    legacy field name so existing route serializers still work.
    """

    folder: str  # legacy field name; actually the source URI
    source_uri: str = ""  # canonical URI (mirrors folder for new callers)
    scanned: int = 0
    ingested: int = 0
    skipped_existing: int = 0
    skipped_unsupported: int = 0
    errors: list[dict] = field(default_factory=list)
    tags_created: int = 0
    findings_created: int = 0
    # Count of prior Evidence rows whose ``superseded_by_id`` got
    # populated during this run (see :mod:`.supersession_tracker`).
    # Surfaced so the UI can tell the user "you uploaded a new Rev of
    # something — N older artifacts were retired automatically".
    superseded_links: int = 0
    # Count of files whose extracted text was truncated to MAX_FILE_BYTES (or
    # the AppConfig override). The raw file size_bytes records the original
    # size; truncation is noted in the extracted text itself via a marker.
    truncated: int = 0
    # Count of Evidence rows evicted by the retention engine after this run.
    # Only populated when enforce_retention() runs (i.e. workbook_id is set
    # and the workbook's evidence count exceeded the cap).
    evicted: int = 0
    # --- Measure-first instrumentation (added 2026-06-11, verdict-neutral) ---
    # Corpus-level rollup of the per-file tagger gate metrics, so an ingest run
    # answers "what fraction of documents reached the Tier-5 LLM judge?" in one
    # place. ``tagger_runs`` is the denominator (files the tagger processed);
    # ``det_cleared`` is how many were fully served by the deterministic tiers
    # (no LLM); ``judge_invoked`` is how many actually consulted the judge.
    # The goal is judge_invoked / tagger_runs < 0.10. None of these alter a
    # verdict — pure observation.
    tagger_runs: int = 0
    det_cleared: int = 0
    judge_invoked: int = 0
    judge_accepted: int = 0
    judge_errored: int = 0
    # Artifacts that ingested successfully but mapped to ZERO controls (no
    # tag from any tier). These are silently invisible on every control page
    # unless we surface them — the failure mode behind the NESSUS / screenshot
    # / scanned-PDF / CSV "evidence vanished" reports. The UI shows this as a
    # warning ("3 files didn't map to any control — review or tag manually")
    # so evidence never disappears without the assessor knowing. Each entry is
    # ``{"path": uri, "reason": "..."}`` where reason hints WHY (no text
    # extracted, no doc/CCI/control-id signal, etc.).
    untagged: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "folder": self.folder,
            "source_uri": self.source_uri or self.folder,
            "scanned": self.scanned,
            "ingested": self.ingested,
            "skipped_existing": self.skipped_existing,
            "skipped_unsupported": self.skipped_unsupported,
            "tags_created": self.tags_created,
            "findings_created": self.findings_created,
            "superseded_links": self.superseded_links,
            "truncated": self.truncated,
            "evicted": self.evicted,
            "tagger_runs": self.tagger_runs,
            "det_cleared": self.det_cleared,
            "judge_invoked": self.judge_invoked,
            "judge_accepted": self.judge_accepted,
            "judge_errored": self.judge_errored,
            "untagged": self.untagged,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256_of_stream(source_file: SourceFile) -> str:
    """Streaming SHA-256 over a SourceFile's bytes.

    Opens the file once via the Source protocol; reads in 1 MB chunks
    so multi-GB PDFs / .nessus files don't blow up memory regardless of
    backend (local, zip, S3, ...).
    """
    h = hashlib.sha256()
    with source_file.open() as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _existing_by_uri(session: Session, uri: str, workbook_id: int) -> Evidence | None:
    """Composite-key URI lookup: ``(workbook_id, path)``.

    Per-workbook hard scoping (PR 2 of the spillage-defense series): the
    same file ingested into two workbooks MUST produce two rows. Looking
    up by ``path`` alone would collapse the second ingest onto the first
    workbook's Evidence row -- a structural cross-workbook leak. Filtering
    by ``workbook_id`` here is the only thing keeping the two workbooks'
    Evidence pools physically separate.
    """
    return session.exec(
        select(Evidence)
        .where(Evidence.path == uri)
        .where(Evidence.workbook_id == workbook_id)
    ).first()


def _existing_by_hash(session: Session, sha: str, workbook_id: int) -> Evidence | None:
    """Composite-key content lookup: ``(workbook_id, sha256)``.

    Same rationale as :func:`_existing_by_uri` -- global sha256 lookup
    would let workbook B's ingest of an identical-content file silently
    bind to workbook A's row. The composite filter forces a fresh row
    per workbook even when the bytes match exactly.
    """
    return session.exec(
        select(Evidence)
        .where(Evidence.sha256 == sha)
        .where(Evidence.workbook_id == workbook_id)
    ).first()


def _persist_extracted_text(evidence_id_hint: str, text: str) -> str | None:
    """Write the extracted text to ``extracted_text/<evidence_id>.txt`` and return path.

    Storing the text on disk (rather than in SQLite) keeps the DB
    small and lets future LLM calls stream the body without a fat
    query.

    Naming convention (PR 2): ``<evidence_id>.txt``. Was ``<sha256>.txt``
    in the global-pool era -- that collided across workbooks (two rows
    with identical content shared one on-disk text file, so deleting
    workbook A would unlink workbook B's body). Per-evidence naming
    means each row owns its text exclusively. Callers must
    ``session.flush()`` before calling so ``evidence.id`` is populated.

    The legacy ``<sha256>.txt`` files for pre-PR-2 rows are left in
    place; :func:`_safe_delete_extracted_text` ref-counts them so
    workbook delete doesn't unlink a file that's still cited by another
    workbook's pre-PR-2 row.
    """
    if not text:
        return None
    out_dir = extracted_text_dir()
    out_path = out_dir / f"{evidence_id_hint}.txt"
    out_path.write_text(text, encoding="utf-8")
    return str(out_path)


def _safe_delete_extracted_text(session: Session, evidence: Evidence) -> None:
    """Unlink the extracted-text file for an Evidence row, with ref counting.

    Post-PR-2 rows use ``<evidence_id>.txt`` and are owned exclusively
    by one Evidence row -- safe to unlink unconditionally. Legacy rows
    (pre-PR-2) use ``<sha256>.txt`` and may be shared with other
    Evidence rows in OTHER workbooks (the global-pool era didn't isolate
    them). For those, count other rows still pointing at the same path
    and skip the unlink if any remain.

    Best-effort: filesystem errors are swallowed (logged) so workbook
    delete never fails because of a stale file. The DB rows are the
    source of truth; an orphan .txt is a janitor problem, not a
    correctness problem.
    """
    text_path = evidence.extracted_text_path
    if not text_path:
        return
    p = Path(text_path)
    if not p.exists():
        return

    # Per-evidence naming: <evidence_id>.txt. Safe to unlink.
    if evidence.id is not None and p.name == f"{evidence.id}.txt":
        try:
            p.unlink()
        except OSError as exc:  # pragma: no cover - filesystem janitor only
            log.warning("could not unlink extracted text %s: %s", p, exc)
        return

    # Legacy <sha256>.txt -- ref count against other Evidence rows.
    other = session.exec(
        select(Evidence)
        .where(Evidence.extracted_text_path == text_path)
        .where(Evidence.id != evidence.id)
    ).first()
    if other is not None:
        return  # another row still references this file; leave it alone
    try:
        p.unlink()
    except OSError as exc:  # pragma: no cover - filesystem janitor only
        log.warning("could not unlink legacy extracted text %s: %s", p, exc)


def _title_fallback(name: str) -> str:
    """Best-effort title from a leaf name when the extractor returns none."""
    return PurePosixPath(name).stem or name


def _normalize_host(name: str) -> str:
    """Same normalization rule asset_crosscheck applies at query time.

    Lowercase + strip dot-domain suffix so a CKL ``Server01.dom.mil`` and
    an HW/SW row ``server01`` collapse to the same key. Empty / whitespace
    input returns empty string (caller filters).
    """
    n = (name or "").strip().lower()
    if "." in n:
        n = n.split(".", 1)[0]
    return n


def _infer_source_kind(uri: str) -> EvidenceSourceKind:
    """Map a canonical source URI to its connector-telemetry enum value.

    v0.1 only emits ``LOCAL_FILE`` and ``SHAREPOINT``; the rest of
    :class:`EvidenceSourceKind` is reserved for the v0.4+ connectors
    (Tenable, Splunk, GitLab, SN-GRC). Defaulting on the URI scheme keeps
    this single-line and means a new connector's URI prefix is the only
    plumbing needed when it lands.
    """
    if uri.startswith(("sp://", "sharepoint://")):
        return EvidenceSourceKind.SHAREPOINT
    if uri.startswith("s3://"):
        return EvidenceSourceKind.S3
    if uri.startswith(("az://", "azblob://")):
        return EvidenceSourceKind.AZBLOB
    # Default: anything with no scheme, a file:// URI, or the zip://
    # sub-URI a LocalFolderSource emits when descending an archive.
    return EvidenceSourceKind.LOCAL_FILE


def _framework_id_for_workbook(session: Session, workbook_id: int | None) -> int | None:
    """Look up Workbook.framework_id with a single get() call.

    Returns None when ``workbook_id`` is None (no workbook context — the
    boundary-doc / manual-upload paths) or when the workbook exists but
    has no framework attached (legacy workbooks created before the picker
    landed). The tagger treats None as the framework-agnostic default.
    """
    if workbook_id is None:
        return None
    wb = session.get(Workbook, workbook_id)
    return wb.framework_id if wb is not None else None


def _capture_host_inventory(metadata: dict) -> str | None:
    """Build the JSON host_inventory blob from extractor metadata.

    Extractors put hostnames in two keys: ``hosts`` (list, used by STIG /
    Nessus parsers) and ``host`` (single string, used when only one is
    known). XLSX / CSV extractors that detect a hostname column also
    publish ``hostnames`` (already-normalized list). Returns the JSON
    string to persist, or ``None`` when nothing usable was captured —
    storing NULL keeps the migration cheap and signals "fall back to the
    re-parse path" to asset_crosscheck for locally-resolvable files.
    """
    raw: list[str] = []
    hosts = metadata.get("hosts")
    if isinstance(hosts, list):
        raw.extend(str(h) for h in hosts if h)
    host = metadata.get("host")
    if isinstance(host, str) and host:
        raw.append(host)
    hostnames = metadata.get("hostnames")
    if isinstance(hostnames, list):
        raw.extend(str(h) for h in hostnames if h)
    seen: set[str] = set()
    for r in raw:
        norm = _normalize_host(r)
        if norm:
            seen.add(norm)
    if not seen:
        return None
    return json.dumps(sorted(seen))


def _build_tagger_llm() -> tuple[Any | None, str | None]:
    """Construct the optional Tier 5-LLM judge client for the tagger.

    Returns ``(client, judge_model)``. Returns ``(None, None)`` when the
    ``tagger_llm_enabled`` kill-switch is off OR client construction raises
    (no provider key, import failure, offline) — in which case the tagger's
    deterministic TF-IDF Tier 5 runs instead. We deliberately do NOT probe the
    API here (no key validation round-trip): construction is cheap and the
    per-candidate judge calls in the tagger already degrade gracefully on any
    network/auth error, falling back to TF-IDF only when every call fails.
    """
    try:
        cfg = load_config()
        if not getattr(cfg, "tagger_llm_enabled", True):
            return None, None
        from ..llm.client import make_client

        client = make_client(cfg)
        return client, getattr(cfg, "llm_judge_model", None)
    except Exception:  # pragma: no cover - never let LLM setup abort an ingest
        log.warning("tagger LLM client unavailable; using deterministic Tier 5", exc_info=True)
        return None, None


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def ingest_source(
    session: Session,
    source: Source,
    *,
    progress_callback: Callable[[IngestSummary], None] | None = None,
    workbook_id: int | None = None,
) -> IngestSummary:
    """Walk a :class:`Source`, ingest every file it yields, return a summary.

    Works uniformly across local folders, NFS mounts, zip archives,
    and (when wired up) cloud buckets. The source controls its own
    iteration order and noise filtering (lock files, dotfiles,
    unsupported extensions); the orchestrator trusts whatever the
    iterator emits.

    The session is committed in batches to bound memory on big
    OneDrive trees (Noah's evidence folder has 400+ files). Batch size
    defaults to 50 but the Source may override via a
    ``commit_batch_size`` attribute — SharePoint sets this to 1 because
    network download per file already dwarfs the SQLite commit cost, and
    per-file commits let the UI's evidence list refresh smoothly during
    the run instead of jumping in batches of 50. Callers that need
    transactional all-or-nothing should wrap externally — the
    orchestrator favours partial-progress on crash.

    ``progress_callback`` (optional) is invoked after every file is
    processed — success, skip, or error — with the live summary. The
    background-job route uses it to drive a polling status endpoint.
    Callback exceptions are swallowed so a bad observer never aborts
    the ingest.

    ``workbook_id`` is required (PR 2 of the per-workbook hard-scoping
    series). Evidence is physically scoped to a single workbook -- there is
    no NULL bucket, no shared pool, no "framework-agnostic" path. Same
    file ingested into two workbooks produces two rows, two extracted-text
    files, no shared state. Spillage becomes structurally impossible.
    Passing None raises so a future caller can't accidentally re-create
    the global pool by omitting the kwarg.
    """
    if workbook_id is None:
        raise ValueError(
            "workbook_id is required for ingest — per-workbook scoping "
            "(PR 2) forbids global-pool Evidence rows; pass the active "
            "workbook id explicitly"
        )

    source_uri = getattr(source, "uri", "")
    summary = IngestSummary(folder=source_uri, source_uri=source_uri)

    # Resolve once at the top: workbook → framework lens. Cheap lookup,
    # and doing it here means the per-file loop doesn't repeat the get()
    # 400 times during a big OneDrive walk.
    framework_id = _framework_id_for_workbook(session, workbook_id)

    # Build the tagger's optional LLM "smart backstop" client ONCE for the whole
    # walk (one provider/key resolution, not 400). When the kill-switch is off or
    # construction fails (no key, offline), tag_evidence falls back to the
    # deterministic TF-IDF Tier 5 — so a missing client never aborts an ingest.
    tagger_client, tagger_judge_model = _build_tagger_llm()

    # Resolve the per-file text byte-cap ONCE for the whole walk. The cap is a
    # process-wide config knob, not a per-file property, so re-reading it inside
    # the loop meant load_config() ran 400x during a big OneDrive walk. Priority:
    # AppConfig.max_file_bytes; fall back to the module constant MAX_FILE_BYTES.
    # A config value of 0 or negative means unlimited (caller opted out).
    try:
        _cfg_limit = load_config().max_file_bytes
    except Exception:  # noqa: BLE001 — never let a config read wedge an ingest
        _cfg_limit = None
    byte_cap = _cfg_limit if (_cfg_limit is not None) else MAX_FILE_BYTES

    # Sources can opt out of the default 50-file batch. SharePoint sets 1
    # so each ingested row becomes visible to the UI's evidence list query
    # as soon as it lands — otherwise the list jumps in batches of 50
    # while the counter strip ticks file-by-file. Clamped to >=1 in case
    # a Source declares 0 or negative.
    commit_batch_size = max(1, int(getattr(source, "commit_batch_size", 50)))

    def _notify() -> None:
        if progress_callback is None:
            return
        try:
            progress_callback(summary)
        except Exception:  # pragma: no cover - observer shouldn't break ingest
            log.exception("progress_callback raised")

    batch_since_commit = 0
    try:
        files_iter = source.iter_files()
    except NotImplementedError as exc:
        # Stub source (S3/Azure/SharePoint pre-v0.2) — surface cleanly.
        summary.errors.append({"path": source_uri, "error": str(exc)})
        return summary
    except Exception as exc:  # pragma: no cover - source init failure
        log.exception("source %s failed to enumerate", source_uri)
        summary.errors.append({"path": source_uri, "error": f"source: {exc}"})
        return summary

    for sf in files_iter:
        summary.scanned += 1
        uri = sf.uri
        name = sf.name

        # URI-based dedupe (cheap): same canonical URI → already ingested.
        # Content dedupe via hash below catches the same bytes under a
        # different URI (renamed file, same archive re-fetched, etc.).
        if _existing_by_uri(session, uri, workbook_id) is not None:
            summary.skipped_existing += 1
            _notify()
            continue

        try:
            sha = _sha256_of_stream(sf)
        except OSError as exc:
            # WinError 32 = ERROR_SHARING_VIOLATION — almost always OneDrive
            # holding the file open mid-sync, or another process editing it.
            # The raw "[WinError 32] The process cannot access the file" is
            # opaque to non-Windows folks, so we annotate.
            winerror = getattr(exc, "winerror", None)
            if winerror == 32:
                msg = (
                    f"hash failed: file is locked (likely OneDrive sync or another "
                    f"process has it open) — close it or wait for sync to finish: {exc}"
                )
            else:
                msg = f"hash failed: {exc}"
            summary.errors.append({"path": uri, "error": msg})
            _notify()
            continue
        except Exception as exc:  # pragma: no cover - backend read error
            log.exception("hash failed on %s", uri)
            summary.errors.append({"path": uri, "error": f"hash failed: {exc}"})
            _notify()
            continue

        if _existing_by_hash(session, sha, workbook_id) is not None:
            # Same bytes under a different URI WITHIN THIS WORKBOOK --
            # don't create a second Evidence row; the original wins.
            # Composite-key scoping means an identical-content file
            # already ingested by ANOTHER workbook does NOT short-circuit
            # here (that would re-create the global pool); each workbook
            # gets its own row.
            summary.skipped_existing += 1
            _notify()
            continue

        # Stream a second time for extraction — extractors need a fresh
        # stream from byte 0, and the hash pass exhausted the first one.
        try:
            with sf.open() as stream:
                doc: ExtractedDoc = extract_stream(stream, name)
        except ExtractorSkip as exc:
            # Intentionally refused (e.g. the xlsx extractor sniffing out a
            # CCIS workbook). Drop quietly — no Evidence row, no red "failed"
            # tile in the UI, no entry in summary.errors. Bump
            # skipped_unsupported so the file is still accounted for in the
            # totals strip, then continue. Must come BEFORE the ExtractorError
            # branch since ExtractorSkip subclasses it.
            log.info("extractor skipped %s: %s", uri, exc)
            summary.skipped_unsupported += 1
            _notify()
            continue
        except ExtractorError as exc:
            # Recoverable: persist the file with empty text so the user
            # can still see it in the evidence list and tag manually.
            log.info("extractor failed for %s: %s", uri, exc)
            doc = ExtractedDoc(
                text="",
                title=_title_fallback(name),
                doc_number=None,
                kind=infer_kind(name),
                metadata={"extractor_error": str(exc)},
            )
            summary.errors.append({"path": uri, "error": str(exc)})
        except Exception as exc:  # pragma: no cover - extractor bugs
            # Persist the file with empty text + the error in metadata so it
            # still appears in the evidence list — the user can re-ingest
            # after a fix, or tag it manually. Silent drop here meant files
            # vanished from the index with only a log line behind them.
            log.exception("unexpected error extracting %s", uri)
            doc = ExtractedDoc(
                text="",
                title=_title_fallback(name),
                doc_number=None,
                kind=infer_kind(name),
                metadata={"unexpected_error": f"{type(exc).__name__}: {exc}"},
            )
            summary.errors.append({"path": uri, "error": f"unexpected: {exc}"})

        size_bytes = sf.size if sf.size is not None else 0

        # ------------------------------------------------------------------
        # Per-file text-extraction byte budget (Task 1)
        #
        # ``byte_cap`` is resolved ONCE above the loop (config knob, not a
        # per-file property). A value of 0 or negative means unlimited.
        #
        # We truncate the EXTRACTED TEXT, not the raw file — the raw
        # size_bytes is always the true on-disk size (recorded below). This
        # means the evidence row's text sidecar is capped, but the file is
        # still hashed, indexed, and tagged; only the text body is shortened.
        # ------------------------------------------------------------------
        _text_was_truncated = False
        if byte_cap and byte_cap > 0 and doc.text:
            _text_bytes = doc.text.encode("utf-8")
            if len(_text_bytes) > byte_cap:
                # Truncate on a char boundary by re-decoding from the byte
                # slice. utf-8 sequences are up to 4 bytes; decoding with
                # errors="ignore" drops any partial sequence at the cut point.
                _truncated_text = _text_bytes[:byte_cap].decode("utf-8", errors="ignore")
                _original_bytes = len(_text_bytes)
                _kept_bytes = len(_truncated_text.encode("utf-8"))
                _truncated_text += (
                    f"\n\n[...TRUNCATED: original was {_original_bytes:,} bytes, "
                    f"kept first {_kept_bytes:,}...]"
                )
                doc = ExtractedDoc(
                    text=_truncated_text,
                    title=doc.title,
                    doc_number=doc.doc_number,
                    kind=doc.kind,
                    metadata=doc.metadata,
                )
                _text_was_truncated = True
                log.info(
                    "extracted text truncated for %s: %d → %d bytes (cap=%d)",
                    uri,
                    _original_bytes,
                    _kept_bytes,
                    byte_cap,
                )

        if _text_was_truncated:
            summary.truncated += 1

        archive_uri = sf.container_uri if sf.container_uri != uri else None

        evidence = Evidence(
            path=uri,
            sha256=sha,
            kind=doc.kind if isinstance(doc.kind, EvidenceKind) else infer_kind(name),
            size_bytes=size_bytes,
            extracted_text_path=None,  # filled in after flush so the file
            # name can be <evidence_id>.txt (PR 2 per-evidence naming);
            # without flush() first, evidence.id is still None.
            title=doc.title or _title_fallback(name),
            doc_number=doc.doc_number,
            archive_uri=archive_uri,
            host_inventory=_capture_host_inventory(doc.metadata or {}),
            # PR 2: workbook_id is structurally required (the ingest_source
            # precondition above raises on None). source_kind records URI
            # provenance for the future "% unknown source" audit.
            workbook_id=workbook_id,
            source_kind=_infer_source_kind(uri).value,
        )
        session.add(evidence)
        session.flush()  # populate evidence.id before tagging / findings

        # Persist extracted text to <evidence_id>.txt (PR 2 naming) and
        # back-fill the FK on the Evidence row. Must run after flush so
        # evidence.id is populated.
        extracted_path = _persist_extracted_text(str(evidence.id), doc.text)
        if extracted_path is not None:
            evidence.extracted_text_path = extracted_path
            session.add(evidence)

        # Link prior evidence rows this artifact supersedes. Runs before
        # tagging so the read-side filters (evidence_bundle, asset
        # crosscheck) see the chain immediately on the next assess pass.
        # Tracker is best-effort — it never raises, and a 0 return is
        # the normal case for unique uploads.
        summary.superseded_links += apply_supersession_at_ingest(session, evidence)

        # STIG / Nessus extractors stash their normalized findings in
        # metadata under "_stig_findings" so we can attach them once
        # the FK is known.
        stig_rows: list[StigFindingRow] = doc.metadata.get("_stig_findings", []) or []
        for fr in stig_rows:
            session.add(
                StigFinding(
                    evidence_id=evidence.id,
                    rule_id=fr.rule_id,
                    rule_version=fr.rule_version,
                    # Pass through the four new STIG detail fields. Use
                    # getattr defensively in case a future extractor rename
                    # slightly differs — the column defaults to None so a
                    # missing attribute produces a null rather than a crash.
                    group_id=getattr(fr, "group_id", None),
                    rule_title=getattr(fr, "rule_title", None),
                    check_text=getattr(fr, "check_text", None),
                    fix_text=getattr(fr, "fix_text", None),
                    cci_refs=fr.cci_refs,
                    severity=fr.severity,
                    status=fr.status,
                    finding_details=fr.finding_details,
                    comments=fr.comments,
                )
            )
            summary.findings_created += 1

        # Auto-tag against the loaded objective catalog. evidence_type /
        # signals come from extractors that can classify a file by content
        # shape (e.g. xlsx asset lists → hw_inventory) — surfaced into the
        # tagger so a HW asset list gets auto-mapped to CM-8 without a
        # filename hint.
        ev_type = doc.metadata.get("evidence_type") if doc.metadata else None
        ev_signals = doc.metadata.get("evidence_type_signals") if doc.metadata else None
        # Lever B: a generic evidence xlsx with a dedicated CCI column emits
        # metadata["cci_refs"] (validated CCI-#### tokens). Routed to the same
        # ungated 0.95 Tier-2 branch as STIG/Nessus structured cci_refs without
        # fabricating StigFinding ORM rows for a non-STIG artifact.
        ev_cci_refs = doc.metadata.get("cci_refs") if doc.metadata else None
        try:
            tag_result = tag_evidence(
                session,
                evidence,
                doc.text,
                stig_findings=stig_rows or None,
                cci_refs=ev_cci_refs,
                evidence_type=ev_type,
                evidence_type_signals=ev_signals,
                framework_id=framework_id,
                client=tagger_client,
                judge_model=tagger_judge_model,
            )
            summary.tags_created += tag_result.tags_created
            # Verdict-neutral gate metrics (see IngestSummary docstring).
            summary.tagger_runs += 1
            if tag_result.gate_cleared_by_det:
                summary.det_cleared += 1
            if tag_result.judge_invoked:
                summary.judge_invoked += 1
            summary.judge_accepted += tag_result.judge_accepted
            summary.judge_errored += tag_result.judge_errored
            # Surface artifacts that mapped to ZERO controls so they don't
            # silently vanish from every control page. Distinguish the two
            # root causes so the user knows whether to add a control-ID/
            # doc-number to the file or tag it manually.
            if tag_result.tags_created == 0:
                if not (doc.text and doc.text.strip()):
                    reason = (
                        "No text could be extracted (image, diagram, scanned "
                        "PDF, or binary) — nothing for the tagger to match."
                    )
                else:
                    reason = (
                        "No document number, CCI, or control ID found — "
                        "tag manually or add a control reference."
                    )
                summary.untagged.append({"path": uri, "reason": reason})
        except Exception as exc:  # pragma: no cover - tagger should not raise
            log.exception("tagger failed on %s", uri)
            summary.errors.append({"path": uri, "error": f"tagger: {exc}"})

        summary.ingested += 1
        batch_since_commit += 1
        if batch_since_commit >= commit_batch_size:
            session.commit()
            batch_since_commit = 0
        _notify()

    if batch_since_commit:
        session.commit()
    _notify()

    # ------------------------------------------------------------------
    # Retention enforcement (Task 2)
    #
    # Run after the final batch commit so every newly-ingested row is
    # visible to the count query. Only runs when workbook_id is in scope
    # (precondition above already guarantees it's not None here, but
    # guard defensively anyway). Best-effort: a retention error must
    # never abort ingest — the Evidence rows are the source of truth;
    # a slightly oversized pool is preferable to a failed ingest.
    # ------------------------------------------------------------------
    if workbook_id is not None:
        try:
            from .evidence_retention import enforce_retention  # local import to avoid circular
            summary.evicted = enforce_retention(session, workbook_id)
        except Exception:
            log.exception(
                "retention enforcement failed for workbook_id=%s — "
                "ingest results are unaffected; pool may exceed cap",
                workbook_id,
            )

    # ------------------------------------------------------------------
    # Corpus-level gate metric (measure-first, verdict-neutral).
    #
    # The whole point of the lever work: drive judge_invoked/tagger_runs
    # below 0.10. This single grep-able line reports the ratio for the
    # whole run so we can baseline before changing any tagger and confirm
    # the trend after each lever — without touching a single verdict.
    # ------------------------------------------------------------------
    if summary.tagger_runs:
        judge_ratio = summary.judge_invoked / summary.tagger_runs
        log.info(
            "tier5_corpus tagger_runs=%d det_cleared=%d judge_invoked=%d "
            "judge_accepted=%d judge_errored=%d judge_ratio=%.4f",
            summary.tagger_runs, summary.det_cleared, summary.judge_invoked,
            summary.judge_accepted, summary.judge_errored, judge_ratio,
        )

    return summary


def ingest_folder(
    session: Session,
    folder: Path | str,
    *,
    recursive: bool = True,
    workbook_id: int | None = None,
) -> IngestSummary:
    """Walk a local folder and ingest every supported file.

    Thin façade over :func:`ingest_source` that builds a
    :class:`LocalFolderSource` for the given path. Kept as a stable
    entry point so the API route and CLI don't need to construct
    Source objects themselves for the common case.

    Zip archives are descended transparently — members are ingested
    individually under ``zip://`` URIs, the archive itself is not
    indexed as evidence.
    """
    root = Path(folder)
    if not root.exists() or not root.is_dir():
        summary = IngestSummary(folder=str(root), source_uri=str(root))
        summary.errors.append({"path": str(root), "error": "not a directory"})
        return summary

    source = LocalFolderSource(root, recursive=recursive)
    return ingest_source(session, source, workbook_id=workbook_id)


def ingest_single_local_file(
    session: Session,
    path: Path | str,
    *,
    workbook_id: int | None = None,
) -> Evidence | None:
    """Ingest exactly one local file and return its Evidence row.

    Synchronous companion to the async folder-ingest job, used by the
    boundary-doc upload route where the assessor picks a single SSP /
    network diagram via the Electron file dialog and expects an
    immediate Evidence row to flag. Reuses the full orchestrator —
    hash, extract, tag, supersession — so single-file uploads land in
    the index identical to folder-walked ones.

    Returns the Evidence row matching the file. If the file was a
    duplicate (URI or sha256 collision), returns the *existing* row so
    the route can stamp boundary-doc flags onto it. Returns None if
    the orchestrator emitted no row (file missing, hash failed) — the
    route turns that into a 4xx.

    ``workbook_id`` is required (PR 2 per-workbook hard-scoping). The
    delegation to :func:`ingest_source` raises on None, but we re-state
    the precondition here so callers that bypass the orchestrator-side
    raise (or read this function in isolation) get the same fail-fast
    signal. The post-ingest lookups below MUST then pass workbook_id
    through — a global lookup would re-introduce the spillage path.
    """
    if workbook_id is None:
        raise ValueError(
            "workbook_id is required for ingest — per-workbook scoping "
            "(PR 2) forbids global-pool Evidence rows; pass the active "
            "workbook id explicitly"
        )

    p = Path(path)
    source = SingleLocalFileSource(p)
    summary = ingest_source(session, source, workbook_id=workbook_id)
    uri = path_to_uri(p)

    # First, try the canonical URI — this matches both the fresh insert
    # and a same-URI re-ingest. Scoped to this workbook: if the same
    # URI was ingested by ANOTHER workbook, that row is invisible here
    # and the caller will see None (correct — that row isn't ours).
    ev = _existing_by_uri(session, uri, workbook_id)
    if ev is not None:
        return ev

    # Fall back to sha256 — if the same bytes already exist under a
    # different URI WITHIN THIS WORKBOOK, the orchestrator dropped the
    # new URI and kept the original row. Same workbook-scoping rule:
    # an identical-content row in another workbook does not satisfy
    # this lookup.
    try:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        ev = _existing_by_hash(session, h.hexdigest(), workbook_id)
        if ev is not None:
            return ev
    except OSError:
        pass

    # No row materialized — orchestrator logged an error in summary.errors.
    log.warning("ingest_single_local_file produced no Evidence row for %s: %s",
                p, summary.errors)
    return None
