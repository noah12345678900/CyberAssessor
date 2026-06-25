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
import time
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
    # Two-class ETA instrumentation (2026-06-23). Per-file wall time is bimodal:
    # deterministic-tier files finish in milliseconds; LLM-judged files pay
    # HyDE + ~15 Opus judge calls (~15-25s). A single blended rate gives a wildly
    # optimistic ETA (the fast files front-load it). We accumulate count + total
    # seconds SEPARATELY for the two classes so the UI can compute
    #   eta = remaining * [p_llm * avg_slow + (1-p_llm) * avg_fast]
    # which is stable under the 100x cost spread. "slow" = a file that invoked
    # the judge; "fast" = everything else (deterministic-cleared, skips, errors).
    # Verdict-neutral pure observation.
    fast_file_count: int = 0
    fast_file_seconds: float = 0.0
    slow_file_count: int = 0
    slow_file_seconds: float = 0.0
    # Artifacts that ingested successfully but mapped to ZERO controls (no
    # tag from any tier). These are silently invisible on every control page
    # unless we surface them — the failure mode behind the NESSUS / screenshot
    # / scanned-PDF / CSV "evidence vanished" reports. The UI shows this as a
    # warning ("3 files didn't map to any control — review or tag manually")
    # so evidence never disappears without the assessor knowing. Each entry is
    # ``{"path": uri, "reason": "..."}`` where reason hints WHY (no text
    # extracted, no doc/CCI/control-id signal, etc.).
    untagged: list[dict] = field(default_factory=list)
    # Tagger LLM availability for THIS ingest: "ok" (judge ran), "disabled"
    # (kill-switch off — user's choice), or "error" (client construction failed
    # unexpectedly). When not "ok", the hybrid-RAG folder lane + vision were
    # skipped, so structural evidence may have tagged to zero controls. The UI
    # raises a banner on "error" (and notes "disabled") so a degraded ingest is
    # never silent. Defaults "ok" so callers/tests that build a summary directly
    # are unaffected.
    tagger_status: str = "ok"

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
            "fast_file_count": self.fast_file_count,
            "fast_file_seconds": self.fast_file_seconds,
            "slow_file_count": self.slow_file_count,
            "slow_file_seconds": self.slow_file_seconds,
            "untagged": self.untagged,
            "tagger_status": self.tagger_status,
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


def _looks_like_ip(token: str) -> bool:
    """True if ``token`` parses as an IPv4 or IPv6 address.

    Used to suppress dot-domain stripping for IP literals — the dots in
    ``172.20.8.86`` are address octets, not a DNS suffix. Kept local to
    this module (mirrors the same helper in asset_crosscheck) to avoid an
    import cycle, per the duplication note on the suffix allowlists.
    """
    import ipaddress

    try:
        ipaddress.ip_address(token.strip())
        return True
    except ValueError:
        return False


def _normalize_host(name: str) -> str:
    """Same normalization rule asset_crosscheck applies at query time.

    Lowercase + strip dot-domain suffix so a CKL ``Server01.dom.mil`` and
    an HW/SW row ``server01`` collapse to the same key. Empty / whitespace
    input returns empty string (caller filters).

    IP guard: an IPv4/IPv6 literal is returned whole — the dots in an
    address are NOT a domain suffix. Without this, ``172.20.8.86`` was
    truncated to ``172`` and every scanned IP in a Nessus/ACAS subnet
    sweep collapsed to a single bogus "172" host (Asset Coverage showed
    "1 host"). Mirror the same guard in ``asset_crosscheck._normalize`` so
    ingest-time and query-time keys stay identical.
    """
    n = _clean_host_token(name)
    if "." in n and not _looks_like_ip(n):
        n = n.split(".", 1)[0]
    return n


def _clean_host_token(name: str) -> str:
    """Lowercase + drop a trailing dot and a ``:port`` suffix before IP checks.

    A host token can arrive as ``1.2.3.4:443`` (scan target with port),
    ``host.dom.mil.`` (FQDN with the DNS root dot), or ``HOST``. Without
    stripping the port/trailing-dot first, ``1.2.3.4:443`` fails the
    ``ip_address()`` guard and gets dot-split to the bogus key ``"1"`` — the
    exact subnet-collapse class the IP guard was added to prevent, just via a
    different input shape. A ``:port`` is removed ONLY when there is exactly
    one colon and an all-digit suffix, so a bare IPv6 literal (``::1``,
    multiple colons) is never mangled. Shared by all three ``_normalize``
    sites (ingest / asset_crosscheck / scope_backfill) so keys stay identical.
    """
    n = (name or "").strip().lower().rstrip(".")
    if n.count(":") == 1:
        head, _, tail = n.partition(":")
        if head and tail.isdigit():
            n = head
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
    # Fold the FQDN side of every (ip, fqdn) pair into the bare-hostname list.
    # The device-centric model treats the hostname (not the IP) as the device
    # identity, so the resolved FQDN must appear here even when the only place
    # that names the device is the credentialed-scan pairing. The IP side is
    # NOT added — _normalize_host's IP guard would keep it whole and it would
    # then count as its own "host", which is exactly the per-IP sprawl the
    # pairing exists to collapse. The IP lives structurally in host_pairs.
    for pair in metadata.get("host_pairs") or []:
        if isinstance(pair, dict):
            fqdn = pair.get("fqdn")
            if isinstance(fqdn, str) and fqdn:
                raw.append(fqdn)
    seen: set[str] = set()
    for r in raw:
        norm = _normalize_host(r)
        if norm:
            seen.add(norm)
    if not seen:
        return None
    return json.dumps(sorted(seen))


def _capture_host_pairs(metadata: dict) -> str | None:
    """Build the JSON ``host_pairs`` sibling blob from extractor metadata.

    Reads ``metadata["host_pairs"]`` — a list of ``{"ip","fqdn"}`` dicts that
    a CREDENTIALED scan emits when it observes both the IP and the OS-resolved
    FQDN/netbios for the same live box (see ``extractors/nessus.py``). Stored
    SEPARATELY from ``host_inventory`` (a flat ``list[str]`` consumed by the
    evidence bundle / corroboration / sweep) so the structured pairing is
    available to scope-backfill (stamp ``Asset.ip_address`` / ``Asset.fqdn``)
    and the asset cross-check (collapse IPs under one device) WITHOUT changing
    the host_inventory contract those other modules depend on.

    Normalizes nothing — the raw IP and FQDN are both load-bearing for the
    device join. Drops malformed entries (missing either half, non-dict).
    Returns the JSON string, or ``None`` when no usable pair was captured
    (uncredentialed scan, single-host format, legacy row) so the column
    stays NULL and the migration stays cheap.
    """
    raw = metadata.get("host_pairs")
    if not isinstance(raw, list):
        return None
    pairs: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ip")
        fqdn = entry.get("fqdn")
        if not (isinstance(ip, str) and ip and isinstance(fqdn, str) and fqdn):
            continue
        key = (ip.strip(), fqdn.strip())
        if key in seen:
            continue
        seen.add(key)
        pairs.append({"ip": key[0], "fqdn": key[1]})
    if not pairs:
        return None
    return json.dumps(pairs)


def _build_tagger_llm() -> tuple[Any | None, str | None, str]:
    """Construct the optional Tier 5-LLM judge client for the tagger.

    Returns ``(client, judge_model, status)``. ``status`` is one of:

    * ``"ok"``       — client built; the hybrid-RAG judge (and vision) will run.
    * ``"disabled"`` — the ``tagger_llm_enabled`` kill-switch is off; the user
                       intentionally turned the judge off. Deterministic-only.
    * ``"error"``    — client construction RAISED (no provider key, import
                       failure, etc.). This is an UNINTENDED degradation — the
                       caller surfaces it loudly so a crippled ingest is never
                       mistaken for a healthy one.

    Why the status matters: when the client is absent the hybrid-RAG folder
    lane AND vision both skip, so structural evidence (a file under ``01.AC/``,
    a screenshot) can tag to ZERO controls. That outcome is acceptable ONLY if
    the assessor KNOWS the judge was unavailable and can re-ingest — a SILENT
    degrade looks identical to a healthy ingest and hides the gap. We do not
    probe the API here (no key round-trip); construction is cheap and the
    per-candidate judge calls degrade gracefully on their own.
    """
    try:
        cfg = load_config()
        if not getattr(cfg, "tagger_llm_enabled", True):
            log.info("tagger LLM disabled by kill-switch; deterministic Tier 5 only")
            return None, None, "disabled"
        from ..llm.client import make_client

        client = make_client(cfg)
        return client, getattr(cfg, "llm_judge_model", None), "ok"
    except Exception:  # pragma: no cover - never let LLM setup abort an ingest
        # ERROR (not the kill-switch): construction failed unexpectedly. Log the
        # real cause AND let the caller raise a degraded-ingest warning so the
        # zero-tag-on-structural-evidence outcome is visible, not silent.
        log.warning(
            "tagger LLM client construction FAILED; ingest will run degraded "
            "(deterministic Tier 5 only) — files may tag to zero controls",
            exc_info=True,
        )
        return None, None, "error"


def _vision_enabled() -> bool:
    """Whether the per-image vision describe step should run (config gate)."""
    try:
        return bool(getattr(load_config(), "vision_enabled", True))
    except Exception:  # pragma: no cover - never let config wedge an ingest
        return True


# Map image suffixes → the media_type the vision API expects.
_VISION_MEDIA_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".webp": "image/webp",
}

# Bounded OUTER vision retry (2026-06-24). describe_image retries ~5x internally
# on 429; these add a couple more patient attempts with a longer pause so a heavy
# rate-limit burst doesn't permanently zero a valid image. Small numbers — the
# never-zero backstop is the guarantee; this just reduces fall-through.
_VISION_OUTER_ATTEMPTS = 3
_VISION_OUTER_RETRY_SLEEP = 8.0  # seconds between outer attempts


def _apply_vision(
    doc: ExtractedDoc,
    source_file: SourceFile,
    name: str,
    client: Any,
) -> ExtractedDoc:
    """Augment an IMAGE doc's text with a vision description (OCR kept).

    The OCR text (from the image extractor) is preserved verbatim — both in the
    combined ``text`` under an ``[ocr]`` section AND in ``metadata["ocr_verbatim"]``
    — while the vision description is the PRIMARY tagging text under ``[vision]``.

    Why keep OCR separately: a VLM paraphrase can flip ``enforcing``/``permissive``
    or an IP octet, so it must never be QUOTED to a 3PAO. The ``ocr_verbatim``
    key is the clean citation surface for a future narrative-validator rule
    ("any quoted string must appear in OCR text"). That validator rule is NOT
    yet implemented — today the key is forward-looking provenance, and the OCR
    text is in any case still present in ``text`` so nothing is lost. Persisting
    it now means the validator can be added later without re-ingesting.

    Best-effort: any failure leaves ``doc`` exactly as OCR produced it (degrade
    to OCR-only, never abort the ingest).
    """
    suffix = PurePosixPath(name).suffix.lower()
    media_type = _VISION_MEDIA_TYPES.get(suffix)
    if media_type is None:
        return doc
    try:
        with source_file.open() as stream:
            raw = stream.read()
    except Exception:  # noqa: BLE001
        return doc
    description = ""
    # Bounded OUTER retry (2026-06-24). describe_image already does ~5 rate-limit
    # retries internally, but during a heavy 429 storm a valid image can exhaust
    # all of them and return "" — which silently became a 0-text image (the
    # step6_FAIL.png cause: a normal PNG, identical to one that read fine, lost
    # only to timing). Vision is rare (images only) + high-value, so we can
    # afford a couple more patient attempts with a longer pause to let the burst
    # subside. The never-zero backstop catches whatever still fails, so this only
    # REDUCES how often an image falls to quarantine; it doesn't have to be
    # perfect. Deliberately uses the MAIN model (Opus) — accuracy over cost.
    for _attempt in range(_VISION_OUTER_ATTEMPTS):
        try:
            description = client.describe_image(raw, media_type=media_type) or ""
        except Exception:  # noqa: BLE001 — degrade to OCR-only
            log.debug("vision describe raised for %s; OCR-only", name, exc_info=True)
            description = ""
        if description.strip():
            break
        if _attempt + 1 < _VISION_OUTER_ATTEMPTS:
            time.sleep(_VISION_OUTER_RETRY_SLEEP)
    if not description.strip():
        # Vision could not be obtained after all attempts. Do NOT silently return
        # a 0-text doc for a content-bearing image — flag it so the never-zero
        # backstop quarantines it (CA-2) instead of an invisible drop, and a
        # re-ingest can retry once the gateway calms down.
        log.info("vision unavailable for %s after %d attempts; flagged for backstop",
                 name, _VISION_OUTER_ATTEMPTS)
        new_meta = dict(doc.metadata or {})
        new_meta["vision_failed"] = True
        if (doc.text or "").strip():
            return doc  # OCR text present → keep the legit OCR path untouched
        return ExtractedDoc(
            text=doc.text or "",
            title=doc.title,
            doc_number=doc.doc_number,
            kind=doc.kind,
            metadata=new_meta,
        )
    ocr_text = doc.text or ""
    new_meta = dict(doc.metadata or {})
    new_meta["vision"] = True
    # Preserve the OCR body verbatim for citation enforcement.
    new_meta["ocr_verbatim"] = ocr_text
    combined = f"[vision] {description}"
    if ocr_text.strip():
        combined += f"\n\n[ocr] {ocr_text}"
    return ExtractedDoc(
        text=combined,
        title=doc.title,
        doc_number=doc.doc_number,
        kind=doc.kind,
        metadata=new_meta,
    )


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
    tagger_client, tagger_judge_model, tagger_status = _build_tagger_llm()
    # Record availability so the UI can raise a degraded-ingest banner. "error"
    # = construction failed unexpectedly (the silent-degrade defect); "disabled"
    # = user turned the judge off on purpose. Either way the folder lane +
    # vision skip, so structural files may tag to zero controls.
    summary.tagger_status = tagger_status
    # Tier-5 escalation model (2026-06-24). Resolved ONCE for the walk. Only
    # meaningful when the judge client is actually live (status "ok"); offline /
    # disabled ingests have no client to escalate with, so we leave it None and
    # tag_evidence never enters the escalation path. None in config also disables.
    tagger_escalation_model: str | None = None
    if tagger_status == "ok":
        try:
            tagger_escalation_model = getattr(
                load_config(), "llm_judge_escalation_model", None
            )
        except Exception:  # pragma: no cover - never let config wedge an ingest
            tagger_escalation_model = None
    # Resolve the vision + corpus-augmentation gates ONCE for the whole walk
    # (config knobs, not per-file properties).
    vision_on = _vision_enabled()
    try:
        augment_corpus_on = bool(getattr(load_config(), "corpus_augmentation_enabled", True))
    except Exception:  # pragma: no cover - never let config wedge an ingest
        augment_corpus_on = True

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
        _file_t0 = time.monotonic()  # per-file wall clock for the two-class ETA
        _file_judged = False  # set True if this file invoked the LLM judge
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

        # Vision augmentation for images (2026-06-22). Every IMAGE gets a
        # multimodal description in addition to OCR when a client is available
        # and the gate is on — fixes pure-graphics screenshots that OCR can't
        # read AND raises tagging quality on OCR label-soup. OCR text is kept
        # verbatim in metadata for citation. Gated identically to the tagger
        # client (offline/disabled → OCR-only, unchanged).
        if (
            doc.kind == EvidenceKind.IMAGE
            and tagger_client is not None
            and vision_on
        ):
            doc = _apply_vision(doc, sf, name, tagger_client)

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
            host_pairs=_capture_host_pairs(doc.metadata or {}),
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
                escalation_model=tagger_escalation_model,
                augment_corpus=augment_corpus_on,
                evidence_metadata=doc.metadata,
            )
            summary.tags_created += tag_result.tags_created
            # Verdict-neutral gate metrics (see IngestSummary docstring).
            summary.tagger_runs += 1
            if tag_result.gate_cleared_by_det:
                summary.det_cleared += 1
            if tag_result.judge_invoked:
                summary.judge_invoked += 1
                _file_judged = True
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
                elif tagger_status != "ok":
                    # The judge / hybrid-RAG folder lane did NOT run this ingest
                    # (client disabled or construction failed), so a structural
                    # file under e.g. 01.AC/ never got its family in front of the
                    # judge. Name THAT cause distinctly from "no CCI found" so the
                    # assessor re-ingests with the tagger LLM available rather
                    # than hand-tagging a file the judge would have placed.
                    why = (
                        "the tagger LLM is disabled in Settings"
                        if tagger_status == "disabled"
                        else "the tagger LLM client failed to start"
                    )
                    reason = (
                        f"Tagger LLM unavailable ({why}) — semantic tagging was "
                        "skipped for this ingest. Re-ingest with the tagger LLM "
                        "enabled, or tag manually."
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
        # Two-class ETA timing: bucket this file's wall time by whether it hit
        # the LLM judge (slow) or was served deterministically (fast). The UI
        # uses the two averages + observed p_llm for a stable bimodal ETA.
        _file_elapsed = time.monotonic() - _file_t0
        if _file_judged:
            summary.slow_file_count += 1
            summary.slow_file_seconds += _file_elapsed
        else:
            summary.fast_file_count += 1
            summary.fast_file_seconds += _file_elapsed
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
