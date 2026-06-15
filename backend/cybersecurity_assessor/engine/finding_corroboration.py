"""Shared corroboration queries: STIG findings + affected hosts for a cluster.

Both the POAM generator (downstream, narrative composition) and the assessor's
evidence bundle (upstream, status decision input) need the same join:

  EvidenceTag → Evidence → StigFinding, filtered by the cluster's CCIs.

Keeping the join in one place means the narrative the LLM reads when deciding
ComplianceStatus is built from the same source-of-truth set the POAM builder
later cites. If they ever drift, an assessor narrative might mention findings
the POAM omits (or vice versa), which destroys the audit trail's coherence.

Corroboration rule (per feedback_corroborate_stig_findings.md): a STIG finding
counts toward a CCI cluster only when BOTH (a) it lives on an Evidence row
that's tagged to one of the cluster's objectives AND (b) its ``cci_refs``
column intersects the cluster's CCI set. A CKL tagged to AC-2 will contain
findings for IA-5 and CM-6 too — tag alone is too noisy.
"""

from __future__ import annotations

import json
import re

from sqlmodel import Session, select

from ..db import chunked
from ..models import Evidence, EvidenceTag, FindingStatus, StigFinding

# STIG severity ranking for picking top findings. Anything outside the table
# sorts last (severity = None or non-standard string). Canonical home — the
# POAM generator re-imports from here.
# DISA tooling emits cci_refs joined with EITHER "," OR ";" depending on the
# scanner (and occasionally whitespace alone). Split on any of them so the
# corroboration join doesn't silently drop semicolon-joined findings.
_CCI_REF_SPLIT = re.compile(r"[,;\s]+")


def _basename(path: str | None) -> str | None:
    """OS-agnostic basename — splits on both / and \\ so Windows-absolute
    paths (no forward slashes) don't leak through the rsplit("/", 1) fallback
    and expose the user's local filesystem in narrative output."""
    if not path:
        return None
    # Strip trailing separators, then take the last segment.
    s = path.rstrip("/\\")
    for sep in ("/", "\\"):
        if sep in s:
            s = s.rsplit(sep, 1)[-1]
    return s or None


_SEVERITY_RANK: dict[str, int] = {
    "high": 0,
    "cat i": 0,
    "medium": 1,
    "cat ii": 1,
    "low": 2,
    "cat iii": 2,
    "informational": 3,
    "info": 3,
    "cat iv": 3,
}


def _severity_sort_key(sev: str | None) -> int:
    if not sev:
        return 99
    return _SEVERITY_RANK.get(sev.strip().lower(), 50)


def corroborating_findings(
    objective_ids: list[int],
    cci_ids_in_cluster: set[str],
    session: Session,
) -> list[tuple[StigFinding, str]]:
    """Return OPEN StigFindings tagged to the cluster that also cite a cluster CCI.

    Args:
      objective_ids: cluster member Objective primary keys.
      cci_ids_in_cluster: the set of CCI ID strings (e.g. {"CCI-001240",
        "CCI-001241"}) the cluster covers. Used to filter the noisy long-tail
        of unrelated findings on the same CKL.
      session: live SQLModel session.

    Returns:
      (finding, evidence_label) pairs sorted by severity desc (high → low).
      evidence_label = Evidence.title if set, else basename of Evidence.path,
      else ``evidence#<id>``. Empty list when nothing corroborates — caller
      decides whether to render an empty section or omit it entirely.
    """
    if not objective_ids:
        return []
    tag_rows = session.exec(
        select(EvidenceTag.evidence_id).where(
            EvidenceTag.objective_id.in_(objective_ids)
        )
    ).all()
    evidence_ids = {eid for eid in tag_rows if eid is not None}
    if not evidence_ids:
        return []
    # Chunk: a control with tens of thousands of tagged artifacts would blow
    # past SQLITE_MAX_VARIABLES on a single .in_(evidence_ids).
    findings: list[StigFinding] = []
    for batch in chunked(list(evidence_ids)):
        findings.extend(
            session.exec(
                select(StigFinding)
                .where(StigFinding.evidence_id.in_(batch))
                .where(StigFinding.status == FindingStatus.OPEN)
            ).all()
        )
    if not findings:
        return []

    # Pre-fetch evidence labels in one shot — avoids N+1 when many findings
    # share the same source CKL.
    ev_label: dict[int, str] = {}
    for batch in chunked([f.evidence_id for f in findings]):
        for eid, title, path in session.exec(
            select(Evidence.id, Evidence.title, Evidence.path).where(
                Evidence.id.in_(batch)
            )
        ).all():
            ev_label[eid] = title or _basename(path) or f"evidence#{eid}"

    # Normalize the cluster's CCI set once — upstream parsers occasionally
    # lowercase CCI ids ("cci-000015") and the comparison must not silently
    # drop them.
    cluster_norm = {c.strip().upper() for c in cci_ids_in_cluster if c.strip()}

    matched: list[tuple[StigFinding, str]] = []
    for f in findings:
        if not f.cci_refs:
            continue
        refs = {
            r.strip().upper()
            for r in _CCI_REF_SPLIT.split(f.cci_refs)
            if r.strip()
        }
        if refs & cluster_norm:
            matched.append(
                (f, ev_label.get(f.evidence_id, f"evidence#{f.evidence_id}"))
            )

    # Highest severity first so callers that take the top N see the most
    # remediation-relevant findings.
    matched.sort(key=lambda pair: _severity_sort_key(pair[0].severity))
    return matched


def format_finding_citation(finding: StigFinding, evidence_label: str) -> str:
    """One-line, reviewer-recognizable citation for a StigFinding.

    Format when both group_id and rule_id are present:
        [V-220706 / SV-220706r569187_rule] <rule_title or evidence_label>

    Falls back gracefully when the V-number (group_id) or SV-rule (rule_id)
    is absent (Nessus findings leave both None):
        [SV-220706r569187_rule] <rule_title or evidence_label>
        <evidence_label>   (if only the evidence label is available)

    The evidence_label is always appended in parentheses so the reader knows
    which CKL/CKLB/XCCDF sourced the finding — without it the V-number alone
    doesn't tell a reviewer WHERE to look.
    """
    parts: list[str] = []
    if finding.group_id:
        parts.append(finding.group_id)
    if finding.rule_id:
        parts.append(finding.rule_id)

    label_text = finding.rule_title or evidence_label
    source_tag = f" ({evidence_label})" if finding.rule_title else ""

    if parts:
        bracket = "[" + " / ".join(parts) + "]"
        return f"{bracket} {label_text}{source_tag}"
    return label_text


# Dotted-quad IPv4 detector — IPv4-shaped tokens never get short-name-folded
# (no DNS truth-source from a workbook alone, so we can't claim "10.0.0.5"
# is the same machine as "server01" without inviting false merges).
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# IPv6 is loosely matched — any token with at least two colons is treated as
# an address. Same reasoning as IPv4: we won't fold IP-shaped tokens into
# hostname-shaped tokens.
_IPV6_HINT_RE = re.compile(r":[0-9a-f:]*:", re.IGNORECASE)


def _looks_like_ip(token: str) -> bool:
    """True if ``token`` looks like an IPv4 or IPv6 literal."""
    return bool(_IPV4_RE.match(token) or _IPV6_HINT_RE.search(token))


def _canonicalize_host(raw: str) -> str | None:
    """Reduce one host string to its canonical form for dedup.

    Lowercases, strips whitespace, drops a trailing dot (FQDNs sometimes
    arrive as ``server01.corp.local.``). Returns None for empty/whitespace.

    Intentionally *not* aggressive: no IP-vs-hostname fusion, no NetBIOS
    transform, no DNS resolution. The goal of this layer is to make sure
    obvious lexical variants of the same string collapse — the harder
    "is this the same physical box?" question lives in the upcoming Asset
    resolver (slice 0.2b), not here.
    """
    s = raw.strip().rstrip(".").lower()
    return s or None


def _collapse_short_to_fqdn(canonical: set[str]) -> set[str]:
    """Fold bare short names into their FQDN when the match is unambiguous.

    Rule: a bare name (no dot, not an IP) collapses INTO an FQDN form if
    exactly ONE FQDN in the set begins with that label. If there are zero
    or multiple candidates, the bare name stays as its own entry — we'd
    rather over-list than misjoin two different machines.

    Examples:
        {"server01", "server01.corp.local"}                 -> {"server01.corp.local"}
        {"server01", "server01.corp.local",
         "server01.dev.local"}                              -> all three kept (ambiguous)
        {"server01", "router01.corp.local"}                 -> both kept (no match)
        {"10.0.0.5", "server01.corp.local"}                 -> both kept (IP, no DNS truth)
    """
    fqdns_by_first_label: dict[str, list[str]] = {}
    for h in canonical:
        if _looks_like_ip(h) or "." not in h:
            continue
        first_label = h.split(".", 1)[0]
        fqdns_by_first_label.setdefault(first_label, []).append(h)

    result = set(canonical)
    for h in canonical:
        if _looks_like_ip(h) or "." in h:
            continue
        candidates = fqdns_by_first_label.get(h, [])
        if len(candidates) == 1:
            # Unambiguous — drop the bare name, keep the FQDN.
            result.discard(h)
    return result


def affected_hosts(
    objective_ids: list[int],
    session: Session,
) -> list[str]:
    """Sorted unique hostnames from Evidence.host_inventory across the cluster.

    Walks every Evidence row tagged to any of ``objective_ids``, decodes the
    JSON ``host_inventory`` payload, and returns the deduped, sorted union of
    hostnames. Empty list when no tagged evidence carries inventory data (the
    common case for policy-only controls) — caller omits the section in that
    case.

    Canonicalization happens here so the upgrade applies to every consumer
    in one shot (POAM narrative + assessor evidence bundle):

      * case-insensitive collapse (``Host-A`` and ``host-a`` ⇒ one entry),
      * trailing-dot strip on FQDNs (``server01.corp.``),
      * conservative short-name → FQDN fold (``server01`` collapses into
        ``server01.corp.local`` IFF exactly one such FQDN is present).

    Intentionally does NOT fuse IPs with hostnames or attempt NetBIOS / DNS
    inference — that's the Asset resolver's job (slice 0.2b). Precision
    over recall: when in doubt we leave entries separate rather than
    misjoin two different machines.
    """
    if not objective_ids:
        return []
    tag_rows = session.exec(
        select(EvidenceTag.evidence_id).where(
            EvidenceTag.objective_id.in_(objective_ids)
        )
    ).all()
    evidence_ids = {eid for eid in tag_rows if eid is not None}
    if not evidence_ids:
        return []
    rows: list = []
    for batch in chunked(list(evidence_ids)):
        rows.extend(
            session.exec(
                select(Evidence.host_inventory).where(Evidence.id.in_(batch))
            ).all()
        )
    canonical: set[str] = set()
    for raw in rows:
        if not raw:
            continue
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(decoded, list):
            for h in decoded:
                if not isinstance(h, str):
                    continue
                c = _canonicalize_host(h)
                if c is not None:
                    canonical.add(c)
    return sorted(_collapse_short_to_fqdn(canonical))
