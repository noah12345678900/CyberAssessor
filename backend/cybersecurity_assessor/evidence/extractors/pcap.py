"""Packet-capture (.pcap/.pcapng) summary extractor.

A pcap is binary and useless to feed raw to the tagger/LLM — the evidence
value is the *shape* of the traffic, not the packet bytes. This extractor
emits a compact **text digest** (capture metadata, protocol breakdown, top
talkers, top ports, conversation count) that reaches the tagger as
searchable text, mapping naturally to SC-7 (boundary protection), AC-4
(information flow), SI-4 (monitoring), CA-3 (interconnections), etc.

Dependency-free by design: parses BOTH the classic libpcap format and the
newer pcapng block format with the stdlib ``struct`` module only (no
dpkt/scapy), so the frozen offline bundle and SCIF deployments need nothing
extra. Both formats produce the same digest fields (protocols, talkers,
ports, conversations) so tagging is identical regardless of capture format.

Best-effort throughout: a truncated or exotic capture yields whatever
digest could be built rather than raising, so one odd pcap never aborts a
folder ingest. Only a completely unreadable stream raises ExtractorError.
"""

from __future__ import annotations

import socket
import struct
from collections import Counter
from pathlib import PurePosixPath
from typing import BinaryIO

from ...models import EvidenceKind
from .base import ExtractedDoc, ExtractorError, register

# libpcap global-header magic numbers (big/little endian, us/ns timestamps).
_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", "us"),  # little-endian, microsecond
    0xD4C3B2A1: (">", "us"),  # big-endian, microsecond
    0xA1B23C4D: ("<", "ns"),  # little-endian, nanosecond
    0x4D3CB2A1: (">", "ns"),  # big-endian, nanosecond
}
# pcapng starts with a Section Header Block: type 0x0A0D0D0A.
_PCAPNG_MAGIC = 0x0A0D0D0A
# pcapng block types we consume.
_PCAPNG_SHB = 0x0A0D0D0A  # Section Header Block
_PCAPNG_IDB = 0x00000001  # Interface Description Block (carries link type)
_PCAPNG_EPB = 0x00000006  # Enhanced Packet Block
_PCAPNG_SPB = 0x00000003  # Simple Packet Block
_PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D  # in SHB body; endianness probe

# Link-layer types we know how to peel to get at IP. 1 = Ethernet (the
# overwhelmingly common case for ACAS/tcpdump captures).
_LINKTYPE_ETHERNET = 1
_LINKTYPE_RAW_IP = (101, 12, 14)  # raw IPv4/IPv6, no L2 header

_IP_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH"}

# Cap how many packets we walk — a multi-GB capture's digest converges long
# before the end, and we must not stall ingest. The summary notes truncation.
_MAX_PACKETS = 200_000
_TOP_N = 15
# Cap how many BYTES we read into memory. The packet cap alone doesn't bound
# memory — `stream.read()` would still pull a whole multi-GB capture into RAM
# before _MAX_PACKETS ever applies, OOM-killing the ingest worker on a large
# ACAS/tcpdump capture. The traffic-shape digest converges in the first slice,
# so read a bounded prefix; the digest notes truncation when the cap is hit.
_MAX_READ_BYTES = 256 * 1024 * 1024  # 256 MB


def _parse_ipv4(payload: bytes) -> tuple[str, str, int, int | None, int | None] | None:
    """Return (src_ip, dst_ip, proto, src_port, dst_port) from an IPv4 packet."""
    if len(payload) < 20:
        return None
    ver_ihl = payload[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(payload) < ihl:
        return None
    proto = payload[9]
    src = socket.inet_ntoa(payload[12:16])
    dst = socket.inet_ntoa(payload[16:20])
    sport = dport = None
    if proto in (6, 17) and len(payload) >= ihl + 4:  # TCP/UDP have ports first
        sport, dport = struct.unpack("!HH", payload[ihl : ihl + 4])
    return src, dst, proto, sport, dport


def _peel_linklayer(linktype: int, frame: bytes) -> bytes | None:
    """Strip the L2 header so the return value starts at the IP header."""
    if linktype == _LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        if ethertype == 0x0800:  # IPv4
            return frame[14:]
        return None  # ARP / IPv6 / VLAN — skip for the digest
    if linktype in _LINKTYPE_RAW_IP:
        return frame
    return None


class _Traffic:
    """Mutable accumulator both format-walkers feed; rendered once at the end."""

    def __init__(self) -> None:
        self.n = 0
        self.truncated = False
        self.total_bytes = 0
        self.protos: Counter = Counter()
        self.src_ips: Counter = Counter()
        self.dst_ips: Counter = Counter()
        self.dst_ports: Counter = Counter()
        self.conversations: set[tuple[str, str]] = set()

    def add_frame(self, linktype: int, frame: bytes) -> None:
        self.n += 1
        self.total_bytes += len(frame)
        ip_payload = _peel_linklayer(linktype, frame)
        if ip_payload is None:
            self.protos["non-IP/other"] += 1
            return
        parsed = _parse_ipv4(ip_payload)
        if parsed is None:
            self.protos["non-IPv4/other"] += 1
            return
        src, dst, proto, _sport, dport = parsed
        self.protos[_IP_PROTO_NAMES.get(proto, f"proto-{proto}")] += 1
        self.src_ips[src] += 1
        self.dst_ips[dst] += 1
        if dport is not None:
            self.dst_ports[dport] += 1
        self.conversations.add((src, dst))


def _walk_classic(data: bytes, endian: str, acc: _Traffic) -> None:
    """Walk classic-libpcap records into the accumulator."""
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    rec_hdr = endian + "IIII"  # ts_sec, ts_frac, incl_len, orig_len
    while off + 16 <= len(data):
        if acc.n >= _MAX_PACKETS:
            acc.truncated = True
            break
        _ts_sec, _ts_frac, incl_len, _orig = struct.unpack(
            rec_hdr, data[off : off + 16]
        )
        off += 16
        if incl_len == 0 or off + incl_len > len(data):
            break
        acc.add_frame(linktype, data[off : off + incl_len])
        off += incl_len


def _walk_pcapng(data: bytes, acc: _Traffic) -> None:
    """Walk pcapng blocks into the accumulator (dependency-free).

    pcapng is a sequence of length-delimited blocks. We read the Section
    Header Block to fix endianness, track each Interface Description Block's
    link type (by interface index), and pull frames from Enhanced/Simple
    Packet Blocks. Unknown blocks are skipped by their declared length.
    """
    # Endianness from the SHB byte-order magic at bytes 8..12.
    if len(data) < 12:
        return
    if struct.unpack("<I", data[8:12])[0] == _PCAPNG_BYTE_ORDER_MAGIC:
        endian = "<"
    elif struct.unpack(">I", data[8:12])[0] == _PCAPNG_BYTE_ORDER_MAGIC:
        endian = ">"
    else:
        return  # not a decodable SHB

    iface_linktypes: list[int] = []
    off = 0
    total = len(data)
    while off + 12 <= total:
        if acc.n >= _MAX_PACKETS:
            acc.truncated = True
            break
        block_type = struct.unpack(endian + "I", data[off : off + 4])[0]
        block_len = struct.unpack(endian + "I", data[off + 4 : off + 8])[0]
        # block_len includes the 12-byte type/len/trailing-len frame; guard
        # against malformed/zero lengths that would loop forever.
        if block_len < 12 or off + block_len > total:
            break
        body = data[off + 8 : off + block_len - 4]

        if block_type == _PCAPNG_IDB:
            # Interface Description Block: linktype is u16 at body[0:2].
            if len(body) >= 2:
                iface_linktypes.append(struct.unpack(endian + "H", body[0:2])[0])
        elif block_type == _PCAPNG_EPB:
            # Enhanced Packet Block: iface_id u32, ts_hi u32, ts_lo u32,
            # cap_len u32, orig_len u32, then packet data.
            if len(body) >= 20:
                iface_id, _hi, _lo, cap_len, _orig = struct.unpack(
                    endian + "IIIII", body[:20]
                )
                pkt = body[20 : 20 + cap_len]
                lt = (
                    iface_linktypes[iface_id]
                    if iface_id < len(iface_linktypes)
                    else _LINKTYPE_ETHERNET
                )
                if pkt:
                    acc.add_frame(lt, pkt)
        elif block_type == _PCAPNG_SPB:
            # Simple Packet Block: orig_len u32, then packet data (cap_len is
            # implied by block length). Uses interface 0's link type.
            if len(body) >= 4:
                pkt = body[4:]
                lt = iface_linktypes[0] if iface_linktypes else _LINKTYPE_ETHERNET
                if pkt:
                    acc.add_frame(lt, pkt)
        # else: SHB (new section) / name-resolution / stats — skip by length.
        off += block_len


def _render_digest(name: str, fmt: str, acc: _Traffic) -> str:
    def _top(counter: Counter, label: str) -> str:
        if not counter:
            return f"{label}: none"
        items = ", ".join(f"{k} ({v})" for k, v in counter.most_common(_TOP_N))
        return f"{label}: {items}"

    lines = [
        f"Packet capture: {PurePosixPath(name).name}",
        f"Format: {fmt}.",
        f"Packets: {acc.n}{' (truncated at cap)' if acc.truncated else ''}.",
        f"Total captured bytes: {acc.total_bytes}.",
        f"Distinct conversations (src->dst): {len(acc.conversations)}.",
        _top(acc.protos, "Protocols"),
        _top(acc.dst_ports, "Top destination ports"),
        _top(acc.src_ips, "Top source hosts"),
        _top(acc.dst_ips, "Top destination hosts"),
        "",
        "Network traffic capture — evidence relevant to boundary protection "
        "(SC-7), information flow enforcement (AC-4), system monitoring "
        "(SI-4), and system interconnections (CA-3).",
    ]
    return "\n".join(lines)


def _build_digest(name: str, data: bytes) -> str:
    """Detect format (classic libpcap vs pcapng), walk it, render the digest."""
    if len(data) < 24:
        raise ExtractorError(f"{name}: too short to be a pcap")
    first_le = struct.unpack("<I", data[:4])[0]
    first_be = struct.unpack(">I", data[:4])[0]

    acc = _Traffic()
    if first_le == _PCAPNG_MAGIC or first_be == _PCAPNG_MAGIC:
        _walk_pcapng(data, acc)
        return _render_digest(name, "pcapng", acc)

    endian_ts = _PCAP_MAGICS.get(first_le)
    if endian_ts is None:
        raise ExtractorError(
            f"{name}: not a recognized pcap (magic={first_le:#x})"
        )
    endian, _ts_unit = endian_ts
    _walk_classic(data, endian, acc)
    return _render_digest(name, "libpcap (classic)", acc)


@register(".pcap", ".pcapng", ".cap")
def extract_pcap(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Read a packet capture and emit a text traffic-digest.

    Raises ExtractorError only when the stream can't be read or isn't a
    recognizable capture at all; a partial/odd capture still yields a
    best-effort digest.
    """
    try:
        # Bounded read: never pull more than _MAX_READ_BYTES into RAM. A larger
        # capture is truncated to the prefix — the traffic-shape digest has
        # already converged, and this prevents an OOM on a multi-GB pcap. We
        # read one extra byte to detect (and note) truncation.
        data = stream.read(_MAX_READ_BYTES + 1)
    except OSError as exc:
        raise ExtractorError(f"Cannot read {name}: {exc}") from exc

    read_truncated = len(data) > _MAX_READ_BYTES
    if read_truncated:
        data = data[:_MAX_READ_BYTES]

    stem = PurePosixPath(name).stem
    digest = _build_digest(name, data)
    if read_truncated:
        digest += (
            f"\n[note: capture exceeded {_MAX_READ_BYTES} bytes; digest computed "
            "from the leading prefix.]"
        )
    return ExtractedDoc(
        text=digest,
        title=stem,
        kind=EvidenceKind.PCAP,
        metadata={"pcap_bytes": len(data)},
    )
