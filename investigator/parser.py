"""Capture-file loading: validation, format detection and streaming
conversion of raw packets into :class:`~investigator.models.NetworkEvent`.

Why Scapy (and not tshark/PyShark)?
-----------------------------------
* Scapy is pure Python and reads pcap/pcapng files directly: no external
  processes and no Wireshark/tshark installation involved (PyShark, by
  contrast, is a wrapper around the tshark binary).
* Only Scapy's *reading/dissection* side is used.  Every packet is
  immediately reduced to a small immutable ``NetworkEvent`` and the Scapy
  object is discarded, so memory stays bounded regardless of capture size.
* All investigation logic (inventory, detection, correlation, scoring) is
  implemented by this project on top of the normalised event stream.

Error philosophy
----------------
Problems with the *file* (missing, empty, wrong format, unreadable) raise
typed exceptions from :mod:`investigator.errors` before analysis starts.
Problems with a *single packet* must never abort a run: captures collected
during real incidents are frequently damaged, and partial evidence is still
evidence.  Malformed packets are counted and skipped; a truncated tail ends
the stream gracefully.
"""

from __future__ import annotations

import contextlib
import gzip
import logging
import struct
from collections.abc import Iterator
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import NoPayload, Packet
from scapy.utils import PcapReader

try:
    # Base class of every ICMPv6 message type.  The name is private but has
    # been stable for many years; if it ever disappears we degrade
    # gracefully (ICMPv6 packets become IP_OTHER).
    from scapy.layers.inet6 import _ICMPv6
except ImportError:  # pragma: no cover - depends on the scapy version
    _ICMPv6 = None

from investigator.errors import (
    CaptureFileNotFoundError,
    CorruptCaptureFileError,
    UnsupportedCaptureFormatError,
)
from investigator.models import (
    CaptureFormat,
    CaptureMetadata,
    NetworkEvent,
    Protocol,
    TcpFlags,
)

LOG = logging.getLogger(__name__)

# First four bytes of each supported container format.
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": CaptureFormat.PCAP_US,  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": CaptureFormat.PCAP_US,  # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": CaptureFormat.PCAP_NS,  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": CaptureFormat.PCAP_NS,  # big-endian, nanoseconds
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # pcapng Section Header Block type
_GZIP_MAGIC = b"\x1f\x8b"


def sniff_format(path: Path | str) -> CaptureMetadata:
    """Validate ``path`` and identify the capture format from magic bytes.

    Doing our own validation, instead of letting Scapy fail somewhere deep,
    gives the user precise errors and lets the CLI distinguish "wrong file"
    from "damaged file".  Gzip-compressed captures (``.pcap.gz``) are
    recognised here and decompressed transparently by the reader later.
    """
    path = Path(path)
    if not path.exists():
        raise CaptureFileNotFoundError(path, "file does not exist")
    if not path.is_file():
        raise CaptureFileNotFoundError(path, "not a regular file")

    file_size = path.stat().st_size
    if file_size == 0:
        raise CorruptCaptureFileError(path, "file is empty")

    with path.open("rb") as handle:
        head = handle.read(4)

    gzipped = False
    if head[:2] == _GZIP_MAGIC:
        gzipped = True
        try:
            with gzip.open(path, "rb") as handle:
                head = handle.read(4)
        except OSError as exc:
            raise CorruptCaptureFileError(path, f"gzip data is corrupt: {exc}") from exc

    if len(head) < 4:
        raise CorruptCaptureFileError(path, "file too small to contain a capture header")

    if head in _PCAP_MAGICS:
        capture_format = _PCAP_MAGICS[head]
    elif head == _PCAPNG_MAGIC:
        capture_format = CaptureFormat.PCAPNG
    else:
        raise UnsupportedCaptureFormatError(
            path,
            f"unknown magic bytes {head.hex(' ')} - not a pcap/pcapng capture",
        )

    return CaptureMetadata(
        path=path,
        file_size=file_size,
        capture_format=capture_format,
        gzipped=gzipped,
    )


# Layer classes we extract, keyed by the *exact* class object.
#
# Exact-class matching is deliberate and must not be relaxed to
# ``isinstance``.  Scapy models the quoted headers inside an ICMP error as
# subclasses of the originals (``TCPerror(TCP)``, ``IPerror(IP)``), while
# ``getlayer`` matches exact classes and therefore ignores them.  An
# isinstance-based walk would match the quoted ``TCPerror`` inside a
# destination-unreachable message and report the packet as TCP - turning an
# unreachable notice into a phantom TCP flow.
_LAYER_KEYS: dict[type, str] = {
    Ether: "ether",
    ARP: "arp",
    IP: "ip",
    IPv6: "ipv6",
    TCP: "tcp",
    UDP: "udp",
    ICMP: "icmp",
}


def _walk_layers(packet: Packet) -> dict[str, Packet]:
    """Collect every layer of interest in a **single** pass of the chain.

    Replaces seven separate ``getlayer`` calls, each of which walked the
    whole chain again: for a plain TCP-over-Ethernet frame that was about
    nineteen layer visits per packet, and dissection is the dominant cost
    of the whole pipeline.

    ICMPv6 is handled separately by ``isinstance`` on purpose: it has no
    single Scapy class, since every message type (echo, neighbour
    solicitation...) is its own layer deriving from ``_ICMPv6``.
    """
    found: dict[str, Packet] = {}
    layer: Packet = packet
    while not isinstance(layer, NoPayload):
        key = _LAYER_KEYS.get(layer.__class__)
        if key is not None:
            found.setdefault(key, layer)
        elif _ICMPv6 is not None and isinstance(layer, _ICMPv6):
            found.setdefault("icmpv6", layer)
        layer = layer.payload
    return found


def packet_to_event(packet: Packet) -> NetworkEvent | None:
    """Reduce one dissected packet to a :class:`NetworkEvent`.

    Returns ``None`` when the packet is too broken to describe (no usable
    timestamp).  Valid-but-unclassified packets are still reported, as
    ``NON_IP`` or ``IP_OTHER``: "something we cannot name is talking on the
    network" is itself useful investigative information.
    """
    try:
        timestamp = float(packet.time)
    except (TypeError, ValueError, ArithmeticError):
        return None

    # Original length on the wire, as recorded by the capture file.  Falls
    # back to the dissected length for packets not created by a file reader.
    wire_bytes = getattr(packet, "wirelen", None) or len(packet)

    layers = _walk_layers(packet)

    ether = layers.get("ether")
    src_mac = ether.src if ether is not None else None
    dst_mac = ether.dst if ether is not None else None

    arp = layers.get("arp")
    if arp is not None:
        # ARP carries no IP header, but its sender/target protocol addresses
        # are exactly what host-discovery analysis will need later.
        return NetworkEvent(
            timestamp=timestamp,
            protocol=Protocol.ARP,
            wire_bytes=wire_bytes,
            src_ip=arp.psrc or None,
            dst_ip=arp.pdst or None,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    # IPv4 takes precedence when both appear (tunnelling), matching the
    # previous ``getlayer(IP) or getlayer(IPv6)`` ordering exactly.
    ip = layers.get("ip") or layers.get("ipv6")
    if ip is None:
        return NetworkEvent(
            timestamp=timestamp,
            protocol=Protocol.NON_IP,
            wire_bytes=wire_bytes,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

    common: dict[str, object] = {
        "timestamp": timestamp,
        "wire_bytes": wire_bytes,
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
    }

    tcp = layers.get("tcp")
    if tcp is not None:
        return NetworkEvent(
            protocol=Protocol.TCP,
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            payload_bytes=len(tcp.payload),
            tcp_flags=TcpFlags(int(tcp.flags)),
            tcp_seq=int(tcp.seq),
            **common,
        )

    udp = layers.get("udp")
    if udp is not None:
        return NetworkEvent(
            protocol=Protocol.UDP,
            src_port=int(udp.sport),
            dst_port=int(udp.dport),
            payload_bytes=len(udp.payload),
            **common,
        )

    icmp = layers.get("icmp")
    if icmp is not None:
        return NetworkEvent(
            protocol=Protocol.ICMP,
            payload_bytes=len(icmp.payload),
            icmp_type=int(icmp.type),
            icmp_code=int(icmp.code),
            **common,
        )

    icmpv6 = layers.get("icmpv6")
    if icmpv6 is not None:
        return NetworkEvent(
            protocol=Protocol.ICMPV6,
            payload_bytes=len(icmpv6.payload),
            icmp_type=int(getattr(icmpv6, "type", 0)),
            icmp_code=int(getattr(icmpv6, "code", 0)),
            **common,
        )

    return NetworkEvent(protocol=Protocol.IP_OTHER, **common)


class PcapLoader:
    """Streams a capture file as :class:`NetworkEvent` objects.

    Usage::

        loader = PcapLoader("capture.pcap")
        for event in loader.events():
            consume(event)
        # loader.read_count / loader.malformed_count / loader.truncated

    The file is validated eagerly in ``__init__`` (fail fast, before any
    expensive work); packets are read lazily, one at a time.
    """

    def __init__(self, path: Path | str, *, max_packets: int | None = None) -> None:
        if max_packets is not None and max_packets <= 0:
            raise ValueError("max_packets must be a positive integer")
        self.metadata = sniff_format(path)
        self.path = self.metadata.path
        self.max_packets = max_packets
        self.read_count = 0
        self.malformed_count = 0
        self.truncated = False

    def events(self) -> Iterator[NetworkEvent]:
        """Yield events one by one; counters reset at every call."""
        for event, _packet in self.packets():
            yield event

    def packets(self) -> Iterator[tuple[NetworkEvent, Packet]]:
        """Yield ``(event, scapy_packet)`` pairs, still streaming.

        Used by the engine when at least one collector needs payload access
        (DNS/HTTP/TLS analysis).  The packet object must not be retained by
        consumers - it is discarded after each iteration.
        """
        self.read_count = 0
        self.malformed_count = 0
        self.truncated = False

        try:
            # PcapReader detects pcap vs pcapng (and gzip) by itself, so the
            # same code path serves every supported container format.
            reader = PcapReader(str(self.path))
        except Scapy_Exception as exc:
            raise CorruptCaptureFileError(
                self.path, f"Scapy could not open the capture: {exc}"
            ) from exc
        except (EOFError, OSError, struct.error) as exc:
            raise CorruptCaptureFileError(
                self.path, f"could not read the capture: {exc}"
            ) from exc

        with contextlib.closing(reader):
            while self.max_packets is None or self.read_count < self.max_packets:
                try:
                    packet = reader.read_packet()
                except EOFError:
                    break  # clean end of file (or truncated mid-record-header)
                except (Scapy_Exception, struct.error) as exc:
                    # Damaged tail: keep everything parsed so far.
                    LOG.warning("stopping early, capture appears truncated: %s", exc)
                    self.truncated = True
                    break

                self.read_count += 1
                try:
                    event = packet_to_event(packet)
                except Exception:  # one bad packet must never kill the run
                    LOG.debug(
                        "failed to convert packet #%d", self.read_count, exc_info=True
                    )
                    event = None

                if event is None:
                    self.malformed_count += 1
                    continue
                yield event, packet
