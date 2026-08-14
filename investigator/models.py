"""Core data structures shared by every module.

Design notes
------------
* :class:`NetworkEvent` is the single normalised representation of one
  captured packet.  Parsing happens exactly once, in
  :mod:`investigator.parser`; every other module (inventory, protocol
  analysis, detectors, correlation...) consumes these events and never
  touches raw Scapy objects.  Keeping the dissection library at the edge of
  the system makes all analysis code testable with hand-built events.
* Events are immutable (``frozen=True``): detectors receive shared objects
  and must never mutate them.  ``slots=True`` keeps the per-event memory
  footprint small, because captures can contain millions of packets.
* Timestamps are raw epoch ``float`` seconds (UTC).  Formatting is a
  presentation concern and happens only at the CLI/reporting layer.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path


class Protocol(str, enum.Enum):
    """Highest network layer we can confidently assign to a packet (V0).

    Application-level classification (DNS, HTTP, TLS...) arrives in V2 and
    will live in dedicated records produced by protocol analysers, not here.
    """

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ICMPV6 = "ICMPv6"
    ARP = "ARP"
    IP_OTHER = "IP-OTHER"  # IPv4/IPv6 packet with an unhandled next protocol
    NON_IP = "NON-IP"      # L2 frame that is neither IP nor ARP


class TcpFlags(enum.IntFlag):
    """TCP header flags as a bitmask (mirrors the on-the-wire bits)."""

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


class CaptureFormat(enum.Enum):
    """Container format of the capture file, detected from magic bytes."""

    PCAP_US = "pcap (microsecond)"
    PCAP_NS = "pcap (nanosecond)"
    PCAPNG = "pcapng"


@dataclass(frozen=True, slots=True)
class NetworkEvent:
    """One captured packet, reduced to the facts the investigation needs."""

    timestamp: float                # epoch seconds, UTC
    protocol: Protocol
    wire_bytes: int                 # original frame length on the wire
    src_ip: str | None = None       # for ARP: sender/target protocol address
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    payload_bytes: int = 0          # transport payload length, 0 if none
    tcp_flags: TcpFlags | None = None
    tcp_seq: int | None = None      # raw sequence number (retransmission analysis)
    icmp_type: int | None = None
    icmp_code: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None

    @property
    def is_tcp_syn_only(self) -> bool:
        """True for a pure SYN, the opening packet of a TCP handshake.

        Defined on the model because several future detectors (port
        scanning, incomplete-connection analysis) share this definition.
        """
        return (
            self.tcp_flags is not None
            and TcpFlags.SYN in self.tcp_flags
            and TcpFlags.ACK not in self.tcp_flags
        )


@dataclass(frozen=True, slots=True)
class CaptureMetadata:
    """Facts about the capture file itself, known before reading packets."""

    path: Path
    file_size: int
    capture_format: CaptureFormat
    gzipped: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "file_size": self.file_size,
            "format": self.capture_format.value,
            "gzipped": self.gzipped,
        }


@dataclass(slots=True)
class CaptureSummary:
    """Incrementally aggregated view of a capture.

    First example of the streaming-consumer pattern the whole project
    follows: it receives one event at a time via :meth:`observe` and never
    stores the events themselves, so memory stays flat regardless of the
    capture size.
    """

    packet_count: int = 0
    total_bytes: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    protocol_counts: dict[str, int] = field(default_factory=dict)

    def observe(self, event: NetworkEvent) -> None:
        self.packet_count += 1
        self.total_bytes += event.wire_bytes
        if self.first_timestamp is None or event.timestamp < self.first_timestamp:
            self.first_timestamp = event.timestamp
        if self.last_timestamp is None or event.timestamp > self.last_timestamp:
            self.last_timestamp = event.timestamp
        key = event.protocol.value
        self.protocol_counts[key] = self.protocol_counts.get(key, 0) + 1

    @property
    def duration(self) -> float | None:
        """Capture time span in seconds (``None`` before any packet).

        Tracks min/max instead of first/last read because packet order
        inside a capture file is not guaranteed to be chronological.
        """
        if self.first_timestamp is None or self.last_timestamp is None:
            return None
        return self.last_timestamp - self.first_timestamp

    def as_dict(self) -> dict[str, object]:
        return {
            "packets": self.packet_count,
            "total_bytes": self.total_bytes,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "duration_seconds": self.duration,
            "protocols": dict(
                sorted(self.protocol_counts.items(), key=lambda kv: (-kv[1], kv[0]))
            ),
        }
