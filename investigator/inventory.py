"""Network inventory: who is on the network and who talks to whom.

Produces three aggregate views from the event stream:

* :class:`HostProfile` - per-IP activity (packets/bytes sent and received,
  first/last appearance, peers, ports, protocols, MAC addresses seen);
* :class:`Conversation` - per directed ``src -> dst`` edge, including a
  compact timestamp series (``array('d')``, 8 bytes per packet) that later
  versions use for temporal analysis (beaconing, timeline) without
  re-reading the capture;
* global port/protocol counters, used later as the *baseline* against which
  unusual behaviour is measured.

Internal vs external is a heuristic: with only a pcap there is no ground
truth about the monitored network, so private/loopback/link-local ranges
(RFC 1918 etc.) are treated as internal.  Multicast, broadcast and
unspecified addresses are kept out of the host count and reported
separately - they are traffic sinks, not hosts.
"""

from __future__ import annotations

import enum
import ipaddress
from array import array
from collections import Counter
from dataclasses import dataclass, field

from investigator.models import NetworkEvent, Protocol

# Timestamps kept per conversation edge; beyond this the series stops
# growing (counters keep counting).  200k doubles = ~1.6 MiB worst case.
MAX_TIMESTAMPS_PER_CONVERSATION = 200_000


class HostKind(str, enum.Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    MULTICAST = "multicast"
    BROADCAST = "broadcast"
    UNSPECIFIED = "unspecified"


_ip_kind_cache: dict[str, HostKind] = {}

# Explicit "internal network" ranges instead of ipaddress.is_private: newer
# Python versions extended is_private to the whole IANA special-purpose
# registry (documentation ranges like 203.0.113.0/24 included), which is not
# what "a host on the monitored LAN" means.  Explicit ranges keep the
# classification stable across Python versions and easy to audit.
_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),     # RFC 6598 carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # IPv4 link-local
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
]
_BROADCAST_V4 = ipaddress.IPv4Address("255.255.255.255")


def classify_ip(ip: str) -> HostKind:
    """Classify an IP string, with caching (captures repeat IPs millions of
    times and ``ipaddress`` parsing is comparatively expensive)."""
    kind = _ip_kind_cache.get(ip)
    if kind is not None:
        return kind
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        kind = HostKind.UNSPECIFIED
    else:
        if addr.is_multicast:
            kind = HostKind.MULTICAST
        elif isinstance(addr, ipaddress.IPv4Address) and addr == _BROADCAST_V4:
            kind = HostKind.BROADCAST
        elif addr.is_unspecified:
            kind = HostKind.UNSPECIFIED
        elif any(addr in network for network in _INTERNAL_NETWORKS):
            kind = HostKind.INTERNAL
        else:
            kind = HostKind.EXTERNAL
    _ip_kind_cache[ip] = kind
    return kind


@dataclass(slots=True)
class HostProfile:
    """Accumulated view of one IP address."""

    ip: str
    kind: HostKind
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    payload_bytes_sent: int = 0
    payload_bytes_received: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    peers: set[str] = field(default_factory=set)
    dst_ports_contacted: Counter = field(default_factory=Counter)  # as client
    ports_served: Counter = field(default_factory=Counter)         # as destination
    protocols: Counter = field(default_factory=Counter)
    macs: set[str] = field(default_factory=set)

    def _touch(self, timestamp: float) -> None:
        if self.first_seen is None or timestamp < self.first_seen:
            self.first_seen = timestamp
        if self.last_seen is None or timestamp > self.last_seen:
            self.last_seen = timestamp

    def record_sent(self, event: NetworkEvent) -> None:
        self.packets_sent += 1
        self.bytes_sent += event.wire_bytes
        self.payload_bytes_sent += event.payload_bytes
        self.protocols[event.protocol.value] += 1
        if event.dst_port is not None:
            self.dst_ports_contacted[event.dst_port] += 1
        if event.src_mac:
            self.macs.add(event.src_mac)
        self._touch(event.timestamp)

    def record_received(self, event: NetworkEvent) -> None:
        self.packets_received += 1
        self.bytes_received += event.wire_bytes
        self.payload_bytes_received += event.payload_bytes
        self.protocols[event.protocol.value] += 1
        if event.dst_port is not None:
            self.ports_served[event.dst_port] += 1
        self._touch(event.timestamp)

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received

    @property
    def is_silent(self) -> bool:
        """True when this IP never sent a packet - it was only referenced
        (e.g. the target of ARP requests or a scanned-but-dead address)."""
        return self.packets_sent == 0

    def as_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "kind": self.kind.value,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "payload_bytes_sent": self.payload_bytes_sent,
            "payload_bytes_received": self.payload_bytes_received,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "silent": self.is_silent,
            "peer_count": len(self.peers),
            "peers": sorted(self.peers),
            "dst_ports_contacted": dict(self.dst_ports_contacted.most_common()),
            "ports_served": dict(self.ports_served.most_common()),
            "protocols": dict(self.protocols.most_common()),
            "macs": sorted(self.macs),
        }


@dataclass(slots=True)
class Conversation:
    """Directed traffic aggregate for one ``src -> dst`` pair."""

    src_ip: str
    dst_ip: str
    packets: int = 0
    bytes: int = 0
    payload_bytes: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    dst_ports: Counter = field(default_factory=Counter)
    protocols: Counter = field(default_factory=Counter)
    timestamps: array = field(default_factory=lambda: array("d"))

    def record(self, event: NetworkEvent) -> None:
        self.packets += 1
        self.bytes += event.wire_bytes
        self.payload_bytes += event.payload_bytes
        self.protocols[event.protocol.value] += 1
        if event.dst_port is not None:
            self.dst_ports[event.dst_port] += 1
        if self.first_seen is None or event.timestamp < self.first_seen:
            self.first_seen = event.timestamp
        if self.last_seen is None or event.timestamp > self.last_seen:
            self.last_seen = event.timestamp
        if len(self.timestamps) < MAX_TIMESTAMPS_PER_CONVERSATION:
            self.timestamps.append(event.timestamp)

    @property
    def duration(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return self.last_seen - self.first_seen

    def as_dict(self) -> dict[str, object]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "packets": self.packets,
            "bytes": self.bytes,
            "payload_bytes": self.payload_bytes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration,
            "dst_ports": dict(self.dst_ports.most_common()),
            "protocols": dict(self.protocols.most_common()),
        }


class NetworkInventory:
    """Collector building the host/conversation/port inventory."""

    def __init__(self) -> None:
        self.hosts: dict[str, HostProfile] = {}
        self.conversations: dict[tuple[str, str], Conversation] = {}
        self.global_dst_ports: Counter = Counter()
        self.global_src_ports: Counter = Counter()
        self.protocol_counts: Counter = Counter()

    def _host(self, ip: str) -> HostProfile:
        profile = self.hosts.get(ip)
        if profile is None:
            profile = HostProfile(ip=ip, kind=classify_ip(ip))
            self.hosts[ip] = profile
        return profile

    def observe(self, event: NetworkEvent) -> None:
        self.protocol_counts[event.protocol.value] += 1
        if event.src_ip is None or event.dst_ip is None:
            return  # NON_IP frames carry no addressing we can inventory

        src = self._host(event.src_ip)
        dst = self._host(event.dst_ip)
        src.record_sent(event)
        dst.record_received(event)
        src.peers.add(event.dst_ip)
        dst.peers.add(event.src_ip)

        if event.src_port is not None:
            self.global_src_ports[event.src_port] += 1
        if event.dst_port is not None:
            self.global_dst_ports[event.dst_port] += 1

        key = (event.src_ip, event.dst_ip)
        conversation = self.conversations.get(key)
        if conversation is None:
            conversation = Conversation(src_ip=event.src_ip, dst_ip=event.dst_ip)
            self.conversations[key] = conversation
        conversation.record(event)

    # ------------------------------------------------------------------ views

    def hosts_of_kind(self, *kinds: HostKind) -> list[HostProfile]:
        return [h for h in self.hosts.values() if h.kind in kinds]

    @property
    def internal_hosts(self) -> list[HostProfile]:
        return self.hosts_of_kind(HostKind.INTERNAL)

    @property
    def external_hosts(self) -> list[HostProfile]:
        return self.hosts_of_kind(HostKind.EXTERNAL)

    def top_talkers(self, limit: int = 10) -> list[HostProfile]:
        real = self.hosts_of_kind(HostKind.INTERNAL, HostKind.EXTERNAL)
        return sorted(real, key=lambda h: -h.total_bytes)[:limit]

    def top_conversations(self, limit: int = 10) -> list[Conversation]:
        return sorted(self.conversations.values(), key=lambda c: -c.bytes)[:limit]

    def as_dict(self, *, max_hosts: int | None = None) -> dict[str, object]:
        hosts = sorted(self.hosts.values(), key=lambda h: -h.total_bytes)
        if max_hosts is not None:
            hosts = hosts[:max_hosts]
        return {
            "host_count": {
                "internal": len(self.internal_hosts),
                "external": len(self.external_hosts),
                "other": len(
                    self.hosts_of_kind(
                        HostKind.MULTICAST, HostKind.BROADCAST, HostKind.UNSPECIFIED
                    )
                ),
            },
            "hosts": [h.as_dict() for h in hosts],
            "conversations": [
                c.as_dict()
                for c in sorted(self.conversations.values(), key=lambda c: -c.bytes)
            ],
            "global_dst_ports": dict(self.global_dst_ports.most_common(50)),
            "global_src_ports": dict(self.global_src_ports.most_common(50)),
            "protocols": dict(self.protocol_counts.most_common()),
        }
