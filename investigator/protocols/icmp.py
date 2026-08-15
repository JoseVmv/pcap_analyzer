"""ICMP tracking: echo traffic shape, per channel and per source.

ICMP is allowed outbound by a great many firewalls that block everything
else, which is exactly why it gets used as a carrier.  The tunnel is not
visible in the header - it is visible in the *shape* of the payloads.

What separates a ping from a carrier
------------------------------------
A real ``ping`` emits a fixed, unchanging payload: 32 bytes on Windows, 56
on Linux, the same size every single time.  A tunnel has to move actual
data, so its payloads are large and their sizes vary.  Those two properties
- magnitude and variability - are measurable without ever reading payload
content, and they are what this tracker aggregates.

This analyser works from :class:`~investigator.models.NetworkEvent` alone:
``icmp_type``, ``icmp_code`` and ``payload_bytes`` are already normalised by
the parser, so no raw packet access is needed and it stays on the engine's
cheaper event path.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from investigator.models import NetworkEvent, Protocol
from investigator.stats import mean

#: Channels ((src, dst) pairs) whose payload shape is tracked.
_MAX_CHANNELS = 100_000
#: Distinct payload sizes remembered per channel.  A ping uses one; a
#: tunnel uses many, and once this many are seen the point is made.
_MAX_SIZES_PER_CHANNEL = 512

#: Echo request/reply type numbers, IPv4 and IPv6.
_ECHO_REQUEST = {Protocol.ICMP: 8, Protocol.ICMPV6: 128}
_ECHO_REPLY = {Protocol.ICMP: 0, Protocol.ICMPV6: 129}

#: Payload sizes produced by the standard ping implementations.  Used only
#: to describe a channel as "ping-shaped" in evidence text - never to
#: whitelist, since a tunnel is free to pad to 56 bytes.
TYPICAL_PING_SIZES = frozenset({0, 8, 16, 32, 40, 48, 56, 64})


@dataclass(slots=True)
class IcmpChannel:
    """Echo traffic between one source and one destination."""

    src_ip: str
    dst_ip: str
    requests: int = 0
    replies: int = 0
    request_payload: int = 0
    reply_payload: int = 0
    max_payload: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    #: payload size -> how many times it was seen (request direction)
    sizes: Counter = field(default_factory=Counter)
    sizes_overflow: bool = False

    def record(self, event: NetworkEvent, *, is_request: bool) -> None:
        payload = event.payload_bytes
        if is_request:
            self.requests += 1
            self.request_payload += payload
            if payload in self.sizes or len(self.sizes) < _MAX_SIZES_PER_CHANNEL:
                self.sizes[payload] += 1
            else:
                self.sizes_overflow = True
        else:
            self.replies += 1
            self.reply_payload += payload
        self.max_payload = max(self.max_payload, payload)
        if self.first_seen is None or event.timestamp < self.first_seen:
            self.first_seen = event.timestamp
        if self.last_seen is None or event.timestamp > self.last_seen:
            self.last_seen = event.timestamp

    @property
    def packets(self) -> int:
        return self.requests + self.replies

    @property
    def total_payload(self) -> int:
        return self.request_payload + self.reply_payload

    @property
    def mean_request_size(self) -> float:
        return self.request_payload / self.requests if self.requests else 0.0

    @property
    def distinct_sizes(self) -> int:
        return len(self.sizes)

    @property
    def size_variability(self) -> float:
        """Fraction of request payloads that were *not* the most common size.

        0.0 means every echo carried an identical payload, which is what a
        ping does.  Values approaching 1.0 mean nearly every packet had its
        own size, which is what carrying data looks like.
        """
        if self.requests <= 1 or not self.sizes:
            return 0.0
        most_common = self.sizes.most_common(1)[0][1]
        return 1.0 - (most_common / self.requests)

    @property
    def duration(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return self.last_seen - self.first_seen

    @property
    def looks_ping_shaped(self) -> bool:
        """One constant, conventional payload size: an ordinary ping."""
        return self.distinct_sizes == 1 and set(self.sizes) <= TYPICAL_PING_SIZES

    def as_dict(self) -> dict[str, object]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "requests": self.requests,
            "replies": self.replies,
            "request_payload": self.request_payload,
            "reply_payload": self.reply_payload,
            "max_payload": self.max_payload,
            "mean_request_size": round(self.mean_request_size, 1),
            "distinct_sizes": self.distinct_sizes,
            "size_variability": round(self.size_variability, 3),
            "ping_shaped": self.looks_ping_shaped,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": round(self.duration, 3),
        }


class IcmpAnalyzer:
    """Collector aggregating ICMP echo shape and reachability signals."""

    def __init__(self) -> None:
        self.channels: dict[tuple[str, str], IcmpChannel] = {}
        self.type_counts: Counter = Counter()
        self.unreachable_by_source: Counter = Counter()
        self.total_packets = 0
        self.total_payload = 0
        self.channels_overflow = False

    def observe(self, event: NetworkEvent) -> None:
        if event.protocol not in (Protocol.ICMP, Protocol.ICMPV6):
            return
        if event.src_ip is None or event.dst_ip is None:
            return

        self.total_packets += 1
        self.total_payload += event.payload_bytes
        icmp_type = event.icmp_type
        self.type_counts[f"{event.protocol.value}/{icmp_type}"] += 1

        # Destination-unreachable (v4 type 3, v6 type 1) tells us a probe
        # found nothing - the same "address does not exist" signal the host
        # discovery detector reads from silence, but stated explicitly.
        if (event.protocol is Protocol.ICMP and icmp_type == 3) or (
            event.protocol is Protocol.ICMPV6 and icmp_type == 1
        ):
            self.unreachable_by_source[event.dst_ip] += 1
            return

        is_request = icmp_type == _ECHO_REQUEST.get(event.protocol)
        is_reply = icmp_type == _ECHO_REPLY.get(event.protocol)
        if not (is_request or is_reply):
            return

        # Key the channel on the *initiator* so a request and its reply land
        # in the same bucket.
        key = (
            (event.src_ip, event.dst_ip)
            if is_request
            else (event.dst_ip, event.src_ip)
        )
        channel = self.channels.get(key)
        if channel is None:
            if len(self.channels) >= _MAX_CHANNELS:
                self.channels_overflow = True
                return
            channel = IcmpChannel(src_ip=key[0], dst_ip=key[1])
            self.channels[key] = channel
        channel.record(event, is_request=is_request)

    # --------------------------------------------------------------- views

    def channels_from(self, src_ip: str) -> list[IcmpChannel]:
        return [c for c in self.channels.values() if c.src_ip == src_ip]

    def destinations_by_source(self) -> dict[str, set[str]]:
        """Distinct echo destinations each source contacted (sweep signal)."""
        out: dict[str, set[str]] = {}
        for channel in self.channels.values():
            out.setdefault(channel.src_ip, set()).add(channel.dst_ip)
        return out

    def median_request_size(self) -> float:
        """Typical echo payload across the whole capture - the local
        baseline a suspicious channel is compared against."""
        sizes = [
            c.mean_request_size for c in self.channels.values() if c.requests
        ]
        return mean(sizes) if sizes else 0.0

    def as_dict(self) -> dict[str, object]:
        busiest = sorted(
            self.channels.values(), key=lambda c: -c.total_payload
        )[:50]
        return {
            "total_packets": self.total_packets,
            "total_payload": self.total_payload,
            "channel_count": len(self.channels),
            "channels_overflow": self.channels_overflow,
            "types": dict(self.type_counts.most_common()),
            "unreachable_by_source": dict(
                self.unreachable_by_source.most_common(20)
            ),
            "top_channels": [c.as_dict() for c in busiest],
        }