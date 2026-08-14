"""Plaintext HTTP analysis (HTTP/1.x).

Parses request/response headers directly from TCP payload bytes - detection
is content-based (a segment starting with a method verb or ``HTTP/1.``), not
port-based, so HTTP on unusual ports is still seen (and *that* asymmetry is
useful evidence later).

Deliberate V2 limitation, marked in the records: there is **no stream
reassembly**.  Only headers contained in the first segment of a message are
parsed; anything split across segments is counted in
``multi_segment_skipped`` instead of being silently lost.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass

from scapy.layers.inet import TCP
from scapy.packet import Packet

from investigator.models import NetworkEvent, Protocol

LOG = logging.getLogger(__name__)

_METHODS = (
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
    b"PATCH ", b"CONNECT ", b"TRACE ",
)
_MAX_RECORDS = 100_000


@dataclass(slots=True)
class HttpRequest:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    method: str
    uri: str
    version: str
    host: str | None
    user_agent: str | None
    content_length: int | None
    headers_complete: bool  # False: header block continued in a later segment

    def as_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "method": self.method,
            "uri": self.uri,
            "version": self.version,
            "host": self.host,
            "user_agent": self.user_agent,
            "content_length": self.content_length,
            "headers_complete": self.headers_complete,
            "observation": "observed",
        }


@dataclass(slots=True)
class HttpResponse:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    status_code: int
    reason: str
    content_type: str | None
    content_length: int | None
    server: str | None
    headers_complete: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "status_code": self.status_code,
            "reason": self.reason,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "server": self.server,
            "headers_complete": self.headers_complete,
            "observation": "observed",
        }


def _parse_headers(block: bytes) -> tuple[dict[str, str], bool]:
    """Parse ``Name: value`` lines; returns (headers, complete) where
    *complete* means the empty line ending the header block was seen."""
    complete = b"\r\n\r\n" in block
    header_part = block.split(b"\r\n\r\n", 1)[0]
    headers: dict[str, str] = {}
    for line in header_part.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers[name.strip().lower().decode("latin-1")] = (
            value.strip().decode("latin-1", errors="replace")
        )
    return headers, complete


def _int_header(headers: dict[str, str], name: str) -> int | None:
    value = headers.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


class HttpAnalyzer:
    """Collector extracting HTTP/1.x messages from TCP payloads."""

    wants_packets = True

    def __init__(self) -> None:
        self.requests: list[HttpRequest] = []
        self.responses: list[HttpResponse] = []
        self.methods: Counter = Counter()
        self.hosts: Counter = Counter()
        self.user_agents: Counter = Counter()
        self.status_codes: Counter = Counter()
        self.uris: Counter = Counter()
        self.parse_errors = 0
        self.multi_segment_skipped = 0

    def observe_packet(self, event: NetworkEvent, packet: Packet) -> None:
        if event.protocol is not Protocol.TCP or event.payload_bytes <= 0:
            return
        tcp = packet.getlayer(TCP)
        if tcp is None:
            return
        payload = bytes(tcp.payload)
        if not payload:
            return
        try:
            if payload.startswith(_METHODS):
                self._parse_request(payload, event)
            elif payload.startswith(b"HTTP/1."):
                self._parse_response(payload, event)
        except Exception:
            self.parse_errors += 1
            LOG.debug("failed to parse HTTP segment", exc_info=True)

    def _parse_request(self, payload: bytes, event: NetworkEvent) -> None:
        first_line = payload.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ")
        if len(parts) < 3:
            self.parse_errors += 1
            return
        method = parts[0].decode("latin-1")
        uri = parts[1].decode("latin-1", errors="replace")
        version = parts[2].decode("latin-1", errors="replace")
        headers, complete = _parse_headers(payload)
        if not complete:
            self.multi_segment_skipped += 1

        request = HttpRequest(
            timestamp=event.timestamp,
            src_ip=event.src_ip or "?",
            dst_ip=event.dst_ip or "?",
            dst_port=event.dst_port or 0,
            method=method,
            uri=uri,
            version=version,
            host=headers.get("host"),
            user_agent=headers.get("user-agent"),
            content_length=_int_header(headers, "content-length"),
            headers_complete=complete,
        )
        if len(self.requests) < _MAX_RECORDS:
            self.requests.append(request)
        self.methods[method] += 1
        self.uris[uri] += 1
        if request.host:
            self.hosts[request.host] += 1
        if request.user_agent:
            self.user_agents[request.user_agent] += 1

    def _parse_response(self, payload: bytes, event: NetworkEvent) -> None:
        first_line = payload.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ", 2)
        if len(parts) < 2:
            self.parse_errors += 1
            return
        try:
            status_code = int(parts[1])
        except ValueError:
            self.parse_errors += 1
            return
        reason = parts[2].decode("latin-1", errors="replace") if len(parts) > 2 else ""
        headers, complete = _parse_headers(payload)
        if not complete:
            self.multi_segment_skipped += 1

        response = HttpResponse(
            timestamp=event.timestamp,
            src_ip=event.src_ip or "?",
            dst_ip=event.dst_ip or "?",
            src_port=event.src_port or 0,
            status_code=status_code,
            reason=reason,
            content_type=headers.get("content-type"),
            content_length=_int_header(headers, "content-length"),
            server=headers.get("server"),
            headers_complete=complete,
        )
        if len(self.responses) < _MAX_RECORDS:
            self.responses.append(response)
        self.status_codes[status_code] += 1

    def as_dict(self) -> dict[str, object]:
        return {
            "request_count": len(self.requests),
            "response_count": len(self.responses),
            "methods": dict(self.methods.most_common()),
            "hosts": dict(self.hosts.most_common(50)),
            "user_agents": dict(self.user_agents.most_common(50)),
            "status_codes": dict(self.status_codes.most_common()),
            "top_uris": dict(self.uris.most_common(50)),
            "parse_errors": self.parse_errors,
            "multi_segment_skipped": self.multi_segment_skipped,
            "requests": [r.as_dict() for r in self.requests[:200]],
            "responses": [r.as_dict() for r in self.responses[:200]],
        }
