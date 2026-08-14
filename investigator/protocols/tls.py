"""TLS handshake analysis - implemented by hand on purpose.

We parse ClientHello/ServerHello directly from TCP payload bytes with
``struct``-style index walking instead of loading Scapy's TLS stack: the
fields we need (SNI, versions, ALPN, cipher) live in the clear at the start
of the handshake, the format is stable, and writing the parser ourselves
keeps the dependency surface small.  Nothing is decrypted - TLS payload
beyond the handshake metadata is out of scope by design.

Limitation (counted, never silent): a hello split across TCP segments is
not reassembled in V2; it increments ``fragmented_hellos``.
"""

from __future__ import annotations

import logging
import struct
from collections import Counter
from dataclasses import dataclass, field

from scapy.layers.inet import TCP
from scapy.packet import Packet

from investigator.models import NetworkEvent, Protocol

LOG = logging.getLogger(__name__)

VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

_MAX_RECORDS = 50_000


def _version_name(raw: int) -> str:
    return VERSION_NAMES.get(raw, f"0x{raw:04x}")


class _Cursor:
    """Bounds-checked byte walker: every overrun raises ValueError, which the
    analyser turns into an honest "could not parse" count."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        if self.pos + count > len(self.data):
            raise ValueError("truncated TLS message")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def skip(self, count: int) -> None:
        self.take(count)


@dataclass(slots=True)
class ClientHello:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    sni: str | None
    legacy_version: str
    supported_versions: list[str] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    cipher_count: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "sni": self.sni,
            "legacy_version": self.legacy_version,
            "supported_versions": self.supported_versions,
            "alpn": self.alpn,
            "cipher_count": self.cipher_count,
            "observation": "observed",
        }


@dataclass(slots=True)
class ServerHello:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    version: str
    cipher: int

    def as_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "version": self.version,
            "cipher": f"0x{self.cipher:04x}",
            "observation": "observed",
        }


def parse_client_hello(payload: bytes, event: NetworkEvent) -> ClientHello:
    cursor = _Cursor(payload)
    cursor.skip(1)                      # record type (0x16, already checked)
    cursor.skip(2)                      # record legacy version
    cursor.skip(2)                      # record length
    if cursor.u8() != 0x01:
        raise ValueError("not a ClientHello")
    cursor.skip(3)                      # handshake length
    legacy_version = cursor.u16()
    cursor.skip(32)                     # client random
    cursor.skip(cursor.u8())            # session id
    cipher_len = cursor.u16()
    cursor.skip(cipher_len)
    cursor.skip(cursor.u8())            # compression methods

    hello = ClientHello(
        timestamp=event.timestamp,
        src_ip=event.src_ip or "?",
        dst_ip=event.dst_ip or "?",
        dst_port=event.dst_port or 0,
        sni=None,
        legacy_version=_version_name(legacy_version),
        cipher_count=cipher_len // 2,
    )

    if cursor.pos + 2 > len(payload):
        return hello                    # legacy hello without extensions

    extensions_end = cursor.pos + 2 + cursor.u16()
    while cursor.pos + 4 <= min(extensions_end, len(payload)):
        ext_type = cursor.u16()
        ext_len = cursor.u16()
        body = _Cursor(cursor.take(ext_len))
        if ext_type == 0:               # server_name
            body.skip(2)                # server name list length
            if body.u8() == 0:          # name type: host_name
                hello.sni = body.take(body.u16()).decode(
                    "ascii", errors="replace"
                ).lower()
        elif ext_type == 16:            # ALPN
            body.skip(2)
            while body.pos < len(body.data):
                hello.alpn.append(
                    body.take(body.u8()).decode("ascii", errors="replace")
                )
        elif ext_type == 43:            # supported_versions
            count = body.u8() // 2
            for _ in range(count):
                hello.supported_versions.append(_version_name(body.u16()))
    return hello


def parse_server_hello(payload: bytes, event: NetworkEvent) -> ServerHello:
    cursor = _Cursor(payload)
    cursor.skip(5)                      # record header
    if cursor.u8() != 0x02:
        raise ValueError("not a ServerHello")
    cursor.skip(3)
    version = cursor.u16()
    cursor.skip(32)                     # server random
    cursor.skip(cursor.u8())            # session id
    cipher = cursor.u16()
    cursor.skip(1)                      # compression
    negotiated = version
    if cursor.pos + 2 <= len(payload):  # extensions (supported_versions=43)
        extensions_end = cursor.pos + 2 + cursor.u16()
        while cursor.pos + 4 <= min(extensions_end, len(payload)):
            ext_type = cursor.u16()
            ext_len = cursor.u16()
            body = _Cursor(cursor.take(ext_len))
            if ext_type == 43 and len(body.data) >= 2:
                negotiated = body.u16()
    return ServerHello(
        timestamp=event.timestamp,
        src_ip=event.src_ip or "?",
        dst_ip=event.dst_ip or "?",
        src_port=event.src_port or 0,
        version=_version_name(negotiated),
        cipher=cipher,
    )


class TlsAnalyzer:
    """Collector extracting TLS handshake metadata from TCP payloads."""

    wants_packets = True

    def __init__(self) -> None:
        self.client_hellos: list[ClientHello] = []
        self.server_hellos: list[ServerHello] = []
        self.sni_counter: Counter = Counter()
        self.version_counter: Counter = Counter()
        self.hellos_without_sni = 0
        self.fragmented_hellos = 0

    def observe_packet(self, event: NetworkEvent, packet: Packet) -> None:
        if event.protocol is not Protocol.TCP or event.payload_bytes <= 0:
            return
        tcp = packet.getlayer(TCP)
        if tcp is None:
            return
        payload = bytes(tcp.payload)
        # TLS record: handshake(0x16) + version 0x03,0x0X
        if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
            return
        handshake_type = payload[5]
        try:
            if handshake_type == 0x01:
                hello = parse_client_hello(payload, event)
                if len(self.client_hellos) < _MAX_RECORDS:
                    self.client_hellos.append(hello)
                if hello.sni:
                    self.sni_counter[hello.sni] += 1
                else:
                    self.hellos_without_sni += 1
            elif handshake_type == 0x02:
                server_hello = parse_server_hello(payload, event)
                if len(self.server_hellos) < _MAX_RECORDS:
                    self.server_hellos.append(server_hello)
                self.version_counter[server_hello.version] += 1
        except ValueError:
            self.fragmented_hellos += 1
        except Exception:
            self.fragmented_hellos += 1
            LOG.debug("unexpected TLS parse failure", exc_info=True)

    def sni_for_destination(self, dst_ip: str) -> set[str]:
        return {
            h.sni for h in self.client_hellos if h.dst_ip == dst_ip and h.sni
        }

    def as_dict(self) -> dict[str, object]:
        return {
            "client_hello_count": len(self.client_hellos),
            "server_hello_count": len(self.server_hellos),
            "top_sni": dict(self.sni_counter.most_common(50)),
            "negotiated_versions": dict(self.version_counter.most_common()),
            "hellos_without_sni": self.hellos_without_sni,
            "fragmented_hellos": self.fragmented_hellos,
            "client_hellos": [h.as_dict() for h in self.client_hellos[:200]],
            "server_hellos": [h.as_dict() for h in self.server_hellos[:200]],
        }
