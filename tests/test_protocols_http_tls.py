"""Tests for the HTTP analyser and the hand-written TLS hello parser.

The TLS ClientHello/ServerHello bytes are built here with ``struct``
following RFC 8446's wire format, so the parser is tested against the
specification rather than against any library's writer.
"""

from __future__ import annotations

import struct

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from investigator.models import NetworkEvent, Protocol, TcpFlags
from investigator.parser import packet_to_event
from investigator.protocols.http import HttpAnalyzer
from investigator.protocols.tls import (
    TlsAnalyzer,
    parse_client_hello,
    parse_server_hello,
)

CLIENT = "10.0.0.15"
SERVER = "203.0.113.80"


def make_packet(payload: bytes, *, sport: int = 52100, dport: int = 443,
                src: str = CLIENT, dst: str = SERVER, ts: float = 100.0):
    packet = (
        Ether(src="aa:aa:aa:aa:aa:01", dst="aa:aa:aa:aa:aa:02")
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="PA", seq=1)
        / Raw(payload)
    )
    packet.time = ts
    event = packet_to_event(packet)
    assert event is not None
    return event, packet


# --------------------------------------------------------------------- TLS

def build_client_hello(sni: str | None = None, alpn: list[str] | None = None,
                       versions: list[int] | None = None) -> bytes:
    extensions = b""
    if sni is not None:
        name = sni.encode()
        entry = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
        extensions += struct.pack("!HH", 0, len(entry)) + entry
    if alpn:
        protos = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        body = struct.pack("!H", len(protos)) + protos
        extensions += struct.pack("!HH", 16, len(body)) + body
    if versions:
        body = bytes([len(versions) * 2]) + b"".join(
            struct.pack("!H", v) for v in versions
        )
        extensions += struct.pack("!HH", 43, len(body)) + body

    hello_body = (
        struct.pack("!H", 0x0303)          # legacy client version: TLS 1.2
        + b"\x00" * 32                     # random
        + b"\x00"                          # session id length 0
        + struct.pack("!H", 4) + b"\x13\x01\x13\x02"  # two cipher suites
        + b"\x01\x00"                      # compression: null
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def build_server_hello(cipher: int = 0x1301, selected_version: int | None = 0x0304) -> bytes:
    extensions = b""
    if selected_version is not None:
        extensions += struct.pack("!HHH", 43, 2, selected_version)
    body = (
        struct.pack("!H", 0x0303)
        + b"\x00" * 32
        + b"\x00"
        + struct.pack("!H", cipher)
        + b"\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


class TestTlsParsing:
    def test_client_hello_full(self):
        payload = build_client_hello(
            sni="c2.evil.io", alpn=["h2", "http/1.1"], versions=[0x0304, 0x0303]
        )
        event, _ = make_packet(payload)
        hello = parse_client_hello(payload, event)
        assert hello.sni == "c2.evil.io"
        assert hello.alpn == ["h2", "http/1.1"]
        assert hello.supported_versions == ["TLS 1.3", "TLS 1.2"]
        assert hello.legacy_version == "TLS 1.2"
        assert hello.cipher_count == 2

    def test_client_hello_without_sni(self):
        payload = build_client_hello()
        event, _ = make_packet(payload)
        assert parse_client_hello(payload, event).sni is None

    def test_server_hello_tls13(self):
        payload = build_server_hello()
        event, _ = make_packet(payload, sport=443, dport=52100,
                               src=SERVER, dst=CLIENT)
        hello = parse_server_hello(payload, event)
        assert hello.version == "TLS 1.3"
        assert hello.cipher == 0x1301

    def test_analyzer_end_to_end(self):
        analyzer = TlsAnalyzer()
        event, packet = make_packet(build_client_hello(sni="portal.empresa.com.br"))
        analyzer.observe_packet(event, packet)
        event2, packet2 = make_packet(
            build_server_hello(), sport=443, dport=52100, src=SERVER, dst=CLIENT
        )
        analyzer.observe_packet(event2, packet2)

        assert analyzer.sni_counter["portal.empresa.com.br"] == 1
        assert analyzer.sni_for_destination(SERVER) == {"portal.empresa.com.br"}
        assert analyzer.version_counter["TLS 1.3"] == 1
        assert analyzer.fragmented_hellos == 0

    def test_truncated_hello_counted_not_crashing(self):
        analyzer = TlsAnalyzer()
        payload = build_client_hello(sni="cut.example.com")[:40]  # cut mid-hello
        event, packet = make_packet(payload)
        analyzer.observe_packet(event, packet)
        assert analyzer.fragmented_hellos == 1
        assert analyzer.client_hellos == []


# --------------------------------------------------------------------- HTTP

class TestHttpAnalyzer:
    def test_request_parsing(self):
        analyzer = HttpAnalyzer()
        raw = (
            b"GET /login?user=a HTTP/1.1\r\n"
            b"Host: intranet.local\r\n"
            b"User-Agent: curl/8.0\r\n"
            b"\r\n"
        )
        event, packet = make_packet(raw, dport=80)
        analyzer.observe_packet(event, packet)

        assert len(analyzer.requests) == 1
        request = analyzer.requests[0]
        assert request.method == "GET"
        assert request.uri == "/login?user=a"
        assert request.host == "intranet.local"
        assert request.user_agent == "curl/8.0"
        assert request.headers_complete
        assert analyzer.methods["GET"] == 1

    def test_response_parsing(self):
        analyzer = HttpAnalyzer()
        raw = (
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 13\r\n"
            b"\r\n"
            b"<html></html>"
        )
        event, packet = make_packet(raw, sport=80, dport=52100,
                                    src=SERVER, dst=CLIENT)
        analyzer.observe_packet(event, packet)

        assert len(analyzer.responses) == 1
        response = analyzer.responses[0]
        assert response.status_code == 404
        assert response.content_type == "text/html"
        assert response.content_length == 13

    def test_incomplete_headers_flagged(self):
        analyzer = HttpAnalyzer()
        raw = b"POST /upload HTTP/1.1\r\nHost: files.local\r\n"  # no empty line
        event, packet = make_packet(raw, dport=8080)
        analyzer.observe_packet(event, packet)
        assert analyzer.requests[0].headers_complete is False
        assert analyzer.multi_segment_skipped == 1

    def test_http_on_unusual_port_still_detected(self):
        analyzer = HttpAnalyzer()
        raw = b"GET /beacon HTTP/1.1\r\nHost: c2.evil.io\r\n\r\n"
        event, packet = make_packet(raw, dport=4444)
        analyzer.observe_packet(event, packet)
        assert analyzer.hosts["c2.evil.io"] == 1

    def test_non_http_payload_ignored(self):
        analyzer = HttpAnalyzer()
        event, packet = make_packet(b"\x00\x01\x02binaryjunk")
        analyzer.observe_packet(event, packet)
        assert not analyzer.requests and not analyzer.responses
