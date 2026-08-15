"""Tests for the TLS client fingerprint (JA3) and its rarity detector.

The fingerprint is built from code points the *client* chooses and orders,
so the properties worth pinning down are: it is stable for one client
implementation, it differs when the implementation differs, and it survives
the randomised GREASE values that exist precisely to vary between
connections.
"""

from __future__ import annotations

import struct

import synth
from scapy.utils import wrpcap
from test_detectors_v8 import build_hello, of_type, tls_packets

from investigator.config import Config
from investigator.parser import PcapLoader, packet_to_event
from investigator.pipeline import analyze_capture
from investigator.protocols.tls import is_grease, parse_client_hello


def hello_of(payload: bytes):
    packet = tls_packets([payload])[0]
    event = packet_to_event(packet)
    assert event is not None
    return parse_client_hello(payload, event)


class TestGrease:
    def test_reserved_values_recognised(self):
        for value in (0x0A0A, 0x1A1A, 0x2A2A, 0xFAFA, 0xDADA):
            assert is_grease(value)

    def test_real_code_points_not_mistaken_for_grease(self):
        # real cipher suites and extension numbers must survive
        for value in (0x1301, 0x1302, 0xC02B, 0x0000, 0x0010, 0x002B):
            assert not is_grease(value)


class TestFingerprint:
    def test_same_stack_same_fingerprint(self):
        first = hello_of(build_hello(sni="a.example.com"))
        second = hello_of(build_hello(sni="b.example.com"))
        # SNI is not part of the fingerprint: the destination changes, the
        # client implementation does not
        assert first.ja3 == second.ja3

    def test_different_cipher_order_changes_fingerprint(self):
        ordered = hello_of(build_hello(ciphers=b"\x13\x01\x13\x02"))
        reversed_ = hello_of(build_hello(ciphers=b"\x13\x02\x13\x01"))
        assert ordered.ja3 != reversed_.ja3

    def test_grease_does_not_change_the_fingerprint(self):
        """GREASE values are randomised per connection by design. If they
        reached the hash, the same client would fingerprint differently on
        every handshake and the whole measure would be worthless."""
        plain = hello_of(build_hello(ciphers=b"\x13\x01\x13\x02"))
        greased = hello_of(build_hello(ciphers=b"\x0a\x0a\x13\x01\x13\x02"))
        assert plain.ja3 == greased.ja3

    def test_curves_and_point_formats_included(self):
        curves = struct.pack("!HH", 10, 6) + struct.pack("!HHH", 4, 0x001D, 0x0017)
        formats = struct.pack("!HH", 11, 2) + b"\x01\x00"
        with_groups = hello_of(build_hello(extra_ext=curves + formats))
        without = hello_of(build_hello())
        assert with_groups.curves == [0x001D, 0x0017]
        assert with_groups.point_formats == [0]
        assert with_groups.ja3 != without.ja3

    def test_ja3_string_shape(self):
        hello = hello_of(build_hello(ciphers=b"\x13\x01\x13\x02"))
        parts = hello.ja3_string.split(",")
        assert len(parts) == 5
        assert parts[0] == str(0x0303)      # legacy version, decimal
        assert parts[1] == "4865-4866"      # ciphers, decimal, in order
        assert len(hello.ja3) == 32         # md5 hex digest


class TestRareFingerprintDetector:
    def test_single_client_many_destinations_flagged(self, tmp_path):
        """One TLS stack, unique on this network, reaching several external
        endpoints."""
        packets = []
        for i, dst in enumerate(
            ("203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13")
        ):
            packets += tls_packets(
                [build_hello(sni=f"node{i}.example.net")],
                dst=dst,
                start=synth.BASE_TS + i * 30,
            )
        path = tmp_path / "ja3_rare.pcap"
        wrpcap(str(path), packets)
        result = analyze_capture(PcapLoader(path), config=Config())

        findings = of_type(result.findings, "tls_rare_fingerprint")
        assert len(findings) == 1
        assert findings[0].metadata["destination_count"] == 4
        assert findings[0].metadata["clients"] == ["10.0.0.15"]
        assert "not compared against any" in findings[0].limitations

    def test_single_destination_not_enough(self, tmp_path):
        """A unique stack talking to one endpoint is just an application;
        the signal is the fan-out."""
        packets = tls_packets([build_hello(sni="only.example.net")] * 4)
        path = tmp_path / "ja3_one.pcap"
        wrpcap(str(path), packets)
        result = analyze_capture(PcapLoader(path), config=Config())
        assert of_type(result.findings, "tls_rare_fingerprint") == []

    def test_shared_fingerprint_is_not_rare(self, tmp_path):
        """Several hosts using the same stack is the ordinary case - that
        is what 'rare within this capture' has to exclude."""
        packets = []
        for host_index in range(3):
            src = f"10.0.0.{20 + host_index}"
            for i, dst in enumerate(
                ("203.0.113.10", "203.0.113.11", "203.0.113.12")
            ):
                packets += tls_packets(
                    [build_hello(sni=f"n{i}.example.net")],
                    src=src, dst=dst,
                    start=synth.BASE_TS + (host_index * 10 + i) * 5,
                )
        path = tmp_path / "ja3_shared.pcap"
        wrpcap(str(path), packets)
        result = analyze_capture(PcapLoader(path), config=Config())
        assert of_type(result.findings, "tls_rare_fingerprint") == []