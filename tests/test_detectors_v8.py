"""Tests for the V8 detectors: ARP integrity, ICMP shape and TLS metadata.

Driven end-to-end through the real pipeline on synthetic captures, matching
the approach of ``test_detectors.py``: the ground truth is traffic we built
ourselves, never a captured artefact of unknown provenance.

Every detector here gets a *non*-detection test as well.  A detector that
cannot stay quiet on ordinary traffic is not usable, and the benign shapes
are the ones that would otherwise fire: a normal ping, a clean ARP
exchange, a TLS session whose SNI DNS actually resolved.
"""

from __future__ import annotations

import struct

import synth
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from investigator.config import Config
from investigator.findings import Finding, Severity
from investigator.parser import PcapLoader
from investigator.pipeline import analyze_capture


def analyze(tmp_path, packets, name="synth_v8.pcap", config=None):
    path = tmp_path / name
    wrpcap(str(path), packets)
    return analyze_capture(PcapLoader(path), config=config or Config())


def of_type(findings: list[Finding], ftype: str) -> list[Finding]:
    return [f for f in findings if f.type == ftype]


# ------------------------------------------------------------------- ARP

class TestArpSpoofing:
    def test_concurrent_claims_detected(self, tmp_path):
        result = analyze(tmp_path, synth.arp_poisoning())
        findings = of_type(result.findings, "arp_spoofing")
        assert len(findings) == 1
        finding = findings[0]
        assert finding.metadata["ip"] == "10.0.0.1"
        assert finding.metadata["mac_count"] == 2
        assert synth.MAC_ATTACKER in finding.metadata["macs"]
        # the claims were interleaved, so overlap must be measured
        assert finding.metadata["overlap_seconds"] > 0
        assert finding.metadata["gratuitous"] > 0

    def test_overlap_raises_confidence_over_sequential_handover(self, tmp_path):
        """A handover and a poisoning differ only in timing - the detector
        has to price that difference, or the finding says nothing."""
        from scapy.layers.l2 import ARP

        def claim(mac, ts):
            pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2, psrc="10.0.0.1", hwsrc=mac, pdst="10.0.0.50",
                hwdst=synth.MAC_A,
            )
            pkt.time = ts
            return pkt

        # old MAC stops at t+40, new MAC starts at t+100: no overlap at all
        sequential = [claim(synth.MAC_B, synth.BASE_TS + i * 10) for i in range(5)]
        sequential += [
            claim(synth.MAC_ATTACKER, synth.BASE_TS + 100 + i * 10)
            for i in range(5)
        ]
        handover = analyze(tmp_path, sequential, name="handover.pcap")
        poisoning = analyze(tmp_path, synth.arp_poisoning(), name="poison.pcap")

        seq_finding = of_type(handover.findings, "arp_spoofing")[0]
        poi_finding = of_type(poisoning.findings, "arp_spoofing")[0]
        assert seq_finding.metadata["overlap_seconds"] == 0
        assert poi_finding.confidence > seq_finding.confidence

    def test_ether_mismatch_recorded(self, tmp_path):
        """A forged frame often leaves Ether.src disagreeing with ARP.hwsrc;
        a normal stack never does."""
        from scapy.layers.l2 import ARP

        packets = []
        for i in range(4):
            pkt = Ether(src=synth.MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2, psrc="10.0.0.1", hwsrc=synth.MAC_ATTACKER,
                pdst="10.0.0.50", hwdst=synth.MAC_B,
            )
            pkt.time = synth.BASE_TS + i
            packets.append(pkt)
        result = analyze(tmp_path, packets, name="mismatch.pcap")
        assert result.protocols.arp.ether_mismatches == 4

    def test_claimant_attributed_to_its_own_ip(self, tmp_path):
        """A finding sourced to a MAC cannot reach a host profile, which are
        keyed by IP - the contesting host would then be missing this
        behaviour from its own record."""
        packets = synth.arp_poisoning()
        # give the attacker MAC some ordinary IP traffic, so the inventory
        # knows which address is behind it
        packets += synth.beacon(client="10.0.0.15", count=3, interval=60.0)
        for pkt in packets[-3:]:
            pkt[Ether].src = synth.MAC_ATTACKER

        result = analyze(tmp_path, packets, name="arp_attrib.pcap")
        finding = of_type(result.findings, "arp_spoofing")[0]
        assert finding.metadata["claimant_mac"] == synth.MAC_ATTACKER
        assert finding.source == "10.0.0.15"
        assert finding.destination == "10.0.0.1"

        profiles = {p.ip: p for p in result.host_profiles}
        assert "10.0.0.15" in profiles

    def test_normal_arp_not_flagged(self, tmp_path):
        result = analyze(tmp_path, synth.arp_normal(), name="arp_ok.pcap")
        assert of_type(result.findings, "arp_spoofing") == []
        assert of_type(result.findings, "arp_mac_flooding") == []

    def test_address_probe_is_not_a_claim(self, tmp_path):
        """RFC 5227 probes use psrc=0.0.0.0 - counting them as ownership
        claims would invent a conflict on every DHCP client boot."""
        from scapy.layers.l2 import ARP

        packets = []
        for i, mac in enumerate((synth.MAC_A, synth.MAC_B, synth.MAC_ATTACKER)):
            pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, psrc="0.0.0.0", hwsrc=mac, pdst="10.0.0.77",
            )
            pkt.time = synth.BASE_TS + i
            packets.append(pkt)
        result = analyze(tmp_path, packets, name="probe.pcap")
        assert result.protocols.arp.probes == 3
        assert result.protocols.arp.bindings == {}
        assert of_type(result.findings, "arp_spoofing") == []


# ------------------------------------------------------------------ ICMP

class TestIcmpAnomalies:
    def test_tunnel_shape_detected(self, tmp_path):
        result = analyze(tmp_path, synth.icmp_tunnel(), name="icmp_tun.pcap")
        findings = of_type(result.findings, "icmp_tunneling")
        assert len(findings) == 1
        finding = findings[0]
        assert finding.source == "10.0.0.15"
        assert finding.destination == "203.0.113.66"
        # external destination -> higher risk
        assert finding.severity is Severity.HIGH
        assert finding.metadata["signals"] >= 2
        assert finding.metadata["mean_payload"] > 128
        assert finding.metadata["size_variability"] > 0.3
        assert finding.limitations and "not inspected" in finding.limitations

    def test_ordinary_ping_not_flagged(self, tmp_path):
        """A fixed-size ping must stay quiet no matter how many packets."""
        result = analyze(
            tmp_path, synth.icmp_ping(count=100), name="icmp_ping.pcap"
        )
        assert of_type(result.findings, "icmp_tunneling") == []
        channel = list(result.protocols.icmp.channels.values())[0]
        assert channel.looks_ping_shaped
        assert channel.size_variability == 0.0

    def test_large_but_constant_payload_needs_a_second_signal(self, tmp_path):
        """Volume alone must not fire it - the same rule DNS anomalies use."""
        from scapy.layers.inet import ICMP

        packets = []
        for i in range(60):
            pkt = Ether() / IP(src="10.0.0.15", dst="10.0.0.23") / ICMP(
                type=8, code=0, id=5, seq=i
            ) / Raw(b"\x41" * 900)          # big, but identical every time
            pkt.time = synth.BASE_TS + i
            packets.append(pkt)
        result = analyze(tmp_path, packets, name="icmp_const.pcap")
        findings = of_type(result.findings, "icmp_tunneling")
        # large payload + volume are two signals, but variability is 0.0, so
        # whatever fires must not claim variability it did not observe
        for finding in findings:
            assert finding.metadata["size_variability"] == 0.0

    def test_sweep_detected(self, tmp_path):
        result = analyze(tmp_path, synth.icmp_sweep(), name="icmp_sweep.pcap")
        findings = of_type(result.findings, "icmp_sweep")
        assert len(findings) == 1
        assert findings[0].metadata["targets"] >= 40
        assert findings[0].metadata["silent_ratio"] == 1.0

    def test_answered_pings_are_not_a_sweep(self, tmp_path):
        """Reaching many hosts that all answer is normal reachability
        checking, not enumeration."""
        packets = []
        for i in range(40):
            packets += synth.icmp_ping(
                server=f"10.0.0.{60 + i}", count=1,
                start=synth.BASE_TS + i * 0.1,
            )
        result = analyze(tmp_path, packets, name="icmp_answered.pcap")
        assert of_type(result.findings, "icmp_sweep") == []


# ------------------------------------------------------------------- TLS

def build_hello(
    sni: str | None = None,
    versions: list[int] | None = None,
    ciphers: bytes = b"\x13\x01\x13\x02",
    extra_ext: bytes = b"",
) -> bytes:
    """Minimal ClientHello, assembled from the RFC 8446 layout."""
    extensions = b""
    if sni is not None:
        name = sni.encode()
        entry = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
        extensions += struct.pack("!HH", 0, len(entry)) + entry
    if versions:
        body = bytes([len(versions) * 2]) + b"".join(
            struct.pack("!H", v) for v in versions
        )
        extensions += struct.pack("!HH", 43, len(body)) + body
    extensions += extra_ext

    hello_body = (
        struct.pack("!H", 0x0303)
        + b"\x00" * 32
        + b"\x00"
        + struct.pack("!H", len(ciphers)) + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_packets(payloads, src="10.0.0.15", dst="203.0.113.66",
                start=synth.BASE_TS):
    packets = []
    for i, payload in enumerate(payloads):
        pkt = Ether(src=synth.MAC_A, dst=synth.MAC_B) / IP(src=src, dst=dst) / TCP(
            sport=52000 + i, dport=443, flags="PA", seq=1
        ) / Raw(payload)
        pkt.time = start + i * 5.0
        packets.append(pkt)
    return packets


def dns_answer(name: str, ip: str, client="10.0.0.15", ts=synth.BASE_TS - 10):
    """A DNS response tying ``name`` to ``ip``, so the SNI cross-check has
    something to find."""
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import UDP

    pkt = Ether(src=synth.MAC_B, dst=synth.MAC_A) / IP(
        src="10.0.0.1", dst=client
    ) / UDP(sport=53, dport=53111) / DNS(
        id=1, qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type=1, rdata=ip)
    )
    pkt.time = ts
    return pkt


class TestTlsAnomalies:
    def test_missing_sni_to_external(self, tmp_path):
        packets = tls_packets([build_hello() for _ in range(3)])
        result = analyze(tmp_path, packets, name="tls_nosni.pcap")
        findings = of_type(result.findings, "tls_no_sni")
        assert len(findings) == 1
        assert findings[0].destination == "203.0.113.66"
        assert findings[0].metadata["hello_count"] == 3

    def test_sni_matching_dns_is_not_flagged(self, tmp_path):
        """The cross-check must clear a session whose name DNS resolved."""
        packets = [dns_answer("cdn.example.com", "203.0.113.66")]
        packets += tls_packets([build_hello(sni="cdn.example.com")])
        result = analyze(tmp_path, packets, name="tls_resolved.pcap")
        assert of_type(result.findings, "tls_unresolved_sni") == []

    def test_sni_never_resolved_is_flagged(self, tmp_path):
        """DNS was observed in this capture, but never tied this name to
        this address."""
        packets = [dns_answer("other.example.com", "198.51.100.9")]
        packets += tls_packets([build_hello(sni="cdn.evil.test")])
        result = analyze(tmp_path, packets, name="tls_unresolved.pcap")
        findings = of_type(result.findings, "tls_unresolved_sni")
        assert len(findings) == 1
        assert findings[0].metadata["sni"] == "cdn.evil.test"
        assert findings[0].metadata["contradicted"] is False

    def test_contradicted_sni_scores_higher(self, tmp_path):
        """DNS resolved the address to a *different* name: stronger than an
        address DNS never named at all."""
        packets = [dns_answer("real.example.com", "203.0.113.66")]
        packets += tls_packets([build_hello(sni="fronted.example.net")])
        result = analyze(tmp_path, packets, name="tls_contradicted.pcap")
        findings = of_type(result.findings, "tls_unresolved_sni")
        assert len(findings) == 1
        assert findings[0].metadata["contradicted"] is True
        assert findings[0].severity is Severity.HIGH

    def test_no_dns_in_capture_suppresses_the_check(self, tmp_path):
        """Without any observed DNS the absence of a resolution says
        something about the capture, not about the client."""
        packets = tls_packets([build_hello(sni="cdn.example.com")])
        result = analyze(tmp_path, packets, name="tls_nodns.pcap")
        assert of_type(result.findings, "tls_unresolved_sni") == []

    def test_legacy_version_flagged(self, tmp_path):
        packets = tls_packets(
            [build_hello(sni="old.example.com", versions=[0x0301])]
        )
        result = analyze(tmp_path, packets, name="tls_legacy.pcap")
        findings = of_type(result.findings, "tls_legacy_version")
        assert len(findings) == 1
        assert findings[0].metadata["version"] == "TLS 1.0"

    def test_tls13_client_with_legacy_record_version_not_flagged(self, tmp_path):
        """RFC 8446 requires a TLS 1.3 client to put 1.2 in the legacy
        field; reading that as an old client would flag every modern
        browser."""
        packets = tls_packets(
            [build_hello(sni="new.example.com", versions=[0x0304, 0x0303])]
        )
        result = analyze(tmp_path, packets, name="tls13.pcap")
        assert of_type(result.findings, "tls_legacy_version") == []