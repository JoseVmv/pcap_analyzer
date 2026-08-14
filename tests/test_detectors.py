"""V3 detector tests, driven end-to-end through the real pipeline on
synthetic attack captures (ground truth we constructed in tests/synth.py)."""

from __future__ import annotations

import synth
from scapy.utils import wrpcap

from investigator.config import Config
from investigator.findings import Finding, Severity
from investigator.parser import PcapLoader
from investigator.pipeline import analyze_capture


def analyze(tmp_path, packets, name="synth.pcap", config=None):
    path = tmp_path / name
    wrpcap(str(path), packets)
    return analyze_capture(PcapLoader(path), config=config or Config())


def of_type(findings: list[Finding], ftype: str) -> list[Finding]:
    return [f for f in findings if f.type == ftype]


class TestPortScan:
    def test_vertical_scan(self, tmp_path):
        result = analyze(tmp_path, synth.vertical_scan(ports=range(1, 41)))
        scans = of_type(result.findings, "port_scan_vertical")
        assert len(scans) == 1
        scan = scans[0]
        assert scan.source == "10.0.0.15"
        assert scan.destination == "10.0.0.23"
        assert scan.severity >= Severity.MEDIUM
        assert scan.metadata["distinct_ports"] == 40
        # evidence must explain *why*
        assert any("distinct destination ports" in e.summary for e in scan.evidence)

    def test_horizontal_scan(self, tmp_path):
        result = analyze(tmp_path, synth.horizontal_scan(port=445))
        scans = of_type(result.findings, "port_scan_horizontal")
        assert len(scans) == 1
        assert scans[0].metadata["port"] == 445
        assert scans[0].metadata["distinct_hosts"] >= 20

    def test_normal_client_not_flagged(self, tmp_path):
        # a client that opens a handful of *established* connections
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether

        packets = []
        ts = synth.BASE_TS
        for i, port in enumerate((80, 443, 53, 22)):
            syn = Ether() / IP(src="10.0.0.15", dst="10.0.0.23") / TCP(
                sport=40000 + i, dport=port, flags="S", seq=1)
            synack = Ether() / IP(src="10.0.0.23", dst="10.0.0.15") / TCP(
                sport=port, dport=40000 + i, flags="SA", seq=9)
            ack = Ether() / IP(src="10.0.0.15", dst="10.0.0.23") / TCP(
                sport=40000 + i, dport=port, flags="A", seq=1)
            for j, pkt in enumerate((syn, synack, ack)):
                pkt.time = ts + i + j * 0.01
            packets += [syn, synack, ack]
        result = analyze(tmp_path, packets)
        assert of_type(result.findings, "port_scan_vertical") == []


class TestBeaconing:
    def test_regular_external_beacon(self, tmp_path):
        result = analyze(tmp_path, synth.beacon(count=30, interval=30.0, dport=4444))
        beacons = of_type(result.findings, "beaconing")
        assert len(beacons) == 1
        beacon = beacons[0]
        assert beacon.destination == "203.0.113.66"
        assert beacon.severity >= Severity.MEDIUM
        assert beacon.confidence >= 0.7
        assert any("mean interval" in e.summary for e in beacon.evidence)

    def test_ntp_beacon_is_suppressed(self, tmp_path):
        """A metronomic NTP poll is a beacon *behaviourally* but benign: it
        must be low on BOTH axes - low risk (the protocol is periodic by
        design) and low confidence that it is noteworthy."""
        result = analyze(tmp_path, synth.ntp_beacon(count=30, interval=64.0))
        beacons = of_type(result.findings, "beaconing")
        for beacon in beacons:
            assert beacon.confidence < 0.6
            assert beacon.risk <= Severity.LOW
            assert "periodic protocol" in beacon.explanation
            # the limitation must be stated, not implied
            assert "does not establish command-and-control" in (
                beacon.limitations or ""
            )

    def test_beacon_beats_ntp_confidence(self, tmp_path):
        c2 = analyze(tmp_path, synth.beacon(dport=4444), name="c2.pcap")
        ntp = analyze(tmp_path, synth.ntp_beacon(), name="ntp.pcap")
        c2_conf = of_type(c2.findings, "beaconing")[0].confidence
        ntp_beacons = of_type(ntp.findings, "beaconing")
        ntp_conf = ntp_beacons[0].confidence if ntp_beacons else 0.0
        assert c2_conf > ntp_conf + 0.2

    def test_irregular_traffic_not_beacon(self, tmp_path):
        result = analyze(
            tmp_path, synth.beacon(count=30, interval=30.0, jitter=25.0, dport=4444)
        )
        # heavy jitter (cv well above threshold) should not be called a beacon
        assert of_type(result.findings, "beaconing") == []


class TestDnsAnomaly:
    def test_dns_tunnel_detected(self, tmp_path):
        result = analyze(tmp_path, synth.dns_tunnel(count=30))
        tunnels = of_type(result.findings, "dns_tunneling")
        assert len(tunnels) == 1
        tunnel = tunnels[0]
        # base-domain grouping folds "<rand>.tunnel.evil.io" to "evil.io"
        assert tunnel.destination == "evil.io"
        assert tunnel.metadata["signal_count"] >= 3
        assert tunnel.severity >= Severity.MEDIUM
        # multiple independent signals must be shown
        assert len(tunnel.evidence) >= 3

    def test_normal_dns_not_flagged(self, tmp_path, dns_pcap):
        result = analyze_capture(PcapLoader(dns_pcap))
        # the small normal-ish DNS fixture should not trip the tunnel detector
        assert of_type(result.findings, "dns_tunneling") == []

    def test_single_signal_insufficient(self, tmp_path):
        # long names but low entropy and few of them -> should not fire
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, UDP
        from scapy.layers.l2 import Ether

        packets = []
        for i in range(10):
            qname = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.org"  # long, low entropy
            pkt = Ether() / IP(src="10.0.0.7", dst="10.0.0.1") / UDP(
                sport=53000 + i, dport=53) / DNS(id=i, rd=1, qd=DNSQR(qname=qname))
            pkt.time = synth.BASE_TS + i
            packets.append(pkt)
        result = analyze(tmp_path, packets)
        assert of_type(result.findings, "dns_tunneling") == []


class TestTrafficBurst:
    def test_burst_detected(self, tmp_path):
        # quiet baseline + a large upload spike
        quiet = synth.beacon(count=20, interval=60.0, dport=4444)
        spike = synth.bulk_upload(segments=1000, seg_bytes=1400)
        result = analyze(tmp_path, quiet + spike)
        bursts = of_type(result.findings, "traffic_burst")
        assert len(bursts) >= 1
        assert any("peak" in e.summary for e in bursts[0].evidence)


class TestConfigTunable:
    def test_threshold_change_suppresses_scan(self, tmp_path):
        strict = Config(scan_min_ports_vertical=100)
        result = analyze(tmp_path, synth.vertical_scan(ports=range(1, 41)),
                         config=strict)
        assert of_type(result.findings, "port_scan_vertical") == []
