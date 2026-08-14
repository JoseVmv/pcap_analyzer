"""V5 threat-detection tests: exfiltration, lateral movement, host
discovery, and tactic annotation."""

from __future__ import annotations

import synth
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from investigator.config import Config
from investigator.findings import Finding, Severity
from investigator.parser import PcapLoader
from investigator.pipeline import analyze_capture
from investigator import threats


def analyze(tmp_path, packets, name="threat.pcap", config=None):
    path = tmp_path / name
    packets = sorted(packets, key=lambda p: p.time)
    wrpcap(str(path), packets)
    return analyze_capture(PcapLoader(path), config=config or Config())


def of_type(findings, ftype):
    return [f for f in findings if f.type == ftype]


class TestDataExfiltration:
    def test_large_upload_detected(self, tmp_path):
        result = analyze(tmp_path, synth.bulk_upload(segments=1000, seg_bytes=1400))
        exfils = of_type(result.findings, "data_exfiltration")
        assert len(exfils) == 1
        exfil = exfils[0]
        assert exfil.source == "10.0.0.15"
        assert exfil.destination == "203.0.113.66"
        assert exfil.tactic == "Exfiltration"
        assert exfil.severity >= Severity.MEDIUM
        assert exfil.metadata["bytes_sent"] >= 1_000_000
        assert any("sent vs" in e.summary for e in exfil.evidence)

    def test_balanced_download_not_flagged(self, tmp_path):
        """A host that downloads more than it uploads is normal traffic."""
        packets = []
        seq_out = seq_in = 1
        t = synth.BASE_TS
        for i in range(1200):
            up = Ether() / IP(src="10.0.0.15", dst="203.0.113.66") / TCP(
                sport=52000, dport=443, flags="PA", seq=seq_out) / Raw(b"U" * 1400)
            down = Ether() / IP(src="203.0.113.66", dst="10.0.0.15") / TCP(
                sport=443, dport=52000, flags="PA", seq=seq_in) / Raw(b"D" * 1400)
            up.time = t
            down.time = t + 0.005
            packets += [up, down]
            seq_out += 1400
            seq_in += 1400
            t += 0.01
        result = analyze(tmp_path, packets, name="balanced.pcap")
        assert of_type(result.findings, "data_exfiltration") == []

    def test_small_transfer_below_threshold(self, tmp_path):
        result = analyze(tmp_path, synth.bulk_upload(segments=50, seg_bytes=1400),
                         name="small.pcap")
        assert of_type(result.findings, "data_exfiltration") == []

    def test_threshold_is_configurable(self, tmp_path):
        result = analyze(
            tmp_path,
            synth.bulk_upload(segments=50, seg_bytes=1400),
            name="small2.pcap",
            config=Config(exfil_min_bytes=10_000),
        )
        assert len(of_type(result.findings, "data_exfiltration")) == 1


class TestLateralMovement:
    def test_admin_sessions_across_hosts(self, tmp_path):
        result = analyze(tmp_path, synth.lateral_movement())
        lateral = of_type(result.findings, "lateral_movement")
        assert len(lateral) == 1
        finding = lateral[0]
        assert finding.source == "10.0.0.15"
        assert finding.metadata["target_count"] == 4
        assert 445 in finding.metadata["ports"]
        assert finding.tactic == "Lateral Movement"

    def test_scan_alone_is_not_lateral_movement(self, tmp_path):
        """Unanswered SYNs are a scan, not lateral movement."""
        result = analyze(tmp_path, synth.horizontal_scan(port=445),
                         name="scan.pcap")
        assert of_type(result.findings, "lateral_movement") == []
        assert of_type(result.findings, "port_scan_horizontal")

    def test_single_target_not_flagged(self, tmp_path):
        result = analyze(tmp_path, synth.lateral_movement(targets=("10.0.0.23",)),
                         name="one.pcap")
        assert of_type(result.findings, "lateral_movement") == []


class TestHostDiscovery:
    def test_sweep_of_dead_addresses(self, tmp_path):
        result = analyze(tmp_path, synth.horizontal_scan(port=445),
                         name="sweep.pcap")
        discovery = of_type(result.findings, "host_discovery")
        assert len(discovery) == 1
        assert discovery[0].metadata["silent_targets"] >= 20
        assert discovery[0].tactic == "Discovery"

    def test_responsive_hosts_not_flagged(self, tmp_path):
        result = analyze(tmp_path, synth.lateral_movement(), name="alive.pcap")
        assert of_type(result.findings, "host_discovery") == []


class TestTacticAnnotation:
    def test_all_known_types_get_a_tactic(self, tmp_path):
        result = analyze(
            tmp_path,
            synth.vertical_scan() + synth.beacon(dport=4444, start=synth.BASE_TS + 100),
            name="tactics.pcap",
        )
        assert result.findings
        for finding in result.findings:
            assert finding.tactic is not None, finding.type

    def test_tactic_summary_groups_findings(self):
        findings = [
            Finding(type="beaconing", title="t", severity=Severity.HIGH,
                    confidence=0.9, explanation="e", source="10.0.0.1"),
            Finding(type="port_scan_vertical", title="t", severity=Severity.MEDIUM,
                    confidence=0.6, explanation="e", source="10.0.0.1"),
        ]
        threats.annotate(findings)
        summary = threats.tactic_summary(findings)
        assert set(summary) == {"Command & Control", "Discovery"}
        assert summary["Command & Control"]["max_confidence"] == 0.9
        assert summary["Discovery"]["finding_count"] == 1
        assert summary["Discovery"]["description"]
