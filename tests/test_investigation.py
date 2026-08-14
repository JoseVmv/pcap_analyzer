"""V7 investigation + reporting tests, including the end-to-end run that
produces all three report files."""

from __future__ import annotations

import json

import synth
from scapy.utils import wrpcap

from investigator.cli import run
from investigator.config import Config
from investigator.correlation import Correlator
from investigator.findings import Finding, Severity
from investigator.inventory import NetworkInventory
from investigator.investigation import build_investigation, rank_suspects
from investigator.models import NetworkEvent, Protocol
from investigator.parser import PcapLoader
from investigator.pipeline import analyze_capture
from investigator.reporting import build_report, render_html
from investigator.scoring import compute_risk_score

BASE = 1_700_000_000.0


def finding(ftype, source, confidence=0.8, severity=Severity.MEDIUM, start=BASE):
    return Finding(
        type=ftype, title=f"test {ftype}", severity=severity, confidence=confidence,
        explanation="reasoning here", source=source, destination="203.0.113.66",
        timestamp=start, start_time=start, end_time=start + 60,
    ).add("concrete evidence")


def small_inventory() -> NetworkInventory:
    inv = NetworkInventory()
    inv.observe(
        NetworkEvent(timestamp=BASE, protocol=Protocol.TCP, wire_bytes=100,
                     src_ip="10.0.0.15", dst_ip="203.0.113.66",
                     src_port=5000, dst_port=443, payload_bytes=40)
    )
    return inv


class TestSuspectRanking:
    def test_severity_outweighs_count(self):
        findings = [
            finding("beaconing", "10.0.0.15", confidence=0.9, severity=Severity.HIGH),
            finding("rare_destination", "10.0.0.99", confidence=0.4,
                    severity=Severity.LOW),
            finding("rare_destination", "10.0.0.99", confidence=0.4,
                    severity=Severity.LOW),
            finding("rare_destination", "10.0.0.99", confidence=0.4,
                    severity=Severity.LOW),
        ]
        suspects = rank_suspects(findings)
        assert suspects[0].ip == "10.0.0.15"
        assert suspects[0].max_severity is Severity.HIGH

    def test_tactics_are_collected(self):
        from investigator import threats

        findings = [
            finding("beaconing", "10.0.0.15"),
            finding("port_scan_vertical", "10.0.0.15"),
        ]
        threats.annotate(findings)
        suspects = rank_suspects(findings)
        assert set(suspects[0].tactics) == {"Command & Control", "Discovery"}


class TestInvestigation:
    def test_no_findings_says_so_honestly(self):
        risk = compute_risk_score([], [], Config())
        investigation = build_investigation(small_inventory(), [], [], risk)
        assert investigation.primary_suspect is None
        assert investigation.primary_hypothesis is None
        assert investigation.confidence == 0.0
        assert "No suspicious behaviour" in investigation.verdict
        # must not claim the traffic is proven benign
        assert any("not proof" in line for line in investigation.summary_lines)

    def test_conclusion_always_has_traceable_evidence(self):
        findings = [
            finding("port_scan_vertical", "10.0.0.15", start=BASE),
            finding("beaconing", "10.0.0.15", start=BASE + 500, confidence=0.9),
        ]
        hypotheses = Correlator(Config()).correlate(findings)
        risk = compute_risk_score(findings, hypotheses, Config())
        investigation = build_investigation(
            small_inventory(), findings, hypotheses, risk
        )
        assert investigation.primary_suspect == "10.0.0.15"
        assert investigation.supporting_evidence
        for item in investigation.supporting_evidence:
            assert item["evidence"], "every conclusion must point at evidence"
            assert item["finding_id"]
            assert item["reasoning"]

    def test_language_stays_probabilistic(self):
        findings = [
            finding("port_scan_vertical", "10.0.0.15", start=BASE),
            finding("beaconing", "10.0.0.15", start=BASE + 500, confidence=0.95),
        ]
        hypotheses = Correlator(Config()).correlate(findings)
        risk = compute_risk_score(findings, hypotheses, Config())
        investigation = build_investigation(
            small_inventory(), findings, hypotheses, risk
        )
        verdict = investigation.verdict.lower()
        assert any(
            word in verdict
            for word in ("possible", "likely", "confidence", "suspicious")
        )
        assert "malicious: true" not in verdict

    def test_isolated_findings_produce_no_chain(self):
        findings = [finding("rare_destination", "10.0.0.15")]
        risk = compute_risk_score(findings, [], Config())
        investigation = build_investigation(small_inventory(), findings, [], risk)
        assert investigation.primary_hypothesis is None
        assert any("stand" in line or "individually" in line
                   for line in investigation.summary_lines)


class TestReportGeneration:
    def test_full_run_writes_three_reports(self, tmp_path, capsys):
        packets = (
            synth.vertical_scan(ports=range(1, 41), start=synth.BASE_TS)
            + synth.beacon(count=30, interval=30.0, dport=4444,
                           start=synth.BASE_TS + 100)
            + synth.dns_tunnel(count=30, start=synth.BASE_TS + 200)
            + synth.bulk_upload(segments=1000, start=synth.BASE_TS + 1100)
        )
        capture = tmp_path / "incident.pcap"
        wrpcap(str(capture), sorted(packets, key=lambda p: p.time))
        out_dir = tmp_path / "reports"

        assert run([str(capture), "--output-dir", str(out_dir)]) == 0

        investigation_json = out_dir / "investigation.json"
        timeline_json = out_dir / "timeline.json"
        html = out_dir / "investigation.html"
        assert investigation_json.is_file()
        assert timeline_json.is_file()
        assert html.is_file()

        report = json.loads(investigation_json.read_text(encoding="utf-8"))
        assert report["investigation"]["primary_suspect"] == "10.0.0.15"
        assert report["investigation"]["risk"]["score"] > 0
        assert report["investigation"]["attack_chain"]
        assert report["findings"]
        assert report["timeline"]["entries"]

        timeline = json.loads(timeline_json.read_text(encoding="utf-8"))
        assert timeline["entry_count"] == len(timeline["entries"])

        out = capsys.readouterr().out
        assert "Risk Score:" in out
        assert "INVESTIGATION SUMMARY" in out
        assert "Possible attack chain" in out

    def test_no_html_flag(self, tmp_path, mixed_pcap):
        out_dir = tmp_path / "reports"
        assert run([str(mixed_pcap), "--output-dir", str(out_dir), "--no-html"]) == 0
        assert not (out_dir / "investigation.html").exists()
        assert (out_dir / "investigation.json").is_file()

    def test_html_escapes_capture_controlled_strings(self, tmp_path):
        """A crafted DNS name must not inject markup into the report."""
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, UDP
        from scapy.layers.l2 import Ether

        evil = "<script>alert(1)</script>"
        packets = []
        for i in range(12):
            pkt = Ether() / IP(src="10.0.0.7", dst="10.0.0.1") / UDP(
                sport=53000 + i, dport=53
            ) / DNS(id=i, rd=1, qd=DNSQR(qname=f"{evil}.attack.test", qtype=16))
            pkt.time = synth.BASE_TS + i
            packets.append(pkt)
        capture = tmp_path / "evil.pcap"
        wrpcap(str(capture), packets)

        result = analyze_capture(PcapLoader(capture))
        html = render_html(build_report(result))
        assert "<script>alert(1)</script>" not in html
        if "alert(1)" in html:  # present only in escaped form
            assert "&lt;script&gt;" in html

    def test_html_contains_all_required_sections(self, tmp_path):
        packets = (
            synth.vertical_scan(ports=range(1, 41))
            + synth.beacon(count=30, dport=4444, start=synth.BASE_TS + 100)
        )
        capture = tmp_path / "sections.pcap"
        wrpcap(str(capture), sorted(packets, key=lambda p: p.time))
        result = analyze_capture(PcapLoader(capture))
        html = render_html(build_report(result))

        for section in (
            "Executive summary", "How the risk score was calculated", "Findings",
            "Timeline", "Hosts", "Top communications", "Protocols", "Evidence trace",
        ):
            assert section in html, f"missing HTML section: {section}"
