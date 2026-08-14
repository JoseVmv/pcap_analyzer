"""V6 timeline reconstruction tests."""

from __future__ import annotations

import synth
from scapy.utils import wrpcap

from investigator.config import Config
from investigator.correlation import Correlator
from investigator.findings import Finding, Severity
from investigator.inventory import NetworkInventory
from investigator.models import NetworkEvent, Protocol
from investigator.parser import PcapLoader
from investigator.pipeline import analyze_capture
from investigator.timeline import build_timeline, format_time, render_timeline_text

BASE = 1_700_000_000.0
SUSPECT = "10.0.0.15"


def inventory_with_traffic() -> NetworkInventory:
    inv = NetworkInventory()
    for i, (dst, ts) in enumerate(
        (("203.0.113.66", BASE + 10), ("10.0.0.23", BASE + 5))
    ):
        for j in range(3):
            inv.observe(
                NetworkEvent(
                    timestamp=ts + j,
                    protocol=Protocol.TCP,
                    wire_bytes=100,
                    src_ip=SUSPECT,
                    dst_ip=dst,
                    src_port=50000 + i,
                    dst_port=443,
                    payload_bytes=40,
                )
            )
    return inv


def finding(ftype, start, confidence=0.8, severity=Severity.MEDIUM):
    return Finding(
        type=ftype, title=f"test {ftype}", severity=severity,
        confidence=confidence, explanation="because",
        source=SUSPECT, destination="203.0.113.66",
        timestamp=start, start_time=start, end_time=start + 60,
    ).add("supporting evidence")


class TestTimelineBuilding:
    def test_entries_are_chronological(self):
        findings = [
            finding("port_scan_vertical", BASE + 100),
            finding("beaconing", BASE + 300),
        ]
        hypotheses = Correlator(Config()).correlate(findings)
        timeline = build_timeline(inventory_with_traffic(), findings, hypotheses)
        stamps = [e.timestamp for e in timeline.sorted_entries()]
        assert stamps == sorted(stamps)

    def test_all_four_kinds_present(self):
        findings = [
            finding("port_scan_vertical", BASE + 100),
            finding("beaconing", BASE + 300),
        ]
        hypotheses = Correlator(Config()).correlate(findings)
        timeline = build_timeline(inventory_with_traffic(), findings, hypotheses)
        kinds = {e.kind for e in timeline.entries}
        assert kinds == {"observation", "finding", "correlation", "hypothesis"}

    def test_findings_carry_severity_and_evidence(self):
        findings = [finding("beaconing", BASE + 300, severity=Severity.HIGH)]
        timeline = build_timeline(inventory_with_traffic(), findings, [])
        entries = [e for e in timeline.entries if e.kind == "finding"]
        assert len(entries) == 1
        assert entries[0].severity is Severity.HIGH
        assert entries[0].detail == "supporting evidence"
        assert entries[0].finding_id == findings[0].id

    def test_filter_per_host(self):
        findings = [finding("beaconing", BASE + 300)]
        timeline = build_timeline(inventory_with_traffic(), findings, [])
        assert timeline.for_host(SUSPECT)
        assert timeline.for_host("192.0.2.99") == []

    def test_observations_are_capped(self):
        inv = NetworkInventory()
        for i in range(120):
            inv.observe(
                NetworkEvent(
                    timestamp=BASE + i, protocol=Protocol.TCP, wire_bytes=100,
                    src_ip=SUSPECT, dst_ip=f"203.0.113.{i % 250}",
                    src_port=40000 + i, dst_port=443, payload_bytes=10,
                )
            )
        timeline = build_timeline(inv, [], [], max_observations=10)
        assert len([e for e in timeline.entries if e.kind == "observation"]) == 10

    def test_as_dict_is_json_ready(self):
        import json

        findings = [finding("beaconing", BASE + 300)]
        timeline = build_timeline(inventory_with_traffic(), findings, [])
        data = timeline.as_dict()
        encoded = json.dumps(data)
        assert "entries" in encoded
        assert data["entry_count"] == len(timeline.entries)
        assert data["entries"][0]["time"] == format_time(data["entries"][0]["timestamp"])

    def test_text_rendering(self):
        findings = [finding("beaconing", BASE + 300)]
        timeline = build_timeline(inventory_with_traffic(), findings, [])
        text = render_timeline_text(timeline, limit=5)
        assert "Timeline" in text
        assert SUSPECT in text


class TestTimelineEndToEnd:
    def test_scenario_timeline_orders_the_attack(self, tmp_path):
        packets = (
            synth.vertical_scan(ports=range(1, 41), start=synth.BASE_TS)
            + synth.beacon(count=30, interval=30.0, dport=4444,
                           start=synth.BASE_TS + 100)
            + synth.bulk_upload(segments=1000, start=synth.BASE_TS + 1100)
        )
        path = tmp_path / "chain.pcap"
        wrpcap(str(path), sorted(packets, key=lambda p: p.time))
        result = analyze_capture(PcapLoader(path))

        entries = result.timeline.sorted_entries()
        assert entries
        findings_in_order = [
            e.title for e in entries if e.kind == "finding"
        ]
        # the scan must appear before the exfiltration in the reconstructed story
        scan_index = next(
            i for i, t in enumerate(findings_in_order) if "port scan" in t
        )
        exfil_index = next(
            i for i, t in enumerate(findings_in_order) if "exfiltration" in t.lower()
        )
        assert scan_index < exfil_index
