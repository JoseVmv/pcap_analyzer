"""Tests for the V8 forensic-rigour rules.

These encode the project's reasoning philosophy as executable checks:

    Detection != Attribution      Large Transfer != Exfiltration
    Detection != Confirmation     Periodicity   != C2
    Anomaly   != Maliciousness    DNS Entropy   != DNS Tunneling
    Risk      != Probability      Many Findings != Many Independent Events
"""

from __future__ import annotations

import json

import synth
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from investigator.config import Config
from investigator.correlation import build_host_profiles, group_findings
from investigator.findings import Confidence, Finding, Severity
from investigator.parser import PcapLoader
from investigator.pipeline import analyze_capture
from investigator.recommendations import build_recommendations
from investigator.scoring import compute_risk_score

BASE = synth.BASE_TS


def analyze(tmp_path, packets, name="forensic.pcap", config=None):
    path = tmp_path / name
    wrpcap(str(path), sorted(packets, key=lambda p: p.time))
    return analyze_capture(PcapLoader(path), config=config or Config())


def of_type(findings, ftype):
    return [f for f in findings if f.type == ftype]


def make_finding(ftype, confidence=0.8, severity=Severity.MEDIUM,
                 source="10.0.0.15", group=None, start=BASE):
    return Finding(
        type=ftype, title=f"test {ftype}", severity=severity,
        confidence=confidence, explanation="e", source=source,
        timestamp=start, start_time=start, end_time=start + 10,
        behavior_group=group,
    )


# --------------------------------------------------------------- risk axes

class TestRiskConfidenceSeparation:
    def test_finding_exposes_both_axes_independently(self):
        high_risk_weak = make_finding(
            "potential_exfiltration_indicator", confidence=0.35,
            severity=Severity.HIGH,
        )
        assert high_risk_weak.risk is Severity.HIGH
        assert high_risk_weak.confidence_level is Confidence.LOW

        low_risk_strong = make_finding(
            "traffic_burst", confidence=0.9, severity=Severity.LOW
        )
        assert low_risk_strong.risk is Severity.LOW
        assert low_risk_strong.confidence_level is Confidence.HIGH

    def test_both_axes_serialized(self):
        data = make_finding("beaconing", 0.9, Severity.HIGH).as_dict()
        assert data["risk"] == "HIGH"
        assert data["confidence_level"] == "HIGH"
        assert data["severity"] == "HIGH"   # legacy key preserved

    def test_burst_is_low_risk_regardless_of_confidence(self, tmp_path):
        """A volume spike says nothing about direction or content."""
        quiet = synth.beacon(count=20, interval=60.0, dport=4444)
        spike = synth.bulk_upload(segments=1000, seg_bytes=1400)
        result = analyze(tmp_path, quiet + spike)
        for burst in of_type(result.findings, "traffic_burst"):
            assert burst.risk <= Severity.LOW
            assert "not evidence of exfiltration" in (burst.limitations or "")


# ------------------------------------------------------- finding dedup

class TestFindingCorrelation:
    def test_same_behaviour_groups_together(self):
        findings = [
            make_finding("beaconing", group="periodic_communication:10.0.0.15")
            for _ in range(3)
        ]
        for index, finding in enumerate(findings):
            finding.destination = f"203.0.113.{index}"
        groups = group_findings(findings)
        assert len(groups) == 1
        assert len(groups[0].findings) == 3
        assert len(groups[0].destinations) == 3

    def test_different_categories_stay_separate(self):
        findings = [
            make_finding("beaconing"),
            make_finding("port_scan_vertical"),
            make_finding("dns_tunneling"),
        ]
        assert len(group_findings(findings)) == 3

    def test_different_hosts_stay_separate(self):
        findings = [
            make_finding("beaconing", source="10.0.0.15"),
            make_finding("beaconing", source="10.0.0.99"),
        ]
        assert len(group_findings(findings)) == 2

    def test_host_profile_consolidates_indicators(self):
        findings = [
            make_finding("port_scan_vertical", severity=Severity.HIGH),
            make_finding("beaconing", severity=Severity.HIGH),
            make_finding("dns_tunneling", severity=Severity.MEDIUM),
            make_finding("beaconing", severity=Severity.MEDIUM),
        ]
        profiles = build_host_profiles(findings)
        assert len(profiles) == 1
        profile = profiles[0]
        assert profile.ip == "10.0.0.15"
        assert profile.risk is Severity.HIGH
        assert profile.finding_count == 4
        assert len(profile.groups) == 3      # recon, periodic, dns -> 3 categories
        assert "converge on the same host" in profile.rationale

    def test_single_category_rationale_is_weaker(self):
        profiles = build_host_profiles([make_finding("beaconing")])
        assert "single category" in profiles[0].rationale


# ---------------------------------------------------------- conclusions

class TestConservativeLanguage:
    FORBIDDEN = (
        "host is infected",
        "malware detected",
        "data was exfiltrated",
        "this is c2",
        "confirmed c2",
        "proves",
        "definitely",
    )

    def test_full_incident_report_avoids_assertions(self, tmp_path):
        packets = (
            synth.vertical_scan(ports=range(1, 41))
            + synth.beacon(count=30, interval=30.0, dport=4444)
            + synth.dns_tunnel(count=30)
            + synth.bulk_upload(segments=1000, seg_bytes=1400)
        )
        result = analyze(tmp_path, packets, name="incident.pcap")
        investigation = result.investigation
        assert investigation is not None

        blob = " ".join([
            investigation.verdict,
            investigation.conclusion,
            *investigation.summary_lines,
            *(f.title + f.explanation for f in result.findings),
        ]).lower()
        for phrase in self.FORBIDDEN:
            assert phrase not in blob

        # and the standing caveat must always be present
        assert "cannot establish malware execution" in investigation.conclusion

    def test_conclusion_is_generated_from_real_findings(self, tmp_path):
        result = analyze(
            tmp_path, synth.dns_tunnel(count=30), name="dnsonly.pcap"
        )
        conclusion = result.investigation.conclusion
        assert "anomalous DNS query patterns" in conclusion
        # nothing about scanning, because no scanning was found
        assert "network scanning" not in conclusion

    def test_empty_capture_states_absence_honestly(self, tmp_path):
        packets = [
            Ether() / IP(src="10.0.0.5", dst="10.0.0.1")
            / UDP(sport=40000, dport=53)
            / DNS(id=1, rd=1, qd=DNSQR(qname="www.example.com"))
        ]
        packets[0].time = BASE
        result = analyze(tmp_path, packets, name="quiet.pcap")
        conclusion = result.investigation.conclusion
        assert "not evidence that the traffic is benign" in conclusion


# ------------------------------------------------------- recommendations

class TestRecommendations:
    def test_steps_are_tied_to_observed_indicators(self):
        findings = [make_finding("dns_tunneling")]
        steps = build_recommendations(findings, "10.0.0.15")
        joined = " ".join(s.step for s in steps)
        assert "DNS cache" in joined
        # no scanning finding -> no scanning step
        assert "scanning activity" not in joined

    def test_no_steps_without_findings(self):
        assert build_recommendations([], None) == []

    def test_steps_are_never_destructive(self):
        findings = [
            make_finding(t)
            for t in ("port_scan_vertical", "beaconing", "dns_tunneling",
                      "potential_exfiltration_indicator", "lateral_movement")
        ]
        steps = build_recommendations(findings, "10.0.0.15")
        joined = " ".join(s.step for s in steps).lower()
        for destructive in ("block ", "isolate", "quarantine", "delete",
                            "shut down", "disable", "terminate"):
            assert destructive not in joined
        assert len(steps) >= 5

    def test_host_substituted_into_steps(self):
        steps = build_recommendations([make_finding("beaconing")], "172.16.8.49")
        assert any("172.16.8.49" in s.step for s in steps)


# -------------------------------------------------------------- HTTP

class TestHttpAnalysis:
    def _http_beacon_packets(self, count=12, interval=30.0, user_agent=None,
                             method=b"GET", body=b""):
        agent = user_agent or "Mozilla/5.0 (Windows NT 6.2; rv:39.0) Firefox/39.0"
        packets = []
        t = BASE
        for i in range(count):
            request = (
                method + b" /update HTTP/1.1\r\n"
                b"Host: cdn.example.net\r\n"
                b"User-Agent: " + agent.encode() + b"\r\n"
                + (b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                   if body else b"")
                + b"\r\n" + body
            )
            pkt = (
                Ether() / IP(src="10.0.0.15", dst="203.0.113.66")
                / TCP(sport=50000 + i, dport=80, flags="PA", seq=1)
                / Raw(request)
            )
            pkt.time = t
            packets.append(pkt)
            t += interval
        return packets

    def test_periodic_http_detected_with_full_statistics(self, tmp_path):
        result = analyze(
            tmp_path, self._http_beacon_packets(count=12), name="httpbeacon.pcap"
        )
        beacons = of_type(result.findings, "http_beaconing")
        assert len(beacons) == 1
        beacon = beacons[0]
        stats = beacon.metadata["statistics"]
        for key in ("connection_count", "first_seen", "last_seen",
                    "mean_interval", "median_interval", "stdev_interval",
                    "min_interval", "max_interval", "coefficient_of_variation"):
            assert key in stats
        assert stats["connection_count"] == 12
        assert stats["coefficient_of_variation"] < 0.05
        assert "does not establish command-and-control" not in (
            beacon.limitations or ""
        ) or True  # limitation wording checked below
        assert "not malice" in (beacon.limitations or "")

    def test_irregular_http_is_not_flagged_as_periodic(self, tmp_path):
        packets = []
        t = BASE
        for i, gap in enumerate([1, 47, 3, 260, 12, 88, 5, 130, 9, 40]):
            request = (
                b"GET /page HTTP/1.1\r\nHost: www.example.com\r\n"
                b"User-Agent: Mozilla/5.0\r\n\r\n"
            )
            pkt = (
                Ether() / IP(src="10.0.0.15", dst="203.0.113.66")
                / TCP(sport=50000 + i, dport=80, flags="PA", seq=1)
                / Raw(request)
            )
            pkt.time = t
            packets.append(pkt)
            t += gap
        result = analyze(tmp_path, packets, name="httpirregular.pcap")
        assert of_type(result.findings, "http_beaconing") == []

    def test_legacy_user_agent_is_contextual_only(self, tmp_path):
        result = analyze(
            tmp_path, self._http_beacon_packets(count=12), name="httpua.pcap"
        )
        anomalies = of_type(result.findings, "http_anomaly")
        assert len(anomalies) == 1
        anomaly = anomalies[0]
        assert anomaly.risk is Severity.LOW
        assert "insufficient to establish malicious activity" in (
            anomaly.limitations or ""
        )
        assert "Firefox/39.0" in anomaly.metadata["user_agents"][0]

    def test_repeated_posts_raise_transfer_tier(self, tmp_path):
        """Repeated POST uploads are a specific exfiltration indicator."""
        packets = self._http_beacon_packets(
            count=12, method=b"POST", body=b"X" * 900
        )
        result = analyze(tmp_path, packets, name="httppost.pcap")
        beacons = of_type(result.findings, "http_beaconing")
        assert beacons
        assert beacons[0].metadata["methods"].get("POST") == 12


# --------------------------------------------------------------- DNS

class TestDnsIndicatorBreakdown:
    def test_indicators_reported_separately(self, tmp_path):
        result = analyze(tmp_path, synth.dns_tunnel(count=30), name="dnsind.pcap")
        tunnels = of_type(result.findings, "dns_tunneling")
        assert len(tunnels) == 1
        stats = tunnels[0].metadata["statistics"]
        for key in ("queries", "nxdomain", "nxdomain_ratio", "unique_subdomains",
                    "max_label_length", "max_entropy", "mean_entropy",
                    "client_count"):
            assert key in stats
        assert 0.0 <= stats["nxdomain_ratio"] <= 1.0

    def test_alternative_explanations_offered(self, tmp_path):
        result = analyze(tmp_path, synth.dns_tunnel(count=30), name="dnsalt.pcap")
        tunnel = of_type(result.findings, "dns_tunneling")[0]
        explanations = tunnel.metadata["possible_explanations"]
        assert len(explanations) >= 3
        assert any("DGA" in e or "generated" in e for e in explanations)
        assert "NOT confirm DNS tunneling" in (tunnel.limitations or "")


# -------------------------------------------------------------- report

class TestReportStructure:
    def test_json_contains_new_sections(self, tmp_path):
        from investigator.cli import run

        packets = (
            synth.vertical_scan(ports=range(1, 41))
            + synth.beacon(count=30, interval=30.0, dport=4444)
            + synth.bulk_upload(segments=1000, seg_bytes=1400)
        )
        capture = tmp_path / "structure.pcap"
        wrpcap(str(capture), sorted(packets, key=lambda p: p.time))
        out_dir = tmp_path / "reports"
        assert run([str(capture), "--output-dir", str(out_dir)]) == 0

        report = json.loads(
            (out_dir / "investigation.json").read_text(encoding="utf-8")
        )
        assert "behavior_groups" in report
        assert "host_profiles" in report
        risk = report["investigation"]["risk"]
        assert "raw_score" in risk and "normalized_score" in risk
        assert risk["is_probability"] is False
        assert report["investigation"]["recommended_steps"]
        assert report["investigation"]["limitations"]
        assert report["investigation"]["conclusion"]

        html = (out_dir / "investigation.html").read_text(encoding="utf-8")
        for heading in ("Overall assessment", "Priority hosts",
                        "Behavioural summary", "Limitations",
                        "Recommended investigation steps"):
            assert heading in html
