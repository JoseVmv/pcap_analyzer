"""V4 correlation tests: findings are hand-built so the correlation logic is
tested in isolation from detection."""

from __future__ import annotations

import synth
from scapy.utils import wrpcap

from investigator.config import Config
from investigator.correlation import Correlator, Phase, phase_of
from investigator.findings import Finding, Severity
from investigator.parser import PcapLoader
from investigator.pipeline import analyze_capture

SUSPECT = "10.0.0.15"
BASE = 1_700_000_000.0


def finding(ftype: str, *, source=SUSPECT, start=BASE, confidence=0.8,
            severity=Severity.MEDIUM, destination=None) -> Finding:
    return Finding(
        type=ftype,
        title=f"test {ftype}",
        severity=severity,
        confidence=confidence,
        explanation="test",
        source=source,
        destination=destination,
        timestamp=start,
        start_time=start,
        end_time=start + 60,
    )


class TestPhaseMapping:
    def test_known_types_map_to_phases(self):
        assert phase_of(finding("port_scan_vertical")) is Phase.RECON
        assert phase_of(finding("beaconing")) is Phase.C2
        assert phase_of(finding("rare_destination")) is Phase.EXTERNAL_COMM
        assert phase_of(finding("traffic_burst")) is Phase.EXFIL

    def test_unknown_type_has_no_phase(self):
        assert phase_of(finding("something_new")) is None


class TestCorrelator:
    def test_single_phase_produces_no_hypothesis(self):
        correlator = Correlator(Config())
        assert correlator.correlate([finding("port_scan_vertical")]) == []

    def test_chain_produces_hypothesis(self):
        findings = [
            finding("port_scan_vertical", start=BASE),
            finding("rare_destination", start=BASE + 100),
            finding("beaconing", start=BASE + 200, confidence=0.9),
            finding("traffic_burst", start=BASE + 700),
        ]
        hypotheses = Correlator(Config()).correlate(findings)
        assert len(hypotheses) == 1
        hypothesis = hypotheses[0]
        assert hypothesis.subject == SUSPECT
        assert hypothesis.narrative == [
            "Reconnaissance",
            "External Communication",
            "Command & Control",
            "Possible Data Exfiltration",
        ]
        assert hypothesis.metadata["chronological"] is True
        assert len(hypothesis.finding_ids) == 4
        assert "C2 and data exfiltration" in hypothesis.title
        assert hypothesis.correlations  # temporal sentences present

    def test_chronological_order_boosts_confidence(self):
        ordered = [
            finding("port_scan_vertical", start=BASE),
            finding("beaconing", start=BASE + 500),
        ]
        shuffled = [
            finding("port_scan_vertical", start=BASE + 500),
            finding("beaconing", start=BASE),
        ]
        correlator = Correlator(Config())
        ordered_hypothesis = correlator.correlate(ordered)[0]
        shuffled_hypothesis = correlator.correlate(shuffled)[0]
        assert ordered_hypothesis.confidence > shuffled_hypothesis.confidence
        assert ordered_hypothesis.metadata["chronological"] is True
        assert shuffled_hypothesis.metadata["chronological"] is False
        assert "does not follow" in shuffled_hypothesis.explanation

    def test_narrative_follows_observed_order(self):
        """The chain is a reconstruction, so it is told in the order things
        actually happened - not in textbook kill-chain order."""
        shuffled = [
            finding("port_scan_vertical", start=BASE + 500),
            finding("beaconing", start=BASE),
        ]
        hypothesis = Correlator(Config()).correlate(shuffled)[0]
        assert hypothesis.narrative == ["Command & Control", "Reconnaissance"]

    def test_findings_grouped_per_subject(self):
        findings = [
            finding("port_scan_vertical", source="10.0.0.15"),
            finding("beaconing", source="10.0.0.15", start=BASE + 10),
            finding("port_scan_vertical", source="10.0.0.99"),
            finding("traffic_burst", source="10.0.0.99", start=BASE + 10),
        ]
        hypotheses = Correlator(Config()).correlate(findings)
        assert {h.subject for h in hypotheses} == {"10.0.0.15", "10.0.0.99"}

    def test_more_phases_increase_confidence(self):
        two = [finding("port_scan_vertical"), finding("beaconing", start=BASE + 10)]
        four = two + [
            finding("rare_destination", start=BASE + 5),
            finding("traffic_burst", start=BASE + 20),
        ]
        correlator = Correlator(Config())
        assert correlator.correlate(four)[0].confidence > correlator.correlate(two)[0].confidence

    def test_correlation_bonus_is_configurable(self):
        findings = [
            finding("port_scan_vertical", start=BASE),
            finding("beaconing", start=BASE + 500),
        ]
        low = Correlator(Config(correlation_bonus=0.0)).correlate(findings)[0]
        high = Correlator(Config(correlation_bonus=25.0)).correlate(findings)[0]
        assert high.confidence > low.confidence


class TestCorrelationEndToEnd:
    def test_scenario_produces_full_chain(self, tmp_path):
        packets = (
            synth.vertical_scan(ports=range(1, 41), start=synth.BASE_TS)
            + synth.beacon(count=30, interval=30.0, dport=4444,
                           start=synth.BASE_TS + 100)
            + synth.bulk_upload(segments=1000, start=synth.BASE_TS + 1100)
        )
        packets.sort(key=lambda p: p.time)
        path = tmp_path / "chain.pcap"
        wrpcap(str(path), packets)

        result = analyze_capture(PcapLoader(path), config=Config())
        assert result.hypotheses, "expected at least one correlated hypothesis"
        top = result.hypotheses[0]
        assert top.subject == "10.0.0.15"
        assert Phase.RECON in top.phases
        assert Phase.C2 in top.phases
        assert top.confidence > 0.7
