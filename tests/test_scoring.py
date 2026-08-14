"""V7 risk-scoring tests: the score must be bounded, explainable and
reproducible from its own components."""

from __future__ import annotations

from investigator.config import Config
from investigator.correlation import Correlator
from investigator.findings import Finding, Severity
from investigator.scoring import compute_risk_score, render_score_text


def finding(ftype, confidence=0.8, severity=Severity.MEDIUM, source="10.0.0.15",
            start=1_700_000_000.0):
    return Finding(
        type=ftype, title=f"test {ftype}", severity=severity,
        confidence=confidence, explanation="e", source=source,
        timestamp=start, start_time=start, end_time=start + 10,
    )


class TestRiskScore:
    def test_empty_capture_scores_zero(self):
        score = compute_risk_score([], [], Config())
        assert score.value == 0
        assert score.band == "MINIMAL"
        assert score.components == []

    def test_weight_and_confidence_are_applied(self):
        config = Config(weights={"beaconing": 25.0})
        score = compute_risk_score([finding("beaconing", confidence=0.8)], [], config)
        assert score.value == 20  # 25 * 0.8
        assert len(score.components) == 1
        component = score.components[0]
        assert component.weight == 25.0
        assert round(component.points, 2) == 20.0

    def test_components_sum_to_total(self):
        findings = [
            finding("beaconing", 0.9),
            finding("port_scan_vertical", 0.7),
            finding("rare_destination", 0.5),
        ]
        score = compute_risk_score(findings, [], Config())
        assert round(sum(c.points for c in score.components), 6) == round(score.total, 6)

    def test_repeated_type_has_diminishing_returns(self):
        one = compute_risk_score([finding("rare_destination", 0.8)], [], Config())
        five = compute_risk_score(
            [finding("rare_destination", 0.8) for _ in range(5)], [], Config()
        )
        # more findings still score higher, but far from 5x
        assert five.total > one.total
        assert five.total < one.total * 3

    def test_same_behaviour_to_many_destinations_does_not_inflate(self):
        """Three periodic-communication findings from one host to three
        destinations are evidence of ONE behaviour, not three."""
        same_activity = [
            finding("beaconing", 0.9, source="10.0.0.15") for _ in range(3)
        ]
        for index, item in enumerate(same_activity):
            item.destination = f"203.0.113.{index + 10}"
            item.behavior_group = "periodic_communication:10.0.0.15"
        grouped = compute_risk_score(same_activity, [], Config())
        single = compute_risk_score([same_activity[0]], [], Config())

        assert grouped.groups_counted == 1
        assert grouped.findings_counted == 3
        # far below 3x: the repeats decay inside the group
        assert grouped.raw_score < single.raw_score * 2

    def test_independent_behaviours_are_counted_separately(self):
        independent = [
            finding("beaconing", 0.9, source="10.0.0.15"),
            finding("port_scan_vertical", 0.9, source="10.0.0.15"),
            finding("dns_tunneling", 0.9, source="10.0.0.15"),
        ]
        score = compute_risk_score(independent, [], Config())
        assert score.groups_counted == 3
        # each contributes at full weight - no cross-group decay
        assert all(c.multiplier >= 0.85 for c in score.components if c.points > 0)

    def test_correlation_adds_bonus(self):
        findings = [
            finding("port_scan_vertical", 0.8, start=1_700_000_000.0),
            finding("beaconing", 0.8, start=1_700_000_500.0),
        ]
        hypotheses = Correlator(Config()).correlate(findings)
        without = compute_risk_score(findings, [], Config())
        with_corr = compute_risk_score(findings, hypotheses, Config())
        assert with_corr.total > without.total
        assert any("Correlated" in c.label for c in with_corr.components)

    def test_raw_and_normalized_are_reported_separately(self):
        """Hitting the ceiling must stay visibly different from exceeding it."""
        findings = [
            finding(t, 0.95, severity=Severity.HIGH)
            for t in ("beaconing", "dns_tunneling",
                      "potential_exfiltration_indicator",
                      "port_scan_vertical", "lateral_movement", "host_discovery")
        ]
        score = compute_risk_score(findings, [], Config())
        assert score.value == 100
        assert score.normalized_score == 100
        assert score.raw_score > 100          # the overflow is preserved
        assert score.capped
        assert any("ceiling" in c.label.lower() for c in score.components)

        data = score.as_dict()
        assert data["raw_score"] > 100
        assert data["normalized_score"] == 100
        # the score must never present itself as a probability
        assert data["is_probability"] is False
        assert "not probability" in data["interpretation"]

    def test_risk_and_confidence_are_independent(self):
        """A high-risk finding with weak evidence must not report high
        confidence, and vice versa."""
        high_risk_weak_evidence = [
            finding("potential_exfiltration_indicator", 0.35, severity=Severity.HIGH)
        ]
        score = compute_risk_score(high_risk_weak_evidence, [], Config())
        assert score.confidence < 0.6
        assert score.confidence_level.label in ("LOW", "VERY LOW")

        low_risk_strong_evidence = [
            finding("traffic_burst", 0.95, severity=Severity.LOW)
        ]
        other = compute_risk_score(low_risk_strong_evidence, [], Config())
        # strong evidence, but the behaviour itself carries little risk
        assert other.confidence > score.confidence
        assert other.band in ("LOW", "MINIMAL", "MEDIUM")

    def test_uncorrelated_findings_cap_assessment_confidence(self):
        """A lone finding cannot yield a high-confidence assessment."""
        score = compute_risk_score([finding("beaconing", 0.97)], [], Config())
        assert score.confidence <= 0.75

    def test_bands(self):
        config = Config(weights={"beaconing": 100.0})
        assert compute_risk_score(
            [finding("beaconing", 0.9)], [], config).band == "CRITICAL"
        assert compute_risk_score(
            [finding("beaconing", 0.65)], [], config).band == "HIGH"
        assert compute_risk_score(
            [finding("beaconing", 0.4)], [], config).band == "MEDIUM"
        assert compute_risk_score(
            [finding("beaconing", 0.1)], [], config).band == "LOW"

    def test_weights_are_configurable(self):
        low = compute_risk_score(
            [finding("beaconing", 0.8)], [], Config(weights={"beaconing": 5.0}))
        high = compute_risk_score(
            [finding("beaconing", 0.8)], [], Config(weights={"beaconing": 50.0}))
        assert high.total > low.total

    def test_render_shows_the_arithmetic(self):
        score = compute_risk_score([finding("beaconing", 0.8)], [], Config())
        text = render_score_text(score)
        assert "Risk Score:" in text
        assert "Severity:" in text
        assert "Confidence:" in text
        assert "Score interpretation:" in text
        assert "not probability of compromise" in text
        assert "How this score was calculated" in text
        assert "weight" in text
        assert "raw" in text and "normalized" in text
