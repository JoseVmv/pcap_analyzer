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

    def test_score_is_capped_and_reports_it(self):
        findings = [
            finding(t, 0.95, severity=Severity.HIGH)
            for t in ("beaconing", "dns_tunneling", "data_exfiltration",
                      "port_scan_vertical", "lateral_movement", "host_discovery")
        ]
        score = compute_risk_score(findings, [], Config())
        assert score.value == 100
        assert score.capped
        assert any("cap" in c.label.lower() for c in score.components)

    def test_bands(self):
        config = Config(weights={"beaconing": 100.0})
        assert compute_risk_score(
            [finding("beaconing", 0.9)], [], config).band == "CRITICAL"
        assert compute_risk_score(
            [finding("beaconing", 0.6)], [], config).band == "HIGH"
        assert compute_risk_score(
            [finding("beaconing", 0.3)], [], config).band == "MEDIUM"
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
        assert "How this score was calculated" in text
        assert "weight" in text
        assert "total" in text
