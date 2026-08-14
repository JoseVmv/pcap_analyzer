"""End-to-end analysis orchestration.

``analyze_capture`` is the one place that wires the collectors, runs the
single streaming pass, then runs the post-pass stages (detection now;
correlation, threat mapping, timeline and scoring in later versions).  The
CLI and the tests both go through here, so behaviour stays identical between
them.  :class:`AnalysisResult` is the growing container passed to reporting.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from investigator import threats
from investigator.config import Config
from investigator.correlation import (
    BehaviorGroup,
    Correlator,
    HostRiskProfile,
    Hypothesis,
    build_host_profiles,
    group_findings,
)
from investigator.detectors import (
    ContactSeriesTracker,
    DetectionContext,
    TrafficRateTracker,
    run_detectors,
)
from investigator.engine import run_analysis
from investigator.findings import Finding
from investigator.inventory import NetworkInventory
from investigator.investigation import Investigation, build_investigation
from investigator.models import CaptureSummary
from investigator.parser import PcapLoader
from investigator.protocols import ProtocolAnalyzers
from investigator.scoring import RiskScore, compute_risk_score
from investigator.timeline import Timeline, build_timeline

LOG = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Aggregated output of a full run (extended each version)."""

    loader: PcapLoader
    config: Config
    summary: CaptureSummary
    inventory: NetworkInventory
    protocols: ProtocolAnalyzers
    findings: list[Finding] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    behavior_groups: list[BehaviorGroup] = field(default_factory=list)
    host_profiles: list[HostRiskProfile] = field(default_factory=list)
    timeline: Timeline = field(default_factory=Timeline)
    risk: RiskScore | None = None
    investigation: Investigation | None = None


def analyze_capture(
    loader: PcapLoader,
    config: Config | None = None,
    *,
    progress_every: int = 100_000,
) -> AnalysisResult:
    config = config or Config()

    summary = CaptureSummary()
    inventory = NetworkInventory()
    protocols = ProtocolAnalyzers()
    rate = TrafficRateTracker()
    contacts = ContactSeriesTracker()

    collectors = [summary, inventory, *protocols.collectors(), rate, contacts]
    run_analysis(loader, collectors, progress_every=progress_every)

    ctx = DetectionContext(
        config=config,
        summary=summary,
        inventory=inventory,
        protocols=protocols,
        rate=rate,
        contacts=contacts,
    )
    findings = run_detectors(ctx)
    threats.annotate(findings)
    LOG.info("detection produced %d finding(s)", len(findings))

    hypotheses = Correlator(config).correlate(findings)
    behavior_groups = group_findings(findings)
    host_profiles = build_host_profiles(findings)
    LOG.info(
        "correlation produced %d hypothes(es), %d behaviour group(s), %d host profile(s)",
        len(hypotheses),
        len(behavior_groups),
        len(host_profiles),
    )

    timeline = build_timeline(inventory, findings, hypotheses)
    LOG.info("timeline reconstructed with %d entries", len(timeline.entries))

    risk = compute_risk_score(findings, hypotheses, config)
    investigation = build_investigation(
        inventory, findings, hypotheses, risk, host_profiles
    )
    LOG.info(
        "risk %d/100 (%s), assessment confidence %s",
        risk.value,
        risk.band,
        risk.confidence_level.label,
    )

    return AnalysisResult(
        loader=loader,
        config=config,
        summary=summary,
        inventory=inventory,
        protocols=protocols,
        findings=findings,
        hypotheses=hypotheses,
        behavior_groups=behavior_groups,
        host_profiles=host_profiles,
        timeline=timeline,
        risk=risk,
        investigation=investigation,
    )
