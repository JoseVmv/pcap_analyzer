"""Event correlation: turning independent findings into a coherent picture.

A pile of unrelated alerts is not an investigation.  This stage groups a
host's findings into behaviour categories and - when several categories
appear together - forms a :class:`Hypothesis`: an aggregated assessment with
an explicit list of the findings that support it.

Observation vs interpretation vs hypothesis
-------------------------------------------
The output deliberately keeps three levels apart:

* **Observed behaviour** (:class:`BehaviorGroup`) - what the packets show,
  grouped by category.  No causal claim whatsoever.
* **Correlated indicators** (:class:`HostRiskProfile`) - several categories
  attributable to one host.  Still not causal, but consolidated.
* **Hypothesis** - an investigative reading of that combination, always
  hedged and always traceable to the findings underneath.

Earlier versions presented an "attack chain" with arrows, which implied that
A *caused* B.  A capture cannot establish causation - only co-occurrence and
ordering - so the arrows are gone.  Chronological ordering is still measured
and reported, because it is genuine corroborating information, but it is
labelled as sequence, not causality.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from investigator.config import Config
from investigator.findings import Confidence, Finding, Severity


# No hypothesis ever reaches certainty: a capture shows behaviour, not intent.
CONFIDENCE_CEILING = 0.98


class Phase(enum.IntEnum):
    """Behaviour categories, ordered as they typically unfold in time.

    Named "Phase" for continuity with earlier versions, but these are
    *observation categories*, not proven stages of an attack.  Their labels
    describe what was seen, not what it means.
    """

    RECON = 1
    LINK_LAYER = 2
    EXTERNAL_COMM = 3
    DNS_ANOMALY = 4
    C2 = 5
    CLIENT_ANOMALY = 6
    COLLECTION = 7
    VOLUME_ANOMALY = 8
    EXFIL = 9
    LATERAL = 10

    @property
    def label(self) -> str:
        """Neutral, observation-level name used in behavioural summaries."""
        return {
            Phase.RECON: "Network Discovery / Scanning",
            Phase.LINK_LAYER: "Local Segment Addressing Anomalies",
            Phase.EXTERNAL_COMM: "Suspicious External Destinations",
            Phase.DNS_ANOMALY: "DNS Anomalies",
            Phase.C2: "Periodic / Automated Communication",
            Phase.CLIENT_ANOMALY: "Anomalous Client Characteristics",
            Phase.COLLECTION: "Internal Data Access",
            Phase.VOLUME_ANOMALY: "Traffic Volume Anomalies",
            Phase.EXFIL: "Potential Outbound Data Transfer",
            Phase.LATERAL: "Internal Host-to-Host Activity",
        }[self]

    @property
    def interpretive_label(self) -> str:
        """Kill-chain reading, used only where interpretation is signposted."""
        return {
            Phase.RECON: "Reconnaissance",
            Phase.LINK_LAYER: "Possible Traffic Interception",
            Phase.EXTERNAL_COMM: "External Communication",
            Phase.DNS_ANOMALY: "Possible Name-Resolution Abuse",
            Phase.C2: "Possible Command & Control",
            Phase.CLIENT_ANOMALY: "Anomalous Client Fingerprint",
            Phase.COLLECTION: "Data Collection",
            Phase.VOLUME_ANOMALY: "Unexplained Volume Spike",
            Phase.EXFIL: "Possible Data Staging / Exfiltration",
            Phase.LATERAL: "Possible Lateral Movement",
        }[self]


# Which behaviour category each finding type belongs to.  New detectors
# register here.  DNS and client-fingerprint anomalies get their own
# categories rather than being folded into C2: they are different
# behaviours that merely *may* serve the same purpose, and collapsing them
# would both mislabel them in the behavioural summary and overstate how
# many independent categories a host exhibits.
TYPE_TO_PHASE: dict[str, Phase] = {
    "port_scan_vertical": Phase.RECON,
    "port_scan_horizontal": Phase.RECON,
    "host_discovery": Phase.RECON,
    "rare_destination": Phase.EXTERNAL_COMM,
    "unusual_port": Phase.EXTERNAL_COMM,
    "dns_tunneling": Phase.DNS_ANOMALY,
    "dns_anomaly": Phase.DNS_ANOMALY,
    "beaconing": Phase.C2,
    "http_beaconing": Phase.C2,
    "http_anomaly": Phase.CLIENT_ANOMALY,
    "data_collection": Phase.COLLECTION,
    # A burst is direction-agnostic by construction, so it must NOT be
    # filed under an outbound-transfer heading - that would assert exactly
    # what the burst detector says it cannot determine.
    "traffic_burst": Phase.VOLUME_ANOMALY,
    "large_transfer": Phase.EXFIL,
    "outbound_data_transfer": Phase.EXFIL,
    "potential_exfiltration_indicator": Phase.EXFIL,
    "data_exfiltration": Phase.EXFIL,
    "lateral_movement": Phase.LATERAL,
    "icmp_sweep": Phase.RECON,
    "icmp_tunneling": Phase.C2,
    # A hostname reached without a resolution that justifies it, or with no
    # hostname at all, describes the *destination* rather than the client's
    # rhythm - so it belongs with the other destination-quality signals and
    # not in the periodic-communication category.
    "tls_no_sni": Phase.EXTERNAL_COMM,
    "tls_unresolved_sni": Phase.EXTERNAL_COMM,
    # The fingerprint says which software is calling, which is exactly the
    # question the client-characteristics category answers.
    "tls_rare_fingerprint": Phase.CLIENT_ANOMALY,
    "tls_legacy_version": Phase.CLIENT_ANOMALY,
    "arp_spoofing": Phase.LINK_LAYER,
    "arp_mac_flooding": Phase.LINK_LAYER,
}


def phase_of(finding: Finding) -> Phase | None:
    return TYPE_TO_PHASE.get(finding.type)


@dataclass(slots=True)
class BehaviorGroup:
    """Several findings that describe **one** underlying observed behaviour.

    Three "periodic communication to X/Y/Z" findings remain three pieces of
    evidence, but they are one behaviour.  Presenting them grouped keeps the
    report readable and is what stops the score from triple-counting a
    single activity.
    """

    category: Phase
    subject: str | None
    findings: list[Finding] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.category.label

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def max_confidence(self) -> float:
        return max((f.confidence for f in self.findings), default=0.0)

    @property
    def destinations(self) -> list[str]:
        seen: list[str] = []
        for finding in self.findings:
            if finding.destination and finding.destination not in seen:
                seen.append(finding.destination)
        return seen

    def as_dict(self) -> dict[str, object]:
        return {
            "category": self.category.label,
            "interpretive_category": self.category.interpretive_label,
            "subject": self.subject,
            "finding_count": len(self.findings),
            "max_severity": self.max_severity.label,
            "max_confidence": round(self.max_confidence, 3),
            "destinations": self.destinations,
            "finding_ids": [f.id for f in self.findings],
            "evidence": [f.title for f in self.findings],
        }


@dataclass(slots=True)
class HostRiskProfile:
    """Consolidated view of everything observed about one host.

    Far more useful to an analyst than 42 independent findings: one host,
    its risk and confidence on separate axes, its behaviour categories, and
    a plain-language explanation of why the combination is suspicious.
    """

    ip: str
    risk: Severity
    confidence: float
    groups: list[BehaviorGroup] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    rationale: str = ""

    @property
    def finding_count(self) -> int:
        return sum(len(g.findings) for g in self.groups)

    @property
    def confidence_level(self) -> Confidence:
        return Confidence.from_score(self.confidence)

    def as_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "risk": self.risk.label,
            "confidence": round(self.confidence, 3),
            "confidence_level": self.confidence_level.label,
            "behavior_categories": [g.as_dict() for g in self.groups],
            "indicators": self.indicators,
            "rationale": self.rationale,
            "finding_count": self.finding_count,
        }


def group_findings(findings: list[Finding]) -> list[BehaviorGroup]:
    """Collapse findings into behaviour groups, per host and category."""
    grouped: dict[tuple[str | None, Phase], BehaviorGroup] = {}
    for finding in findings:
        category = phase_of(finding)
        if category is None:
            continue
        key = (finding.source, category)
        group = grouped.get(key)
        if group is None:
            group = BehaviorGroup(category=category, subject=finding.source)
            grouped[key] = group
        group.findings.append(finding)

    return sorted(
        grouped.values(),
        key=lambda g: (-g.max_severity, -g.max_confidence, g.category),
    )


def build_host_profiles(findings: list[Finding]) -> list[HostRiskProfile]:
    """One consolidated risk profile per host that has findings."""
    by_host: dict[str, list[BehaviorGroup]] = {}
    for group in group_findings(findings):
        if group.subject is None:
            continue
        by_host.setdefault(group.subject, []).append(group)

    profiles: list[HostRiskProfile] = []
    for ip, groups in by_host.items():
        all_findings = [f for g in groups for f in g.findings]
        risk = max((f.severity for f in all_findings), default=Severity.INFO)

        # Confidence in the *host-level* assessment: anchored on the best
        # supported finding, raised by how many distinct behaviour
        # categories independently point at this host.
        best = max((f.confidence for f in all_findings), default=0.0)
        breadth = min(0.15, 0.05 * (len(groups) - 1))
        confidence = min(CONFIDENCE_CEILING, best + breadth)

        indicators = [g.label for g in groups]
        rationale = _host_rationale(ip, groups, all_findings)
        profiles.append(
            HostRiskProfile(
                ip=ip,
                risk=risk,
                confidence=confidence,
                groups=groups,
                indicators=indicators,
                rationale=rationale,
            )
        )

    profiles.sort(key=lambda p: (-p.risk, -p.confidence, p.ip))
    return profiles


def _host_rationale(
    ip: str, groups: list[BehaviorGroup], findings: list[Finding]
) -> str:
    """Plain-language answer to 'why is this host suspicious?'."""
    if len(groups) == 1:
        return (
            f"{ip} shows a single category of anomalous behaviour "
            f"({groups[0].label.lower()}), supported by {len(findings)} finding(s). "
            f"A single behaviour category is weaker evidence than several "
            f"independent ones, and may well have a benign explanation."
        )

    category_text = ", ".join(g.label.lower() for g in groups[:-1])
    category_text += f" and {groups[-1].label.lower()}"
    return (
        f"{ip} is notable because {len(groups)} independent categories of "
        f"anomalous behaviour converge on the same host: {category_text}. "
        f"Each category was detected by a different mechanism, so their "
        f"co-occurrence is less easily explained by a single benign cause or "
        f"by one over-sensitive detector. This makes {ip} the highest-value "
        f"host to investigate first - it does not by itself establish that "
        f"the host is compromised."
    )


@dataclass(slots=True)
class Hypothesis:
    """A correlated narrative about one subject host."""

    subject: str
    title: str
    confidence: float
    severity: Severity
    phases: list[Phase]
    finding_ids: list[str]
    narrative: list[str]          # phase labels, in chain order
    correlations: list[str]       # temporal correlation sentences
    explanation: str
    start_time: float | None = None
    end_time: float | None = None
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def confidence_level(self) -> Confidence:
        return Confidence.from_score(self.confidence)

    def as_dict(self) -> dict[str, object]:
        return {
            "subject": self.subject,
            "title": self.title,
            "confidence": round(self.confidence, 3),
            "confidence_pct": round(self.confidence * 100),
            "confidence_level": self.confidence_level.label,
            "risk": self.severity.label,
            "severity": self.severity.label,
            "behavior_categories": [p.label for p in self.phases],
            "observed_behavior": self.narrative,
            # Retained for backwards compatibility with earlier report
            # consumers; it is an observation sequence, NOT a causal chain.
            "attack_chain": self.narrative,
            "finding_ids": self.finding_ids,
            "sequence_notes": self.correlations,
            "correlations": self.correlations,
            "explanation": self.explanation,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "metadata": self.metadata,
        }


def _representative_time(finding: Finding) -> float | None:
    return finding.start_time if finding.start_time is not None else finding.timestamp


def _fmt_time(epoch: float | None) -> str:
    if epoch is None:
        return "unknown time"
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%H:%M:%S")


class Correlator:
    """Builds hypotheses from a flat list of findings."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def correlate(self, findings: list[Finding]) -> list[Hypothesis]:
        by_subject: dict[str, list[Finding]] = {}
        for finding in findings:
            if finding.source is None:
                continue
            by_subject.setdefault(finding.source, []).append(finding)

        hypotheses: list[Hypothesis] = []
        for subject, subject_findings in by_subject.items():
            hypothesis = self._build(subject, subject_findings)
            if hypothesis is not None:
                hypotheses.append(hypothesis)

        hypotheses.sort(key=lambda h: (-h.confidence, -h.severity))
        return hypotheses

    def _build(self, subject: str, findings: list[Finding]) -> Hypothesis | None:
        # Group findings by phase, keeping the strongest per phase for the
        # narrative but counting them all for support.
        phases: dict[Phase, list[Finding]] = {}
        for finding in findings:
            phase = phase_of(finding)
            if phase is None:
                continue
            phases.setdefault(phase, []).append(finding)

        if len(phases) < 2:
            return None  # need at least two phases to tell a story

        ordered_phases = sorted(phases)
        member_findings = [f for group in phases.values() for f in group]
        finding_ids = [f.id for f in member_findings]

        # --- confidence aggregation ------------------------------------
        # Anchor on the findings themselves (strongest one, tempered by the
        # average so a crowd of weak findings cannot masquerade as strong),
        # then let corroboration consume a *fraction of the remaining
        # headroom*.  That keeps the result strictly monotonic in the amount
        # of corroboration while never saturating at the ceiling.
        confidences = [f.confidence for f in member_findings]
        max_conf = max(confidences)
        mean_conf = sum(confidences) / len(confidences)
        confidence = 0.5 * max_conf + 0.5 * mean_conf

        # chronological corroboration: do phase start-times increase along
        # the canonical order?
        phase_times = {
            phase: min(
                (t for t in (_representative_time(f) for f in group) if t is not None),
                default=None,
            )
            for phase, group in phases.items()
        }
        known_times = [
            phase_times[p] for p in ordered_phases if phase_times[p] is not None
        ]
        chronological = len(known_times) >= 2 and all(
            a <= b + 1e-9 for a, b in zip(known_times, known_times[1:])
        )

        phase_fraction = min(0.6, 0.1 * (len(phases) - 1))
        confidence += (CONFIDENCE_CEILING - confidence) * phase_fraction
        if chronological:
            order_fraction = min(0.6, self.config.correlation_bonus / 100.0)
            confidence += (CONFIDENCE_CEILING - confidence) * order_fraction
        confidence = min(CONFIDENCE_CEILING, confidence)

        # --- narrative + temporal correlation sentences ----------------
        # The chain is told in *observed* order, because this is a
        # reconstruction of what happened, not a textbook diagram.  Whether
        # that order matches the canonical kill-chain progression is
        # reported separately (and is what earns the confidence bonus).
        observed_order = sorted(
            ordered_phases,
            key=lambda p: (phase_times[p] is None, phase_times[p] or 0.0, p),
        )
        narrative = [p.label for p in observed_order]
        correlations = self._temporal_sentences(observed_order, phase_times, phases)

        severity = max((f.severity for f in member_findings), default=Severity.LOW)
        start_time = min(
            (t for t in phase_times.values() if t is not None), default=None
        )
        end_time = max(
            (f.end_time for f in member_findings if f.end_time is not None),
            default=start_time,
        )

        phase_summary = ", then ".join(narrative)
        explanation = (
            f"Host {subject} exhibits {len(phases)} distinct categories of anomalous "
            f"behaviour, first observed in this order: {phase_summary}. This is drawn "
            f"from {len(member_findings)} correlated findings. "
            + (
                "The order in which they appear is consistent with a typical attack "
                "progression, which adds corroboration - though sequence alone does "
                "not establish that one behaviour caused the next."
                if chronological
                else "They do not appear in the order a textbook attack progression "
                "would predict, so the grouping is suggestive rather than "
                "conclusive - activity may overlap, or the capture may start "
                "mid-incident."
            )
        )

        title = self._title(ordered_phases)
        return Hypothesis(
            subject=subject,
            title=title,
            confidence=confidence,
            severity=severity,
            phases=ordered_phases,
            finding_ids=finding_ids,
            narrative=narrative,
            correlations=correlations,
            explanation=explanation,
            start_time=start_time,
            end_time=end_time,
            metadata={
                "phase_count": len(phases),
                "finding_count": len(member_findings),
                "chronological": chronological,
                "max_finding_confidence": round(max_conf, 3),
            },
        )

    def _temporal_sentences(self, ordered_phases, phase_times, phases) -> list[str]:
        sentences: list[str] = []
        for earlier, later in zip(ordered_phases, ordered_phases[1:]):
            t_early = phase_times.get(earlier)
            t_late = phase_times.get(later)
            if t_early is None or t_late is None:
                continue
            delta = t_late - t_early
            if delta >= 0:
                sentences.append(
                    f"{earlier.label} at {_fmt_time(t_early)} preceded "
                    f"{later.label} at {_fmt_time(t_late)} "
                    f"(+{delta:.0f}s later)."
                )
            else:
                sentences.append(
                    f"{later.label} at {_fmt_time(t_late)} appeared before "
                    f"{earlier.label} at {_fmt_time(t_early)} "
                    f"(out of expected order)."
                )
        return sentences

    def _title(self, ordered_phases: list[Phase]) -> str:
        """Hedged summary title.

        Never asserts compromise, exfiltration or C2 as fact - the wording
        stays at "consistent with" / "possible", because the packet data
        supports a reading, not a verdict.
        """
        has = set(ordered_phases)
        if {Phase.C2, Phase.EXFIL} <= has:
            return (
                "Behaviour consistent with possible compromise: automated external "
                "communication and outbound data transfer"
            )
        if Phase.C2 in has and Phase.RECON in has:
            return (
                "Behaviour consistent with possible compromise: network scanning "
                "and automated external communication"
            )
        if Phase.C2 in has:
            return "Possible automated command-and-control communication"
        if Phase.EXFIL in has:
            return "Potential outbound data transfer alongside other anomalies"
        if Phase.LATERAL in has:
            return "Possible internal lateral activity from an anomalous host"
        return "Correlated anomalous network behaviour"
