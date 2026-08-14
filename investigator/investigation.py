"""Automatic investigation (V7): the conclusions layer.

Takes everything the earlier stages produced and answers the three questions
an analyst actually asks:

1. *Which host should I look at first?*  - the primary suspect, ranked by
   the weight of evidence against it, not by traffic volume.
2. *What probably happened?*             - the primary hypothesis with its
   attack chain and confidence.
3. *Why should I believe it?*            - supporting evidence, each item
   traceable to the finding that produced it.

The invariant the project demands is enforced here: a conclusion is only
emitted when it can point at concrete evidence.  With no findings, the
summary says so plainly rather than inventing a narrative.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from investigator.correlation import HostRiskProfile, Hypothesis
from investigator.findings import Confidence, Finding, Severity
from investigator.inventory import HostKind, NetworkInventory
from investigator.recommendations import Recommendation, build_recommendations
from investigator.scoring import RiskScore


@dataclass(slots=True)
class SuspectScore:
    """Per-host evidence weight, used to pick the primary suspect."""

    ip: str
    weight: float
    finding_count: int
    max_severity: Severity
    max_confidence: float
    finding_ids: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "evidence_weight": round(self.weight, 2),
            "finding_count": self.finding_count,
            "max_severity": self.max_severity.label,
            "max_confidence": round(self.max_confidence, 3),
            "finding_ids": self.finding_ids,
            "tactics": self.tactics,
        }


@dataclass(slots=True)
class Investigation:
    """The final, self-contained conclusion of a run."""

    risk: RiskScore
    suspects: list[SuspectScore]
    primary_hypothesis: Hypothesis | None
    supporting_evidence: list[dict[str, object]]
    summary_lines: list[str]
    confidence: float
    verdict: str
    host_profiles: list[HostRiskProfile] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    conclusion: str = ""

    @property
    def primary_suspect(self) -> str | None:
        return self.suspects[0].ip if self.suspects else None

    @property
    def confidence_level(self) -> Confidence:
        return Confidence.from_score(self.confidence)

    def as_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "conclusion": self.conclusion,
            "confidence": round(self.confidence, 3),
            "confidence_pct": round(self.confidence * 100),
            "confidence_level": self.confidence_level.label,
            "risk": self.risk.as_dict(),
            "primary_suspect": self.primary_suspect,
            "suspects": [s.as_dict() for s in self.suspects],
            "host_profiles": [p.as_dict() for p in self.host_profiles],
            "primary_hypothesis": (
                self.primary_hypothesis.as_dict() if self.primary_hypothesis else None
            ),
            "observed_behavior": (
                self.primary_hypothesis.narrative if self.primary_hypothesis else []
            ),
            # Legacy alias; this is an observation sequence, not a causal chain.
            "attack_chain": (
                self.primary_hypothesis.narrative if self.primary_hypothesis else []
            ),
            "supporting_evidence": self.supporting_evidence,
            "summary": self.summary_lines,
            "limitations": self.limitations,
            "recommended_steps": [r.as_dict() for r in self.recommendations],
        }


# Severity contributes to suspect ranking on top of confidence, so a single
# HIGH finding outranks several LOW ones.
_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 5.0,
    Severity.HIGH: 4.0,
    Severity.MEDIUM: 2.5,
    Severity.LOW: 1.0,
    Severity.INFO: 0.3,
}


def rank_suspects(findings: list[Finding]) -> list[SuspectScore]:
    """Rank hosts by the weight of evidence pointing at them."""
    by_host: dict[str, SuspectScore] = {}
    for finding in findings:
        if not finding.source:
            continue
        entry = by_host.get(finding.source)
        if entry is None:
            entry = SuspectScore(
                ip=finding.source,
                weight=0.0,
                finding_count=0,
                max_severity=Severity.INFO,
                max_confidence=0.0,
            )
            by_host[finding.source] = entry
        entry.weight += _SEVERITY_WEIGHT.get(finding.severity, 1.0) * finding.confidence
        entry.finding_count += 1
        entry.max_severity = max(entry.max_severity, finding.severity)
        entry.max_confidence = max(entry.max_confidence, finding.confidence)
        entry.finding_ids.append(finding.id)
        if finding.tactic and finding.tactic not in entry.tactics:
            entry.tactics.append(finding.tactic)

    return sorted(by_host.values(), key=lambda s: (-s.weight, s.ip))


def _hedge(confidence: float) -> str:
    """Probabilistic language, never assertion."""
    if confidence >= 0.85:
        return "High confidence"
    if confidence >= 0.65:
        return "Likely"
    if confidence >= 0.4:
        return "Possible"
    return "Weak / inconclusive"


#: Standing limitations of packet-only analysis.  Stated in every report so
#: a conclusion is never read as more than the data can support.
_BASE_LIMITATIONS = [
    "Network evidence alone cannot establish malware execution, compromise, or "
    "attacker intent with certainty.",
    "Encrypted payloads were not decrypted, so the content of TLS sessions is "
    "unknown.",
    "Conclusions apply only to traffic visible at this capture point and within "
    "the captured time window.",
]


def _behaviour_phrases(findings: list[Finding]) -> list[str]:
    """Neutral, observation-level phrases for the conclusion paragraph."""
    present = {f.type for f in findings}
    phrases: list[str] = []
    if present & {"port_scan_vertical", "port_scan_horizontal", "host_discovery"}:
        phrases.append("network scanning and host discovery")
    if present & {"beaconing", "http_beaconing"}:
        phrases.append("periodic automated external communication")
    if present & {"dns_anomaly", "dns_tunneling"}:
        phrases.append("anomalous DNS query patterns")
    if present & {"rare_destination", "unusual_port"}:
        phrases.append("communication with uncommon external destinations")
    if "http_anomaly" in present:
        phrases.append("anomalous HTTP client characteristics")
    if present & {
        "outbound_data_transfer", "potential_exfiltration_indicator",
        "data_exfiltration",
    }:
        phrases.append("potentially significant outbound data transfers")
    elif "large_transfer" in present:
        # Direction was not upload-dominant: say so rather than implying it.
        phrases.append("large data transfers of undetermined direction")
    if "lateral_movement" in present:
        phrases.append("internal host-to-host administrative activity")
    if "traffic_burst" in present:
        phrases.append("abnormal traffic volume bursts")
    return phrases


def _build_conclusion(
    primary_suspect: str | None,
    findings: list[Finding],
    hypothesis: Hypothesis | None,
    confidence: float,
) -> str:
    """Generate the forensic conclusion paragraph from real findings."""
    if not findings:
        return (
            "No behaviour in this capture crossed the configured detection "
            "thresholds. This is not evidence that the traffic is benign: the "
            "capture may be too short, may not include the relevant hosts, or the "
            "activity may be indistinguishable from normal use at this vantage "
            "point."
        )

    host = primary_suspect or "The observed traffic"
    phrases = _behaviour_phrases(findings)
    parts: list[str] = []

    if primary_suspect:
        parts.append(f"{host} exhibits anomalous network behaviour.")
    else:
        parts.append("Anomalous network behaviour was observed in this capture.")

    if phrases:
        parts.append("Observed indicators include " + "; ".join(phrases) + ".")

    present = {f.type for f in findings}
    if hypothesis is not None and len(hypothesis.phases) >= 2:
        parts.append(
            f"The combination of these indicators is consistent with a potentially "
            f"compromised host and warrants further investigation "
            f"({round(confidence * 100)}% confidence in this reading)."
        )
    else:
        parts.append(
            "The indicators do not currently converge into a single correlated "
            "pattern, so they stand as individual anomalies rather than a unified "
            "assessment."
        )

    if present & {"beaconing", "http_beaconing"}:
        parts.append(
            "Possible automated command-and-control communication is supported by "
            "the observed periodic behaviour, though periodicity is also produced "
            "by legitimate automated software."
        )

    if present & {"potential_exfiltration_indicator", "outbound_data_transfer",
                  "large_transfer", "data_exfiltration"}:
        parts.append(
            "Potential outbound data transfer was observed, but the available "
            "network evidence does not independently establish data exfiltration; "
            "payload content could not be determined."
        )

    if present & {"dns_tunneling", "dns_anomaly"}:
        parts.append(
            "DNS query patterns were anomalous; this is consistent with several "
            "explanations, of which tunneling is only one and is not confirmed by "
            "these indicators alone."
        )

    parts.append(
        "Network evidence alone cannot establish malware execution, compromise, or "
        "attacker intent with certainty."
    )
    return " ".join(parts)


def build_investigation(
    inventory: NetworkInventory,
    findings: list[Finding],
    hypotheses: list[Hypothesis],
    risk: RiskScore,
    host_profiles: list[HostRiskProfile] | None = None,
) -> Investigation:
    suspects = rank_suspects(findings)
    primary_suspect = suspects[0].ip if suspects else None

    # Prefer a hypothesis about the primary suspect; otherwise the strongest.
    primary_hypothesis: Hypothesis | None = None
    if hypotheses:
        for hypothesis in hypotheses:
            if hypothesis.subject == primary_suspect:
                primary_hypothesis = hypothesis
                break
        if primary_hypothesis is None:
            primary_hypothesis = hypotheses[0]

    # --- confidence in the overall conclusion --------------------------
    if primary_hypothesis is not None:
        confidence = primary_hypothesis.confidence
    elif findings:
        confidence = max(f.confidence for f in findings)
    else:
        confidence = 0.0

    # --- supporting evidence, always traceable to a finding ------------
    relevant = [
        f for f in findings
        if primary_suspect is None or f.source == primary_suspect
    ] or findings
    supporting_evidence = [
        {
            "finding_id": f.id,
            "finding": f.title,
            "tactic": f.tactic,
            "confidence": round(f.confidence, 3),
            "severity": f.severity.label,
            "reasoning": f.explanation,
            "evidence": [e.summary for e in f.evidence],
        }
        for f in relevant[:10]
    ]

    # --- executive summary ---------------------------------------------
    lines: list[str] = []
    if not findings:
        verdict = "No suspicious behaviour detected"
        lines.append(
            "No behaviour in this capture crossed the configured detection "
            "thresholds. That is not proof the traffic is benign: the capture may "
            "be too short, may not include the relevant hosts, or the activity may "
            "be indistinguishable from normal use at this vantage point."
        )
    else:
        hedge = _hedge(confidence)
        if primary_hypothesis is not None:
            verdict = f"{hedge}: {primary_hypothesis.title.lower()}"
            lines.append(
                f"Priority host: {primary_suspect} "
                f"({suspects[0].finding_count} findings, "
                f"tactics: {', '.join(suspects[0].tactics) or 'n/a'})."
            )
            lines.append(
                f"Assessment: {primary_hypothesis.title} "
                f"(risk {primary_hypothesis.severity.label}, confidence "
                f"{primary_hypothesis.confidence_level.label} / "
                f"{round(primary_hypothesis.confidence * 100)}%)."
            )
            lines.append(
                "Observed behaviour categories: "
                + ", ".join(primary_hypothesis.narrative) + "."
            )
            lines.append(primary_hypothesis.explanation)
        else:
            top = max(findings, key=lambda f: (f.severity, f.confidence))
            verdict = f"{hedge}: isolated anomalous activity ({top.type})"
            lines.append(
                f"Priority host: {primary_suspect} "
                f"({suspects[0].finding_count} finding(s))."
            )
            lines.append(
                "The findings did not correlate into a single pattern, so they "
                "stand individually rather than as a unified assessment."
            )
        lines.append(
            f"Risk {risk.value}/100 ({risk.band}), assessment confidence "
            f"{risk.confidence_level.label}. {risk.interpretation}"
        )

    internal = len([h for h in inventory.hosts.values() if h.kind is HostKind.INTERNAL])
    external = len([h for h in inventory.hosts.values() if h.kind is HostKind.EXTERNAL])

    limitations = list(_BASE_LIMITATIONS)
    limitations.insert(
        0,
        f"Scope: {internal} internal and {external} external hosts were observed at "
        f"this capture point.",
    )
    # Surface detector-specific caveats, de-duplicated.
    for finding in findings:
        if finding.limitations and finding.limitations not in limitations:
            limitations.append(finding.limitations)

    conclusion = _build_conclusion(
        primary_suspect, findings, primary_hypothesis, confidence
    )

    return Investigation(
        risk=risk,
        suspects=suspects[:10],
        primary_hypothesis=primary_hypothesis,
        supporting_evidence=supporting_evidence,
        summary_lines=lines,
        confidence=confidence,
        verdict=verdict,
        host_profiles=list(host_profiles or []),
        recommendations=build_recommendations(findings, primary_suspect),
        limitations=limitations,
        conclusion=conclusion,
    )


def render_host_profiles_text(
    profiles: list[HostRiskProfile], *, limit: int = 3
) -> str:
    """Consolidated per-host view - far more useful than N loose findings."""
    if not profiles:
        return ""
    lines = ["", "Host risk profiles:"]
    for profile in profiles[:limit]:
        lines.append("")
        lines.append(f"  {profile.ip}")
        lines.append(
            f"    Risk: {profile.risk.label}    "
            f"Confidence: {profile.confidence_level.label} "
            f"({round(profile.confidence * 100)}%)"
        )
        lines.append(f"    Indicators ({profile.finding_count} findings):")
        for group in profile.groups:
            destinations = group.destinations
            suffix = ""
            if destinations:
                shown = ", ".join(destinations[:3])
                if len(destinations) > 3:
                    shown += f", +{len(destinations) - 3} more"
                suffix = f" -> {shown}"
            lines.append(
                f"      [+] {group.label} ({len(group.findings)}){suffix}"
            )
    return "\n".join(lines)


def render_investigation_text(investigation: Investigation) -> str:
    """Executive summary block for the terminal."""
    lines = ["", "=" * 40, "INVESTIGATION SUMMARY".center(40).rstrip(), "=" * 40, ""]
    lines.append(f"Verdict:    {investigation.verdict}")
    lines.append(
        f"Risk:       {investigation.risk.band} ({investigation.risk.value}/100)"
    )
    lines.append(
        f"Confidence: {investigation.confidence_level.label} "
        f"({round(investigation.confidence * 100)}%)"
    )
    if investigation.primary_suspect:
        lines.append(f"Priority host: {investigation.primary_suspect}")
    lines.append("")
    for line in investigation.summary_lines:
        lines.append(f"  {line}")

    if investigation.primary_hypothesis:
        lines.append("")
        lines.append("Observed behaviour (categories, not a causal chain):")
        for phase in investigation.primary_hypothesis.narrative:
            lines.append(f"    |-- {phase}")

    if investigation.supporting_evidence:
        lines.append("")
        lines.append("Supporting evidence:")
        for item in investigation.supporting_evidence[:6]:
            lines.append(
                f"  - {item['finding']} "
                f"(risk {item['severity']}, confidence "
                f"{round(float(item['confidence']) * 100)}%)"
            )
            for evidence in list(item["evidence"])[:2]:
                lines.append(f"      * {evidence}")

    lines.append("")
    lines.append("Conclusion:")
    for chunk in _wrap(investigation.conclusion, 72):
        lines.append(f"  {chunk}")

    if investigation.limitations:
        lines.append("")
        lines.append("Limitations:")
        for limitation in investigation.limitations[:4]:
            for index, chunk in enumerate(_wrap(limitation, 70)):
                lines.append(f"  {'- ' if index == 0 else '  '}{chunk}")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    """Minimal greedy wrapper (avoids a textwrap import for one call site)."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines
