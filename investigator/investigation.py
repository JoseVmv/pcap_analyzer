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

from investigator.correlation import Hypothesis
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind, NetworkInventory
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

    @property
    def primary_suspect(self) -> str | None:
        return self.suspects[0].ip if self.suspects else None

    def as_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "confidence_pct": round(self.confidence * 100),
            "risk": self.risk.as_dict(),
            "primary_suspect": self.primary_suspect,
            "suspects": [s.as_dict() for s in self.suspects],
            "primary_hypothesis": (
                self.primary_hypothesis.as_dict() if self.primary_hypothesis else None
            ),
            "attack_chain": (
                self.primary_hypothesis.narrative if self.primary_hypothesis else []
            ),
            "supporting_evidence": self.supporting_evidence,
            "summary": self.summary_lines,
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


def build_investigation(
    inventory: NetworkInventory,
    findings: list[Finding],
    hypotheses: list[Hypothesis],
    risk: RiskScore,
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
                f"Most suspicious host: {primary_suspect} "
                f"({suspects[0].finding_count} findings, "
                f"tactics: {', '.join(suspects[0].tactics) or 'n/a'})."
            )
            lines.append(
                f"Primary hypothesis: {primary_hypothesis.title} "
                f"({round(primary_hypothesis.confidence * 100)}% confidence)."
            )
            lines.append(
                "Attack chain: " + " -> ".join(primary_hypothesis.narrative) + "."
            )
            lines.append(primary_hypothesis.explanation)
        else:
            top = max(findings, key=lambda f: (f.severity, f.confidence))
            verdict = f"{hedge}: isolated suspicious activity ({top.type})"
            lines.append(
                f"Most suspicious host: {primary_suspect} "
                f"({suspects[0].finding_count} finding(s))."
            )
            lines.append(
                "No multi-phase chain was established, so the findings stand "
                "individually rather than as a single narrative."
            )
        lines.append(
            f"Risk score: {risk.value}/100 ({risk.band}) - see the score breakdown "
            f"for how it was derived."
        )

    internal = len([h for h in inventory.hosts.values() if h.kind is HostKind.INTERNAL])
    external = len([h for h in inventory.hosts.values() if h.kind is HostKind.EXTERNAL])
    lines.append(
        f"Scope of this capture: {internal} internal and {external} external hosts "
        f"observed. Conclusions apply only to traffic visible at this capture point."
    )

    return Investigation(
        risk=risk,
        suspects=suspects[:10],
        primary_hypothesis=primary_hypothesis,
        supporting_evidence=supporting_evidence,
        summary_lines=lines,
        confidence=confidence,
        verdict=verdict,
    )


def render_investigation_text(investigation: Investigation) -> str:
    """Executive summary block for the terminal."""
    lines = ["", "=" * 40, "INVESTIGATION SUMMARY".center(40).rstrip(), "=" * 40, ""]
    lines.append(f"Verdict:   {investigation.verdict}")
    lines.append(f"Confidence: {round(investigation.confidence * 100)}%")
    if investigation.primary_suspect:
        lines.append(f"Primary suspect: {investigation.primary_suspect}")
    lines.append("")
    for line in investigation.summary_lines:
        lines.append(f"  {line}")

    if investigation.primary_hypothesis:
        lines.append("")
        lines.append("Possible attack chain:")
        for index, phase in enumerate(investigation.primary_hypothesis.narrative):
            if index:
                lines.append("        |")
                lines.append("        v")
            lines.append(f"    {phase}")

    if investigation.supporting_evidence:
        lines.append("")
        lines.append("Supporting evidence:")
        for item in investigation.supporting_evidence[:6]:
            lines.append(
                f"  - {item['finding']} ({round(float(item['confidence']) * 100)}%)"
            )
            for evidence in list(item["evidence"])[:2]:
                lines.append(f"      * {evidence}")
    return "\n".join(lines)
