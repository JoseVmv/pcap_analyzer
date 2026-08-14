"""Event correlation (V4): turning independent findings into a story.

A pile of unrelated alerts is not an investigation.  This stage groups a
host's findings, places each into a kill-chain *phase*, and - when several
phases appear together, ideally in chronological order - forms a
:class:`Hypothesis`: a single narrative with an aggregated confidence and an
explicit chain of the findings that support it.

Crucially, confidence goes *up* when phases corroborate each other in time
(recon before C2 before exfiltration), because a coherent sequence is far
less likely to be coincidence than any one finding alone.  The reasoning is
always shown, never asserted.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from investigator.config import Config
from investigator.findings import Finding, Severity


# No hypothesis ever reaches certainty: a capture shows behaviour, not intent.
CONFIDENCE_CEILING = 0.98


class Phase(enum.IntEnum):
    """Kill-chain phases, ordered as they typically unfold in time."""

    RECON = 1
    EXTERNAL_COMM = 2
    C2 = 3
    COLLECTION = 4
    EXFIL = 5
    LATERAL = 6

    @property
    def label(self) -> str:
        return {
            Phase.RECON: "Reconnaissance",
            Phase.EXTERNAL_COMM: "External Communication",
            Phase.C2: "Command & Control",
            Phase.COLLECTION: "Data Collection",
            Phase.EXFIL: "Possible Data Exfiltration",
            Phase.LATERAL: "Lateral Movement",
        }[self]


# Which phase each finding type belongs to.  New detectors register here.
TYPE_TO_PHASE: dict[str, Phase] = {
    "port_scan_vertical": Phase.RECON,
    "port_scan_horizontal": Phase.RECON,
    "host_discovery": Phase.RECON,
    "rare_destination": Phase.EXTERNAL_COMM,
    "unusual_port": Phase.EXTERNAL_COMM,
    "beaconing": Phase.C2,
    "dns_tunneling": Phase.C2,
    "dns_anomaly": Phase.C2,
    "data_collection": Phase.COLLECTION,
    "traffic_burst": Phase.EXFIL,
    "data_exfiltration": Phase.EXFIL,
    "lateral_movement": Phase.LATERAL,
}


def phase_of(finding: Finding) -> Phase | None:
    return TYPE_TO_PHASE.get(finding.type)


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

    def as_dict(self) -> dict[str, object]:
        return {
            "subject": self.subject,
            "title": self.title,
            "confidence": round(self.confidence, 3),
            "confidence_pct": round(self.confidence * 100),
            "severity": self.severity.label,
            "phases": [p.label for p in self.phases],
            "attack_chain": self.narrative,
            "finding_ids": self.finding_ids,
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

        phase_summary = " -> ".join(narrative)
        explanation = (
            f"Host {subject} exhibits behaviour spanning {len(phases)} attack phases, "
            f"observed in this order: {phase_summary}. This is drawn from "
            f"{len(member_findings)} correlated findings. "
            + (
                "The observed order matches the expected attack progression, which "
                "strengthens the hypothesis beyond any single finding."
                if chronological
                else "The observed order does not follow the textbook attack "
                "progression, so the chain is suggestive rather than conclusive - "
                "activity may overlap, or the capture may start mid-incident."
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
        has = set(ordered_phases)
        if {Phase.C2, Phase.EXFIL} <= has:
            return "Possible compromised host with C2 and data exfiltration"
        if Phase.C2 in has and Phase.RECON in has:
            return "Possible compromised host: reconnaissance and C2 activity"
        if Phase.C2 in has:
            return "Possible command-and-control activity"
        if Phase.EXFIL in has:
            return "Possible data exfiltration following suspicious activity"
        if Phase.LATERAL in has:
            return "Possible lateral movement from a suspicious host"
        return "Correlated suspicious activity"
