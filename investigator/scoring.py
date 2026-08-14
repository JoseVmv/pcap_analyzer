"""Explainable risk scoring.

The score is never a black box: every contribution is recorded as a
:class:`ScoreComponent` saying which finding contributed, what the
configured weight was, how confidence scaled it, and what the running total
became.  The report can therefore print the arithmetic that produced the
number, and an operator can retune ``Config.weights`` without touching code.

What the number is - and is not
-------------------------------
The score is a **heuristic risk indicator**, not a probability.  92/100 does
not mean "92% chance of compromise"; it means the weighted, de-duplicated
indicators accumulated 92 points on a scale whose top is reached by any
sufficiently severe combination.  Both numbers are therefore reported:

* ``raw_score``        - the unbounded accumulation, so a run that vastly
  exceeds the ceiling is visibly different from one that just reaches it;
* ``normalized_score`` - the 0-100 presentation value.

Double counting is the main threat to a score's meaning, so contributions
decay within a **behaviour group** rather than per finding type.  Three
"periodic communication" findings from one host to three destinations are
three pieces of evidence for *one* underlying activity, and are scored as
such: full weight for the strongest, then 1/2, 1/3, and so on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from investigator.config import Config
from investigator.correlation import Hypothesis
from investigator.findings import Confidence, Finding


@dataclass(slots=True)
class ScoreComponent:
    """One line of the score's arithmetic."""

    label: str
    detail: str
    weight: float
    multiplier: float
    points: float
    running_total: float
    finding_id: str | None = None
    group: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "detail": self.detail,
            "weight": round(self.weight, 2),
            "multiplier": round(self.multiplier, 3),
            "points": round(self.points, 2),
            "running_total": round(self.running_total, 2),
            "finding_id": self.finding_id,
            "group": self.group,
        }


@dataclass(slots=True)
class RiskScore:
    """Risk and confidence as separate, explicitly reported axes."""

    raw_score: float
    normalized_score: float
    capped: bool
    confidence: float = 0.0
    components: list[ScoreComponent] = field(default_factory=list)
    groups_counted: int = 0
    findings_counted: int = 0

    # ``total`` kept as an alias so pre-existing callers keep working.
    @property
    def total(self) -> float:
        return self.normalized_score

    @property
    def value(self) -> int:
        return int(round(self.normalized_score))

    @property
    def raw_value(self) -> float:
        return round(self.raw_score, 2)

    @property
    def band(self) -> str:
        """Severity band of the risk axis (not a probability)."""
        if self.normalized_score >= 85:
            return "CRITICAL"
        if self.normalized_score >= 60:
            return "HIGH"
        if self.normalized_score >= 35:
            return "MEDIUM"
        if self.normalized_score > 0:
            return "LOW"
        return "MINIMAL"

    @property
    def confidence_level(self) -> Confidence:
        return Confidence.from_score(self.confidence)

    @property
    def interpretation(self) -> str:
        """One sentence stating what the number does and does not mean."""
        band_text = {
            "CRITICAL": "Multiple severe correlated network behaviours detected.",
            "HIGH": "High-risk correlated network behaviour detected.",
            "MEDIUM": "Moderate anomalous network behaviour detected.",
            "LOW": "Minor anomalies detected.",
            "MINIMAL": "No behaviour crossed the configured detection thresholds.",
        }[self.band]
        return (
            f"{band_text} Score represents heuristic risk, not probability of "
            f"compromise."
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "raw_score": self.raw_value,
            "normalized_score": self.value,
            "score": self.value,          # backwards-compatible alias
            "max": 100,
            "severity": self.band,
            "band": self.band,            # backwards-compatible alias
            "confidence": round(self.confidence, 3),
            "confidence_level": self.confidence_level.label,
            "capped": self.capped,
            "is_probability": False,
            "interpretation": self.interpretation,
            "groups_counted": self.groups_counted,
            "findings_counted": self.findings_counted,
            "components": [c.as_dict() for c in self.components],
        }


def _score_confidence(findings: list[Finding], hypotheses: list[Hypothesis]) -> float:
    """Overall confidence in the assessment - independent of the risk score.

    Driven by the best-supported conclusion available: a correlated
    hypothesis if one exists, otherwise the strongest single finding,
    tempered by how much corroborating evidence there is overall.
    """
    if not findings:
        return 0.0
    if hypotheses:
        base = max(h.confidence for h in hypotheses)
    else:
        base = max(f.confidence for f in findings)
        # Isolated findings are inherently less well supported than a
        # correlated chain, so an uncorroborated conclusion is capped.
        base = min(base, 0.75)
    distinct_groups = len({f.group_key for f in findings})
    corroboration = min(0.15, 0.05 * (distinct_groups - 1))
    return max(0.0, min(0.98, base + corroboration))


def compute_risk_score(
    findings: list[Finding],
    hypotheses: list[Hypothesis],
    config: Config,
) -> RiskScore:
    """Accumulate a bounded, fully itemised, de-duplicated risk score."""
    raw_total = 0.0
    components: list[ScoreComponent] = []
    seen_per_group: dict[str, int] = {}

    # Strongest findings first, so the decay penalises the *weaker* repeats
    # inside each behaviour group.
    for finding in sorted(findings, key=lambda f: (-f.severity, -f.confidence)):
        weight = config.weight_for(finding.type)
        group = finding.group_key
        occurrence = seen_per_group.get(group, 0) + 1
        seen_per_group[group] = occurrence
        decay = 1.0 / occurrence
        multiplier = finding.confidence * decay
        points = weight * multiplier
        if points <= 0:
            continue
        raw_total += points
        detail = f"confidence {finding.confidence_pct}%"
        if occurrence > 1:
            detail += (
                f", occurrence #{occurrence} of behaviour group "
                f"'{group}' (x{decay:.2f} - same underlying activity)"
            )
        components.append(
            ScoreComponent(
                label=finding.title,
                detail=detail,
                weight=weight,
                multiplier=multiplier,
                points=points,
                running_total=raw_total,
                finding_id=finding.id,
                group=group,
            )
        )

    if hypotheses:
        best = max(hypotheses, key=lambda h: h.confidence)
        bonus = config.correlation_bonus * best.confidence
        if bonus > 0:
            raw_total += bonus
            components.append(
                ScoreComponent(
                    label="Correlated behaviour across multiple categories",
                    detail=(
                        f"{len(best.phases)} behaviour categories linked for "
                        f"{best.subject} at {round(best.confidence * 100)}% confidence"
                    ),
                    weight=config.correlation_bonus,
                    multiplier=best.confidence,
                    points=bonus,
                    running_total=raw_total,
                    group="correlation",
                )
            )

    capped = raw_total > config.score_cap
    normalized = min(raw_total, config.score_cap)
    if capped:
        components.append(
            ScoreComponent(
                label="Score ceiling reached",
                detail=(
                    f"raw total {raw_total:.1f} exceeds the "
                    f"{config.score_cap:.0f}-point presentation ceiling; the ceiling "
                    f"marks 'severe combination of indicators', not certainty"
                ),
                weight=config.score_cap,
                multiplier=1.0,
                points=0.0,
                running_total=normalized,
                group="ceiling",
            )
        )

    return RiskScore(
        raw_score=raw_total,
        normalized_score=normalized,
        capped=capped,
        confidence=_score_confidence(findings, hypotheses),
        components=components,
        groups_counted=len(seen_per_group),
        findings_counted=len(findings),
    )


def render_score_text(score: RiskScore, *, limit: int = 10) -> str:
    """Show the score together with the arithmetic that produced it."""
    lines = [
        "",
        f"Risk Score: {score.value}/100",
        f"Severity:   {score.band}",
        f"Confidence: {score.confidence_level.label} "
        f"({round(score.confidence * 100)}%)",
        "",
        "Score interpretation:",
        f"  {score.interpretation}",
        "",
        "How this score was calculated:",
    ]
    for component in score.components[:limit]:
        if component.points > 0:
            lines.append(
                f"  +{component.points:5.1f}  {component.label}"
                f"  [weight {component.weight:.0f} x {component.multiplier:.2f}"
                f" = {component.detail}]"
            )
        else:
            lines.append(f"   (---)  {component.label}: {component.detail}")
    if len(score.components) > limit:
        lines.append(f"  ... {len(score.components) - limit} more contributions")
    lines.append(
        f"  ------  raw {score.raw_value} -> normalized {score.value}/100"
        + (
            f"  ({score.findings_counted} findings in {score.groups_counted} "
            f"behaviour groups)"
            if score.findings_counted
            else ""
        )
    )
    return "\n".join(lines)
