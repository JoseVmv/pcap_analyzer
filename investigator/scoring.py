"""Explainable risk scoring (V7).

The score is never a black box: every contribution is recorded as a
:class:`ScoreComponent` saying which finding contributed, what the
configured weight was, how confidence scaled it, and what the running total
became.  The report can therefore print the arithmetic that produced the
number, and an operator can retune ``Config.weights`` without touching code.

Design choices worth stating:

* **Confidence-scaled weights.** A 40%-confidence beacon must not add the
  same points as a 95%-confidence one, so each contribution is
  ``weight * confidence``.
* **Diminishing returns per finding type.** Twenty rare-destination findings
  are not twenty times more alarming than one, so repeats of the same type
  decay (1, 1/2, 1/3, ...).  Without this, a noisy detector could dominate
  the score.
* **Correlation bonus.** A coherent multi-phase chain is stronger evidence
  than the sum of its parts; the best hypothesis adds a bonus scaled by its
  own confidence.
* **Bounded.** The total is capped (default 100) and the cap is reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from investigator.config import Config
from investigator.correlation import Hypothesis
from investigator.findings import Finding


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

    def as_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "detail": self.detail,
            "weight": round(self.weight, 2),
            "multiplier": round(self.multiplier, 3),
            "points": round(self.points, 2),
            "running_total": round(self.running_total, 2),
            "finding_id": self.finding_id,
        }


@dataclass(slots=True)
class RiskScore:
    total: float
    capped: bool
    components: list[ScoreComponent] = field(default_factory=list)

    @property
    def value(self) -> int:
        return int(round(self.total))

    @property
    def band(self) -> str:
        if self.total >= 75:
            return "CRITICAL"
        if self.total >= 50:
            return "HIGH"
        if self.total >= 25:
            return "MEDIUM"
        if self.total > 0:
            return "LOW"
        return "MINIMAL"

    def as_dict(self) -> dict[str, object]:
        return {
            "score": self.value,
            "max": 100,
            "band": self.band,
            "capped": self.capped,
            "components": [c.as_dict() for c in self.components],
        }


def compute_risk_score(
    findings: list[Finding],
    hypotheses: list[Hypothesis],
    config: Config,
) -> RiskScore:
    """Accumulate a bounded, fully itemised risk score."""
    total = 0.0
    components: list[ScoreComponent] = []
    seen_per_type: dict[str, int] = {}

    # Strongest findings first, so the decay penalises the *weaker* repeats.
    for finding in sorted(findings, key=lambda f: -f.confidence):
        weight = config.weight_for(finding.type)
        occurrence = seen_per_type.get(finding.type, 0) + 1
        seen_per_type[finding.type] = occurrence
        decay = 1.0 / occurrence
        multiplier = finding.confidence * decay
        points = weight * multiplier
        if points <= 0:
            continue
        total += points
        detail = f"confidence {finding.confidence_pct}%"
        if occurrence > 1:
            detail += f", occurrence #{occurrence} of this type (x{decay:.2f})"
        components.append(
            ScoreComponent(
                label=finding.title,
                detail=detail,
                weight=weight,
                multiplier=multiplier,
                points=points,
                running_total=total,
                finding_id=finding.id,
            )
        )

    if hypotheses:
        best = max(hypotheses, key=lambda h: h.confidence)
        bonus = config.correlation_bonus * best.confidence
        if bonus > 0:
            total += bonus
            components.append(
                ScoreComponent(
                    label="Correlated behaviour chain",
                    detail=(
                        f"{len(best.phases)} attack phases linked for {best.subject} "
                        f"at {round(best.confidence * 100)}% confidence"
                    ),
                    weight=config.correlation_bonus,
                    multiplier=best.confidence,
                    points=bonus,
                    running_total=total,
                )
            )

    capped = total > config.score_cap
    if capped:
        total = config.score_cap
        components.append(
            ScoreComponent(
                label="Score cap applied",
                detail=f"raw total exceeded the {config.score_cap:.0f}-point maximum",
                weight=config.score_cap,
                multiplier=1.0,
                points=0.0,
                running_total=total,
            )
        )
    return RiskScore(total=total, capped=capped, components=components)


def render_score_text(score: RiskScore, *, limit: int = 10) -> str:
    """Show the score together with the arithmetic that produced it."""
    lines = [
        "",
        f"Risk Score: {score.value}/100  ({score.band})",
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
            lines.append(f"   (cap)  {component.label}: {component.detail}")
    if len(score.components) > limit:
        lines.append(f"  ... {len(score.components) - limit} more contributions")
    lines.append(f"  ------  total {score.value}/100")
    return "\n".join(lines)
