"""The vocabulary of the investigation: Evidence, Finding, Severity.

These types are the contract between every stage from V3 onward.  A
detector never returns a bare boolean or a bare alert string; it returns a
:class:`Finding` that carries *why* it fired - a list of :class:`Evidence`
items with the concrete numbers - plus a plain-language explanation and a
calibrated confidence.  Correlation (V4), threat mapping (V5), the timeline
(V6) and scoring (V7) all consume the same objects.
"""

from __future__ import annotations

import enum
import itertools
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Ordered so findings can be sorted/compared directly."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def from_confidence(cls, confidence: float, ceiling: "Severity") -> "Severity":
        """Map a confidence to a severity, never exceeding a per-detector
        ceiling (a rare-destination hit is LOW even at high confidence)."""
        if confidence >= 0.85:
            level = cls.HIGH
        elif confidence >= 0.6:
            level = cls.MEDIUM
        elif confidence >= 0.35:
            level = cls.LOW
        else:
            level = cls.INFO
        return cls(min(level, ceiling))


@dataclass(frozen=True, slots=True)
class Evidence:
    """One concrete, human-readable reason, with the numbers behind it.

    ``summary`` is the sentence shown to an analyst; ``data`` holds the raw
    values for the JSON report and for later programmatic use.
    """

    summary: str
    data: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {"summary": self.summary}
        if self.data:
            out["data"] = self.data
        return out


_id_counter = itertools.count(1)


@dataclass(slots=True)
class Finding:
    """A single suspicious observation.

    Confidence is a probability-like number in [0, 1]; language stays
    hedged ("possible", "likely") in titles/explanations, honouring the
    rule that a pcap rarely *proves* an attack.
    """

    type: str
    title: str
    severity: Severity
    confidence: float
    explanation: str
    source: str | None = None
    destination: str | None = None
    timestamp: float | None = None
    start_time: float | None = None
    end_time: float | None = None
    evidence: list[Evidence] = field(default_factory=list)
    tactic: str | None = None            # filled by V5 threat mapping
    metadata: dict[str, object] = field(default_factory=dict)
    id: str = field(default_factory=lambda: f"F{next(_id_counter):04d}")

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def add(self, summary: str, **data: object) -> "Finding":
        """Fluent helper to attach one piece of evidence."""
        self.evidence.append(Evidence(summary, dict(data)))
        return self

    @property
    def confidence_pct(self) -> int:
        return round(self.confidence * 100)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "severity": self.severity.label,
            "confidence": round(self.confidence, 3),
            "explanation": self.explanation,
            "source": self.source,
            "destination": self.destination,
            "timestamp": self.timestamp,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "tactic": self.tactic,
            "evidence": [e.as_dict() for e in self.evidence],
            "metadata": self.metadata,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most important first: severity desc, then confidence desc, then time."""
    return sorted(
        findings,
        key=lambda f: (-f.severity, -f.confidence, f.start_time or f.timestamp or 0.0),
    )
