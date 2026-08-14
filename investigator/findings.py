"""The vocabulary of the investigation: Evidence, Finding, Severity, Confidence.

These types are the contract between every stage from V3 onward.  A
detector never returns a bare boolean or a bare alert string; it returns a
:class:`Finding` that carries *why* it fired - a list of :class:`Evidence`
items with the concrete numbers - plus a plain-language explanation and a
calibrated confidence.

Risk and confidence are deliberately **independent axes**:

* :class:`Severity` (also exposed as ``Finding.risk``) answers *how serious
  would this be if the interpretation is correct?*
* :class:`Confidence` answers *how strongly does the available evidence
  support that interpretation?*

Both directions are legitimate and common in real investigations: a large
outbound transfer is HIGH risk with LOW confidence of being exfiltration
(we cannot see payload content), while a textbook port scan is MEDIUM risk
with HIGH confidence (the behaviour is unmistakable but rarely the incident
itself).  Collapsing the two into one number - which earlier versions did -
destroys exactly the nuance an analyst needs.
"""

from __future__ import annotations

import enum
import itertools
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Potential seriousness of the behaviour *if* the reading is correct.

    Ordered so findings can be sorted/compared directly.
    """

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
        """Deprecated: derives risk from confidence, conflating the two axes.

        Kept so older detectors and third-party code keep working.  New code
        should state risk explicitly and pass confidence separately.
        """
        if confidence >= 0.85:
            level = cls.HIGH
        elif confidence >= 0.6:
            level = cls.MEDIUM
        elif confidence >= 0.35:
            level = cls.LOW
        else:
            level = cls.INFO
        return cls(min(level, ceiling))


class Confidence(enum.IntEnum):
    """Strength of the evidence supporting a finding's interpretation."""

    VERY_LOW = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.replace("_", " ")

    @classmethod
    def from_score(cls, confidence: float) -> "Confidence":
        if confidence >= 0.8:
            return cls.HIGH
        if confidence >= 0.55:
            return cls.MEDIUM
        if confidence >= 0.3:
            return cls.LOW
        return cls.VERY_LOW


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

    ``severity`` is the *risk* axis and ``confidence`` (0..1) the *evidence*
    axis; see the module docstring for why they are kept apart.  Language
    stays hedged ("possible", "likely") in titles and explanations,
    honouring the rule that a pcap rarely *proves* an attack.

    ``interpretation`` says what the behaviour would mean if the reading
    holds; ``limitations`` states plainly what the packet data cannot
    establish.  Both are optional so existing detectors keep working, but
    every detector reworked from V8 onward fills them in.
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
    interpretation: str | None = None
    limitations: str | None = None
    #: findings sharing a group key describe one underlying activity, so
    #: scoring applies diminishing returns across the group (see scoring.py)
    behavior_group: str | None = None
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

    @property
    def confidence_level(self) -> Confidence:
        return Confidence.from_score(self.confidence)

    @property
    def risk(self) -> Severity:
        """Alias making the risk axis explicit at call sites."""
        return self.severity

    @property
    def group_key(self) -> str:
        """Key identifying the underlying activity this finding describes.

        Defaults to ``type`` per source host, so several destinations
        exhibiting the same behaviour from the same host collapse into one
        activity for scoring purposes.
        """
        if self.behavior_group:
            return self.behavior_group
        return f"{self.type}:{self.source or '-'}"

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "severity": self.severity.label,
            "risk": self.severity.label,
            "confidence": round(self.confidence, 3),
            "confidence_level": self.confidence_level.label,
            "explanation": self.explanation,
            "interpretation": self.interpretation,
            "limitations": self.limitations,
            "behavior_group": self.behavior_group,
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
