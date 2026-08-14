"""Timeline reconstruction (V6).

Merges four kinds of records into one chronological narrative:

* **observations** - notable facts straight from the capture (a host's first
  appearance, a new external destination, the first contact on a port);
* **findings**     - what the detectors concluded, at the moment it started;
* **correlations** - the temporal links the correlator established;
* **hypotheses**   - the overall story, anchored at its first phase.

Each entry keeps its ``kind`` so a report can style them differently, and
its ``source``/``destination`` so the timeline can be filtered per host.
Observations are capped and ranked by significance: a timeline nobody can
read is not a timeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from investigator.correlation import Hypothesis
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind, NetworkInventory


def format_time(epoch: float | None, *, with_date: bool = False) -> str:
    if epoch is None:
        return "--:--:--"
    stamp = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return stamp.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


@dataclass(slots=True)
class TimelineEntry:
    timestamp: float
    kind: str                     # observation | finding | correlation | hypothesis
    title: str
    detail: str = ""
    source: str | None = None
    destination: str | None = None
    severity: Severity | None = None
    confidence: float | None = None
    finding_id: str | None = None
    end_time: float | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "time": format_time(self.timestamp),
            "datetime": datetime.fromtimestamp(
                self.timestamp, tz=timezone.utc
            ).isoformat(timespec="seconds"),
            "kind": self.kind,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "destination": self.destination,
            "severity": self.severity.label if self.severity is not None else None,
            "confidence": round(self.confidence, 3) if self.confidence is not None else None,
            "finding_id": self.finding_id,
            "end_time": self.end_time,
        }


@dataclass(slots=True)
class Timeline:
    entries: list[TimelineEntry] = field(default_factory=list)

    def add(self, entry: TimelineEntry) -> None:
        self.entries.append(entry)

    def sorted_entries(self) -> list[TimelineEntry]:
        # Ties broken by kind so a finding follows the observation that
        # explains it, rather than appearing above it.
        order = {"observation": 0, "finding": 1, "correlation": 2, "hypothesis": 3}
        return sorted(
            self.entries, key=lambda e: (e.timestamp, order.get(e.kind, 9))
        )

    def for_host(self, ip: str) -> list[TimelineEntry]:
        return [
            e for e in self.sorted_entries()
            if e.source == ip or e.destination == ip
        ]

    def as_dict(self) -> dict[str, object]:
        entries = self.sorted_entries()
        return {
            "entry_count": len(entries),
            "start": entries[0].timestamp if entries else None,
            "end": entries[-1].timestamp if entries else None,
            "entries": [e.as_dict() for e in entries],
        }


def _observation_entries(
    inventory: NetworkInventory, subjects: set[str], limit: int
) -> list[TimelineEntry]:
    """Notable raw observations, ranked so the timeline stays readable.

    Priority goes to hosts involved in findings (the ``subjects``), then to
    first contacts with external destinations, then to volume.
    """
    candidates: list[tuple[float, TimelineEntry]] = []

    for (src, dst), conv in inventory.conversations.items():
        if conv.first_seen is None:
            continue
        src_host = inventory.hosts.get(src)
        dst_host = inventory.hosts.get(dst)
        if src_host is None or dst_host is None:
            continue
        if src_host.kind is not HostKind.INTERNAL:
            continue

        external = dst_host.kind is HostKind.EXTERNAL
        ports = ",".join(str(p) for p, _ in conv.dst_ports.most_common(3))
        protos = ",".join(p for p, _ in conv.protocols.most_common(2))
        label = f"{protos}:{ports}" if ports else protos

        if external:
            title = f"First contact with external host {dst}"
            weight = 3.0
        else:
            title = f"First contact with internal host {dst}"
            weight = 1.0
        if src in subjects:
            weight += 5.0
        weight += min(2.0, conv.bytes / 1_000_000)

        candidates.append((
            weight,
            TimelineEntry(
                timestamp=conv.first_seen,
                kind="observation",
                title=title,
                detail=f"{label}, {conv.packets} packets, {conv.bytes} bytes",
                source=src,
                destination=dst,
                end_time=conv.last_seen,
            ),
        ))

    candidates.sort(key=lambda item: -item[0])
    return [entry for _weight, entry in candidates[:limit]]


def build_timeline(
    inventory: NetworkInventory,
    findings: list[Finding],
    hypotheses: list[Hypothesis],
    *,
    max_observations: int = 40,
) -> Timeline:
    timeline = Timeline()
    subjects = {f.source for f in findings if f.source} | {
        h.subject for h in hypotheses
    }

    for entry in _observation_entries(inventory, subjects, max_observations):
        timeline.add(entry)

    for finding in findings:
        stamp = finding.start_time if finding.start_time is not None else finding.timestamp
        if stamp is None:
            continue
        timeline.add(
            TimelineEntry(
                timestamp=stamp,
                kind="finding",
                title=finding.title,
                detail=(
                    finding.evidence[0].summary if finding.evidence else finding.explanation
                ),
                source=finding.source,
                destination=finding.destination,
                severity=finding.severity,
                confidence=finding.confidence,
                finding_id=finding.id,
                end_time=finding.end_time,
            )
        )

    findings_by_id = {f.id: f for f in findings}
    for hypothesis in hypotheses:
        if hypothesis.start_time is not None:
            timeline.add(
                TimelineEntry(
                    timestamp=hypothesis.start_time,
                    kind="hypothesis",
                    title=hypothesis.title,
                    detail=" -> ".join(hypothesis.narrative),
                    source=hypothesis.subject,
                    severity=hypothesis.severity,
                    confidence=hypothesis.confidence,
                    end_time=hypothesis.end_time,
                )
            )
        # Anchor each correlation sentence at the finding that starts it.
        for sentence in hypothesis.correlations:
            anchor = min(
                (
                    findings_by_id[fid].start_time or findings_by_id[fid].timestamp
                    for fid in hypothesis.finding_ids
                    if fid in findings_by_id
                    and (findings_by_id[fid].start_time or findings_by_id[fid].timestamp)
                    is not None
                ),
                default=hypothesis.start_time,
            )
            if anchor is None:
                continue
            timeline.add(
                TimelineEntry(
                    timestamp=anchor,
                    kind="correlation",
                    title="Temporal correlation",
                    detail=sentence,
                    source=hypothesis.subject,
                    confidence=hypothesis.confidence,
                )
            )
    return timeline


def render_timeline_text(timeline: Timeline, *, limit: int = 25) -> str:
    """Compact terminal rendering of the reconstructed timeline."""
    entries = timeline.sorted_entries()
    if not entries:
        return ""
    marker = {
        "observation": ".",
        "finding": "!",
        "correlation": "+",
        "hypothesis": "*",
    }
    lines = ["", f"Timeline ({len(entries)} entries, first {min(limit, len(entries))}):"]
    for entry in entries[:limit]:
        flow = ""
        if entry.source and entry.destination:
            flow = f"{entry.source} -> {entry.destination}"
        elif entry.source:
            flow = entry.source
        lines.append(
            f"  {format_time(entry.timestamp)} [{marker.get(entry.kind, '?')}] "
            f"{entry.title}"
        )
        if flow:
            lines.append(f"           {flow}")
    if len(entries) > limit:
        lines.append(f"  ... {len(entries) - limit} more (see timeline.json)")
    return "\n".join(lines)
