"""Beaconing detection: regular, automated communication over time.

Periodicity is a *behaviour*, not a verdict - NTP, DNS refreshes, software
update checks and monitoring agents all beacon.  So this detector measures
regularity precisely and then contextualises it, lowering confidence for
destinations that look service-like, and never claims "C2" on its own (that
mapping is V5's job, and only after correlation).

Regularity is measured two ways so one huge gap cannot mask an otherwise
metronomic beacon:

* coefficient of variation (stdev/mean) of inter-arrival intervals;
* MAD-based regularity (median absolute deviation / median).
"""

from __future__ import annotations

from array import array
from dataclasses import dataclass, field

from investigator.config import COMMON_SERVICE_PORTS, PERIODIC_INFRA_PORTS
from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind, classify_ip
from investigator.models import NetworkEvent, Protocol
from investigator.stats import (
    coefficient_of_variation,
    mean,
    median,
    median_absolute_deviation,
    stdev,
)

MAX_SERIES = 300_000
MAX_TS_PER_SERIES = 100_000

# key: (src_ip, dst_ip, dst_port, protocol)
SeriesKey = tuple[str, str, int, str]


class ContactSeriesTracker:
    """Stream collector recording *contact* timestamps per client->service.

    A "contact" is a request-side event:

    * TCP: a pure SYN (one per connection attempt - the natural beacon unit);
    * UDP: each datagram to the destination port.

    This yields a clean timestamp series per (client, dst, dst_port) whose
    inter-arrival regularity the detector then analyses.
    """

    def __init__(
        self, max_series: int = MAX_SERIES, max_ts: int = MAX_TS_PER_SERIES
    ) -> None:
        self.series: dict[SeriesKey, array] = {}
        self.max_series = max_series
        self.max_ts = max_ts
        self.dropped_series = 0

    def _append(self, key: SeriesKey, timestamp: float) -> None:
        arr = self.series.get(key)
        if arr is None:
            if len(self.series) >= self.max_series:
                self.dropped_series += 1
                return
            arr = array("d")
            self.series[key] = arr
        if len(arr) < self.max_ts:
            arr.append(timestamp)

    def observe(self, event: NetworkEvent) -> None:
        if event.src_ip is None or event.dst_ip is None or event.dst_port is None:
            return
        if event.protocol is Protocol.TCP:
            if event.tcp_flags is not None and event.is_tcp_syn_only:
                self._append(
                    (event.src_ip, event.dst_ip, event.dst_port, "TCP"),
                    event.timestamp,
                )
        elif event.protocol is Protocol.UDP:
            self._append(
                (event.src_ip, event.dst_ip, event.dst_port, "UDP"),
                event.timestamp,
            )


@dataclass(slots=True)
class BeaconStats:
    key: SeriesKey
    count: int
    mean_interval: float
    stdev_interval: float
    cv: float
    mad_ratio: float
    duration: float
    regularity: float  # 0..1, higher = more regular


def analyse_series(timestamps: array, min_interval: float) -> BeaconStats | None:
    """Compute regularity statistics for one contact series."""
    if len(timestamps) < 3:
        return None
    ordered = sorted(timestamps)
    intervals = [
        b - a for a, b in zip(ordered, ordered[1:]) if (b - a) >= min_interval
    ]
    if len(intervals) < 2:
        return None
    mu = mean(intervals)
    if mu <= 0:
        return None
    sd = stdev(intervals)
    cv = coefficient_of_variation(intervals)
    med = median(intervals)
    mad = median_absolute_deviation(intervals)
    mad_ratio = (mad / med) if med > 0 else float("inf")
    # Regularity: 1 when intervals are identical, decaying with dispersion.
    # Use the gentler of the two dispersion measures.
    dispersion = min(cv, mad_ratio)
    regularity = max(0.0, 1.0 - dispersion)
    return BeaconStats(
        key=("", "", 0, ""),  # filled by caller
        count=len(ordered),
        mean_interval=mu,
        stdev_interval=sd,
        cv=cv,
        mad_ratio=mad_ratio,
        duration=ordered[-1] - ordered[0],
        regularity=regularity,
    )


class BeaconingDetector(Detector):
    name = "beaconing"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        contacts: ContactSeriesTracker | None = ctx.contacts
        if contacts is None:
            return []
        cfg = ctx.config
        findings: list[Finding] = []

        for (src, dst, dport, proto), timestamps in contacts.series.items():
            if len(timestamps) < cfg.beacon_min_events:
                continue
            stats = analyse_series(timestamps, cfg.beacon_min_interval)
            if stats is None:
                continue
            if stats.cv > cfg.beacon_jitter_cv:
                continue  # too irregular to call a beacon

            finding = self._build_finding(ctx, src, dst, dport, proto, stats)
            if finding is not None:
                findings.append(finding)
        return findings

    def _build_finding(
        self,
        ctx: DetectionContext,
        src: str,
        dst: str,
        dport: int,
        proto: str,
        stats: "BeaconStats",
    ) -> Finding | None:
        cfg = ctx.config
        dst_kind = classify_ip(dst)

        # Base confidence from regularity, then adjust for context.
        if stats.cv <= cfg.beacon_regular_cv:
            confidence = 0.6 + 0.3 * stats.regularity
        else:  # jittered band
            confidence = 0.4 + 0.2 * stats.regularity

        # More samples and longer persistence => more trustworthy.
        if stats.count >= 20:
            confidence += 0.05
        if stats.duration >= cfg.beacon_strong_duration:
            confidence += 0.05

        # --- false-positive context ------------------------------------
        fp_notes: list[str] = []
        if dport in PERIODIC_INFRA_PORTS:
            confidence -= cfg.beacon_infra_port_penalty
            fp_notes.append(
                f"destination port {dport} is an inherently periodic protocol "
                f"(time sync / name resolution / DHCP) - usually benign"
            )
        elif dport in COMMON_SERVICE_PORTS:
            confidence -= cfg.beacon_common_port_penalty
            fp_notes.append(
                f"destination port {dport} is a common service port"
            )
        if dst_kind is not HostKind.EXTERNAL:
            confidence -= 0.1
            fp_notes.append(f"destination is {dst_kind.value}, not external")

        resolved_names = ctx.dns.names_for_ip(dst)
        if resolved_names:
            confidence -= 0.05
            fp_notes.append(
                "destination was resolved via DNS as "
                + ", ".join(sorted(resolved_names)[:3])
            )
        else:
            confidence += 0.05  # contacting a raw IP nobody resolved is odder

        confidence = max(0.05, min(0.97, confidence))
        # External + regular + unresolved is the case we most want to surface.
        severity_ceiling = (
            Severity.HIGH if dst_kind is HostKind.EXTERNAL else Severity.MEDIUM
        )
        severity = Severity.from_confidence(confidence, severity_ceiling)
        if severity < Severity.LOW:
            return None

        label = "likely" if confidence >= 0.7 else "possible"
        title = f"{label.capitalize()} periodic beaconing to {dst}:{dport}"
        explanation = (
            f"Host {src} contacted {dst}:{dport}/{proto} {stats.count} times at a "
            f"near-constant interval of ~{stats.mean_interval:.1f}s. Regular, "
            f"automated timing like this is characteristic of scheduled check-ins "
            f"(including benign agents); it is reported as {label} beaconing, not "
            f"a confirmed threat."
        )
        if fp_notes:
            explanation += " Mitigating context: " + "; ".join(fp_notes) + "."

        finding = Finding(
            type="beaconing",
            title=title,
            severity=severity,
            confidence=confidence,
            explanation=explanation,
            source=src,
            destination=dst,
            timestamp=None,
            metadata={
                "dst_port": dport,
                "protocol": proto,
                "mean_interval": round(stats.mean_interval, 3),
                "resolved_names": sorted(resolved_names),
            },
        )
        finding.add(
            f"{stats.count} contacts over {stats.duration:.0f}s",
            count=stats.count,
            duration_seconds=round(stats.duration, 1),
        )
        finding.add(
            f"mean interval {stats.mean_interval:.1f}s, stdev {stats.stdev_interval:.2f}s "
            f"(coefficient of variation {stats.cv:.3f})",
            mean_interval=round(stats.mean_interval, 3),
            stdev_interval=round(stats.stdev_interval, 3),
            cv=round(stats.cv, 4),
            mad_ratio=round(stats.mad_ratio, 4),
        )
        conv = ctx.inventory.conversations.get((src, dst))
        if conv is not None:
            finding.start_time = conv.first_seen
            finding.end_time = conv.last_seen
            finding.timestamp = conv.first_seen

        internal_contacts = sum(
            1
            for host in ctx.inventory.hosts.values()
            if host.kind is HostKind.INTERNAL and dst in host.peers
        )
        if internal_contacts == 1:
            finding.add(f"only internal host {src} contacted this destination")
        else:
            finding.add(
                f"destination contacted by {internal_contacts} internal hosts"
            )
        return finding
