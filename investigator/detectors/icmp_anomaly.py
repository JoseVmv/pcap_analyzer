"""ICMP anomaly detection: echo traffic that is carrying rather than probing.

Two behaviours, both read from the shape of echo traffic:

* **Tunnelling** - echo payloads that are large *and* variable *and*
  numerous.  A diagnostic ping sends one constant, small payload forever;
  moving data requires room and produces variety.  Following the same rule
  the DNS detector uses, at least two independent signals must agree before
  anything is reported, so a single unusual measurement cannot fire it.

* **Sweeping** - one source echoing many distinct addresses, most of which
  never answer.  This is the ICMP counterpart of the host-discovery
  detector, which reads the same intent from conversation silence.

Both stop at *observation*.  Payload content is never inspected, so this
module can say "these echoes are shaped like a carrier" and never "this is
a tunnel carrying X".
"""

from __future__ import annotations

from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind
from investigator.protocols.icmp import TYPICAL_PING_SIZES


class IcmpTunnelDetector(Detector):
    """Flags echo channels whose payload shape is inconsistent with ping."""

    name = "icmp_tunneling"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        icmp = ctx.protocols.icmp
        inv = ctx.inventory
        findings: list[Finding] = []

        for channel in icmp.channels.values():
            if channel.requests < cfg.icmp_min_echo_packets:
                continue
            if channel.looks_ping_shaped:
                continue  # one constant conventional size: an ordinary ping

            mean_size = channel.mean_request_size
            variability = channel.size_variability

            # Independent signals, in the spirit of dns_min_signals: no
            # single measurement is allowed to fire this on its own.
            signals: list[tuple[str, dict[str, object]]] = []
            if mean_size >= cfg.icmp_large_payload:
                signals.append((
                    f"mean echo payload {mean_size:.0f} B exceeds the "
                    f"{cfg.icmp_large_payload} B threshold (ping implementations "
                    f"send 32-56 B)",
                    {"mean_payload": round(mean_size, 1),
                     "threshold": cfg.icmp_large_payload},
                ))
            if variability >= cfg.icmp_size_variability:
                signals.append((
                    f"{variability:.0%} of echoes differed from the channel's "
                    f"most common payload size ({channel.distinct_sizes} distinct "
                    f"sizes) - a ping repeats one size",
                    {"size_variability": round(variability, 3),
                     "distinct_sizes": channel.distinct_sizes},
                ))
            if channel.total_payload >= cfg.icmp_min_tunnel_bytes:
                signals.append((
                    f"{channel.total_payload:,} B carried over ICMP echo in "
                    f"{channel.packets} packets",
                    {"total_payload": channel.total_payload,
                     "packets": channel.packets},
                ))

            if len(signals) < 2:
                continue

            confidence = cfg.icmp_tunnel_base_confidence
            if variability >= cfg.icmp_size_variability:
                confidence += cfg.icmp_variability_bonus
            if channel.total_payload >= cfg.icmp_min_tunnel_bytes:
                confidence += cfg.icmp_volume_bonus
            confidence = min(0.85, confidence)

            dst = inv.hosts.get(channel.dst_ip)
            external = dst is not None and dst.kind is HostKind.EXTERNAL
            severity = Severity.HIGH if external else Severity.MEDIUM

            finding = Finding(
                type="icmp_tunneling",
                title=(
                    f"ICMP echo payloads inconsistent with ping: "
                    f"{channel.src_ip} -> {channel.dst_ip}"
                ),
                severity=severity,
                confidence=confidence,
                explanation=(
                    f"{channel.src_ip} sent {channel.requests} echo requests to "
                    f"{channel.dst_ip} carrying {channel.total_payload:,} B, with "
                    f"a mean payload of {mean_size:.0f} B across "
                    f"{channel.distinct_sizes} distinct sizes. Diagnostic ping "
                    f"repeats a single fixed payload; varying, oversized payloads "
                    f"are the shape of data being moved."
                    + (
                        " The destination is external, so this would be traffic "
                        "leaving the monitored network."
                        if external else ""
                    )
                ),
                source=channel.src_ip,
                destination=channel.dst_ip,
                timestamp=channel.first_seen,
                start_time=channel.first_seen,
                end_time=channel.last_seen,
                tactic="Command & Control",
                interpretation=(
                    "Echo traffic shaped like a carrier is consistent with ICMP "
                    "tunnelling, which is used because ICMP is often permitted "
                    "outbound where other protocols are filtered."
                ),
                limitations=(
                    "Payload content is not inspected, so this establishes shape "
                    "only - not that a tunnel exists, nor what any of it carried. "
                    "Some monitoring agents and MTU-discovery tools also emit "
                    "large or varying echo payloads."
                ),
                metadata={
                    "requests": channel.requests,
                    "replies": channel.replies,
                    "total_payload": channel.total_payload,
                    "mean_payload": round(mean_size, 1),
                    "max_payload": channel.max_payload,
                    "distinct_sizes": channel.distinct_sizes,
                    "size_variability": round(variability, 3),
                    "signals": len(signals),
                },
            )
            for summary, data in signals:
                finding.add(summary, **data)
            if channel.max_payload not in TYPICAL_PING_SIZES:
                finding.add(
                    f"largest echo payload {channel.max_payload} B",
                    max_payload=channel.max_payload,
                )
            findings.append(finding)
        return findings


class IcmpSweepDetector(Detector):
    """Flags one source echoing many distinct addresses."""

    name = "icmp_sweep"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        icmp = ctx.protocols.icmp
        inv = ctx.inventory
        findings: list[Finding] = []

        for src, destinations in icmp.destinations_by_source().items():
            if len(destinations) < cfg.icmp_sweep_min_targets:
                continue

            channels = [
                c for c in icmp.channels_from(src)
                if c.dst_ip in destinations
            ]
            unanswered = [c for c in channels if c.replies == 0]
            silent_ratio = len(unanswered) / len(channels) if channels else 0.0
            if silent_ratio < 0.3:
                continue  # nearly everything answered: reachability checking

            starts = [c.first_seen for c in channels if c.first_seen is not None]
            ends = [c.last_seen for c in channels if c.last_seen is not None]
            start = min(starts) if starts else None
            end = max(ends) if ends else start

            internal_targets = sum(
                1 for ip in destinations
                if (h := inv.hosts.get(ip)) is not None
                and h.kind is HostKind.INTERNAL
            )
            confidence = min(
                0.80,
                0.35
                + 0.30 * silent_ratio
                + 0.10 * (len(destinations) / cfg.icmp_sweep_min_targets),
            )

            finding = Finding(
                type="icmp_sweep",
                title=f"ICMP sweep of {len(destinations)} addresses by {src}",
                severity=Severity.MEDIUM,
                confidence=confidence,
                explanation=(
                    f"{src} sent echo requests to {len(destinations)} distinct "
                    f"addresses ({internal_targets} internal), and "
                    f"{len(unanswered)} of them never replied "
                    f"({silent_ratio:.0%} unanswered). Probing a range that "
                    f"includes many non-existent addresses is characteristic of "
                    f"enumeration rather than of reaching a known host."
                ),
                source=src,
                timestamp=start,
                start_time=start,
                end_time=end,
                tactic="Discovery",
                interpretation=(
                    "A ping sweep is typically the first step in mapping which "
                    "addresses on a segment are live."
                ),
                limitations=(
                    "Monitoring systems, asset inventory scanners and network "
                    "management tools sweep on a schedule by design. Whether "
                    "this source is authorised to do so cannot be read from the "
                    "capture."
                ),
                metadata={
                    "targets": len(destinations),
                    "internal_targets": internal_targets,
                    "unanswered": len(unanswered),
                    "silent_ratio": round(silent_ratio, 3),
                },
            )
            finding.add(
                f"{len(destinations)} addresses echoed, {len(unanswered)} never "
                f"replied ({silent_ratio:.0%} unanswered)",
                targets=len(destinations), unanswered=len(unanswered),
            )
            findings.append(finding)
        return findings