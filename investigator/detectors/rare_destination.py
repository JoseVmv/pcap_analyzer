"""Rare external destination detection.

"Rare" is defined *relative to this capture's own baseline*, not a blocklist
(a hard project rule).  A destination is a candidate when only a very small
number of internal hosts ever contacted it - most external endpoints (CDNs,
update servers, SaaS) are contacted by many hosts, so a single-host,
seldom-seen external IP stands out.

On its own this is weak evidence, so severity is capped at LOW/MEDIUM and
confidence is raised only by corroborating context: the destination was
never resolved via DNS (direct-to-IP), or an uncommon port was used, or a
non-trivial amount of data moved.  The value of this detector is mostly as
correlation fuel for later stages.
"""

from __future__ import annotations

from investigator.config import COMMON_SERVICE_PORTS
from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind


class RareDestinationDetector(Detector):
    name = "rare_destination"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        inv = ctx.inventory

        # Which internal hosts contacted each external destination?
        contacted_by: dict[str, set[str]] = {}
        for (src, dst), conv in inv.conversations.items():
            dst_host = inv.hosts.get(dst)
            src_host = inv.hosts.get(src)
            if dst_host is None or dst_host.kind is not HostKind.EXTERNAL:
                continue
            if src_host is None or src_host.kind is not HostKind.INTERNAL:
                continue
            contacted_by.setdefault(dst, set()).add(src)

        candidates: list[Finding] = []
        for dst, sources in contacted_by.items():
            if len(sources) > cfg.rare_max_internal_hosts:
                continue
            src = next(iter(sources))
            conv = inv.conversations.get((src, dst))
            if conv is None or conv.packets < cfg.rare_min_packets:
                continue

            finding = self._build(ctx, src, dst, conv)
            if finding is not None:
                candidates.append(finding)

        # Rank by confidence and cap, so a noisy capture doesn't flood.
        candidates.sort(key=lambda f: -f.confidence)
        return candidates[: cfg.rare_max_findings]

    def _build(self, ctx, src, dst, conv):
        confidence = 0.3
        signals: list[str] = ["contacted by a single internal host"]

        resolved = ctx.dns.names_for_ip(dst)
        if not resolved:
            confidence += 0.2
            signals.append("no DNS resolution observed (direct-to-IP connection)")

        ports = set(conv.dst_ports)
        uncommon_ports = ports - COMMON_SERVICE_PORTS
        if uncommon_ports and ports and uncommon_ports == ports:
            confidence += 0.15
            signals.append(
                "only uncommon destination port(s): "
                + ",".join(str(p) for p in sorted(uncommon_ports)[:5])
            )

        if conv.bytes >= 100_000:
            confidence += 0.1
            signals.append(f"{conv.bytes} bytes transferred")

        confidence = min(0.8, confidence)
        severity = Severity.from_confidence(confidence, Severity.MEDIUM)
        if severity < Severity.LOW:
            severity = Severity.LOW  # always at least LOW: it's a real oddity

        finding = Finding(
            type="rare_destination",
            title=f"Rare external destination: {dst}",
            severity=severity,
            confidence=confidence,
            explanation=(
                f"{dst} was contacted by only {src} and by no other internal host in "
                f"this capture. Combined with the context below, it is an unusual "
                f"external endpoint worth review (weak on its own)."
            ),
            source=src,
            destination=dst,
            timestamp=conv.first_seen,
            start_time=conv.first_seen,
            end_time=conv.last_seen,
            metadata={
                "resolved_names": sorted(resolved),
                "ports": sorted(ports),
                "packets": conv.packets,
                "bytes": conv.bytes,
            },
        )
        for signal in signals:
            finding.add(signal)
        return finding
