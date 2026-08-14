"""Data-collection / exfiltration detection.

Exfiltration looks like an *inversion of the normal client ratio*: ordinary
endpoints download far more than they upload.  So instead of a fixed byte
threshold (which would fire on any busy host), the detector compares each
internal host's outbound volume against:

* its own inbound volume (the out/in ratio), and
* the median outbound volume of all other internal hosts - a baseline
  derived from this capture itself, as the project requires.

A destination that no other internal host contacted, or that was never
resolved through DNS, raises confidence further.
"""

from __future__ import annotations

from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind
from investigator.stats import median


def _fmt_bytes(num: int) -> str:
    value = float(num)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


class DataExfiltrationDetector(Detector):
    name = "data_exfiltration"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        inv = ctx.inventory

        internal = [h for h in inv.hosts.values() if h.kind is HostKind.INTERNAL]
        if not internal:
            return []
        baseline_upload = median([float(h.payload_bytes_sent) for h in internal])

        # Outbound internal -> external conversations, aggregated per pair.
        findings: list[Finding] = []
        for (src, dst), conv in inv.conversations.items():
            src_host = inv.hosts.get(src)
            dst_host = inv.hosts.get(dst)
            if src_host is None or dst_host is None:
                continue
            if src_host.kind is not HostKind.INTERNAL:
                continue
            if dst_host.kind is not HostKind.EXTERNAL:
                continue
            sent = conv.payload_bytes
            if sent < cfg.exfil_min_bytes:
                continue

            reverse = inv.conversations.get((dst, src))
            received = reverse.payload_bytes if reverse else 0
            ratio = sent / received if received else float("inf")
            if ratio < cfg.exfil_out_in_ratio:
                continue  # balanced exchange: looks like normal use

            finding = self._build(
                ctx, src, dst, conv, sent, received, ratio, baseline_upload
            )
            findings.append(finding)

        findings.sort(key=lambda f: -f.confidence)
        return findings

    def _build(self, ctx, src, dst, conv, sent, received, ratio, baseline_upload):
        cfg = ctx.config
        confidence = 0.45
        signals: list[tuple[str, dict]] = [
            (
                f"{_fmt_bytes(sent)} sent vs {_fmt_bytes(received)} received "
                + (
                    f"(ratio {ratio:.0f}:1)"
                    if ratio != float("inf")
                    else "(nothing received back)"
                ),
                {"bytes_sent": sent, "bytes_received": received},
            )
        ]

        if baseline_upload > 0 and sent >= baseline_upload * cfg.exfil_baseline_multiple:
            confidence += 0.2
            signals.append((
                f"upload is {sent / baseline_upload:.0f}x the median internal-host "
                f"upload in this capture ({_fmt_bytes(int(baseline_upload))})",
                {"baseline_upload_bytes": int(baseline_upload)},
            ))
        elif baseline_upload == 0:
            confidence += 0.1
            signals.append((
                "no other internal host uploaded a comparable amount of data", {}
            ))

        resolved = ctx.dns.names_for_ip(dst)
        if not resolved:
            confidence += 0.15
            signals.append(("destination was never resolved via DNS "
                            "(direct-to-IP transfer)", {}))

        contacted_by = sum(
            1
            for host in ctx.inventory.hosts.values()
            if host.kind is HostKind.INTERNAL and dst in host.peers
        )
        if contacted_by == 1:
            confidence += 0.1
            signals.append((f"only {src} contacted this destination", {}))

        duration = conv.duration
        if duration > 0:
            rate = sent / duration
            signals.append((
                f"transfer sustained {_fmt_bytes(int(rate))}/s over {duration:.0f}s",
                {"duration_seconds": round(duration, 1)},
            ))

        confidence = min(0.9, confidence)
        label = "Likely" if confidence >= 0.7 else "Possible"
        finding = Finding(
            type="data_exfiltration",
            title=f"{label} data exfiltration: {src} -> {dst}",
            severity=Severity.from_confidence(confidence, Severity.HIGH),
            confidence=confidence,
            explanation=(
                f"{src} sent {_fmt_bytes(sent)} to the external host {dst} while "
                f"receiving only {_fmt_bytes(received)} back. Normal client traffic is "
                f"download-dominant, so a strongly upload-dominant transfer to an "
                f"external endpoint is consistent with data being moved out. This is "
                f"{label.lower()}, not proven: backups, uploads and sync tools produce "
                f"the same shape."
            ),
            source=src,
            destination=dst,
            timestamp=conv.first_seen,
            start_time=conv.first_seen,
            end_time=conv.last_seen,
            tactic="Exfiltration",
            metadata={
                "bytes_sent": sent,
                "bytes_received": received,
                "ports": sorted(conv.dst_ports),
                "resolved_names": sorted(resolved),
            },
        )
        for summary, data in signals:
            finding.add(summary, **data)
        return finding
