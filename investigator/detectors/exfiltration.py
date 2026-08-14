"""Outbound data-transfer analysis, graded by how much the evidence supports.

The central rule of this module: **volume alone is never exfiltration**.
A large transfer can be a backup, a software update, a video upload, a
sync client, a scan, or an actual data theft.  A capture usually cannot
distinguish them, because the payload content is unavailable or encrypted.

So instead of one detector that shouts "exfiltration", the assessment is
tiered, and a finding is only promoted to the next tier when *additional
independent evidence* justifies it:

===========================================  ==================================
Tier                                         Requires
===========================================  ==================================
``large_transfer``                           volume above the floor
``outbound_data_transfer``                   + upload-dominant direction
``potential_exfiltration_indicator``         + >=2 corroborating indicators
                                               (rare destination, no DNS
                                               resolution, repeated POSTs,
                                               low response volume, far above
                                               the capture's own baseline)
===========================================  ==================================

Even the top tier is called an *indicator*, never a conclusion, and every
finding carries an explicit ``limitations`` note stating that payload
content could not be established.
"""

from __future__ import annotations

from dataclasses import dataclass

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


@dataclass(slots=True)
class _Indicator:
    """One corroborating signal beyond raw volume."""

    summary: str
    data: dict
    weight: float


class DataTransferDetector(Detector):
    """Grades outbound transfers from 'large' to 'possible exfiltration'."""

    name = "data_transfer"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        inv = ctx.inventory

        internal = [h for h in inv.hosts.values() if h.kind is HostKind.INTERNAL]
        if not internal:
            return []
        baseline_upload = median([float(h.payload_bytes_sent) for h in internal])

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
            if sent < cfg.transfer_min_bytes:
                continue

            reverse = inv.conversations.get((dst, src))
            received = reverse.payload_bytes if reverse else 0
            finding = self._assess(
                ctx, src, dst, conv, sent, received, baseline_upload
            )
            if finding is not None:
                findings.append(finding)

        findings.sort(key=lambda f: (-f.severity, -f.confidence))
        return findings

    # ------------------------------------------------------------- tiering

    def _assess(self, ctx, src, dst, conv, sent, received, baseline_upload):
        cfg = ctx.config
        ratio = sent / received if received else float("inf")
        upload_dominant = ratio >= cfg.transfer_out_in_ratio

        indicators = self._gather_indicators(
            ctx, src, dst, conv, sent, received, baseline_upload
        )

        # --- tier selection ------------------------------------------
        if not upload_dominant:
            tier = "large_transfer"
        elif len(indicators) >= cfg.exfil_min_indicators:
            tier = "potential_exfiltration_indicator"
        else:
            tier = "outbound_data_transfer"

        builder = {
            "large_transfer": self._large_transfer,
            "outbound_data_transfer": self._outbound_transfer,
            "potential_exfiltration_indicator": self._exfil_indicator,
        }[tier]
        return builder(ctx, src, dst, conv, sent, received, ratio, indicators)

    def _gather_indicators(
        self, ctx, src, dst, conv, sent, received, baseline_upload
    ) -> list[_Indicator]:
        """Evidence *beyond* volume and direction."""
        cfg = ctx.config
        indicators: list[_Indicator] = []

        if baseline_upload > 0 and sent >= baseline_upload * cfg.exfil_baseline_multiple:
            indicators.append(_Indicator(
                f"upload is {sent / baseline_upload:.0f}x the median internal-host "
                f"upload in this capture ({_fmt_bytes(int(baseline_upload))})",
                {"baseline_upload_bytes": int(baseline_upload)},
                0.15,
            ))

        if not ctx.dns.names_for_ip(dst):
            indicators.append(_Indicator(
                "destination was never resolved via DNS in this capture "
                "(direct-to-IP transfer)",
                {"dns_resolved": False},
                0.12,
            ))

        contacted_by = sum(
            1
            for host in ctx.inventory.hosts.values()
            if host.kind is HostKind.INTERNAL and dst in host.peers
        )
        if contacted_by == 1:
            indicators.append(_Indicator(
                f"only {src} contacted this destination; no other internal host did",
                {"internal_hosts_contacting": 1},
                0.12,
            ))

        # HTTP upload shape: repeated POST/PUT with little coming back is a
        # markedly more specific signal than raw byte volume.
        http_stats = self._http_upload_stats(ctx, src, dst)
        if http_stats is not None:
            uploads, bytes_posted = http_stats
            if uploads >= cfg.exfil_min_uploads:
                indicators.append(_Indicator(
                    f"{uploads} repeated HTTP upload requests (POST/PUT) carrying "
                    f"{_fmt_bytes(bytes_posted)} of request bodies",
                    {"http_uploads": uploads, "http_body_bytes": bytes_posted},
                    0.2,
                ))

        if received > 0 and sent / received >= cfg.exfil_low_response_ratio:
            indicators.append(_Indicator(
                f"response volume is very low relative to what was sent "
                f"({_fmt_bytes(received)} back for {_fmt_bytes(sent)} out)",
                {"bytes_received": received},
                0.1,
            ))

        return indicators

    def _http_upload_stats(self, ctx, src, dst) -> tuple[int, int] | None:
        """Count HTTP POST/PUT requests from src to dst and their body sizes."""
        uploads = 0
        body_bytes = 0
        for request in ctx.http.requests:
            if request.src_ip != src or request.dst_ip != dst:
                continue
            if request.method not in ("POST", "PUT"):
                continue
            uploads += 1
            if request.content_length:
                body_bytes += request.content_length
        return (uploads, body_bytes) if uploads else None

    # ------------------------------------------------------- tier builders

    def _common_metadata(self, conv, sent, received, indicators):
        return {
            "bytes_sent": sent,
            "bytes_received": received,
            "ports": sorted(conv.dst_ports),
            "indicator_count": len(indicators),
            "duration_seconds": round(conv.duration, 1),
        }

    def _attach(self, finding, conv, sent, received, ratio, indicators):
        ratio_text = (
            f"ratio {ratio:.0f}:1" if ratio != float("inf") else "nothing received back"
        )
        finding.add(
            f"{_fmt_bytes(sent)} sent vs {_fmt_bytes(received)} received ({ratio_text})",
            bytes_sent=sent, bytes_received=received,
        )
        if conv.duration > 0:
            finding.add(
                f"transfer sustained {_fmt_bytes(int(sent / conv.duration))}/s over "
                f"{conv.duration:.0f}s",
                duration_seconds=round(conv.duration, 1),
            )
        for indicator in indicators:
            finding.add(indicator.summary, **indicator.data)
        return finding

    def _large_transfer(self, ctx, src, dst, conv, sent, received, ratio, indicators):
        """Tier 1: notable volume, but the exchange is not upload-dominant."""
        confidence = 0.75  # that a large transfer happened is well established
        finding = Finding(
            type="large_transfer",
            title=f"Large data transfer: {src} <-> {dst}",
            severity=Severity.LOW,
            confidence=confidence,
            explanation=(
                f"{_fmt_bytes(sent)} was sent from {src} to the external host {dst}, "
                f"with {_fmt_bytes(received)} received back. The exchange is not "
                f"upload-dominant, so it resembles ordinary use (download, streaming "
                f"or a bidirectional session) more than data being moved out."
            ),
            interpretation=(
                "A substantial volume of traffic was exchanged with an external "
                "host. On its own this is a capacity observation, not a security "
                "finding."
            ),
            limitations=(
                "Payload content could not be established from the available packet "
                "data, so the nature of the transferred data is unknown."
            ),
            source=src,
            destination=dst,
            timestamp=conv.first_seen,
            start_time=conv.first_seen,
            end_time=conv.last_seen,
            behavior_group=f"outbound_transfer:{src}",
            metadata=self._common_metadata(conv, sent, received, indicators),
        )
        return self._attach(finding, conv, sent, received, ratio, indicators)

    def _outbound_transfer(self, ctx, src, dst, conv, sent, received, ratio, indicators):
        """Tier 2: upload-dominant, but without further corroboration."""
        confidence = 0.6
        finding = Finding(
            type="outbound_data_transfer",
            title=f"Possible outbound data transfer: {src} -> {dst}",
            severity=Severity.MEDIUM,
            confidence=confidence,
            explanation=(
                f"{src} sent {_fmt_bytes(sent)} to the external host {dst} while "
                f"receiving only {_fmt_bytes(received)} back. Ordinary client traffic "
                f"is download-dominant, so an upload-dominant flow is worth reviewing. "
                f"Backups, cloud sync, file sharing and media uploads produce exactly "
                f"the same shape."
            ),
            interpretation=(
                "Outbound-dominant data movement to an external destination. This "
                "warrants review of what application produced it."
            ),
            limitations=(
                "Payload content could not be established from the available packet "
                "data. Direction and volume alone do not distinguish a legitimate "
                "upload from data theft."
            ),
            source=src,
            destination=dst,
            timestamp=conv.first_seen,
            start_time=conv.first_seen,
            end_time=conv.last_seen,
            behavior_group=f"outbound_transfer:{src}",
            metadata=self._common_metadata(conv, sent, received, indicators),
        )
        return self._attach(finding, conv, sent, received, ratio, indicators)

    def _exfil_indicator(self, ctx, src, dst, conv, sent, received, ratio, indicators):
        """Tier 3: upload-dominant *and* corroborated by other evidence."""
        confidence = min(0.8, 0.45 + sum(i.weight for i in indicators))
        finding = Finding(
            type="potential_exfiltration_indicator",
            title=f"Potential data exfiltration indicator: {src} -> {dst}",
            # High *risk* if the reading is right, while confidence stays
            # bounded because content is unknowable here - exactly the
            # risk/confidence split this tool insists on.
            severity=Severity.HIGH,
            confidence=confidence,
            explanation=(
                f"{src} sent {_fmt_bytes(sent)} to {dst} while receiving only "
                f"{_fmt_bytes(received)} back, and {len(indicators)} additional "
                f"indicators corroborate the pattern (listed below). The combination "
                f"is consistent with data being moved off the network, but the "
                f"capture cannot confirm what was transferred."
            ),
            interpretation=(
                "Upload-dominant transfer to an external destination with multiple "
                "corroborating indicators. This pattern may warrant investigation "
                "for possible data exfiltration."
            ),
            limitations=(
                "Payload content could not be established from the available packet "
                "data. Network evidence alone does not establish that sensitive data "
                "was transferred, nor the intent behind the transfer. Legitimate "
                "backup, sync and upload tools can produce every indicator listed."
            ),
            source=src,
            destination=dst,
            timestamp=conv.first_seen,
            start_time=conv.first_seen,
            end_time=conv.last_seen,
            tactic="Exfiltration",
            behavior_group=f"outbound_transfer:{src}",
            metadata=self._common_metadata(conv, sent, received, indicators),
        )
        return self._attach(finding, conv, sent, received, ratio, indicators)


#: Backwards-compatible alias: the detector was called
#: ``DataExfiltrationDetector`` before the tiering rework.
DataExfiltrationDetector = DataTransferDetector
