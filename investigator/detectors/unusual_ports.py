"""Unusual destination-port usage.

Flags TCP services that *actually carried traffic* (established, or with
payload) on a port that is both (a) not a common service port and (b) rare
in this capture's own port baseline.  Malware C2 and backdoors frequently
listen on odd high ports; a real connection there - as opposed to a scan
probe - is worth surfacing.  The baseline comparison is what stops every
ephemeral peer-to-peer port from being reported.
"""

from __future__ import annotations

from investigator.config import COMMON_SERVICE_PORTS
from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.protocols.tcp import TcpState


class UnusualPortDetector(Detector):
    name = "unusual_port"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        global_dst = ctx.inventory.global_dst_ports

        findings: list[Finding] = []
        for flow in ctx.tcp.flows.values():
            port = flow.server_port
            if port in COMMON_SERVICE_PORTS:
                continue
            if port < 1024:
                continue  # a low port we simply don't name is still probably a service
            # only count flows that carried real traffic (exclude scan probes)
            carried = flow.total_payload > 0 or flow.state in (
                TcpState.ESTABLISHED,
                TcpState.CLOSED,
            )
            if not carried:
                continue
            if global_dst.get(port, 0) > cfg.unusual_port_max_global_flows * 4:
                continue  # port is actually common in this capture

            confidence = 0.35
            signals = [f"port {port} is not a well-known service port"]
            if flow.total_payload >= 10_000:
                confidence += 0.1
                signals.append(f"{flow.total_payload} bytes of payload exchanged")
            if flow.payload_out > flow.payload_in:
                confidence += 0.05
                signals.append("more data sent than received")

            confidence = min(0.7, confidence)
            finding = Finding(
                type="unusual_port",
                title=f"Unusual service port in use: {flow.server_ip}:{port}",
                severity=Severity.from_confidence(confidence, Severity.MEDIUM),
                confidence=confidence,
                explanation=(
                    f"{flow.client_ip} established a TCP session to {flow.server_ip} on "
                    f"port {port}, which is neither a standard service port nor common "
                    f"elsewhere in this capture. Real sessions on odd ports can indicate "
                    f"a non-standard or hidden service."
                ),
                source=flow.client_ip,
                destination=flow.server_ip,
                timestamp=flow.first_seen,
                start_time=flow.first_seen,
                end_time=flow.last_seen,
                metadata={"port": port, "state": flow.state.value},
            )
            for signal in signals:
                finding.add(signal)
            findings.append(finding)

        findings.sort(key=lambda f: -f.confidence)
        return findings[: cfg.unusual_port_max_findings]
