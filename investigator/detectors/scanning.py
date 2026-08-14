"""Port-scan detection: vertical (many ports on one host) and horizontal
(one port across many hosts).

Signal comes mainly from *unanswered* TCP connection attempts - half-open
SYN flows and RST-refused flows.  A busy web client also opens many
connections, but they *establish*; a scanner's mostly do not.  So the
detector requires both breadth (distinct ports/hosts) and a high
unestablished ratio before firing, which is the primary false-positive
guard against mistaking a normal client or a legitimate server for a
scanner.
"""

from __future__ import annotations

from collections import defaultdict

from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind, classify_ip
from investigator.protocols.tcp import TcpFlow, TcpState

_UNESTABLISHED = {TcpState.HALF_OPEN, TcpState.RESET}


def _is_unestablished(flow: TcpFlow) -> bool:
    return flow.state in _UNESTABLISHED


class PortScanDetector(Detector):
    name = "port_scan"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        cfg = ctx.config

        # Group this capture's TCP flows by client for both scan shapes.
        by_client_server: dict[tuple[str, str], list[TcpFlow]] = defaultdict(list)
        by_client_port: dict[tuple[str, int], list[TcpFlow]] = defaultdict(list)
        for flow in ctx.tcp.flows.values():
            by_client_server[(flow.client_ip, flow.server_ip)].append(flow)
            by_client_port[(flow.client_ip, flow.server_port)].append(flow)

        findings.extend(self._vertical(ctx, by_client_server))
        findings.extend(self._horizontal(ctx, by_client_port))
        return findings

    # --------------------------------------------------------- vertical

    def _vertical(self, ctx, by_client_server) -> list[Finding]:
        cfg = ctx.config
        findings: list[Finding] = []
        for (client, server), flows in by_client_server.items():
            ports = {f.server_port for f in flows}
            if len(ports) < cfg.scan_min_ports_vertical:
                continue
            unestablished = [f for f in flows if _is_unestablished(f)]
            ratio = len(unestablished) / len(flows)
            if ratio < cfg.scan_unestablished_ratio:
                continue  # looks like a real multi-service client, not a scan

            times = [f.first_seen for f in flows]
            span = max(times) - min(times)
            confidence = min(
                0.95, 0.5 + 0.1 * (len(ports) / cfg.scan_min_ports_vertical) + 0.3 * ratio
            )
            severity = Severity.from_confidence(confidence, Severity.HIGH)
            finding = Finding(
                type="port_scan_vertical",
                title=f"Possible vertical port scan: {client} -> {server}",
                severity=severity,
                confidence=confidence,
                explanation=(
                    f"{client} attempted {len(ports)} distinct TCP ports on {server}, "
                    f"{len(unestablished)}/{len(flows)} of which never completed a "
                    f"handshake. Sweeping many ports on a single host while most "
                    f"attempts fail is characteristic of service enumeration."
                ),
                source=client,
                destination=server,
                timestamp=min(times),
                start_time=min(times),
                end_time=max(times),
                metadata={
                    "distinct_ports": len(ports),
                    "ports_sample": sorted(ports)[:40],
                    "unestablished_ratio": round(ratio, 3),
                },
            )
            finding.add(
                f"{len(ports)} distinct destination ports in {span:.0f}s",
                distinct_ports=len(ports), span_seconds=round(span, 1),
            )
            finding.add(
                f"{len(unestablished)}/{len(flows)} attempts unestablished "
                f"(half-open or reset)",
                unestablished=len(unestablished), total=len(flows),
            )
            findings.append(finding)
        return findings

    # ------------------------------------------------------- horizontal

    def _horizontal(self, ctx, by_client_port) -> list[Finding]:
        cfg = ctx.config
        findings: list[Finding] = []
        for (client, port), flows in by_client_port.items():
            servers = {f.server_ip for f in flows}
            if len(servers) < cfg.scan_min_hosts_horizontal:
                continue
            unestablished = [f for f in flows if _is_unestablished(f)]
            ratio = len(unestablished) / len(flows)
            if ratio < cfg.scan_unestablished_ratio:
                continue

            times = [f.first_seen for f in flows]
            span = max(times) - min(times)
            internal_targets = sum(
                1 for s in servers if classify_ip(s) is HostKind.INTERNAL
            )
            confidence = min(
                0.95, 0.5 + 0.1 * (len(servers) / cfg.scan_min_hosts_horizontal)
                + 0.3 * ratio
            )
            severity = Severity.from_confidence(confidence, Severity.HIGH)
            finding = Finding(
                type="port_scan_horizontal",
                title=f"Possible horizontal scan: {client} -> *:{port}",
                severity=severity,
                confidence=confidence,
                explanation=(
                    f"{client} probed port {port} across {len(servers)} distinct hosts "
                    f"({internal_targets} internal), {len(unestablished)}/{len(flows)} "
                    f"without completing a handshake. Sweeping one service across many "
                    f"hosts is characteristic of network-wide service discovery."
                ),
                source=client,
                destination=None,
                timestamp=min(times),
                start_time=min(times),
                end_time=max(times),
                metadata={
                    "port": port,
                    "distinct_hosts": len(servers),
                    "internal_targets": internal_targets,
                    "hosts_sample": sorted(servers)[:40],
                    "unestablished_ratio": round(ratio, 3),
                },
            )
            finding.add(
                f"{len(servers)} distinct hosts probed on port {port} in {span:.0f}s",
                distinct_hosts=len(servers), span_seconds=round(span, 1),
            )
            finding.add(
                f"{len(unestablished)}/{len(flows)} attempts unestablished",
                unestablished=len(unestablished), total=len(flows),
            )
            findings.append(finding)
        return findings
