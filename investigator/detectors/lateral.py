"""Lateral-movement and host-discovery detection (internal-to-internal).

Two related behaviours, both about *internal* traffic:

* **Lateral movement** - one internal host opening administrative or
  file-sharing sessions (SSH/RDP/SMB/WinRM/DB) to several other internal
  hosts.  Only *successful* sessions count, which is what separates it from
  a scan: a scanner sprays SYNs, an operator (or an attacker with
  credentials) actually connects.  A legitimate admin jump box does the same
  thing, so language stays probabilistic and the finding notes it.

* **Host discovery** - one host touching many distinct internal addresses
  (ARP/ICMP/TCP), including addresses that never answer.  The dead-address
  ratio is the key signal: normal hosts talk to hosts that exist.
"""

from __future__ import annotations

from collections import defaultdict

from investigator.config import ADMIN_PORTS
from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind
from investigator.protocols.tcp import TcpState

_ESTABLISHED = {TcpState.ESTABLISHED, TcpState.CLOSED}

_SERVICE_NAMES = {
    22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
    5985: "WinRM", 5986: "WinRM-TLS",
}


class LateralMovementDetector(Detector):
    name = "lateral_movement"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        inv = ctx.inventory

        # client -> {target: {ports}} for *established* admin sessions
        sessions: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        times: dict[str, list[float]] = defaultdict(list)
        for flow in ctx.tcp.flows.values():
            if flow.server_port not in ADMIN_PORTS:
                continue
            if flow.state not in _ESTABLISHED:
                continue
            client = inv.hosts.get(flow.client_ip)
            server = inv.hosts.get(flow.server_ip)
            if client is None or server is None:
                continue
            if client.kind is not HostKind.INTERNAL or server.kind is not HostKind.INTERNAL:
                continue
            sessions[flow.client_ip][flow.server_ip].add(flow.server_port)
            times[flow.client_ip].append(flow.first_seen)

        findings: list[Finding] = []
        for client, targets in sessions.items():
            if len(targets) < cfg.lateral_min_targets:
                continue
            ports = sorted({p for portset in targets.values() for p in portset})
            service_text = ", ".join(
                f"{_SERVICE_NAMES.get(p, 'port ' + str(p))}" for p in ports[:5]
            )
            start = min(times[client])
            end = max(times[client])

            confidence = min(
                0.85,
                0.4 + 0.1 * (len(targets) / cfg.lateral_min_targets) + 0.1 * len(ports),
            )
            finding = Finding(
                type="lateral_movement",
                title=f"Possible lateral movement from {client}",
                severity=Severity.from_confidence(confidence, Severity.HIGH),
                confidence=confidence,
                explanation=(
                    f"{client} established administrative/file-sharing sessions "
                    f"({service_text}) with {len(targets)} distinct internal hosts. "
                    f"Successful admin connections fanning out across the internal "
                    f"network are consistent with lateral movement - though a jump "
                    f"host, backup agent or management server behaves the same way, "
                    f"so context about this host's role is required."
                ),
                source=client,
                timestamp=start,
                start_time=start,
                end_time=end,
                tactic="Lateral Movement",
                metadata={
                    "target_count": len(targets),
                    "targets": sorted(targets)[:40],
                    "ports": ports,
                },
            )
            finding.add(
                f"{len(targets)} internal hosts reached over admin services "
                f"({service_text})",
                target_count=len(targets), ports=ports,
            )
            finding.add(
                f"sessions completed a TCP handshake (not merely attempted)",
            )
            findings.append(finding)
        return findings


class HostDiscoveryDetector(Detector):
    name = "host_discovery"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        inv = ctx.inventory
        cfg = ctx.config

        # internal targets touched per internal source
        touched: dict[str, set[str]] = defaultdict(set)
        for (src, dst) in inv.conversations:
            src_host = inv.hosts.get(src)
            dst_host = inv.hosts.get(dst)
            if src_host is None or dst_host is None:
                continue
            if src_host.kind is not HostKind.INTERNAL:
                continue
            if dst_host.kind is not HostKind.INTERNAL:
                continue
            touched[src].add(dst)

        findings: list[Finding] = []
        for src, targets in touched.items():
            if len(targets) < cfg.scan_min_hosts_horizontal:
                continue
            silent = [t for t in targets if inv.hosts[t].is_silent]
            silent_ratio = len(silent) / len(targets)
            if silent_ratio < 0.3:
                continue  # most targets answered: looks like normal usage

            conversations = [
                inv.conversations[(src, t)] for t in targets
                if (src, t) in inv.conversations
            ]
            starts = [c.first_seen for c in conversations if c.first_seen is not None]
            start = min(starts) if starts else None
            end = max(
                (c.last_seen for c in conversations if c.last_seen is not None),
                default=start,
            )
            confidence = min(0.85, 0.4 + 0.35 * silent_ratio
                             + 0.1 * (len(targets) / cfg.scan_min_hosts_horizontal))
            finding = Finding(
                type="host_discovery",
                title=f"Possible internal host discovery by {src}",
                severity=Severity.from_confidence(confidence, Severity.MEDIUM),
                confidence=confidence,
                explanation=(
                    f"{src} contacted {len(targets)} distinct internal addresses, of "
                    f"which {len(silent)} never responded. Sweeping a range including "
                    f"many non-existent addresses is characteristic of network "
                    f"enumeration rather than normal communication."
                ),
                source=src,
                timestamp=start,
                start_time=start,
                end_time=end,
                tactic="Discovery",
                metadata={
                    "targets_touched": len(targets),
                    "silent_targets": len(silent),
                    "silent_ratio": round(silent_ratio, 3),
                },
            )
            finding.add(
                f"{len(targets)} internal addresses contacted, {len(silent)} never "
                f"replied ({silent_ratio:.0%} unresponsive)",
                targets=len(targets), silent=len(silent),
            )
            findings.append(finding)
        return findings
