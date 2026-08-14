"""Report generation.

V1 scope: a machine-readable ``investigation.json`` plus the terminal
sections for hosts and conversations.  The JSON structure grows with each
version (protocol analysis, findings, timeline...), always under stable
top-level keys so downstream consumers do not break.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from investigator import __version__, threats
from investigator.findings import Finding, Severity
from investigator.inventory import Conversation, HostKind, HostProfile, NetworkInventory

if TYPE_CHECKING:
    from investigator.pipeline import AnalysisResult

LOG = logging.getLogger(__name__)


def build_report(result: "AnalysisResult") -> dict[str, object]:
    """Assemble the full report as a JSON-ready dict."""
    loader = result.loader
    capture: dict[str, object] = dict(loader.metadata.as_dict())
    capture.update(result.summary.as_dict())
    capture["malformed_packets"] = loader.malformed_count
    capture["truncated"] = loader.truncated
    return {
        "tool": {"name": "pcap-investigator", "version": __version__},
        "generated_at": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        "capture": capture,
        "inventory": result.inventory.as_dict(),
        "protocols": result.protocols.as_dict(),
        "findings": [f.as_dict() for f in result.findings],
        "tactics": threats.tactic_summary(result.findings),
        "behavior_groups": [g.as_dict() for g in result.behavior_groups],
        "host_profiles": [p.as_dict() for p in result.host_profiles],
        "hypotheses": [h.as_dict() for h in result.hypotheses],
        "timeline": result.timeline.as_dict(),
        "investigation": result.investigation.as_dict()
        if result.investigation is not None
        else None,
    }


def build_timeline_report(result: "AnalysisResult") -> dict[str, object]:
    """Stand-alone ``timeline.json`` payload."""
    return {
        "tool": {"name": "pcap-investigator", "version": __version__},
        "generated_at": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        "capture": str(result.loader.path),
        **result.timeline.as_dict(),
    }


def write_json(data: dict[str, object], output_dir: Path, filename: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
    LOG.info("wrote %s", path)
    return path


# ------------------------------------------------------------------- HTML

def _filter_filesize(num) -> str:
    if num is None:
        return "-"
    return _format_size(int(num))


def _filter_duration(seconds) -> str:
    if seconds is None:
        return "-"
    seconds = float(seconds)
    if seconds < 60:
        return f"{seconds:.1f}s"
    total = int(round(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    return f"{minutes}m {secs:02d}s"


def _filter_clock(epoch) -> str:
    if epoch is None:
        return "-"
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%H:%M:%S")


def _filter_basename(path) -> str:
    return Path(str(path)).name


def _filter_first_n(values, count: int = 4) -> str:
    items = list(values)[:count]
    return ", ".join(str(v) for v in items) if items else "-"


def render_html(report: dict[str, object]) -> str:
    """Render the HTML report from the JSON-ready report dict.

    Jinja2 is used with ``autoescape=True``.  That is a security decision,
    not a formatting one: the report embeds attacker-controllable strings
    from the capture (DNS names, TLS SNI, HTTP URIs/User-Agents), and
    escaping them stops a crafted packet from injecting markup into the
    analyst's browser.
    """
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
        autoescape=select_autoescape(["html", "xml", "j2"], default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["filesize"] = _filter_filesize
    env.filters["duration"] = _filter_duration
    env.filters["clock"] = _filter_clock
    env.filters["basename"] = _filter_basename
    env.filters["first_n"] = _filter_first_n
    return env.get_template("report.html.j2").render(**report)


def write_html(report: dict[str, object], output_dir: Path, filename: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(render_html(report), encoding="utf-8")
    LOG.info("wrote %s", path)
    return path


# ---------------------------------------------------------------- terminal

def _format_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def _host_line(host: HostProfile) -> str:
    return (
        f"  {host.ip:<18} {host.kind.value:<9}"
        f" tx {_format_size(host.bytes_sent):>9}"
        f"  rx {_format_size(host.bytes_received):>9}"
        f"  peers {len(host.peers)}"
    )


def _conversation_line(conv: Conversation) -> str:
    ports = ",".join(str(p) for p, _ in conv.dst_ports.most_common(3))
    protos = ",".join(p for p, _ in conv.protocols.most_common(2))
    label = protos + (f":{ports}" if ports else "")
    return (
        f"  {conv.src_ip:>15} -> {conv.dst_ip:<15}"
        f" {label:<14} {conv.packets:>6} pkts  {_format_size(conv.bytes):>9}"
    )


def render_inventory_text(inventory: NetworkInventory, *, limit: int = 10) -> str:
    """Terminal sections for the network inventory (pure function)."""
    other = inventory.hosts_of_kind(
        HostKind.MULTICAST, HostKind.BROADCAST, HostKind.UNSPECIFIED
    )
    silent = [h for h in inventory.hosts.values() if h.is_silent]
    lines = [
        "",
        f"Hosts:     {len(inventory.internal_hosts)} internal, "
        f"{len(inventory.external_hosts)} external"
        + (f", {len(other)} multicast/broadcast" if other else ""),
    ]
    if silent:
        lines.append(
            f"           ({len(silent)} referenced but silent - never sent a packet)"
        )

    talkers = inventory.top_talkers(limit)
    if talkers:
        lines.append("")
        lines.append("Top talkers (by bytes):")
        lines.extend(_host_line(h) for h in talkers)

    conversations = inventory.top_conversations(limit)
    if conversations:
        lines.append("")
        lines.append("Top conversations (by bytes):")
        lines.extend(_conversation_line(c) for c in conversations)

    return "\n".join(lines)


_SEVERITY_TAG = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def render_findings_text(findings: list[Finding], *, limit: int = 20) -> str:
    """Terminal section listing findings, highest risk first.

    Risk and confidence are printed as separate columns, because a HIGH-risk
    / LOW-confidence finding and a LOW-risk / HIGH-confidence one demand
    very different responses from an analyst.
    """
    if not findings:
        return "\nFindings:  none (no anomalies crossed detection thresholds)"
    lines = ["", f"Findings:  {len(findings)} (highest risk first)"]
    for finding in findings[:limit]:
        tag = _SEVERITY_TAG.get(finding.severity, "INFO")
        lines.append(
            f"  [risk {tag:<4} | confidence "
            f"{finding.confidence_level.label:<8}] {finding.title}"
        )
        for evidence in finding.evidence[:4]:
            lines.append(f"      - {evidence.summary}")
        if finding.limitations:
            lines.append(f"      ! {finding.limitations.split('.')[0]}.")
    if len(findings) > limit:
        lines.append(f"  ... and {len(findings) - limit} more (see investigation.json)")
    return "\n".join(lines)


def render_behavior_groups_text(groups, *, limit: int = 10) -> str:
    """Group related findings so one activity reads as one behaviour."""
    if not groups:
        return ""
    lines = ["", "Observed behaviour (grouped):"]
    for group in groups[:limit]:
        subject = group.subject or "unattributed"
        lines.append(
            f"  |-- {group.label} - {subject} "
            f"({len(group.findings)} finding(s), "
            f"risk {group.max_severity.label})"
        )
        for destination in group.destinations[:4]:
            lines.append(f"  |     * {destination}")
    return "\n".join(lines)


def render_hypotheses_text(hypotheses, *, limit: int = 5) -> str:
    """Terminal section describing correlated attack hypotheses."""
    if not hypotheses:
        return ""
    lines = ["", "Correlated hypotheses:"]
    for hypothesis in hypotheses[:limit]:
        lines.append(
            f"  [{hypothesis.severity.label}] {hypothesis.title}"
            f"  (subject {hypothesis.subject}, {round(hypothesis.confidence * 100)}%)"
        )
        # attack chain as arrows
        chain = "\n".join(
            f"           {'  ' * i}{'|' if i else ''}{'-> ' if i else ''}{label}"
            for i, label in enumerate(hypothesis.narrative)
        )
        lines.append(chain)
    return "\n".join(lines)


def render_protocols_text(protocols) -> str:
    """One compact terminal line per protocol that actually appeared."""
    lines: list[str] = []

    dns = protocols.dns
    if dns.total_queries or dns.total_responses:
        top = sorted(dns.domains.values(), key=lambda d: -d.queries)[:3]
        top_text = ", ".join(f"{d.base_domain} x{d.queries}" for d in top)
        line = (
            f"DNS:       {dns.total_queries} queries, "
            f"{dns.nxdomain_responses} NXDOMAIN, {len(dns.domains)} domains"
        )
        if top_text:
            line += f"  (top: {top_text})"
        lines.append(line)

    tcp = protocols.tcp
    if tcp.flows:
        states = tcp.state_counts()
        state_text = ", ".join(f"{count} {name}" for name, count in states.most_common())
        lines.append(f"TCP:       {len(tcp.flows)} flows: {state_text}")

    http = protocols.http
    if http.requests or http.responses:
        methods = ", ".join(
            f"{name} x{count}" for name, count in http.methods.most_common(3)
        )
        line = f"HTTP:      {len(http.requests)} requests ({methods})"
        top_host = http.hosts.most_common(1)
        if top_host:
            line += f", top host: {top_host[0][0]}"
        lines.append(line)

    tls = protocols.tls
    if tls.client_hellos or tls.server_hellos:
        line = f"TLS:       {len(tls.client_hellos)} ClientHello"
        top_sni = tls.sni_counter.most_common(1)
        if top_sni:
            line += f", top SNI: {top_sni[0][0]}"
        if tls.fragmented_hellos:
            line += f"  ({tls.fragmented_hellos} unparsed/fragmented)"
        lines.append(line)

    if not lines:
        return ""
    return "\n" + "\n".join(lines)
