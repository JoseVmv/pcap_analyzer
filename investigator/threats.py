"""Threat mapping (V5): naming the *behaviour class* a finding belongs to.

Detectors describe what the traffic did; this layer names what that kind of
behaviour is usually called (Discovery, Command & Control, Exfiltration...),
using ATT&CK-style tactic vocabulary as a shared language for analysts.

The mapping is deliberately thin and separate from detection, so that
renaming or re-categorising never touches detector logic - and so that a
finding's *evidence* always remains the ground truth behind whatever label
it carries.
"""

from __future__ import annotations

from investigator.findings import Finding

TACTICS: dict[str, str] = {
    "port_scan_vertical": "Discovery",
    "port_scan_horizontal": "Discovery",
    "host_discovery": "Discovery",
    "rare_destination": "Command & Control",
    "unusual_port": "Command & Control",
    "beaconing": "Command & Control",
    "dns_tunneling": "Command & Control",
    "dns_anomaly": "Command & Control",
    "traffic_burst": "Collection",
    "data_exfiltration": "Exfiltration",
    "lateral_movement": "Lateral Movement",
    "icmp_sweep": "Discovery",
    "icmp_tunneling": "Command & Control",
    "tls_no_sni": "Command & Control",
    "tls_unresolved_sni": "Command & Control",
    "tls_rare_fingerprint": "Command & Control",
    # Poisoning the address bindings of a segment is how an attacker gets
    # into the path of traffic - credentials and sessions included.
    "arp_spoofing": "Credential Access",
    "arp_mac_flooding": "Credential Access",
}

# One-line description of what the behaviour class means, shown in reports.
TACTIC_DESCRIPTIONS: dict[str, str] = {
    "Discovery": "Mapping the network and the services available on it.",
    "Command & Control": (
        "Communication patterns consistent with a host taking direction from, "
        "or reporting to, a remote controller."
    ),
    "Collection": "Gathering or staging data before it is moved.",
    "Exfiltration": "Moving data out of the network to an external destination.",
    "Lateral Movement": "Reaching further internal hosts from an initial foothold.",
    "Credential Access": (
        "Positioning to observe traffic that other hosts believe is going "
        "somewhere else."
    ),
}


def annotate(findings: list[Finding]) -> list[Finding]:
    """Attach a tactic to each finding that does not already declare one."""
    for finding in findings:
        if finding.tactic is None:
            finding.tactic = TACTICS.get(finding.type)
    return findings


def tactic_summary(findings: list[Finding]) -> dict[str, dict[str, object]]:
    """Group findings by tactic for the report."""
    summary: dict[str, dict[str, object]] = {}
    for finding in findings:
        if finding.tactic is None:
            continue
        entry = summary.setdefault(
            finding.tactic,
            {
                "description": TACTIC_DESCRIPTIONS.get(finding.tactic, ""),
                "finding_count": 0,
                "max_confidence": 0.0,
                "finding_ids": [],
            },
        )
        entry["finding_count"] = int(entry["finding_count"]) + 1
        entry["max_confidence"] = max(
            float(entry["max_confidence"]), round(finding.confidence, 3)
        )
        ids = entry["finding_ids"]
        assert isinstance(ids, list)
        ids.append(finding.id)
    return summary
