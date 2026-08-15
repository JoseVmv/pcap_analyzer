"""ARP integrity detection: contested address bindings on the local segment.

The signal
----------
One IP address claimed by two different MAC addresses during a single
capture.  ARP has no authentication, so the claim is simply believed by
every host on the segment - which is what makes poisoning both trivial and
worth detecting.

Why this detector is cheap and strong
-------------------------------------
Unlike most behaviour here, this one is close to a *fact* rather than a
statistical reading: either two MACs claimed the address or they did not.
What stays uncertain is the **cause**, and that is where confidence is
spent rather than on the observation itself.

The benign explanations are real and common:

* DHCP reassigned the address to a different machine;
* a NIC was replaced, or a VM migrated to another host;
* a VRRP/CARP pair failed over, which moves an IP between MACs by design;
* a router answers ARP on behalf of other addresses (proxy ARP).

What distinguishes those from poisoning is *timing and persistence*.  A
handover is sequential: the old MAC goes quiet, the new one takes over.
Poisoning is concurrent: both MACs claim the address in the same window,
and the attacker repeats gratuitous announcements to keep its forged entry
from expiring.  Confidence is therefore driven by overlap, repetition and
header disagreement - not by the bare existence of two bindings.
"""

from __future__ import annotations

from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind

#: A contested address that many hosts talk to (a gateway, a DNS server)
#: puts far more traffic at risk than a contested workstation address.
#: Used to raise *risk*, never confidence - it says nothing about whether
#: the conflict was malicious.
_INFRASTRUCTURE_PEERS = 5


def _ip_behind_mac(ctx: DetectionContext, mac: str, exclude: str) -> str | None:
    """The IP this MAC uses as *its own* sender address, if we saw one.

    Matters for correlation rather than for detection.  A finding whose
    ``source`` is a MAC cannot be attributed to a host profile, because
    profiles are keyed by IP - so the host contesting an address would be
    missing this behaviour from its own record, and the correlation layer
    would count one category fewer for it.

    ``exclude`` is the contested address itself: the whole point is that
    the MAC claims that one, so it must not be mistaken for the claimant's
    real identity.

    Returns ``None`` when the answer is ambiguous.  One MAC sending for
    several addresses is a router, a NAT or a virtualisation host, and
    picking one of those addresses would attribute the behaviour to a host
    that may have nothing to do with it - a far worse outcome than leaving
    the finding attributed to the hardware address we actually observed.
    """
    candidates = [
        host.ip
        for host in ctx.inventory.hosts.values()
        if host.ip != exclude
        and host.macs
        and mac in {m.lower() for m in host.macs}
    ]
    return candidates[0] if len(candidates) == 1 else None


class ArpSpoofingDetector(Detector):
    """Flags IP addresses claimed by more than one MAC."""

    name = "arp_spoofing"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        arp = ctx.protocols.arp
        inv = ctx.inventory
        findings: list[Finding] = []

        for entry in arp.conflicts():
            claims = [
                b for b in entry.ordered() if b.packets >= cfg.arp_min_claims
            ]
            if len(claims) < 2:
                continue  # a single stray frame is not a competing claim

            overlap = entry.overlap_seconds
            concurrent = overlap >= cfg.arp_conflict_min_overlap
            gratuitous = sum(b.gratuitous for b in claims)

            confidence = cfg.arp_conflict_base_confidence
            if concurrent:
                confidence += cfg.arp_overlap_bonus
            if gratuitous:
                confidence += cfg.arp_gratuitous_bonus
            if entry.ether_mismatches:
                confidence += cfg.arp_ether_mismatch_bonus
            confidence = min(0.95, confidence)

            # Risk follows blast radius: contesting an address the whole
            # segment depends on is more serious than contesting an idle one.
            host = inv.hosts.get(entry.ip)
            peers = len(host.peers) if host is not None else 0
            infrastructure = peers >= _INFRASTRUCTURE_PEERS
            severity = Severity.HIGH if infrastructure else Severity.MEDIUM

            start = min(b.first_seen for b in claims)
            end = max(b.last_seen for b in claims)
            mac_list = ", ".join(f"{b.mac} ({b.packets}x)" for b in claims[:4])

            # Attribute the finding to the *latest* claimant, which is the
            # one that arrived to contest an address already in use, and
            # prefer its own IP so the host profile picks this up.
            claimant_mac = claims[-1].mac
            claimant_ip = _ip_behind_mac(ctx, claimant_mac, entry.ip)

            finding = Finding(
                type="arp_spoofing",
                title=f"Conflicting ARP claims for {entry.ip}",
                severity=severity,
                confidence=confidence,
                explanation=(
                    f"{len(claims)} distinct MAC addresses claimed to own "
                    f"{entry.ip} during the capture: {mac_list}. "
                    + (
                        "The claims overlapped in time, which an ordinary "
                        "address handover does not produce - a DHCP "
                        "reassignment or NIC swap releases the address before "
                        "the next owner announces it."
                        if concurrent
                        else "The claims did not overlap in time, which is "
                        "also what a legitimate handover looks like."
                    )
                ),
                source=claimant_ip or claimant_mac,
                destination=entry.ip,
                timestamp=start,
                start_time=start,
                end_time=end,
                tactic="Credential Access",
                interpretation=(
                    "Concurrent competing claims on one address are "
                    "consistent with ARP cache poisoning, the standard way "
                    "to place a host in the middle of traffic it should not "
                    "see."
                ),
                limitations=(
                    "ARP carries no authentication, so the capture cannot "
                    "establish which claim is legitimate. DHCP reassignment, "
                    "a replaced NIC, a VM migration and a VRRP/CARP failover "
                    "all move an address between MACs by design. Confirmation "
                    "requires the switch's port/MAC table or DHCP lease log."
                ),
                metadata={
                    "ip": entry.ip,
                    "mac_count": len(claims),
                    "macs": [b.mac for b in claims],
                    "claimant_mac": claimant_mac,
                    "claimant_ip": claimant_ip,
                    "overlap_seconds": round(overlap, 3),
                    "gratuitous": gratuitous,
                    "ether_mismatches": entry.ether_mismatches,
                    "peer_count": peers,
                },
            )
            finding.add(
                f"{len(claims)} MACs claimed {entry.ip}: {mac_list}",
                ip=entry.ip,
                macs=[b.mac for b in claims],
            )
            if concurrent:
                finding.add(
                    f"claims coexisted for {overlap:.1f}s (threshold "
                    f"{cfg.arp_conflict_min_overlap}s)",
                    overlap_seconds=round(overlap, 3),
                )
            if gratuitous:
                finding.add(
                    f"{gratuitous} unprompted (gratuitous) announcement(s) - "
                    f"the mechanism that keeps a forged cache entry alive",
                    gratuitous=gratuitous,
                )
            if entry.ether_mismatches:
                finding.add(
                    f"{entry.ether_mismatches} frame(s) where the Ethernet "
                    f"source MAC disagreed with the ARP sender MAC - a normal "
                    f"stack does not emit that",
                    ether_mismatches=entry.ether_mismatches,
                )
            if infrastructure:
                finding.add(
                    f"{entry.ip} communicates with {peers} hosts, so traffic "
                    f"from many peers depends on this binding",
                    peer_count=peers,
                )
            findings.append(finding)

        findings.extend(self._mac_claiming_many(ctx))
        return findings

    def _mac_claiming_many(self, ctx: DetectionContext) -> list[Finding]:
        """One MAC answering for an unusual number of addresses.

        Kept separate and deliberately low-confidence: a router doing proxy
        ARP produces exactly this pattern legitimately, and so does any
        gateway on a segment with secondary addressing.
        """
        cfg = ctx.config
        arp = ctx.protocols.arp
        inv = ctx.inventory
        findings: list[Finding] = []

        for mac, ips in arp.macs_claiming_many(cfg.arp_mac_many_ips):
            internal = [
                ip for ip in ips
                if (h := inv.hosts.get(ip)) is not None
                and h.kind is HostKind.INTERNAL
            ]
            if len(internal) < cfg.arp_mac_many_ips:
                continue
            sample = sorted(internal)[:10]
            finding = Finding(
                type="arp_mac_flooding",
                title=f"One MAC answering for {len(internal)} addresses",
                severity=Severity.LOW,
                confidence=0.35,
                explanation=(
                    f"MAC {mac} announced ownership of {len(internal)} distinct "
                    f"internal addresses ({', '.join(sample)}"
                    f"{', ...' if len(internal) > len(sample) else ''}). A "
                    f"router performing proxy ARP behaves this way legitimately, "
                    f"so this is reported as context rather than as a problem."
                ),
                source=mac,
                tactic="Credential Access",
                interpretation=(
                    "A single interface answering for many addresses is the "
                    "shape of either a router or a host attempting to "
                    "intercept traffic for several targets at once."
                ),
                limitations=(
                    "Proxy ARP, a gateway with secondary addresses and a "
                    "virtualisation host bridging several guests all produce "
                    "this pattern. The role of the interface has to come from "
                    "network documentation, not from the capture."
                ),
                metadata={
                    "mac": mac,
                    "claimed_ips": len(internal),
                    "sample": sample,
                },
            )
            finding.add(
                f"{len(internal)} internal addresses claimed by {mac}",
                mac=mac, claimed_ips=len(internal), sample=sample,
            )
            findings.append(finding)
        return findings