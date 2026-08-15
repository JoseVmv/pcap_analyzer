"""ARP tracking: who claims to own which address on the local segment.

ARP has no authentication whatsoever - any host can announce "this IP is at
my MAC" and the segment believes it.  That makes it the classic vehicle for
man-in-the-middle on a LAN, and it makes the *binding history* the thing
worth aggregating: one IP claimed by two different MACs during a single
capture is the observable trace of that behaviour.

Why this analyser needs raw packets
-----------------------------------
:class:`~investigator.models.NetworkEvent` carries the Ethernet source MAC,
which is enough for inventory, but ARP spoofing lives in the *difference*
between two places where a MAC appears:

* the Ethernet header (``Ether.src``), rewritten by any switch-attached NIC;
* the ARP payload (``ARP.hwsrc``), which is what receivers cache.

A forged ARP frequently leaves those two disagreeing, so the analyser reads
the ARP layer directly - the same ``wants_packets`` contract DNS, HTTP and
TLS already use.

What is deliberately *not* concluded here
-----------------------------------------
A changed binding is not proof of an attack.  DHCP reassignment, a replaced
NIC, a VM migration and a VRRP/CARP failover all move an IP between MACs
legitimately.  The tracker therefore records *bindings and their timing* and
leaves interpretation to the detector, which weighs how rapidly and how
often the claims alternate.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from scapy.layers.l2 import ARP
from scapy.packet import Packet

from investigator.models import NetworkEvent

LOG = logging.getLogger(__name__)

#: Distinct IPs whose binding history is tracked.  Beyond this, new
#: addresses are counted but not stored (never silently dropped).
_MAX_TRACKED_IPS = 50_000
#: Distinct MACs remembered per IP.  A genuine conflict shows up in the
#: first handful; a flood of them is itself recorded via ``binding_overflow``.
_MAX_MACS_PER_IP = 32

#: ARP opcodes we care to name.
_OPCODES = {1: "request", 2: "reply"}

#: Unset / placeholder addresses that must never be read as a claim.
#: ``0.0.0.0`` is an ARP probe (RFC 5227 duplicate-address detection): the
#: sender is asking whether an address is free, not announcing that it owns
#: it.  Counting probes as bindings would invent conflicts on every DHCP
#: client boot.
_NULL_IPS = frozenset({"0.0.0.0", "", "::"})
_NULL_MACS = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", ""})


@dataclass(slots=True)
class MacBinding:
    """One MAC's claim on one IP, with how long and how loudly it claimed."""

    mac: str
    packets: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    replies: int = 0
    gratuitous: int = 0

    def record(self, timestamp: float, opcode: int, gratuitous: bool) -> None:
        if self.packets == 0:
            self.first_seen = timestamp
        self.packets += 1
        self.last_seen = max(self.last_seen, timestamp)
        if opcode == 2:
            self.replies += 1
        if gratuitous:
            self.gratuitous += 1

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    def as_dict(self) -> dict[str, object]:
        return {
            "mac": self.mac,
            "packets": self.packets,
            "replies": self.replies,
            "gratuitous": self.gratuitous,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(slots=True)
class ArpBindings:
    """Every MAC observed claiming one particular IP address."""

    ip: str
    bindings: dict[str, MacBinding] = field(default_factory=dict)
    #: frames whose Ethernet source disagreed with the ARP sender hardware
    #: address - a mismatch a normal stack does not produce
    ether_mismatches: int = 0
    binding_overflow: bool = False

    def record(
        self,
        mac: str,
        timestamp: float,
        opcode: int,
        *,
        gratuitous: bool,
        ether_mismatch: bool,
    ) -> None:
        binding = self.bindings.get(mac)
        if binding is None:
            if len(self.bindings) >= _MAX_MACS_PER_IP:
                self.binding_overflow = True
                return
            binding = MacBinding(mac=mac)
            self.bindings[mac] = binding
        binding.record(timestamp, opcode, gratuitous)
        if ether_mismatch:
            self.ether_mismatches += 1

    @property
    def is_conflicted(self) -> bool:
        """True when more than one MAC claimed this address."""
        return len(self.bindings) > 1

    def ordered(self) -> list[MacBinding]:
        """Claims ordered by when they first appeared."""
        return sorted(self.bindings.values(), key=lambda b: b.first_seen)

    def dominant(self) -> MacBinding | None:
        """The MAC that claimed this IP in the most frames."""
        if not self.bindings:
            return None
        return max(self.bindings.values(), key=lambda b: b.packets)

    @property
    def overlap_seconds(self) -> float:
        """How long two claims coexisted.

        A sequential handover (old MAC stops, new MAC starts) has ~no
        overlap and is the ordinary explanation - DHCP reassignment, a
        replaced NIC.  Two MACs claiming the same address *at the same
        time* is the shape that ordinary operation does not produce, so
        the detector weighs this heavily.
        """
        claims = self.ordered()
        if len(claims) < 2:
            return 0.0
        overlap = 0.0
        for i, claim in enumerate(claims):
            for other in claims[i + 1:]:
                start = max(claim.first_seen, other.first_seen)
                end = min(claim.last_seen, other.last_seen)
                overlap = max(overlap, end - start)
        return max(0.0, overlap)

    def as_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "mac_count": len(self.bindings),
            "conflicted": self.is_conflicted,
            "ether_mismatches": self.ether_mismatches,
            "overlap_seconds": round(self.overlap_seconds, 3),
            "binding_overflow": self.binding_overflow,
            "bindings": [b.as_dict() for b in self.ordered()],
        }


class ArpTracker:
    """Collector building the ARP binding history of the local segment."""

    wants_packets = True

    def __init__(self) -> None:
        self.bindings: dict[str, ArpBindings] = {}
        self.mac_to_ips: dict[str, set[str]] = {}
        self.opcodes: dict[str, int] = {}
        self.requests = 0
        self.replies = 0
        self.gratuitous = 0
        self.probes = 0
        self.ether_mismatches = 0
        self.tracked_overflow = False
        self.parse_errors = 0

    def observe_packet(self, event: NetworkEvent, packet: Packet) -> None:
        arp = packet.getlayer(ARP)
        if arp is None:
            return
        try:
            self._record(arp, event)
        except Exception:  # a malformed ARP must never abort the run
            self.parse_errors += 1
            LOG.debug("failed to parse ARP message", exc_info=True)

    def _record(self, arp: Packet, event: NetworkEvent) -> None:
        opcode = int(arp.op)
        self.opcodes[_OPCODES.get(opcode, str(opcode))] = (
            self.opcodes.get(_OPCODES.get(opcode, str(opcode)), 0) + 1
        )
        if opcode == 1:
            self.requests += 1
        elif opcode == 2:
            self.replies += 1

        psrc = (arp.psrc or "").strip()
        hwsrc = (arp.hwsrc or "").strip().lower()
        pdst = (arp.pdst or "").strip()

        if psrc in _NULL_IPS:
            self.probes += 1
            return  # duplicate-address probe, not an ownership claim
        if hwsrc in _NULL_MACS:
            return

        # Gratuitous ARP: sender announces its own address unprompted.
        # Legitimate on interface-up and after failover, and also the
        # standard way a poisoner keeps its forged entry alive - so it is
        # counted as context, never treated as a verdict on its own.
        gratuitous = psrc == pdst or (opcode == 2 and pdst in _NULL_IPS)
        if gratuitous:
            self.gratuitous += 1

        ether_src = (event.src_mac or "").strip().lower()
        ether_mismatch = bool(ether_src) and ether_src != hwsrc
        if ether_mismatch:
            self.ether_mismatches += 1

        entry = self.bindings.get(psrc)
        if entry is None:
            if len(self.bindings) >= _MAX_TRACKED_IPS:
                self.tracked_overflow = True
                return
            entry = ArpBindings(ip=psrc)
            self.bindings[psrc] = entry
        entry.record(
            hwsrc,
            event.timestamp,
            opcode,
            gratuitous=gratuitous,
            ether_mismatch=ether_mismatch,
        )
        self.mac_to_ips.setdefault(hwsrc, set()).add(psrc)

    # --------------------------------------------------------------- views

    def conflicts(self) -> list[ArpBindings]:
        """IPs claimed by more than one MAC, most-claimed first."""
        return sorted(
            (b for b in self.bindings.values() if b.is_conflicted),
            key=lambda b: (-len(b.bindings), b.ip),
        )

    def macs_claiming_many(self, minimum: int) -> list[tuple[str, set[str]]]:
        """MACs that claimed at least ``minimum`` distinct IPs."""
        return sorted(
            ((mac, ips) for mac, ips in self.mac_to_ips.items() if len(ips) >= minimum),
            key=lambda item: -len(item[1]),
        )

    def as_dict(self) -> dict[str, object]:
        conflicted = self.conflicts()
        return {
            "packets": self.requests + self.replies,
            "requests": self.requests,
            "replies": self.replies,
            "gratuitous": self.gratuitous,
            "probes": self.probes,
            "ether_mismatches": self.ether_mismatches,
            "tracked_ips": len(self.bindings),
            "tracked_overflow": self.tracked_overflow,
            "parse_errors": self.parse_errors,
            "conflicted_ips": [b.as_dict() for b in conflicted[:50]],
        }