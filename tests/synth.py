"""Reusable builders of synthetic attack traffic for detector tests.

Each function returns a list of Scapy packets with fixed timestamps.  They
encode textbook behaviours (a SYN sweep, a metronomic beacon, an entropic
DNS-tunnel) so a detector test asserts on ground truth we constructed, not
on a captured artefact of unknown provenance.
"""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

BASE_TS = 1_700_000_000.0
MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"
MAC_ATTACKER = "02:00:00:00:00:66"


def _eth() -> Ether:
    return Ether(src=MAC_A, dst=MAC_B)


def vertical_scan(
    attacker: str = "10.0.0.15",
    target: str = "10.0.0.23",
    ports=range(1, 41),
    start: float = BASE_TS,
) -> list[Packet]:
    """One host sends unanswered SYNs to many ports on one target."""
    packets = []
    for i, port in enumerate(ports):
        pkt = _eth() / IP(src=attacker, dst=target) / TCP(
            sport=40000 + i, dport=int(port), flags="S", seq=1
        )
        pkt.time = start + i * 0.05
        packets.append(pkt)
    return packets


def horizontal_scan(
    attacker: str = "10.0.0.15",
    port: int = 445,
    targets=None,
    start: float = BASE_TS,
) -> list[Packet]:
    """One host sends unanswered SYNs to one port across many hosts."""
    targets = targets or [f"10.0.0.{i}" for i in range(20, 45)]
    packets = []
    for i, target in enumerate(targets):
        pkt = _eth() / IP(src=attacker, dst=target) / TCP(
            sport=41000 + i, dport=port, flags="S", seq=1
        )
        pkt.time = start + i * 0.05
        packets.append(pkt)
    return packets


def beacon(
    client: str = "10.0.0.15",
    server: str = "203.0.113.66",
    dport: int = 4444,
    count: int = 30,
    interval: float = 30.0,
    jitter: float = 0.0,
    start: float = BASE_TS,
) -> list[Packet]:
    """Regular TCP SYN check-ins (optionally with +/- jitter seconds)."""
    packets = []
    for i in range(count):
        offset = start + i * interval + (jitter if i % 2 else -jitter)
        pkt = _eth() / IP(src=client, dst=server) / TCP(
            sport=50000 + i, dport=dport, flags="S", seq=1
        )
        pkt.time = offset
        packets.append(pkt)
    return packets


def ntp_beacon(
    client: str = "10.0.0.15",
    server: str = "203.0.113.123",
    count: int = 30,
    interval: float = 64.0,
    start: float = BASE_TS,
) -> list[Packet]:
    """Regular UDP/123 poll - a *legitimate* beacon, for FP-suppression tests."""
    packets = []
    for i in range(count):
        pkt = _eth() / IP(src=client, dst=server) / UDP(sport=48000, dport=123) / Raw(
            b"\x1b" + b"\x00" * 47
        )
        pkt.time = start + i * interval
        packets.append(pkt)
    return packets


def dns_tunnel(
    client: str = "10.0.0.21",
    resolver: str = "10.0.0.1",
    base_domain: str = "tunnel.evil.io",
    count: int = 30,
    start: float = BASE_TS,
) -> list[Packet]:
    """Many high-entropy, long-label TXT queries under one base domain."""
    import random

    rng = random.Random(1234)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    packets = []
    for i in range(count):
        label = "".join(rng.choice(alphabet) for _ in range(45))
        qname = f"{label}.{base_domain}"
        pkt = _eth() / IP(src=client, dst=resolver) / UDP(
            sport=53000 + i, dport=53
        ) / DNS(id=i + 1, rd=1, qd=DNSQR(qname=qname, qtype=16))
        pkt.time = start + i * 1.0
        packets.append(pkt)
    return packets


def lateral_movement(
    attacker: str = "10.0.0.15",
    targets=("10.0.0.23", "10.0.0.24", "10.0.0.25", "10.0.0.26"),
    port: int = 445,
    start: float = BASE_TS,
) -> list[Packet]:
    """Successful (handshake-completing) admin sessions to several internal
    hosts - the shape that separates lateral movement from a scan."""
    packets = []
    t = start
    for i, target in enumerate(targets):
        sport = 47000 + i
        syn = _eth() / IP(src=attacker, dst=target) / TCP(
            sport=sport, dport=port, flags="S", seq=1)
        synack = _eth() / IP(src=target, dst=attacker) / TCP(
            sport=port, dport=sport, flags="SA", seq=900)
        ack = _eth() / IP(src=attacker, dst=target) / TCP(
            sport=sport, dport=port, flags="A", seq=2)
        data = _eth() / IP(src=attacker, dst=target) / TCP(
            sport=sport, dport=port, flags="PA", seq=2) / Raw(b"S" * 200)
        for j, pkt in enumerate((syn, synack, ack, data)):
            pkt.time = t + j * 0.01
        packets += [syn, synack, ack, data]
        t += 20.0
    return packets


def arp_poisoning(
    victim_ip: str = "10.0.0.1",
    real_mac: str = MAC_B,
    attacker_mac: str = MAC_ATTACKER,
    count: int = 8,
    start: float = BASE_TS,
) -> list[Packet]:
    """Two MACs claiming one address *at the same time*.

    The real owner keeps answering normally while the attacker interleaves
    gratuitous announcements for the same address - the concurrency is what
    separates poisoning from an ordinary address handover.
    """
    packets = []
    for i in range(count):
        legit = Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, psrc=victim_ip, hwsrc=real_mac,
            pdst="10.0.0.50", hwdst=MAC_A,
        )
        legit.time = start + i * 10.0
        forged = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, psrc=victim_ip, hwsrc=attacker_mac,
            pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff",   # gratuitous
        )
        forged.time = start + i * 10.0 + 1.0
        packets += [legit, forged]
    return packets


def arp_normal(
    start: float = BASE_TS,
    count: int = 10,
) -> list[Packet]:
    """Ordinary request/reply ARP: one MAC per address, no conflict."""
    packets = []
    for i in range(count):
        request = Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, psrc="10.0.0.50", hwsrc=MAC_A, pdst="10.0.0.1",
        )
        request.time = start + i * 5.0
        reply = Ether(src=MAC_B, dst=MAC_A) / ARP(
            op=2, psrc="10.0.0.1", hwsrc=MAC_B, pdst="10.0.0.50", hwdst=MAC_A,
        )
        reply.time = start + i * 5.0 + 0.01
        packets += [request, reply]
    return packets


def icmp_tunnel(
    client: str = "10.0.0.15",
    server: str = "203.0.113.66",
    count: int = 40,
    start: float = BASE_TS,
) -> list[Packet]:
    """Echo requests carrying large, varying payloads - carrier-shaped."""
    import random

    rng = random.Random(99)
    packets = []
    for i in range(count):
        size = rng.randint(600, 1200)   # large and different every time
        pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src=client, dst=server) / ICMP(
            type=8, code=0, id=1, seq=i
        ) / Raw(bytes(rng.getrandbits(8) for _ in range(size)))
        pkt.time = start + i * 0.5
        packets.append(pkt)
    return packets


def icmp_ping(
    client: str = "10.0.0.15",
    server: str = "10.0.0.23",
    count: int = 30,
    payload: int = 32,
    start: float = BASE_TS,
) -> list[Packet]:
    """A *legitimate* ping: one constant conventional payload size.

    Used for false-positive suppression - this must never be reported as
    tunnelling, however many packets it contains.
    """
    packets = []
    for i in range(count):
        request = Ether(src=MAC_A, dst=MAC_B) / IP(src=client, dst=server) / ICMP(
            type=8, code=0, id=7, seq=i
        ) / Raw(b"\x61" * payload)
        request.time = start + i * 1.0
        reply = Ether(src=MAC_B, dst=MAC_A) / IP(src=server, dst=client) / ICMP(
            type=0, code=0, id=7, seq=i
        ) / Raw(b"\x61" * payload)
        reply.time = start + i * 1.0 + 0.01
        packets += [request, reply]
    return packets


def icmp_sweep(
    attacker: str = "10.0.0.15",
    targets=None,
    start: float = BASE_TS,
) -> list[Packet]:
    """Echo requests across many addresses, none of which answer."""
    targets = targets or [f"10.0.0.{i}" for i in range(60, 100)]
    packets = []
    for i, target in enumerate(targets):
        pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src=attacker, dst=target) / ICMP(
            type=8, code=0, id=3, seq=i
        ) / Raw(b"\x00" * 32)
        pkt.time = start + i * 0.05
        packets.append(pkt)
    return packets


def bulk_upload(
    client: str = "10.0.0.15",
    server: str = "203.0.113.66",
    dport: int = 443,
    segments: int = 400,
    seg_bytes: int = 1400,
    start: float = BASE_TS + 500,
) -> list[Packet]:
    """A large one-directional data transfer (exfil-shaped) in a short burst."""
    packets = []
    seq = 1
    for i in range(segments):
        pkt = _eth() / IP(src=client, dst=server) / TCP(
            sport=52000, dport=dport, flags="PA", seq=seq
        ) / Raw(b"D" * seg_bytes)
        pkt.time = start + i * 0.01
        packets.append(pkt)
        seq += seg_bytes
    return packets
