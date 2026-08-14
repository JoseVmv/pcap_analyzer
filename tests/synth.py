"""Reusable builders of synthetic attack traffic for detector tests.

Each function returns a list of Scapy packets with fixed timestamps.  They
encode textbook behaviours (a SYN sweep, a metronomic beacon, an entropic
DNS-tunnel) so a detector test asserts on ground truth we constructed, not
on a captured artefact of unknown provenance.
"""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

BASE_TS = 1_700_000_000.0
MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


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
