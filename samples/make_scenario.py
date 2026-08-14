"""Generate ``samples/scenario_incident.pcap`` - a synthetic, self-contained
incident used to demonstrate the whole pipeline (V3 detection through V7
investigation).

Storyline, all from suspect 10.0.0.15, interleaved with benign background
traffic from other hosts:

1. Reconnaissance   - horizontal SMB(445) sweep of the /24, then a vertical
   port sweep of one neighbour.
2. Lateral movement - successful SMB sessions to several internal hosts.
3. C2               - regular 30s beacon to an external IP on an odd port,
   with no DNS resolution (direct-to-IP).
4. DNS tunneling    - high-entropy TXT queries under one base domain.
5. Exfiltration     - a large one-directional upload to the C2 host.

Everything uses RFC 5737 documentation IPs and fixed timestamps, so the file
is harmless and reproducible.  This is *constructed* ground truth, not a real
capture.
"""

from __future__ import annotations

import random
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

BASE = 1_755_086_400.0  # 2025-08-13 12:00:00 UTC
SUSPECT = "10.0.0.15"
RESOLVER = "10.0.0.1"
C2 = "203.0.113.66"
MAC = "02:00:00:00:00:15"
GW_MAC = "02:00:00:00:00:01"

rng = random.Random(20250813)


def eth() -> Ether:
    return Ether(src=MAC, dst=GW_MAC)


def at(packets: list[Packet], t: float, pkt: Packet) -> None:
    pkt.time = BASE + t
    packets.append(pkt)


def background(packets: list[Packet]) -> None:
    """Benign traffic from a few ordinary hosts (web + DNS)."""
    for host_id, t0 in ((11, 5), (12, 12), (13, 40), (14, 75)):
        host = f"10.0.0.{host_id}"
        # DNS lookup
        at(packets, t0, eth() / IP(src=host, dst=RESOLVER)
           / UDP(sport=40000 + host_id, dport=53)
           / DNS(id=host_id, rd=1, qd=DNSQR(qname="www.example.com")))
        at(packets, t0 + 0.03, eth() / IP(src=RESOLVER, dst=host)
           / UDP(sport=53, dport=40000 + host_id)
           / DNS(id=host_id, qr=1, rd=1, ra=1, qd=DNSQR(qname="www.example.com"),
                 an=DNSRR(rrname="www.example.com", ttl=300, rdata="203.0.113.80")))
        # short established HTTPS session (SYN/SYN-ACK/ACK + data)
        at(packets, t0 + 0.1, eth() / IP(src=host, dst="203.0.113.80")
           / TCP(sport=51000 + host_id, dport=443, flags="S", seq=1))
        at(packets, t0 + 0.15, eth() / IP(src="203.0.113.80", dst=host)
           / TCP(sport=443, dport=51000 + host_id, flags="SA", seq=100))
        at(packets, t0 + 0.16, eth() / IP(src=host, dst="203.0.113.80")
           / TCP(sport=51000 + host_id, dport=443, flags="A", seq=2))
        at(packets, t0 + 0.2, eth() / IP(src=host, dst="203.0.113.80")
           / TCP(sport=51000 + host_id, dport=443, flags="PA", seq=2)
           / Raw(b"\x16\x03\x01" + b"\x00" * 200))


def reconnaissance(packets: list[Packet]) -> None:
    t = 100.0
    # horizontal SMB sweep across the /24 (unanswered SYNs)
    for i in range(2, 40):
        at(packets, t, eth() / IP(src=SUSPECT, dst=f"10.0.0.{i}")
           / TCP(sport=42000 + i, dport=445, flags="S", seq=1))
        t += 0.05
    # vertical port sweep of one neighbour
    t = 140.0
    for i, port in enumerate(range(1, 61)):
        at(packets, t, eth() / IP(src=SUSPECT, dst="10.0.0.23")
           / TCP(sport=43000 + i, dport=port, flags="S", seq=1))
        t += 0.05
    # one port answers -> a "discovered service"
    at(packets, 143.0, eth() / IP(src="10.0.0.23", dst=SUSPECT)
       / TCP(sport=445, dport=43044, flags="SA", seq=77))


def lateral_movement(packets: list[Packet]) -> None:
    """Successful SMB sessions to several internal hosts after the sweep."""
    t = 170.0
    for i, target in enumerate(("10.0.0.23", "10.0.0.24", "10.0.0.25", "10.0.0.26")):
        sport = 47000 + i
        at(packets, t, eth() / IP(src=SUSPECT, dst=target)
           / TCP(sport=sport, dport=445, flags="S", seq=1))
        at(packets, t + 0.01, eth() / IP(src=target, dst=SUSPECT)
           / TCP(sport=445, dport=sport, flags="SA", seq=900))
        at(packets, t + 0.02, eth() / IP(src=SUSPECT, dst=target)
           / TCP(sport=sport, dport=445, flags="A", seq=2))
        at(packets, t + 0.05, eth() / IP(src=SUSPECT, dst=target)
           / TCP(sport=sport, dport=445, flags="PA", seq=2) / Raw(b"S" * 300))
        t += 5.0


def c2_beacon(packets: list[Packet]) -> None:
    """30s beacon to an external IP on an odd port, direct-to-IP."""
    t = 200.0
    for i in range(30):
        at(packets, t, eth() / IP(src=SUSPECT, dst=C2)
           / TCP(sport=44000 + i, dport=4444, flags="S", seq=1))
        at(packets, t + 0.05, eth() / IP(src=C2, dst=SUSPECT)
           / TCP(sport=4444, dport=44000 + i, flags="SA", seq=500))
        at(packets, t + 0.06, eth() / IP(src=SUSPECT, dst=C2)
           / TCP(sport=44000 + i, dport=4444, flags="A", seq=2))
        at(packets, t + 0.1, eth() / IP(src=SUSPECT, dst=C2)
           / TCP(sport=44000 + i, dport=4444, flags="PA", seq=2) / Raw(b"ping" * 8))
        t += 30.0  # exactly periodic


def dns_tunnel(packets: list[Packet]) -> None:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    t = 260.0
    for i in range(40):
        label = "".join(rng.choice(alphabet) for _ in range(48))
        at(packets, t, eth() / IP(src=SUSPECT, dst=RESOLVER)
           / UDP(sport=45000 + i, dport=53)
           / DNS(id=1000 + i, rd=1, qd=DNSQR(qname=f"{label}.x.dataleak.io", qtype=16)))
        # half of them NXDOMAIN
        rcode = 3 if i % 2 else 0
        at(packets, t + 0.02, eth() / IP(src=RESOLVER, dst=SUSPECT)
           / UDP(sport=53, dport=45000 + i)
           / DNS(id=1000 + i, qr=1, rd=1, ra=1, rcode=rcode,
                 qd=DNSQR(qname=f"{label}.x.dataleak.io", qtype=16)))
        t += 2.0


def exfiltration(packets: list[Packet]) -> None:
    """Large one-directional upload to the C2 host."""
    t = 900.0
    seq = 1
    for i in range(1500):
        at(packets, t, eth() / IP(src=SUSPECT, dst=C2)
           / TCP(sport=46000, dport=4444, flags="PA", seq=seq) / Raw(b"E" * 1400))
        # sparse ACKs back
        if i % 20 == 0:
            at(packets, t + 0.001, eth() / IP(src=C2, dst=SUSPECT)
               / TCP(sport=4444, dport=46000, flags="A", seq=1))
        seq += 1400
        t += 0.01


def build() -> list[Packet]:
    packets: list[Packet] = []
    background(packets)
    reconnaissance(packets)
    lateral_movement(packets)
    c2_beacon(packets)
    dns_tunnel(packets)
    exfiltration(packets)
    packets.sort(key=lambda p: p.time)
    return packets


def main() -> None:
    packets = build()
    output = Path(__file__).with_name("scenario_incident.pcap")
    wrpcap(str(output), packets)
    print(f"wrote {output} ({len(packets)} packets)")


if __name__ == "__main__":
    main()
