"""Generate ``samples/scenario_incident.pcap`` - a synthetic, self-contained
incident used to demonstrate the whole pipeline (V3 detection through V7
investigation).

Storyline, all from suspect 10.0.0.15, interleaved with benign background
traffic from other hosts:

1. Reconnaissance   - horizontal SMB(445) sweep of the /24, then a vertical
   port sweep of one neighbour, plus an ICMP sweep of a second range.
2. ARP poisoning    - the suspect contests the gateway's address, claiming
   10.0.0.1 while the real gateway is still answering for it.
3. Lateral movement - successful SMB sessions to several internal hosts.
4. C2               - regular 30s beacon to an external IP on an odd port,
   with no DNS resolution (direct-to-IP), plus a TLS session whose SNI no
   DNS answer in the capture ever resolved.
5. DNS tunneling    - high-entropy TXT queries under one base domain.
6. Exfiltration     - a large one-directional upload to the C2 host, and an
   ICMP echo channel carrying large, varying payloads.

Everything uses RFC 5737 documentation IPs and fixed timestamps, so the file
is harmless and reproducible.  This is *constructed* ground truth, not a real
capture.
"""

from __future__ import annotations

import random
import struct
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

BASE = 1_755_086_400.0  # 2025-08-13 12:00:00 UTC
SUSPECT = "10.0.0.15"
RESOLVER = "10.0.0.1"
C2 = "203.0.113.66"
MAC = "02:00:00:00:00:15"
GW_MAC = "02:00:00:00:00:01"
CDN = "203.0.113.80"

rng = random.Random(20250813)


def eth() -> Ether:
    """Frame from the suspect towards the gateway."""
    return Ether(src=MAC, dst=GW_MAC)


def mac_for(ip: str) -> str:
    """A stable per-host MAC derived from the last octet.

    Each host needs its own hardware address, exactly as on a real segment:
    sharing one MAC across hosts would make address-level attribution
    meaningless - and it is what the ARP analysis reasons about.
    """
    return f"02:00:00:00:00:{int(ip.rsplit('.', 1)[1]):02x}"


def eth_from(ip: str, dst_ip: str = "") -> Ether:
    """Frame from ``ip``, using that host's own MAC."""
    dst = mac_for(dst_ip) if dst_ip.startswith("10.0.0.") else GW_MAC
    return Ether(src=mac_for(ip), dst=dst)


def eth_in() -> Ether:
    """Frame arriving for the suspect from outside: it crosses the router,
    so the source MAC on this segment is the gateway's, not the remote
    host's."""
    return Ether(src=GW_MAC, dst=MAC)


def at(packets: list[Packet], t: float, pkt: Packet) -> None:
    pkt.time = BASE + t
    packets.append(pkt)


def client_hello(sni: str | None, ciphers: bytes = b"\x13\x01\x13\x02\xc0\x2b") -> bytes:
    """A TLS ClientHello, assembled per RFC 8446 (cleartext preamble only)."""
    extensions = b""
    if sni is not None:
        name = sni.encode()
        entry = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
        extensions += struct.pack("!HH", 0, len(entry)) + entry
    versions = bytes([4]) + struct.pack("!HH", 0x0304, 0x0303)
    extensions += struct.pack("!HH", 43, len(versions)) + versions

    body = (
        struct.pack("!H", 0x0303)
        + b"\x00" * 32
        + b"\x00"
        + struct.pack("!H", len(ciphers)) + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def background(packets: list[Packet]) -> None:
    """Benign traffic from a few ordinary hosts (web + DNS)."""
    for host_id, t0 in ((11, 5), (12, 12), (13, 40), (14, 75)):
        host = f"10.0.0.{host_id}"
        # DNS lookup
        at(packets, t0, eth_from(host) / IP(src=host, dst=RESOLVER)
           / UDP(sport=40000 + host_id, dport=53)
           / DNS(id=host_id, rd=1, qd=DNSQR(qname="www.example.com")))
        at(packets, t0 + 0.03, eth_from(RESOLVER, host) / IP(src=RESOLVER, dst=host)
           / UDP(sport=53, dport=40000 + host_id)
           / DNS(id=host_id, qr=1, rd=1, ra=1, qd=DNSQR(qname="www.example.com"),
                 an=DNSRR(rrname="www.example.com", ttl=300, rdata=CDN)))
        # short established HTTPS session (SYN/SYN-ACK/ACK + real ClientHello).
        # The SNI matches the name the DNS answer above resolved to this
        # address, so the TLS cross-check must stay silent on it - the
        # scenario carries its own false-positive control.
        at(packets, t0 + 0.1, eth_from(host) / IP(src=host, dst=CDN)
           / TCP(sport=51000 + host_id, dport=443, flags="S", seq=1))
        at(packets, t0 + 0.15, Ether(src=GW_MAC, dst=mac_for(host))
           / IP(src=CDN, dst=host)
           / TCP(sport=443, dport=51000 + host_id, flags="SA", seq=100))
        at(packets, t0 + 0.16, eth_from(host) / IP(src=host, dst=CDN)
           / TCP(sport=51000 + host_id, dport=443, flags="A", seq=2))
        at(packets, t0 + 0.2, eth_from(host) / IP(src=host, dst=CDN)
           / TCP(sport=51000 + host_id, dport=443, flags="PA", seq=2)
           / Raw(client_hello("www.example.com")))


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
    at(packets, 143.0, eth_from("10.0.0.23", SUSPECT) / IP(src="10.0.0.23", dst=SUSPECT)
       / TCP(sport=445, dport=43044, flags="SA", seq=77))


def arp_poisoning(packets: list[Packet]) -> None:
    """The suspect claims the gateway's address while the gateway still
    answers for it - two MACs owning 10.0.0.1 at the same time."""
    t = 150.0
    for i in range(10):
        # the real gateway replying normally to a neighbour
        real = Ether(src=GW_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, psrc=RESOLVER, hwsrc=GW_MAC, pdst="10.0.0.12",
            hwdst="02:00:00:00:00:12",
        )
        at(packets, t, real)
        # the suspect announcing the same address, unprompted
        forged = Ether(src=MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, psrc=RESOLVER, hwsrc=MAC, pdst=RESOLVER,
            hwdst="ff:ff:ff:ff:ff:ff",
        )
        at(packets, t + 1.0, forged)
        t += 6.0


def icmp_sweep(packets: list[Packet]) -> None:
    """Ping sweep of a range where almost nothing exists."""
    t = 130.0
    for i in range(60, 110):
        at(packets, t, eth() / IP(src=SUSPECT, dst=f"10.0.1.{i}")
           / ICMP(type=8, code=0, id=9, seq=i) / Raw(b"\x00" * 32))
        t += 0.05


def icmp_tunnel(packets: list[Packet]) -> None:
    """Echo requests carrying large, varying payloads to an external host."""
    t = 1000.0
    for i in range(60):
        size = rng.randint(700, 1300)
        at(packets, t, eth() / IP(src=SUSPECT, dst=C2)
           / ICMP(type=8, code=0, id=11, seq=i)
           / Raw(bytes(rng.getrandbits(8) for _ in range(size))))
        at(packets, t + 0.05, eth_in() / IP(src=C2, dst=SUSPECT)
           / ICMP(type=0, code=0, id=11, seq=i) / Raw(b"\x00" * 16))
        t += 1.5


def suspicious_tls(packets: list[Packet]) -> None:
    """A TLS session whose SNI no DNS answer in this capture resolved, from
    a client whose TLS fingerprint no other host on the network shares."""
    t = 320.0
    for i, host in enumerate(("cdn-sync.telemetry-node.io", "api.telemetry-node.io")):
        sport = 53000 + i
        at(packets, t, eth() / IP(src=SUSPECT, dst=C2)
           / TCP(sport=sport, dport=443, flags="S", seq=1))
        at(packets, t + 0.02, eth_in() / IP(src=C2, dst=SUSPECT)
           / TCP(sport=443, dport=sport, flags="SA", seq=700))
        at(packets, t + 0.03, eth() / IP(src=SUSPECT, dst=C2)
           / TCP(sport=sport, dport=443, flags="A", seq=2))
        at(packets, t + 0.05, eth() / IP(src=SUSPECT, dst=C2)
           / TCP(sport=sport, dport=443, flags="PA", seq=2)
           # a distinct cipher ordering: a different TLS stack from the
           # browsers the background hosts run
           / Raw(client_hello(host, ciphers=b"\xc0\x2b\x13\x02\x13\x01")))
        t += 45.0


def lateral_movement(packets: list[Packet]) -> None:
    """Successful SMB sessions to several internal hosts after the sweep."""
    t = 170.0
    for i, target in enumerate(("10.0.0.23", "10.0.0.24", "10.0.0.25", "10.0.0.26")):
        sport = 47000 + i
        at(packets, t, eth() / IP(src=SUSPECT, dst=target)
           / TCP(sport=sport, dport=445, flags="S", seq=1))
        at(packets, t + 0.01, eth_from(target, SUSPECT) / IP(src=target, dst=SUSPECT)
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
        at(packets, t + 0.05, eth_in() / IP(src=C2, dst=SUSPECT)
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
        at(packets, t + 0.02, eth_from(RESOLVER, SUSPECT) / IP(src=RESOLVER, dst=SUSPECT)
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
            at(packets, t + 0.001, eth_in() / IP(src=C2, dst=SUSPECT)
               / TCP(sport=4444, dport=46000, flags="A", seq=1))
        seq += 1400
        t += 0.01


def build() -> list[Packet]:
    packets: list[Packet] = []
    background(packets)
    reconnaissance(packets)
    icmp_sweep(packets)
    arp_poisoning(packets)
    lateral_movement(packets)
    c2_beacon(packets)
    suspicious_tls(packets)
    dns_tunnel(packets)
    exfiltration(packets)
    icmp_tunnel(packets)
    packets.sort(key=lambda p: p.time)
    return packets


def main() -> None:
    packets = build()
    output = Path(__file__).with_name("scenario_incident.pcap")
    wrpcap(str(output), packets)
    print(f"wrote {output} ({len(packets)} packets)")


if __name__ == "__main__":
    main()
