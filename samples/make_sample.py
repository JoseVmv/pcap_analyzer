"""Generate ``samples/sample_small.pcap``.

A tiny, fully synthetic capture used to demo the CLI: one workstation
resolves names via DNS, opens a short HTTP session, pings a neighbour and
polls NTP.  External addresses come from documentation ranges (RFC 5737)
and timestamps are fixed, so the file is harmless by construction and
reproducible.

Usage:
    python samples/make_sample.py
"""

from __future__ import annotations

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

BASE_TS = 1_755_086_400.0  # 2025-08-13 12:00:00 UTC (fixed for reproducibility)

CLIENT = "10.0.0.15"
NEIGHBOUR = "10.0.0.23"
GATEWAY = "10.0.0.1"
WEB_SERVER = "203.0.113.80"    # RFC 5737 TEST-NET-3
NTP_SERVER = "203.0.113.123"

CLIENT_MAC = "02:00:00:00:00:15"
GATEWAY_MAC = "02:00:00:00:00:01"
NEIGHBOUR_MAC = "02:00:00:00:00:23"

HTTP_GET = (
    b"GET / HTTP/1.1\r\n"
    b"Host: www.example.com\r\n"
    b"User-Agent: sample-client\r\n"
    b"\r\n"
)
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 512\r\n"
    b"\r\n" + b"A" * 512
)


def build_packets() -> list[Packet]:
    packets: list[Packet] = []

    def at(offset: float, packet: Packet) -> None:
        packet.time = BASE_TS + offset
        packets.append(packet)

    def client_out(dst_ip: str) -> Packet:
        return Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT, dst=dst_ip)

    def client_in(src_ip: str) -> Packet:
        return Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src=src_ip, dst=CLIENT)

    # --- ARP: client resolves the gateway --------------------------------
    at(0.000, Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
       / ARP(op=1, psrc=CLIENT, pdst=GATEWAY, hwsrc=CLIENT_MAC))
    at(0.002, Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
       / ARP(op=2, psrc=GATEWAY, pdst=CLIENT, hwsrc=GATEWAY_MAC, hwdst=CLIENT_MAC))

    # --- DNS: www.example.com --------------------------------------------
    at(0.010, client_out(GATEWAY) / UDP(sport=53411, dport=53)
       / DNS(id=0x1001, rd=1, qd=DNSQR(qname="www.example.com")))
    at(0.048, client_in(GATEWAY) / UDP(sport=53, dport=53411)
       / DNS(id=0x1001, qr=1, rd=1, ra=1,
             qd=DNSQR(qname="www.example.com"),
             an=DNSRR(rrname="www.example.com", ttl=300, rdata=WEB_SERVER)))

    # --- HTTP: handshake, request, response, close ------------------------
    at(0.060, client_out(WEB_SERVER)
       / TCP(sport=52100, dport=80, flags="S", seq=1000))
    at(0.110, client_in(WEB_SERVER)
       / TCP(sport=80, dport=52100, flags="SA", seq=5000, ack=1001))
    at(0.111, client_out(WEB_SERVER)
       / TCP(sport=52100, dport=80, flags="A", seq=1001, ack=5001))
    at(0.115, client_out(WEB_SERVER)
       / TCP(sport=52100, dport=80, flags="PA", seq=1001, ack=5001)
       / Raw(HTTP_GET))
    at(0.190, client_in(WEB_SERVER)
       / TCP(sport=80, dport=52100, flags="PA", seq=5001, ack=1001 + len(HTTP_GET))
       / Raw(HTTP_RESPONSE))
    at(0.191, client_out(WEB_SERVER)
       / TCP(sport=52100, dport=80, flags="A",
             seq=1001 + len(HTTP_GET), ack=5001 + len(HTTP_RESPONSE)))
    at(5.000, client_out(WEB_SERVER)
       / TCP(sport=52100, dport=80, flags="FA",
             seq=1001 + len(HTTP_GET), ack=5001 + len(HTTP_RESPONSE)))
    at(5.050, client_in(WEB_SERVER)
       / TCP(sport=80, dport=52100, flags="FA",
             seq=5001 + len(HTTP_RESPONSE), ack=1002 + len(HTTP_GET)))
    at(5.051, client_out(WEB_SERVER)
       / TCP(sport=52100, dport=80, flags="A",
             seq=1002 + len(HTTP_GET), ack=5002 + len(HTTP_RESPONSE)))

    # --- ICMP: ping a neighbour -------------------------------------------
    at(30.000, Ether(src=CLIENT_MAC, dst=NEIGHBOUR_MAC)
       / IP(src=CLIENT, dst=NEIGHBOUR) / ICMP(type=8, id=7, seq=1)
       / Raw(b"x" * 32))
    at(30.001, Ether(src=NEIGHBOUR_MAC, dst=CLIENT_MAC)
       / IP(src=NEIGHBOUR, dst=CLIENT) / ICMP(type=0, id=7, seq=1)
       / Raw(b"x" * 32))

    # --- NTP poll -----------------------------------------------------------
    at(60.000, client_out(NTP_SERVER) / UDP(sport=48000, dport=123)
       / Raw(b"\x1b" + b"\x00" * 47))
    at(60.045, client_in(NTP_SERVER) / UDP(sport=123, dport=48000)
       / Raw(b"\x1c" + b"\x00" * 47))

    # --- second DNS lookup, 90s in --------------------------------------
    at(90.000, client_out(GATEWAY) / UDP(sport=53412, dport=53)
       / DNS(id=0x1002, rd=1, qd=DNSQR(qname="api.example.com")))
    at(90.040, client_in(GATEWAY) / UDP(sport=53, dport=53412)
       / DNS(id=0x1002, qr=1, rd=1, ra=1,
             qd=DNSQR(qname="api.example.com"),
             an=DNSRR(rrname="api.example.com", ttl=300, rdata="203.0.113.90")))

    return packets


def main() -> None:
    packets = build_packets()
    output = Path(__file__).with_name("sample_small.pcap")
    wrpcap(str(output), packets)
    print(f"wrote {output} ({len(packets)} packets)")


if __name__ == "__main__":
    main()
