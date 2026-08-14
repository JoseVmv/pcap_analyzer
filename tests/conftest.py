"""Shared fixtures: tiny synthetic captures built in memory with Scapy.

No real-world pcaps are used in tests: hand-built packets make every
expected value (IPs, ports, sizes, timestamps) deterministic and keep the
repository free of binary blobs of unknown origin.  The pcapng sample is
assembled byte-by-byte with ``struct`` on purpose, so the reading path is
proven against the file-format spec and not against Scapy's own writer.
"""

from __future__ import annotations

import gzip
import logging
import struct
from pathlib import Path

# Silence Scapy's import-time warnings (missing libpcap etc.) before it loads.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

BASE_TS = 1_700_000_000.0  # arbitrary fixed instant (2023-11-14 22:13:20 UTC)
PCAPNG_TS = BASE_TS + 100.0

CLIENT_MAC = "aa:aa:aa:aa:aa:01"
SERVER_MAC = "aa:aa:aa:aa:aa:02"


def make_dns_query() -> DNS:
    """Fresh DNS layer per call: Scapy layers keep parent links, so sharing
    one instance between packets would taint the fixtures."""
    return DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com"))


def build_mixed_packets() -> list[Packet]:
    """Five packets covering TCP/UDP/ICMP/ARP, with fixed timestamps."""
    packets = [
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.15", dst="93.184.216.34")
        / TCP(sport=51334, dport=443, flags="S"),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.15", dst="93.184.216.34")
        / TCP(sport=51334, dport=443, flags="PA")
        / Raw(b"hello"),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.15", dst="10.0.0.1")
        / UDP(sport=53444, dport=53)
        / make_dns_query(),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.15", dst="10.0.0.23")
        / ICMP(),  # echo request: type 8, code 0
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / ARP(
            op=1,
            psrc="10.0.0.15",
            pdst="10.0.0.23",
            hwsrc=CLIENT_MAC,
            hwdst="00:00:00:00:00:00",
        ),
    ]
    for offset, packet in enumerate(packets):
        packet.time = BASE_TS + offset
    return packets


@pytest.fixture()
def mixed_pcap(tmp_path: Path) -> Path:
    path = tmp_path / "mixed.pcap"
    wrpcap(str(path), build_mixed_packets())
    return path


@pytest.fixture()
def gzipped_pcap(tmp_path: Path, mixed_pcap: Path) -> Path:
    path = tmp_path / "mixed.pcap.gz"
    path.write_bytes(gzip.compress(mixed_pcap.read_bytes()))
    return path


@pytest.fixture()
def truncated_pcap(tmp_path: Path, mixed_pcap: Path) -> Path:
    """Global header + first full record + 10 bytes of the next record header.

    Simulates a capture cut mid-write; the loader must keep the first packet
    and stop cleanly.
    """
    first_frame_len = len(bytes(build_mixed_packets()[0]))
    cut = 24 + 16 + first_frame_len + 10  # global hdr + record hdr + frame + partial
    path = tmp_path / "truncated.pcap"
    path.write_bytes(mixed_pcap.read_bytes()[:cut])
    return path


@pytest.fixture()
def header_only_pcap(tmp_path: Path) -> Path:
    """A valid pcap global header with zero packet records."""
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    path = tmp_path / "header_only.pcap"
    path.write_bytes(header)
    return path


def pcapng_bytes(frame: bytes, ts_microseconds: int) -> bytes:
    """Hand-built minimal pcapng: SHB + IDB + one Enhanced Packet Block."""
    shb = struct.pack(
        "<IIIHHqI",
        0x0A0D0D0A,  # block type: Section Header Block
        28,          # block total length
        0x1A2B3C4D,  # byte-order magic
        1, 0,        # version 1.0
        -1,          # section length: unknown
        28,
    )
    idb = struct.pack(
        "<IIHHII",
        0x00000001,  # block type: Interface Description Block
        20,
        1,           # linktype 1 = Ethernet
        0,           # reserved
        262_144,     # snaplen
        20,
    )
    padding = (-len(frame)) % 4
    block_len = 32 + len(frame) + padding
    epb = (
        struct.pack(
            "<IIIIIII",
            0x00000006,  # block type: Enhanced Packet Block
            block_len,
            0,           # interface id
            ts_microseconds >> 32,
            ts_microseconds & 0xFFFFFFFF,
            len(frame),  # captured length
            len(frame),  # original length
        )
        + frame
        + b"\x00" * padding
        + struct.pack("<I", block_len)
    )
    return shb + idb + epb


@pytest.fixture()
def pcapng_file(tmp_path: Path) -> Path:
    frame = bytes(
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.9", dst="8.8.8.8")
        / UDP(sport=40000, dport=53)
        / Raw(b"ab")
    )
    path = tmp_path / "capture.pcapng"
    path.write_bytes(pcapng_bytes(frame, int(PCAPNG_TS * 1_000_000)))
    return path


def build_dns_packets() -> list[Packet]:
    """DNS traffic for the V2 analyser: normal query/response, an NXDOMAIN,
    and a tunnel-looking TXT query with a long random subdomain."""
    client = "10.0.0.15"
    other_client = "10.0.0.21"
    resolver = "10.0.0.1"

    def pkt(src: str, dst: str, sport: int, dport: int, dns: DNS) -> Packet:
        return (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=src, dst=dst)
            / UDP(sport=sport, dport=dport)
            / dns
        )

    packets = [
        # normal query + A response
        pkt(client, resolver, 53001, 53,
            DNS(id=1, rd=1, qd=DNSQR(qname="www.example.com"))),
        pkt(resolver, client, 53, 53001,
            DNS(id=1, qr=1, rd=1, ra=1,
                qd=DNSQR(qname="www.example.com"),
                an=DNSRR(rrname="www.example.com", ttl=60, rdata="203.0.113.80"))),
        # NXDOMAIN
        pkt(client, resolver, 53002, 53,
            DNS(id=2, rd=1, qd=DNSQR(qname="doesnotexist.example.com"))),
        pkt(resolver, client, 53, 53002,
            DNS(id=2, qr=1, rd=1, ra=1, rcode=3,
                qd=DNSQR(qname="doesnotexist.example.com"))),
        # tunnel-looking TXT query from another client
        pkt(other_client, resolver, 53003, 53,
            DNS(id=3, rd=1,
                qd=DNSQR(qname="mzxw6ytboi2gk3tpobzxe33om4qgcidu.t.evil.io",
                         qtype=16))),
        # query for a brazilian-style multi-label suffix
        pkt(client, resolver, 53004, 53,
            DNS(id=4, rd=1, qd=DNSQR(qname="loja.empresa.com.br"))),
    ]
    for offset, packet in enumerate(packets):
        packet.time = BASE_TS + offset * 0.5
    return packets


@pytest.fixture()
def dns_pcap(tmp_path: Path) -> Path:
    path = tmp_path / "dns.pcap"
    wrpcap(str(path), build_dns_packets())
    return path


@pytest.fixture()
def garbage_file(tmp_path: Path) -> Path:
    path = tmp_path / "garbage.bin"
    path.write_bytes(b"This is definitely not a packet capture file.")
    return path


@pytest.fixture()
def empty_file(tmp_path: Path) -> Path:
    path = tmp_path / "empty.pcap"
    path.touch()
    return path
