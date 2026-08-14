"""Tests for file validation, format sniffing and event streaming."""

from __future__ import annotations

import pytest
from conftest import (
    BASE_TS,
    CLIENT_MAC,
    PCAPNG_TS,
    SERVER_MAC,
    build_mixed_packets,
    make_dns_query,
)

from investigator.errors import (
    CaptureFileNotFoundError,
    CorruptCaptureFileError,
    UnsupportedCaptureFormatError,
)
from investigator.models import CaptureFormat, Protocol, TcpFlags
from investigator.parser import PcapLoader, sniff_format


class TestSniffFormat:
    def test_pcap_microseconds(self, mixed_pcap):
        meta = sniff_format(mixed_pcap)
        assert meta.capture_format is CaptureFormat.PCAP_US
        assert meta.gzipped is False
        assert meta.file_size == mixed_pcap.stat().st_size

    def test_pcap_nanoseconds(self, tmp_path):
        path = tmp_path / "nano.pcap"
        path.write_bytes(b"\x4d\x3c\xb2\xa1" + b"\x00" * 20)
        assert sniff_format(path).capture_format is CaptureFormat.PCAP_NS

    def test_pcap_big_endian(self, tmp_path):
        path = tmp_path / "be.pcap"
        path.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 20)
        assert sniff_format(path).capture_format is CaptureFormat.PCAP_US

    def test_pcapng(self, pcapng_file):
        assert sniff_format(pcapng_file).capture_format is CaptureFormat.PCAPNG

    def test_gzip_wrapped(self, gzipped_pcap):
        meta = sniff_format(gzipped_pcap)
        assert meta.capture_format is CaptureFormat.PCAP_US
        assert meta.gzipped is True

    def test_missing_file(self, tmp_path):
        with pytest.raises(CaptureFileNotFoundError):
            sniff_format(tmp_path / "nope.pcap")

    def test_directory(self, tmp_path):
        with pytest.raises(CaptureFileNotFoundError):
            sniff_format(tmp_path)

    def test_empty_file(self, empty_file):
        with pytest.raises(CorruptCaptureFileError):
            sniff_format(empty_file)

    def test_garbage(self, garbage_file):
        with pytest.raises(UnsupportedCaptureFormatError):
            sniff_format(garbage_file)


class TestPcapLoader:
    def test_reads_all_packets(self, mixed_pcap):
        loader = PcapLoader(mixed_pcap)
        events = list(loader.events())
        assert len(events) == 5
        assert loader.read_count == 5
        assert loader.malformed_count == 0
        assert loader.truncated is False
        for index, event in enumerate(events):
            assert event.timestamp == pytest.approx(BASE_TS + index)

    def test_tcp_syn_event(self, mixed_pcap):
        event = list(PcapLoader(mixed_pcap).events())[0]
        assert event.protocol is Protocol.TCP
        assert (event.src_ip, event.dst_ip) == ("10.0.0.15", "93.184.216.34")
        assert (event.src_port, event.dst_port) == (51334, 443)
        assert event.tcp_flags == TcpFlags.SYN
        assert event.is_tcp_syn_only
        assert event.payload_bytes == 0
        assert event.wire_bytes == len(bytes(build_mixed_packets()[0]))
        assert event.src_mac == CLIENT_MAC
        assert event.dst_mac == SERVER_MAC

    def test_tcp_payload_event(self, mixed_pcap):
        event = list(PcapLoader(mixed_pcap).events())[1]
        assert event.tcp_flags == TcpFlags.PSH | TcpFlags.ACK
        assert not event.is_tcp_syn_only
        assert event.payload_bytes == 5  # b"hello"

    def test_udp_dns_event(self, mixed_pcap):
        event = list(PcapLoader(mixed_pcap).events())[2]
        assert event.protocol is Protocol.UDP
        assert (event.src_port, event.dst_port) == (53444, 53)
        assert event.payload_bytes == len(bytes(make_dns_query()))
        assert event.tcp_flags is None

    def test_icmp_event(self, mixed_pcap):
        event = list(PcapLoader(mixed_pcap).events())[3]
        assert event.protocol is Protocol.ICMP
        assert (event.icmp_type, event.icmp_code) == (8, 0)
        assert event.src_port is None and event.dst_port is None

    def test_arp_event(self, mixed_pcap):
        event = list(PcapLoader(mixed_pcap).events())[4]
        assert event.protocol is Protocol.ARP
        assert (event.src_ip, event.dst_ip) == ("10.0.0.15", "10.0.0.23")
        assert event.src_port is None and event.dst_port is None
        assert event.tcp_flags is None

    def test_max_packets(self, mixed_pcap):
        loader = PcapLoader(mixed_pcap, max_packets=2)
        assert len(list(loader.events())) == 2

    def test_max_packets_must_be_positive(self, mixed_pcap):
        with pytest.raises(ValueError):
            PcapLoader(mixed_pcap, max_packets=0)

    def test_header_only_capture_yields_nothing(self, header_only_pcap):
        loader = PcapLoader(header_only_pcap)
        assert list(loader.events()) == []
        assert loader.read_count == 0

    def test_truncated_capture_keeps_partial_results(self, truncated_pcap):
        loader = PcapLoader(truncated_pcap)
        events = list(loader.events())
        assert len(events) == 1
        assert events[0].protocol is Protocol.TCP

    def test_gzipped_capture(self, gzipped_pcap):
        events = list(PcapLoader(gzipped_pcap).events())
        assert len(events) == 5

    def test_pcapng_capture(self, pcapng_file):
        events = list(PcapLoader(pcapng_file).events())
        assert len(events) == 1
        event = events[0]
        assert event.protocol is Protocol.UDP
        assert (event.src_ip, event.dst_ip) == ("10.0.0.9", "8.8.8.8")
        assert event.dst_port == 53
        assert event.timestamp == pytest.approx(PCAPNG_TS)
