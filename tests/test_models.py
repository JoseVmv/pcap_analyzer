"""Tests for the core data models (no Scapy involved: models are built by
hand, proving analysis code can be tested without touching capture files)."""

from __future__ import annotations

import dataclasses

import pytest

from investigator.models import CaptureSummary, NetworkEvent, Protocol, TcpFlags


def make_event(**overrides) -> NetworkEvent:
    base: dict = {
        "timestamp": 1000.0,
        "protocol": Protocol.TCP,
        "wire_bytes": 60,
    }
    base.update(overrides)
    return NetworkEvent(**base)


class TestTcpFlags:
    def test_syn_ack_bitmask(self):
        flags = TcpFlags(0x12)  # raw wire value
        assert flags == TcpFlags.SYN | TcpFlags.ACK
        assert TcpFlags.SYN in flags
        assert TcpFlags.ACK in flags
        assert TcpFlags.FIN not in flags


class TestNetworkEvent:
    def test_is_immutable(self):
        event = make_event()
        with pytest.raises(dataclasses.FrozenInstanceError):
            event.src_ip = "1.2.3.4"  # type: ignore[misc]

    def test_is_tcp_syn_only(self):
        assert make_event(tcp_flags=TcpFlags.SYN).is_tcp_syn_only
        assert not make_event(tcp_flags=TcpFlags.SYN | TcpFlags.ACK).is_tcp_syn_only
        assert not make_event(tcp_flags=TcpFlags.ACK).is_tcp_syn_only
        assert not make_event(tcp_flags=None).is_tcp_syn_only


class TestCaptureSummary:
    def test_starts_empty(self):
        summary = CaptureSummary()
        assert summary.packet_count == 0
        assert summary.total_bytes == 0
        assert summary.duration is None

    def test_accumulates_and_handles_out_of_order_timestamps(self):
        summary = CaptureSummary()
        summary.observe(make_event(timestamp=200.0, wire_bytes=100))
        summary.observe(
            make_event(timestamp=100.0, wire_bytes=50, protocol=Protocol.UDP)
        )
        assert summary.packet_count == 2
        assert summary.total_bytes == 150
        # min/max survive captures whose packets are not in chronological order
        assert summary.first_timestamp == 100.0
        assert summary.last_timestamp == 200.0
        assert summary.duration == 100.0
        assert summary.protocol_counts == {"TCP": 1, "UDP": 1}

    def test_as_dict(self):
        summary = CaptureSummary()
        summary.observe(make_event())
        summary.observe(make_event(protocol=Protocol.UDP))
        summary.observe(make_event(protocol=Protocol.UDP))
        data = summary.as_dict()
        assert data["packets"] == 3
        assert data["duration_seconds"] == 0.0
        # protocols come sorted by count (desc), then name
        assert list(data["protocols"].items()) == [("UDP", 2), ("TCP", 1)]
