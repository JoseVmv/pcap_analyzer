"""Tests for host/conversation inventory - built from hand-made events,
no capture files involved."""

from __future__ import annotations

import json

from investigator.inventory import HostKind, NetworkInventory, classify_ip
from investigator.models import NetworkEvent, Protocol, TcpFlags


def ev(**overrides) -> NetworkEvent:
    base: dict = {
        "timestamp": 1000.0,
        "protocol": Protocol.TCP,
        "wire_bytes": 60,
        "src_ip": "10.0.0.15",
        "dst_ip": "203.0.113.80",
        "src_port": 50000,
        "dst_port": 443,
        "payload_bytes": 10,
    }
    base.update(overrides)
    return NetworkEvent(**base)


class TestClassifyIp:
    def test_kinds(self):
        assert classify_ip("10.0.0.5") is HostKind.INTERNAL
        assert classify_ip("192.168.1.1") is HostKind.INTERNAL
        assert classify_ip("127.0.0.1") is HostKind.INTERNAL
        assert classify_ip("fe80::1") is HostKind.INTERNAL
        assert classify_ip("8.8.8.8") is HostKind.EXTERNAL
        assert classify_ip("2001:4860:4860::8888") is HostKind.EXTERNAL
        assert classify_ip("224.0.0.251") is HostKind.MULTICAST
        assert classify_ip("255.255.255.255") is HostKind.BROADCAST
        assert classify_ip("0.0.0.0") is HostKind.UNSPECIFIED
        assert classify_ip("not-an-ip") is HostKind.UNSPECIFIED

    def test_cache_returns_same_result(self):
        assert classify_ip("10.9.9.9") is classify_ip("10.9.9.9")


class TestNetworkInventory:
    def test_host_accumulation_both_directions(self):
        inv = NetworkInventory()
        inv.observe(ev(timestamp=100.0))
        inv.observe(ev(timestamp=101.0, wire_bytes=100, payload_bytes=40))
        # reply direction
        inv.observe(
            ev(
                timestamp=102.0,
                src_ip="203.0.113.80",
                dst_ip="10.0.0.15",
                src_port=443,
                dst_port=50000,
                wire_bytes=200,
                payload_bytes=150,
            )
        )

        client = inv.hosts["10.0.0.15"]
        server = inv.hosts["203.0.113.80"]

        assert client.kind is HostKind.INTERNAL
        assert server.kind is HostKind.EXTERNAL
        assert client.packets_sent == 2
        assert client.packets_received == 1
        assert client.bytes_sent == 160
        assert client.bytes_received == 200
        assert client.payload_bytes_sent == 50
        assert client.first_seen == 100.0
        assert client.last_seen == 102.0
        assert client.peers == {"203.0.113.80"}
        assert client.dst_ports_contacted[443] == 2
        assert server.ports_served[443] == 2
        assert not client.is_silent

    def test_directed_conversations(self):
        inv = NetworkInventory()
        inv.observe(ev(timestamp=100.0))
        inv.observe(ev(timestamp=130.0))
        inv.observe(
            ev(timestamp=131.0, src_ip="203.0.113.80", dst_ip="10.0.0.15",
               src_port=443, dst_port=50000)
        )

        assert set(inv.conversations) == {
            ("10.0.0.15", "203.0.113.80"),
            ("203.0.113.80", "10.0.0.15"),
        }
        out = inv.conversations[("10.0.0.15", "203.0.113.80")]
        assert out.packets == 2
        assert out.duration == 30.0
        assert list(out.timestamps) == [100.0, 130.0]
        assert out.dst_ports[443] == 2

    def test_arp_marks_target_as_silent_host(self):
        inv = NetworkInventory()
        inv.observe(
            ev(
                protocol=Protocol.ARP,
                src_ip="10.0.0.15",
                dst_ip="10.0.0.99",
                src_port=None,
                dst_port=None,
                payload_bytes=0,
            )
        )
        assert inv.hosts["10.0.0.99"].is_silent
        assert not inv.hosts["10.0.0.15"].is_silent

    def test_non_ip_events_are_ignored(self):
        inv = NetworkInventory()
        inv.observe(
            ev(protocol=Protocol.NON_IP, src_ip=None, dst_ip=None,
               src_port=None, dst_port=None)
        )
        assert inv.hosts == {}
        assert inv.conversations == {}

    def test_multicast_kept_out_of_host_counts(self):
        inv = NetworkInventory()
        inv.observe(
            ev(protocol=Protocol.UDP, dst_ip="224.0.0.251", dst_port=5353)
        )
        assert len(inv.internal_hosts) == 1
        assert len(inv.external_hosts) == 0
        assert inv.hosts["224.0.0.251"].kind is HostKind.MULTICAST
        # multicast destinations are not "talkers"
        assert all(h.ip != "224.0.0.251" for h in inv.top_talkers())

    def test_as_dict_is_json_serializable(self):
        inv = NetworkInventory()
        inv.observe(ev())
        inv.observe(ev(protocol=Protocol.UDP, dst_port=53))
        data = inv.as_dict()
        encoded = json.dumps(data)
        assert "10.0.0.15" in encoded
        assert data["host_count"] == {"internal": 1, "external": 1, "other": 0}
