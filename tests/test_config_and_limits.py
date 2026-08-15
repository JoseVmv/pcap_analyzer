"""Tests for configuration loading, table ceilings and parser layer walking.

Three concerns that share a theme: the tool has to stay honest about what
it is doing.  A mistyped threshold must not be silently ignored, a table
that stops growing must say so, and a faster layer lookup must classify
packets identically to the one it replaced.
"""

from __future__ import annotations

import json

import pytest
import synth
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import Ether

from investigator.config import Config, load_config
from investigator.errors import ConfigError
from investigator.inventory import (
    MAX_PEERS_PER_HOST,
    NetworkInventory,
    classify_ip,
)
from investigator.models import NetworkEvent, Protocol, TcpFlags
from investigator.parser import packet_to_event
from investigator.protocols.tcp import TcpFlowTracker


# ----------------------------------------------------------- config files

class TestConfigLoading:
    def test_json_overrides_applied(self, tmp_path):
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"beacon_min_events": 3, "burst_sigma": 2.5}))
        config = load_config(path)
        assert config.beacon_min_events == 3
        assert config.burst_sigma == 2.5
        # untouched settings keep their defaults
        assert config.scan_min_ports_vertical == Config().scan_min_ports_vertical

    def test_weights_merge_instead_of_replacing(self, tmp_path):
        """A file that retunes one weight must not silently drop the rest."""
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"weights": {"beaconing": 40}}))
        config = load_config(path)
        assert config.weight_for("beaconing") == 40.0
        assert config.weight_for("lateral_movement") == 18.0

    def test_unknown_key_rejected_with_suggestion(self, tmp_path):
        """A silently ignored typo would leave the operator believing a
        threshold was retuned while the default stayed in force."""
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"beacon_min_evnts": 3}))
        with pytest.raises(ConfigError) as excinfo:
            load_config(path)
        assert "beacon_min_events" in str(excinfo.value)

    def test_wrong_type_rejected(self, tmp_path):
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"beacon_min_events": "many"}))
        with pytest.raises(ConfigError):
            load_config(path)

    def test_bool_not_accepted_as_int(self, tmp_path):
        """bool is an int subclass; accepting it would let `true` quietly
        set a threshold to 1."""
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"beacon_min_events": True}))
        with pytest.raises(ConfigError):
            load_config(path)

    def test_tuple_setting_from_list(self, tmp_path):
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"tls_legacy_versions": ["TLS 1.0"]}))
        assert load_config(path).tls_legacy_versions == ("TLS 1.0",)

    def test_unsupported_extension(self, tmp_path):
        path = tmp_path / "cfg.yaml"
        path.write_text("beacon_min_events: 3")
        with pytest.raises(ConfigError):
            load_config(path)

    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError):
            load_config(tmp_path / "nope.json")

    def test_toml_when_available(self, tmp_path):
        tomllib = pytest.importorskip("tomllib")
        assert tomllib is not None
        path = tmp_path / "cfg.toml"
        path.write_text(
            "beacon_min_events = 3\n\n[weights]\nbeaconing = 40.0\n"
        )
        config = load_config(path)
        assert config.beacon_min_events == 3
        assert config.weight_for("beaconing") == 40.0


# ------------------------------------------------------------ table caps

def _event(src: str, dst: str, *, ts: float = 0.0, sport: int = 1234,
           dport: int = 80) -> NetworkEvent:
    """A minimal TCP SYN event - enough to exercise the aggregate tables."""
    return NetworkEvent(
        timestamp=ts, protocol=Protocol.TCP, wire_bytes=60,
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        tcp_flags=TcpFlags.SYN, tcp_seq=1,
    )


class TestInventoryLimits:
    def test_host_table_stops_growing_and_counts(self, monkeypatch):
        import investigator.inventory as inventory

        monkeypatch.setattr(inventory, "MAX_TRACKED_HOSTS", 4)
        inv = inventory.NetworkInventory()
        for i in range(20):
            inv.observe(_event("10.0.0.1", f"10.0.1.{i}", ts=float(i)))

        assert len(inv.hosts) == 4
        assert inv.untracked_host_events > 0
        # global port counters must stay exact regardless of table pressure
        assert sum(inv.global_dst_ports.values()) == 20
        assert inv.as_dict()["limits"]["hosts_capped"] is True

    def test_conversation_table_capped(self, monkeypatch):
        import investigator.inventory as inventory

        monkeypatch.setattr(inventory, "MAX_TRACKED_CONVERSATIONS", 3)
        inv = inventory.NetworkInventory()
        for i in range(10):
            inv.observe(_event("10.0.0.1", f"10.0.2.{i}", ts=float(i)))

        assert len(inv.conversations) == 3
        assert inv.untracked_conversation_events == 7

    def test_peer_set_capped_and_flagged(self, monkeypatch):
        import investigator.inventory as inventory

        monkeypatch.setattr(inventory, "MAX_PEERS_PER_HOST", 5)
        inv = inventory.NetworkInventory()
        for i in range(12):
            inv.observe(_event("10.0.0.1", f"10.0.3.{i}", ts=float(i)))

        host = inv.hosts["10.0.0.1"]
        assert len(host.peers) == 5
        assert host.peers_overflow is True
        assert host.as_dict()["peers_overflow"] is True

    def test_uncapped_run_reports_no_overflow(self):
        inv = NetworkInventory()
        for i in range(10):
            inv.observe(_event("10.0.0.1", f"10.0.4.{i}", ts=float(i)))
        limits = inv.as_dict()["limits"]
        assert limits["hosts_capped"] is False
        assert limits["untracked_conversation_events"] == 0
        assert inv.hosts["10.0.0.1"].peers_overflow is False
        assert MAX_PEERS_PER_HOST > 0


class TestTcpFlowLimits:
    def test_flow_table_capped_and_counted(self, monkeypatch):
        import investigator.protocols.tcp as tcp_module

        monkeypatch.setattr(tcp_module, "MAX_TRACKED_FLOWS", 5)
        tracker = tcp_module.TcpFlowTracker()
        for port in range(30):
            tracker.observe(_event("10.0.0.1", "10.0.0.2", dport=port, sport=port))

        assert len(tracker.flows) == 5
        assert tracker.untracked_flows == 25
        summary = tracker.as_dict()
        assert summary["flows_capped"] is True
        assert summary["untracked_flows"] == 25

    def test_known_flows_keep_updating_after_cap(self, monkeypatch):
        """Hitting the ceiling must not stop accounting for flows already
        being tracked."""
        import investigator.protocols.tcp as tcp_module

        monkeypatch.setattr(tcp_module, "MAX_TRACKED_FLOWS", 1)
        tracker = tcp_module.TcpFlowTracker()
        tracker.observe(_event("10.0.0.1", "10.0.0.2", dport=80, sport=1000))
        for _ in range(5):
            tracker.observe(_event("10.0.0.1", "10.0.0.2", dport=80, sport=1000))
        tracker.observe(_event("10.0.0.1", "10.0.0.3", dport=80, sport=1001))

        flow = list(tracker.flows.values())[0]
        assert flow.packets_out == 6
        assert tracker.untracked_flows == 1

    def test_uncapped_tracker_is_clean(self):
        tracker = TcpFlowTracker()
        tracker.observe(_event("10.0.0.1", "10.0.0.2"))
        assert tracker.untracked_flows == 0
        assert tracker.as_dict()["flows_capped"] is False


class TestIpCacheBound:
    def test_cache_is_bounded(self, monkeypatch):
        import investigator.inventory as inventory

        monkeypatch.setattr(inventory, "_IP_CACHE_LIMIT", 10)
        inventory._ip_kind_cache.clear()
        for i in range(300):
            classify_ip(f"10.1.{i // 256}.{i % 256}")
        assert len(inventory._ip_kind_cache) <= 10
        # correctness is unaffected by eviction
        assert classify_ip("10.0.0.1") is inventory.HostKind.INTERNAL
        assert classify_ip("8.8.8.8") is inventory.HostKind.EXTERNAL


# --------------------------------------------------------- parser walking

class TestLayerWalk:
    """The single-pass walk must classify exactly like seven getlayer calls."""

    def _event(self, packet):
        packet = Ether(bytes(packet))
        packet.time = synth.BASE_TS
        event = packet_to_event(packet)
        assert event is not None
        return event

    def test_tcp(self):
        event = self._event(Ether() / IP() / TCP(sport=1234, dport=80))
        assert event.protocol is Protocol.TCP
        assert event.dst_port == 80

    def test_udp(self):
        event = self._event(Ether() / IP() / UDP(sport=1234, dport=53))
        assert event.protocol is Protocol.UDP
        assert event.dst_port == 53

    def test_icmp(self):
        event = self._event(Ether() / IP() / ICMP(type=8))
        assert event.protocol is Protocol.ICMP
        assert event.icmp_type == 8

    def test_icmpv6(self):
        event = self._event(Ether() / IPv6() / ICMPv6EchoRequest())
        assert event.protocol is Protocol.ICMPV6

    def test_arp(self):
        from scapy.layers.l2 import ARP

        event = self._event(Ether() / ARP(psrc="10.0.0.1", pdst="10.0.0.2"))
        assert event.protocol is Protocol.ARP
        assert event.src_ip == "10.0.0.1"

    def test_icmp_error_quoting_tcp_stays_icmp(self):
        """Scapy models the quoted header as ``TCPerror(TCP)``. Matching
        layers with isinstance would find it and report a phantom TCP flow
        for what is actually an unreachable notice."""
        packet = (
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=3, code=3)
            / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=1234, dport=80)
        )
        event = self._event(packet)
        assert event.protocol is Protocol.ICMP
        assert event.icmp_type == 3
        assert event.src_port is None      # the quoted ports are not the flow

    def test_non_ip_frame(self):
        packet = Ether(type=0x9999) / (b"\x00" * 20)
        event = self._event(packet)
        assert event.protocol is Protocol.NON_IP