"""Tests for the single-pass streaming engine."""

from __future__ import annotations

from investigator.engine import run_analysis
from investigator.models import NetworkEvent
from investigator.parser import PcapLoader


class RecordingCollector:
    def __init__(self) -> None:
        self.events: list[NetworkEvent] = []
        self.finalized = False

    def observe(self, event: NetworkEvent) -> None:
        self.events.append(event)

    def finalize(self) -> None:
        self.finalized = True


class MinimalCollector:
    """No finalize(): the engine must cope."""

    def __init__(self) -> None:
        self.count = 0

    def observe(self, event: NetworkEvent) -> None:
        self.count += 1


class PacketRecordingCollector:
    """Packet-aware collector: must receive raw Scapy packets too."""

    wants_packets = True

    def __init__(self) -> None:
        self.pairs: list[tuple[NetworkEvent, object]] = []

    def observe_packet(self, event: NetworkEvent, packet: object) -> None:
        self.pairs.append((event, packet))


def test_all_collectors_see_every_event(mixed_pcap):
    loader = PcapLoader(mixed_pcap)
    first, second, minimal = RecordingCollector(), RecordingCollector(), MinimalCollector()
    processed = run_analysis(loader, [first, second, minimal])
    assert processed == 5
    assert len(first.events) == 5
    assert first.events == second.events
    assert minimal.count == 5
    assert first.finalized and second.finalized


def test_mixed_event_and_packet_collectors(mixed_pcap):
    loader = PcapLoader(mixed_pcap)
    events_only = RecordingCollector()
    packets_too = PacketRecordingCollector()
    processed = run_analysis(loader, [events_only, packets_too])
    assert processed == 5
    assert len(events_only.events) == 5
    assert len(packets_too.pairs) == 5
    # the packet collector received real scapy packets alongside the events
    event, packet = packets_too.pairs[0]
    assert event is events_only.events[0]
    assert hasattr(packet, "time")
