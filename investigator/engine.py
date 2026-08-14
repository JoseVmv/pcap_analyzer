"""Single-pass streaming analysis engine.

The whole project is built around one architectural rule: the capture file
is read **once**, and every analysis component consumes the same stream of
:class:`~investigator.models.NetworkEvent` objects incrementally.

A *collector* is any object with an ``observe(event)`` method (and an
optional ``finalize()`` called after the last event).  Collectors keep
compact aggregates - host tables, flow tables, counters - never the events
themselves, so memory stays bounded no matter how large the capture is.

Detectors added in later versions do not consume packets at all: they run
on top of the aggregates the collectors produced.  This layering is what
keeps every stage independently testable.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Iterable, Protocol, runtime_checkable

if TYPE_CHECKING:
    from investigator.models import NetworkEvent
    from investigator.parser import PcapLoader

LOG = logging.getLogger(__name__)


@runtime_checkable
class Collector(Protocol):
    """Structural interface: anything with ``observe(event)`` qualifies.

    Two kinds of collectors exist:

    * event collectors - implement ``observe(event)``; they never see Scapy
      objects and are trivially testable with hand-built events;
    * packet collectors - set ``wants_packets = True`` and implement
      ``observe_packet(event, packet)``; used by protocol analysers that
      need payload bytes (DNS/HTTP/TLS).

    ``finalize()`` is optional; the engine calls it when present.  Using a
    Protocol (instead of a base class) lets existing types such as
    ``CaptureSummary`` participate without inheriting from anything.
    """

    def observe(self, event: "NetworkEvent") -> None: ...


def run_analysis(
    loader: "PcapLoader",
    collectors: Iterable[object],
    *,
    progress_every: int = 100_000,
) -> int:
    """Stream the capture through every collector in a single pass.

    Returns the number of events processed.  Collector ``finalize()`` hooks
    run after the stream ends, in the order the collectors were given.
    When no collector needs raw packets the cheaper event stream is used.
    """
    event_collectors: list[object] = []
    packet_collectors: list[object] = []
    # Split by identity (not `in`, which would use __eq__ and mis-bucket
    # value-comparing dataclasses like CaptureSummary).
    for collector in collectors:
        if getattr(collector, "wants_packets", False):
            packet_collectors.append(collector)
        else:
            event_collectors.append(collector)

    count = 0
    if packet_collectors:
        for event, packet in loader.packets():
            count += 1
            for collector in event_collectors:
                collector.observe(event)
            for collector in packet_collectors:
                collector.observe_packet(event, packet)
            if progress_every and count % progress_every == 0:
                LOG.info("processed %d events...", count)
    else:
        for event in loader.events():
            count += 1
            for collector in event_collectors:
                collector.observe(event)
            if progress_every and count % progress_every == 0:
                LOG.info("processed %d events...", count)

    for collector in (*event_collectors, *packet_collectors):
        finalize = getattr(collector, "finalize", None)
        if callable(finalize):
            finalize()
    return count
