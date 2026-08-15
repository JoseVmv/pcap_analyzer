"""Protocol analysers (V2).

Each analyser is a collector fed by the engine during the single streaming
pass.  DNS/HTTP/TLS/ARP need raw payload bytes, so they declare
``wants_packets = True`` and receive ``observe_packet(event, packet)``;
the TCP and ICMP trackers work from ``NetworkEvent`` alone (flags, seq,
ICMP type/code and payload sizes are all normalised by the parser).

Every extracted record distinguishes what was *observed* on the wire from
what was *inferred* (e.g. client/server roles guessed from the first packet
of a mid-capture flow).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from investigator.protocols.arp import ArpTracker
from investigator.protocols.dns import DnsAnalyzer
from investigator.protocols.http import HttpAnalyzer
from investigator.protocols.icmp import IcmpAnalyzer
from investigator.protocols.tcp import TcpFlowTracker
from investigator.protocols.tls import TlsAnalyzer


@dataclass
class ProtocolAnalyzers:
    """Convenience bundle wiring every analyser into the engine."""

    dns: DnsAnalyzer = field(default_factory=DnsAnalyzer)
    tcp: TcpFlowTracker = field(default_factory=TcpFlowTracker)
    http: HttpAnalyzer = field(default_factory=HttpAnalyzer)
    tls: TlsAnalyzer = field(default_factory=TlsAnalyzer)
    arp: ArpTracker = field(default_factory=ArpTracker)
    icmp: IcmpAnalyzer = field(default_factory=IcmpAnalyzer)

    def collectors(self) -> list[object]:
        return [self.dns, self.tcp, self.http, self.tls, self.arp, self.icmp]

    def as_dict(self) -> dict[str, object]:
        return {
            "dns": self.dns.as_dict(),
            "tcp": self.tcp.as_dict(),
            "http": self.http.as_dict(),
            "tls": self.tls.as_dict(),
            "arp": self.arp.as_dict(),
            "icmp": self.icmp.as_dict(),
        }
