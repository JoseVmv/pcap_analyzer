"""Protocol analysers (V2).

Each analyser is a collector fed by the engine during the single streaming
pass.  DNS/HTTP/TLS need raw payload bytes, so they declare
``wants_packets = True`` and receive ``observe_packet(event, packet)``;
the TCP tracker works from ``NetworkEvent`` alone (flags + seq).

Every extracted record distinguishes what was *observed* on the wire from
what was *inferred* (e.g. client/server roles guessed from the first packet
of a mid-capture flow).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from investigator.protocols.dns import DnsAnalyzer
from investigator.protocols.http import HttpAnalyzer
from investigator.protocols.tcp import TcpFlowTracker
from investigator.protocols.tls import TlsAnalyzer


@dataclass
class ProtocolAnalyzers:
    """Convenience bundle wiring all V2 analysers into the engine."""

    dns: DnsAnalyzer = field(default_factory=DnsAnalyzer)
    tcp: TcpFlowTracker = field(default_factory=TcpFlowTracker)
    http: HttpAnalyzer = field(default_factory=HttpAnalyzer)
    tls: TlsAnalyzer = field(default_factory=TlsAnalyzer)

    def collectors(self) -> list[object]:
        return [self.dns, self.tcp, self.http, self.tls]

    def as_dict(self) -> dict[str, object]:
        return {
            "dns": self.dns.as_dict(),
            "tcp": self.tcp.as_dict(),
            "http": self.http.as_dict(),
            "tls": self.tls.as_dict(),
        }
