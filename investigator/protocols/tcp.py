"""TCP connection tracking.

Works purely on :class:`NetworkEvent` (flags, seq, payload sizes) - no raw
packets needed.  Produces per-flow state that later versions rely on:

* half-open flows (SYN never answered) -> port-scan evidence;
* established flows with per-direction byte counts -> exfiltration sizing;
* client/server roles, marked *observed* when derived from a SYN and
  *inferred* when the flow was already running when the capture started.

Retransmission counting is a heuristic: a data segment whose range ends at
or below the highest byte already seen in that direction is counted as a
retransmission and its bytes are not added again (so byte totals approximate
*unique* application data).  Sequence-number wrap-around (32-bit) is not
handled; for the capture sizes this tool targets that is acceptable and
documented.
"""

from __future__ import annotations

import enum
import logging
from collections import Counter
from dataclasses import dataclass

from investigator.models import NetworkEvent, Protocol, TcpFlags

LOG = logging.getLogger(__name__)

FlowKey = tuple[tuple[str, int], tuple[str, int]]


class TcpState(str, enum.Enum):
    HALF_OPEN = "half-open"        # SYN seen, no SYN/ACK
    CONNECTING = "connecting"      # SYN + SYN/ACK, no final ACK yet
    ESTABLISHED = "established"
    CLOSED = "closed"              # FIN exchange completed
    RESET = "reset"
    MIDSTREAM = "midstream"        # no handshake observed (started pre-capture)


@dataclass(slots=True)
class TcpFlow:
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    roles_observed: bool  # True: roles from SYN; False: inferred from first packet
    state: TcpState
    first_seen: float
    last_seen: float
    syn_time: float | None = None
    synack_time: float | None = None
    established_time: float | None = None
    packets_out: int = 0            # client -> server
    packets_in: int = 0             # server -> client
    payload_out: int = 0
    payload_in: int = 0
    retransmissions_out: int = 0
    retransmissions_in: int = 0
    fin_out: bool = False
    fin_in: bool = False
    rst_seen: bool = False
    _highest_end_out: int = 0
    _highest_end_in: int = 0

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def handshake_rtt(self) -> float | None:
        if self.syn_time is not None and self.synack_time is not None:
            return self.synack_time - self.syn_time
        return None

    @property
    def total_payload(self) -> int:
        return self.payload_out + self.payload_in

    def as_dict(self) -> dict[str, object]:
        return {
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "roles": "observed" if self.roles_observed else "inferred",
            "state": self.state.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration,
            "handshake_rtt": self.handshake_rtt,
            "packets_out": self.packets_out,
            "packets_in": self.packets_in,
            "payload_out": self.payload_out,
            "payload_in": self.payload_in,
            "retransmissions": self.retransmissions_out + self.retransmissions_in,
        }


class TcpFlowTracker:
    """Collector maintaining one :class:`TcpFlow` per TCP 4-tuple."""

    def __init__(self) -> None:
        self.flows: dict[FlowKey, TcpFlow] = {}

    @staticmethod
    def _key(event: NetworkEvent) -> FlowKey:
        a = (event.src_ip or "", event.src_port or 0)
        b = (event.dst_ip or "", event.dst_port or 0)
        return (a, b) if a <= b else (b, a)

    def observe(self, event: NetworkEvent) -> None:
        if (
            event.protocol is not Protocol.TCP
            or event.src_ip is None
            or event.dst_ip is None
            or event.src_port is None
            or event.dst_port is None
            or event.tcp_flags is None
        ):
            return

        flags = event.tcp_flags
        key = self._key(event)
        flow = self.flows.get(key)

        if flow is None:
            syn_only = TcpFlags.SYN in flags and TcpFlags.ACK not in flags
            if syn_only:
                flow = TcpFlow(
                    client_ip=event.src_ip,
                    client_port=event.src_port,
                    server_ip=event.dst_ip,
                    server_port=event.dst_port,
                    roles_observed=True,
                    state=TcpState.HALF_OPEN,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    syn_time=event.timestamp,
                )
            else:
                # Mid-capture flow: guess that the first sender is the client
                # (and mark the guess as inferred).
                flow = TcpFlow(
                    client_ip=event.src_ip,
                    client_port=event.src_port,
                    server_ip=event.dst_ip,
                    server_port=event.dst_port,
                    roles_observed=False,
                    state=TcpState.MIDSTREAM,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                )
            self.flows[key] = flow

        flow.last_seen = max(flow.last_seen, event.timestamp)
        outbound = event.src_ip == flow.client_ip and event.src_port == flow.client_port

        # --- handshake / teardown state machine (simplified) --------------
        if TcpFlags.SYN in flags and TcpFlags.ACK in flags and not outbound:
            if flow.synack_time is None:
                flow.synack_time = event.timestamp
            if flow.state is TcpState.HALF_OPEN:
                flow.state = TcpState.CONNECTING
        elif (
            flow.state is TcpState.CONNECTING
            and outbound
            and TcpFlags.ACK in flags
            and TcpFlags.SYN not in flags
        ):
            flow.established_time = event.timestamp
            flow.state = TcpState.ESTABLISHED

        if TcpFlags.RST in flags:
            flow.rst_seen = True
            if flow.state is not TcpState.CLOSED:
                flow.state = TcpState.RESET
        if TcpFlags.FIN in flags:
            if outbound:
                flow.fin_out = True
            else:
                flow.fin_in = True
            if flow.fin_out and flow.fin_in and flow.state in (
                TcpState.ESTABLISHED,
                TcpState.MIDSTREAM,
                TcpState.CONNECTING,
            ):
                flow.state = TcpState.CLOSED

        # --- packet / byte accounting with retransmission heuristic -------
        if outbound:
            flow.packets_out += 1
        else:
            flow.packets_in += 1

        payload = event.payload_bytes
        if payload > 0:
            if event.tcp_seq is not None:
                end = event.tcp_seq + payload
                highest = flow._highest_end_out if outbound else flow._highest_end_in
                if end <= highest:
                    if outbound:
                        flow.retransmissions_out += 1
                    else:
                        flow.retransmissions_in += 1
                    return  # do not double-count retransmitted bytes
                if outbound:
                    flow._highest_end_out = end
                else:
                    flow._highest_end_in = end
            if outbound:
                flow.payload_out += payload
            else:
                flow.payload_in += payload

    # --------------------------------------------------------------- views

    def state_counts(self) -> Counter:
        counts: Counter = Counter()
        for flow in self.flows.values():
            counts[flow.state.value] += 1
        return counts

    def half_open_by_client(self) -> Counter:
        """How many unanswered SYN flows each client produced (scan signal)."""
        counts: Counter = Counter()
        for flow in self.flows.values():
            if flow.state is TcpState.HALF_OPEN and flow.roles_observed:
                counts[flow.client_ip] += 1
        return counts

    def flows_from(self, client_ip: str) -> list[TcpFlow]:
        return [f for f in self.flows.values() if f.client_ip == client_ip]

    def top_flows_by_payload(self, limit: int = 20) -> list[TcpFlow]:
        return sorted(self.flows.values(), key=lambda f: -f.total_payload)[:limit]

    def as_dict(self) -> dict[str, object]:
        return {
            "flow_count": len(self.flows),
            "states": dict(self.state_counts().most_common()),
            "half_open_by_client": dict(self.half_open_by_client().most_common(20)),
            "retransmissions": sum(
                f.retransmissions_out + f.retransmissions_in
                for f in self.flows.values()
            ),
            "top_flows_by_payload": [
                f.as_dict() for f in self.top_flows_by_payload(20)
            ],
        }
