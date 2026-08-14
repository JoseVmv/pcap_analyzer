"""Tests for the TCP flow tracker - pure hand-built events, no capture."""

from __future__ import annotations

from investigator.models import NetworkEvent, Protocol, TcpFlags
from investigator.protocols.tcp import TcpFlowTracker, TcpState

CLIENT = "10.0.0.15"
SERVER = "203.0.113.80"


def tcp_event(
    ts: float,
    src: str,
    dst: str,
    sport: int,
    dport: int,
    flags: TcpFlags,
    payload: int = 0,
    seq: int = 0,
) -> NetworkEvent:
    return NetworkEvent(
        timestamp=ts,
        protocol=Protocol.TCP,
        wire_bytes=60 + payload,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        payload_bytes=payload,
        tcp_flags=flags,
        tcp_seq=seq,
    )


def run_session(tracker: TcpFlowTracker) -> None:
    """Full handshake + request/response + FIN teardown."""
    s = TcpFlags.SYN
    sa = TcpFlags.SYN | TcpFlags.ACK
    a = TcpFlags.ACK
    pa = TcpFlags.PSH | TcpFlags.ACK
    fa = TcpFlags.FIN | TcpFlags.ACK
    tracker.observe(tcp_event(0.0, CLIENT, SERVER, 52100, 80, s, seq=1000))
    tracker.observe(tcp_event(0.1, SERVER, CLIENT, 80, 52100, sa, seq=5000))
    tracker.observe(tcp_event(0.2, CLIENT, SERVER, 52100, 80, a, seq=1001))
    tracker.observe(tcp_event(0.3, CLIENT, SERVER, 52100, 80, pa, payload=100, seq=1001))
    tracker.observe(tcp_event(0.4, SERVER, CLIENT, 80, 52100, pa, payload=500, seq=5001))
    tracker.observe(tcp_event(5.0, CLIENT, SERVER, 52100, 80, fa, seq=1101))
    tracker.observe(tcp_event(5.1, SERVER, CLIENT, 80, 52100, fa, seq=5501))


class TestTcpFlowTracker:
    def test_full_session(self):
        tracker = TcpFlowTracker()
        run_session(tracker)
        assert len(tracker.flows) == 1
        flow = next(iter(tracker.flows.values()))
        assert flow.client_ip == CLIENT and flow.server_ip == SERVER
        assert flow.roles_observed
        assert flow.state is TcpState.CLOSED
        assert flow.established_time == 0.2
        assert flow.handshake_rtt == 0.1
        assert flow.payload_out == 100
        assert flow.payload_in == 500
        assert flow.duration == 5.1

    def test_retransmission_not_double_counted(self):
        tracker = TcpFlowTracker()
        run_session(tracker)
        flow = next(iter(tracker.flows.values()))
        # same data segment again (identical seq range)
        tracker.observe(
            tcp_event(0.5, CLIENT, SERVER, 52100, 80,
                      TcpFlags.PSH | TcpFlags.ACK, payload=100, seq=1001)
        )
        assert flow.payload_out == 100
        assert flow.retransmissions_out == 1

    def test_half_open_syn_scan_pattern(self):
        tracker = TcpFlowTracker()
        for i, port in enumerate((21, 22, 23, 25, 80)):
            tracker.observe(
                tcp_event(float(i), CLIENT, "10.0.0.23", 40000 + i, port,
                          TcpFlags.SYN, seq=1)
            )
        assert len(tracker.flows) == 5
        assert all(f.state is TcpState.HALF_OPEN for f in tracker.flows.values())
        assert tracker.half_open_by_client()[CLIENT] == 5

    def test_rst_marks_reset(self):
        tracker = TcpFlowTracker()
        tracker.observe(tcp_event(0.0, CLIENT, SERVER, 52100, 80, TcpFlags.SYN, seq=1))
        tracker.observe(
            tcp_event(0.1, SERVER, CLIENT, 80, 52100,
                      TcpFlags.RST | TcpFlags.ACK, seq=0)
        )
        flow = next(iter(tracker.flows.values()))
        assert flow.state is TcpState.RESET
        assert flow.rst_seen

    def test_midstream_flow_roles_are_inferred(self):
        tracker = TcpFlowTracker()
        tracker.observe(
            tcp_event(0.0, SERVER, CLIENT, 80, 52100,
                      TcpFlags.PSH | TcpFlags.ACK, payload=200, seq=900)
        )
        flow = next(iter(tracker.flows.values()))
        assert flow.state is TcpState.MIDSTREAM
        assert not flow.roles_observed
        assert flow.as_dict()["roles"] == "inferred"

    def test_non_tcp_ignored(self):
        tracker = TcpFlowTracker()
        tracker.observe(
            NetworkEvent(timestamp=0.0, protocol=Protocol.UDP, wire_bytes=60,
                         src_ip=CLIENT, dst_ip=SERVER, src_port=1, dst_port=2)
        )
        assert tracker.flows == {}
