"""HTTP behaviour analysis.

Correlates the HTTP records extracted in V2 into per-channel views
(source -> destination:port) and looks for three things a plain packet
count cannot show:

1. **Periodic HTTP request patterns** - requests issued at machine-regular
   intervals, the HTTP-level equivalent of beaconing.
2. **Request/response asymmetry** - a channel that consistently sends far
   more than it receives, which is the HTTP shape of an upload channel.
3. **Contextually anomalous client identity** - legacy or scripted
   User-Agent strings.

The third one is explicitly *contextual*.  An old Firefox UA proves
nothing: users do run old browsers, and any client can forge the header.
It is reported only as a weak supporting signal, and its risk stays LOW
unless the surrounding channel is itself automated.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind, classify_ip
from investigator.stats import (
    coefficient_of_variation,
    mean,
    median,
    stdev,
)


def _fmt_bytes(num: int) -> str:
    value = float(num)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


@dataclass(slots=True)
class HttpChannel:
    """All HTTP requests from one host to one destination:port."""

    src_ip: str
    dst_ip: str
    dst_port: int
    timestamps: list[float] = field(default_factory=list)
    methods: dict[str, int] = field(default_factory=dict)
    hosts: set[str] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)
    uris: list[str] = field(default_factory=list)
    request_body_bytes: int = 0

    def record(self, request) -> None:
        self.timestamps.append(request.timestamp)
        self.methods[request.method] = self.methods.get(request.method, 0) + 1
        if request.host:
            self.hosts.add(request.host)
        if request.user_agent:
            self.user_agents.add(request.user_agent)
        self.uris.append(request.uri)
        if request.content_length:
            self.request_body_bytes += request.content_length

    @property
    def count(self) -> int:
        return len(self.timestamps)

    @property
    def upload_requests(self) -> int:
        return self.methods.get("POST", 0) + self.methods.get("PUT", 0)


class HttpAnomalyDetector(Detector):
    name = "http_anomaly"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        channels = self._build_channels(ctx)
        findings: list[Finding] = []
        for channel in channels.values():
            findings.extend(self._assess_channel(ctx, channel))
        findings.sort(key=lambda f: (-f.severity, -f.confidence))
        return findings

    def _build_channels(self, ctx) -> dict[tuple[str, str, int], HttpChannel]:
        channels: dict[tuple[str, str, int], HttpChannel] = {}
        for request in ctx.http.requests:
            key = (request.src_ip, request.dst_ip, request.dst_port)
            channel = channels.get(key)
            if channel is None:
                channel = HttpChannel(
                    src_ip=request.src_ip,
                    dst_ip=request.dst_ip,
                    dst_port=request.dst_port,
                )
                channels[key] = channel
            channel.record(request)
        return channels

    def _response_bytes(self, ctx, channel: HttpChannel) -> int:
        """Total response body bytes coming back on this channel."""
        total = 0
        for response in ctx.http.responses:
            if response.src_ip == channel.dst_ip and response.dst_ip == channel.src_ip:
                total += response.content_length or 0
        return total

    def _assess_channel(self, ctx, channel: HttpChannel) -> list[Finding]:
        cfg = ctx.config
        findings: list[Finding] = []
        if channel.count < cfg.http_min_requests_for_pattern:
            return findings

        external = classify_ip(channel.dst_ip) is HostKind.EXTERNAL
        response_bytes = self._response_bytes(ctx, channel)

        periodic = self._periodicity(channel, cfg)
        if periodic is not None:
            findings.append(
                self._beacon_finding(
                    ctx, channel, periodic, external, response_bytes
                )
            )

        legacy = self._legacy_agents(channel, cfg)
        if legacy:
            findings.append(
                self._user_agent_finding(
                    ctx, channel, legacy, external, periodic is not None
                )
            )
        return findings

    # ---------------------------------------------------------- periodicity

    def _periodicity(self, channel: HttpChannel, cfg) -> dict | None:
        if channel.count < cfg.http_min_requests_for_pattern:
            return None
        ordered = sorted(channel.timestamps)
        intervals = [b - a for a, b in zip(ordered, ordered[1:]) if b > a]
        if len(intervals) < 2:
            return None
        mu = mean(intervals)
        if mu <= 0:
            return None
        cv = coefficient_of_variation(intervals)
        if cv > cfg.http_beacon_cv:
            return None
        return {
            "connection_count": channel.count,
            "first_seen": ordered[0],
            "last_seen": ordered[-1],
            "duration_seconds": round(ordered[-1] - ordered[0], 2),
            "mean_interval": round(mu, 3),
            "median_interval": round(median(intervals), 3),
            "stdev_interval": round(stdev(intervals), 4),
            "min_interval": round(min(intervals), 3),
            "max_interval": round(max(intervals), 3),
            "coefficient_of_variation": round(cv, 4),
        }

    def _beacon_finding(self, ctx, channel, stats, external, response_bytes):
        confidence = 0.55 + 0.3 * max(0.0, 1.0 - stats["coefficient_of_variation"] * 4)
        signals: list[str] = []

        if external:
            confidence += 0.05
        if channel.upload_requests >= ctx.config.exfil_min_uploads:
            confidence += 0.05
            signals.append(
                f"{channel.upload_requests} of the requests are POST/PUT uploads "
                f"carrying {_fmt_bytes(channel.request_body_bytes)} of request bodies"
            )
        if len(set(channel.uris)) == 1:
            confidence += 0.05
            signals.append(f"every request targets the same URI ({channel.uris[0]})")

        ratio_note = None
        if response_bytes and channel.request_body_bytes:
            ratio = channel.request_body_bytes / max(1, response_bytes)
            if ratio >= ctx.config.http_low_response_ratio:
                confidence += 0.05
                ratio_note = (
                    f"request bodies outweigh response bodies "
                    f"{ratio:.0f}:1 ({_fmt_bytes(channel.request_body_bytes)} sent vs "
                    f"{_fmt_bytes(response_bytes)} received)"
                )
                signals.append(ratio_note)

        confidence = min(0.92, confidence)
        risk = Severity.HIGH if external else Severity.MEDIUM

        finding = Finding(
            type="http_beaconing",
            title=(
                f"Periodic HTTP communication: {channel.src_ip} -> "
                f"{channel.dst_ip}:{channel.dst_port}"
            ),
            severity=risk,
            confidence=confidence,
            explanation=(
                f"{channel.src_ip} issued {channel.count} HTTP requests to "
                f"{channel.dst_ip}:{channel.dst_port} at a mean interval of "
                f"{stats['mean_interval']}s with a coefficient of variation of "
                f"{stats['coefficient_of_variation']}. Request timing this regular "
                f"indicates an automated client rather than user-driven browsing."
            ),
            interpretation=(
                "Repeated periodic HTTP requests are consistent with automated "
                "check-in behaviour, which is one shape command-and-control "
                "channels take."
            ),
            limitations=(
                "Periodicity establishes automation, not malice. Update checks, "
                "API polling, telemetry, RSS readers and monitoring agents are all "
                "legitimately periodic. Request payloads were not reconstructed, "
                "so the purpose of this channel is not established."
            ),
            source=channel.src_ip,
            destination=channel.dst_ip,
            timestamp=stats["first_seen"],
            start_time=stats["first_seen"],
            end_time=stats["last_seen"],
            behavior_group=f"periodic_communication:{channel.src_ip}",
            metadata={
                "dst_port": channel.dst_port,
                "http_hosts": sorted(channel.hosts),
                "methods": dict(channel.methods),
                "user_agents": sorted(channel.user_agents),
                "statistics": stats,
                "request_body_bytes": channel.request_body_bytes,
                "response_body_bytes": response_bytes,
            },
        )
        finding.add(
            f"{channel.count} requests over {stats['duration_seconds']}s to "
            f"{channel.dst_ip}:{channel.dst_port}",
            **stats,
        )
        finding.add(
            f"mean interval {stats['mean_interval']}s, median "
            f"{stats['median_interval']}s, stdev {stats['stdev_interval']}s, "
            f"coefficient of variation {stats['coefficient_of_variation']}",
        )
        methods_text = ", ".join(f"{m} x{c}" for m, c in sorted(channel.methods.items()))
        finding.add(f"methods: {methods_text}")
        if channel.hosts:
            finding.add(f"Host header(s): {', '.join(sorted(channel.hosts))}")
        for signal in signals:
            finding.add(signal)
        return finding

    # ----------------------------------------------------------- user agent

    def _legacy_agents(self, channel: HttpChannel, cfg) -> list[str]:
        return [
            agent
            for agent in channel.user_agents
            if any(marker in agent for marker in cfg.http_legacy_agents)
        ]

    def _user_agent_finding(self, ctx, channel, legacy, external, periodic):
        # Deliberately weak on its own; meaningful only in context.
        confidence = 0.4 if periodic else 0.3
        risk = Severity.LOW
        agents_text = "; ".join(sorted(legacy)[:3])

        finding = Finding(
            type="http_anomaly",
            title=(
                f"Legacy or scripted HTTP User-Agent from {channel.src_ip} "
                f"to {channel.dst_ip}"
            ),
            severity=risk,
            confidence=confidence,
            explanation=(
                f"{channel.src_ip} identified itself as \"{agents_text}\" across "
                f"{channel.count} requests to {channel.dst_ip}:{channel.dst_port}. "
                f"The string corresponds to an outdated browser build or a scripted "
                f"HTTP client."
                + (
                    " The surrounding requests on this channel are machine-regular, "
                    "which makes the client identity more notable."
                    if periodic
                    else ""
                )
            ),
            interpretation=(
                "Potentially anomalous in the context of the surrounding HTTP "
                "behaviour. Automated tooling frequently ships a fixed, dated or "
                "library-default User-Agent."
            ),
            limitations=(
                "This indicator alone is insufficient to establish malicious "
                "activity. User-Agent strings are trivially forged, legitimate "
                "scripts and monitoring tools set library defaults, and users do "
                "run outdated browsers."
            ),
            source=channel.src_ip,
            destination=channel.dst_ip,
            timestamp=min(channel.timestamps),
            start_time=min(channel.timestamps),
            end_time=max(channel.timestamps),
            behavior_group=f"http_client_anomaly:{channel.src_ip}",
            metadata={
                "user_agents": sorted(legacy),
                "request_count": channel.count,
                "dst_port": channel.dst_port,
                "channel_is_periodic": periodic,
            },
        )
        for agent in sorted(legacy)[:5]:
            finding.add(f"User-Agent: {agent}")
        finding.add(
            f"used across {channel.count} requests to "
            f"{channel.dst_ip}:{channel.dst_port}"
        )
        return finding
