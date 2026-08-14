"""Traffic-burst detection: abnormal spikes in volume over time.

During the streaming pass a lightweight tracker bins bytes/packets into
one-second buckets (memory proportional to distinct seconds, not packets).
The detector then re-bins to a sensible resolution for the capture's
duration and flags buckets that stand far above a *robust* baseline (median
+ k*MAD), so a single spike does not inflate the very threshold meant to
catch it.  Adjacent flagged buckets are merged into one burst window.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.models import NetworkEvent
from investigator.stats import mean, median, median_absolute_deviation, stdev


class TrafficRateTracker:
    """Stream collector: bytes and packets per one-second bucket."""

    def __init__(self, max_buckets: int = 5_000_000) -> None:
        self.bytes_per_second: dict[int, int] = {}
        self.packets_per_second: dict[int, int] = {}
        self.max_buckets = max_buckets

    def observe(self, event: NetworkEvent) -> None:
        bucket = int(event.timestamp)
        if bucket not in self.bytes_per_second and len(self.bytes_per_second) >= self.max_buckets:
            return
        self.bytes_per_second[bucket] = self.bytes_per_second.get(bucket, 0) + event.wire_bytes
        self.packets_per_second[bucket] = self.packets_per_second.get(bucket, 0) + 1


@dataclass(slots=True)
class _Window:
    start: int
    end: int
    total_bytes: int
    peak_bytes: int


class TrafficBurstDetector(Detector):
    name = "traffic_burst"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        rate: TrafficRateTracker | None = ctx.rate
        if rate is None or not rate.bytes_per_second:
            return []

        seconds = rate.bytes_per_second
        start = min(seconds)
        end = max(seconds)
        span = max(1, end - start + 1)
        bucket_size = max(1, math.ceil(span / cfg.burst_target_buckets))

        # Re-bin into contiguous buckets (including empty ones: quiet gaps
        # are part of the baseline).
        n_buckets = math.ceil(span / bucket_size)
        binned = [0] * n_buckets
        for second, value in seconds.items():
            binned[(second - start) // bucket_size] += value

        baseline = median(binned)
        mad = median_absolute_deviation(binned)
        spread = 1.4826 * mad if mad > 0 else stdev(binned)
        threshold = baseline + cfg.burst_sigma * spread
        floor = max(cfg.burst_min_bucket_bytes, baseline * 3)

        flagged = [
            i for i, value in enumerate(binned)
            if value > threshold and value >= floor
        ]
        if not flagged:
            return []

        windows = self._merge(flagged, binned, start, bucket_size)
        windows.sort(key=lambda w: -w.total_bytes)

        findings: list[Finding] = []
        for window in windows[: cfg.burst_max_findings]:
            has_baseline = baseline > 0
            ratio = (window.peak_bytes / baseline) if has_baseline else float("inf")
            # For confidence, express magnitude against the robust spread when
            # the median baseline is ~0 (an otherwise idle link).
            magnitude = ratio if has_baseline else max(
                2.0, window.peak_bytes / max(1.0, spread)
            )
            confidence = min(0.85, 0.4 + 0.1 * math.log2(max(2.0, magnitude)))
            if has_baseline:
                comparison = (
                    f"roughly {ratio:.0f}x the median of {_fmt_bytes(int(baseline))}"
                )
                evidence_summary = (
                    f"peak {_fmt_bytes(window.peak_bytes)} vs median "
                    f"{_fmt_bytes(int(baseline))} ({ratio:.0f}x)"
                )
            else:
                comparison = "against an otherwise near-silent baseline"
                evidence_summary = (
                    f"peak {_fmt_bytes(window.peak_bytes)} against a near-silent "
                    f"baseline (median 0 B)"
                )
            top = self._dominant_talker(ctx, window)
            finding = Finding(
                type="traffic_burst",
                title=f"Traffic burst around {_fmt(window.start)}",
                # A burst is a *volume observation*. It is deliberately LOW
                # risk on its own: it says how much moved, never what it was
                # or where it went. Correlation may raise its significance.
                severity=Severity.LOW,
                confidence=confidence,
                explanation=(
                    f"Traffic volume between {_fmt(window.start)} and {_fmt(window.end)} "
                    f"reached {_fmt_bytes(window.peak_bytes)} per {bucket_size}s bucket, "
                    f"{comparison}."
                ),
                interpretation=(
                    "A short period of markedly elevated traffic volume. Bursts "
                    "accompany many ordinary activities - downloads, updates, "
                    "backups, streaming - as well as bulk transfers, scanning and "
                    "flooding."
                ),
                limitations=(
                    "Volume alone establishes neither the direction of the data nor "
                    "its content or purpose. A burst is not evidence of exfiltration."
                ),
                source=top,
                timestamp=float(window.start),
                start_time=float(window.start),
                end_time=float(window.end),
                behavior_group=f"traffic_burst:{top or '-'}",
                metadata={
                    "bucket_size_seconds": bucket_size,
                    "peak_bytes": window.peak_bytes,
                    "window_bytes": window.total_bytes,
                    "baseline_bytes": int(baseline),
                    "attribution": "capture-wide top talker (approximate)",
                },
            )
            finding.add(
                evidence_summary,
                peak_bytes=window.peak_bytes, baseline_bytes=int(baseline),
            )
            if top:
                finding.add(f"dominant talker overall: {top}")
            findings.append(finding)
        return findings

    def _merge(self, flagged, binned, start, bucket_size) -> list[_Window]:
        windows: list[_Window] = []
        current: _Window | None = None
        for index in flagged:
            bstart = start + index * bucket_size
            bend = bstart + bucket_size - 1
            value = binned[index]
            if current is not None and bstart <= current.end + bucket_size:
                current.end = bend
                current.total_bytes += value
                current.peak_bytes = max(current.peak_bytes, value)
            else:
                if current is not None:
                    windows.append(current)
                current = _Window(bstart, bend, value, value)
        if current is not None:
            windows.append(current)
        return windows

    def _dominant_talker(self, ctx: DetectionContext, window: _Window) -> str | None:
        # Approximation: the overall top talker by bytes sent (per-window
        # attribution would need per-source time series; documented).
        talkers = ctx.inventory.top_talkers(1)
        return talkers[0].ip if talkers else None


def _fmt(epoch: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%H:%M:%S")


def _fmt_bytes(num: int) -> str:
    value = float(num)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"
