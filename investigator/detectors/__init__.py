"""Detector registry and runner (V3).

The default set is ordered but order does not affect results - findings are
sorted globally afterwards.  ``run_detectors`` isolates each detector so one
failure cannot lose the others' findings.
"""

from __future__ import annotations

from investigator.detectors.base import DetectionContext, Detector
from investigator.detectors.beaconing import BeaconingDetector, ContactSeriesTracker
from investigator.detectors.bursts import TrafficBurstDetector, TrafficRateTracker
from investigator.detectors.dns_anomaly import DnsAnomalyDetector
from investigator.detectors.exfiltration import (
    DataExfiltrationDetector,
    DataTransferDetector,
)
from investigator.detectors.http_anomaly import HttpAnomalyDetector
from investigator.detectors.lateral import HostDiscoveryDetector, LateralMovementDetector
from investigator.detectors.rare_destination import RareDestinationDetector
from investigator.detectors.scanning import PortScanDetector
from investigator.detectors.unusual_ports import UnusualPortDetector
from investigator.findings import Finding, sort_findings

DEFAULT_DETECTORS: list[Detector] = [
    PortScanDetector(),
    HostDiscoveryDetector(),
    BeaconingDetector(),
    HttpAnomalyDetector(),
    DnsAnomalyDetector(),
    RareDestinationDetector(),
    UnusualPortDetector(),
    TrafficBurstDetector(),
    DataTransferDetector(),
    LateralMovementDetector(),
]


def run_detectors(
    ctx: DetectionContext, detectors: list[Detector] | None = None
) -> list[Finding]:
    detectors = detectors if detectors is not None else DEFAULT_DETECTORS
    findings: list[Finding] = []
    for detector in detectors:
        findings.extend(detector.safe_detect(ctx))
    return sort_findings(findings)


__all__ = [
    "DetectionContext",
    "Detector",
    "DEFAULT_DETECTORS",
    "run_detectors",
    "ContactSeriesTracker",
    "TrafficRateTracker",
    "BeaconingDetector",
    "TrafficBurstDetector",
    "DnsAnomalyDetector",
    "DataExfiltrationDetector",
    "DataTransferDetector",
    "HttpAnomalyDetector",
    "HostDiscoveryDetector",
    "LateralMovementDetector",
    "RareDestinationDetector",
    "PortScanDetector",
    "UnusualPortDetector",
]
