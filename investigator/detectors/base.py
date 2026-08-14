"""Detector base class and the context handed to every detector.

Detectors run *after* the single streaming pass, on the aggregates the
collectors produced - never on raw packets.  That is what keeps them fast,
deterministic and unit-testable with hand-built inventories.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass

from investigator.config import Config
from investigator.findings import Finding
from investigator.inventory import NetworkInventory
from investigator.models import CaptureSummary
from investigator.protocols import ProtocolAnalyzers

LOG = logging.getLogger(__name__)


@dataclass
class DetectionContext:
    """Everything a detector may read.  Kept read-only by convention."""

    config: Config
    summary: CaptureSummary
    inventory: NetworkInventory
    protocols: ProtocolAnalyzers
    # stream-time collectors specific to certain detectors (V3):
    rate: "object" = None       # detectors.bursts.TrafficRateTracker
    contacts: "object" = None   # detectors.beaconing.ContactSeriesTracker

    @property
    def dns(self):
        return self.protocols.dns

    @property
    def tcp(self):
        return self.protocols.tcp

    @property
    def http(self):
        return self.protocols.http

    @property
    def tls(self):
        return self.protocols.tls


class Detector(abc.ABC):
    """A detector turns aggregates into a list of :class:`Finding`."""

    #: stable slug used in logs and tests
    name: str = "detector"

    @abc.abstractmethod
    def detect(self, ctx: DetectionContext) -> list[Finding]:
        ...

    def safe_detect(self, ctx: DetectionContext) -> list[Finding]:
        """Run ``detect`` but never let one detector's bug abort the rest."""
        try:
            return self.detect(ctx)
        except Exception:
            LOG.exception("detector %s failed", self.name)
            return []
