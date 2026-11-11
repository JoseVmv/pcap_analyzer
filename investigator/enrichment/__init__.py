"""IOC enrichment: context for the addresses and sites in a capture.

Findings say what the traffic did; this layer says what the traffic talked to.
It works in two levels:

* **Offline, always on** - what the capture itself recorded about each external
  address and domain (names, SNI, URLs, clients, volume), plus a small built-in
  table of well-known operators.  Nothing leaves the machine.
* **Online, only with** ``--enrich`` - ASN, registration and reputation data
  from third-party services.

Enrichment runs *after* scoring and feeds nothing back into it, which is the
central design decision here.  Detection measures behaviour against the capture
itself, so the same file always produces the same findings and the same risk.
A third-party verdict is context for the analyst, not evidence: it changes over
time, it reflects the moment of the lookup rather than of the capture, and a
score that moved with it could not be reproduced or explained.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from investigator.enrichment.indicators import (
    DomainIndicator,
    IpIndicator,
    build_indicators,
)
from investigator.enrichment.lookups import (
    LookupRunner,
    ProviderRun,
    build_lookup_runner,
    lookup_order,
)
from investigator.enrichment.providers import LookupStatus, Signal, clean_text
from investigator.findings import Finding
from investigator.inventory import NetworkInventory
from investigator.models import CaptureSummary
from investigator.reporting import _format_size

if TYPE_CHECKING:
    from investigator.config import Config
    from investigator.protocols import ProtocolAnalyzers

__all__ = [
    "DomainIndicator",
    "Enrichment",
    "IpIndicator",
    "LookupRunner",
    "build_enrichment",
    "build_lookup_runner",
    "render_enrichment_text",
]

_DAY_SECONDS = 86_400.0


@dataclass(slots=True)
class Enrichment:
    """Everything known about the capture's external indicators."""

    ips: list[IpIndicator] = field(default_factory=list)
    domains: list[DomainIndicator] = field(default_factory=list)
    ips_omitted: int = 0
    domains_omitted: int = 0
    notes: list[str] = field(default_factory=list)
    runs: list[ProviderRun] = field(default_factory=list)
    unavailable: dict[str, str] = field(default_factory=dict)
    #: Entries per listing in the report; the totals are always kept.
    sample_limit: int = 10

    @property
    def contacted_services(self) -> list[str]:
        """Services this run actually sent something to."""
        return [run.name for run in self.runs if run.looked_up]

    @property
    def indicators(self) -> list[IpIndicator | DomainIndicator]:
        return [*self.ips, *self.domains]

    def labels(self) -> dict[str, str]:
        """Indicator -> one line of context, for the rest of the report."""
        labels = {i.value: i.label() for i in self.indicators}
        return {value: label for value, label in labels.items() if label}

    def as_dict(self) -> dict[str, object]:
        signals = [i.reputation["signal"] for i in self.indicators]
        return {
            "mode": "online" if self.runs else "offline",
            "contacted_services": self.contacted_services,
            "lookups_sent": sum(run.looked_up for run in self.runs),
            "providers": [run.as_dict() for run in self.runs],
            "unavailable_providers": self.unavailable,
            "ip_count": len(self.ips),
            "domain_count": len(self.domains),
            "ips_omitted": self.ips_omitted,
            "domains_omitted": self.domains_omitted,
            "flagged_count": signals.count(Signal.FLAGGED.value),
            "reported_count": signals.count(Signal.REPORTED.value),
            "notes": self.notes,
            "ips": [i.as_dict(self.sample_limit) for i in self.ips],
            "domains": [d.as_dict(self.sample_limit) for d in self.domains],
            "labels": self.labels(),
        }


def _capture_notes(
    inventory: NetworkInventory, protocols: "ProtocolAnalyzers"
) -> list[str]:
    """Why names may be missing.

    With no explanation, an address with no name reads as suspicious, when
    usually the capture simply could not have shown one.
    """
    external = inventory.external_hosts
    if not external:
        return []
    notes = []
    if not protocols.dns.total_responses:
        notes.append(
            "No DNS responses in this capture, so addresses could not be tied to "
            "names through DNS. The resolver may be outside the capture point, or "
            "clients may be using encrypted DNS."
        )
    quic = [
        h for h in external if h.protocols.get("UDP") and h.ports_served.get(443)
    ]
    if quic:
        notes.append(
            f"{len(quic)} address(es) exchanged UDP traffic on port 443, most "
            f"likely QUIC. This tool does not parse the QUIC handshake, so those "
            f"sessions show no server name here."
        )
    tcp_tls = [
        h for h in external if h.protocols.get("TCP") and h.ports_served.get(443)
    ]
    if tcp_tls and not protocols.tls.client_hellos:
        notes.append(
            f"{len(tcp_tls)} address(es) had TCP traffic on port 443 but no TLS "
            f"ClientHello was parsed, so no SNI is available. The capture may have "
            f"started after those handshakes."
        )
    return notes


def _note_registration_age(
    domain: DomainIndicator, capture_start: float | None, config: "Config"
) -> None:
    """Domain age, measured against the capture rather than today.

    A domain registered last week says nothing about traffic from two years
    ago, and what matters is how new it was when the client reached for it.
    Registries answer with the *current* registration, so one that postdates
    the capture is reported as such instead of as a negative age.
    """
    if capture_start is None:
        return
    for result in domain.lookups:
        registered = result.fields.get("registered_ts")
        if not isinstance(registered, (int, float)) or isinstance(registered, bool):
            continue
        age_days = (capture_start - registered) / _DAY_SECONDS
        if age_days < 0:
            domain.notes.append(
                "current registration postdates this capture, so the name may have "
                "changed hands since"
            )
        elif age_days <= config.enrich_new_domain_days:
            domain.notes.append(
                f"registered {int(age_days)} day(s) before this capture"
            )
        return


def build_enrichment(
    inventory: NetworkInventory,
    protocols: "ProtocolAnalyzers",
    summary: CaptureSummary,
    findings: list[Finding],
    config: "Config",
    *,
    lookups: LookupRunner | None = None,
) -> Enrichment:
    """Build the context.  Without ``lookups``, no network code runs at all."""
    ips, domains, ips_omitted, domains_omitted = build_indicators(
        inventory, protocols, findings, config
    )
    enrichment = Enrichment(
        ips=ips,
        domains=domains,
        ips_omitted=ips_omitted,
        domains_omitted=domains_omitted,
        notes=_capture_notes(inventory, protocols),
        sample_limit=config.enrich_max_listed,
    )
    if lookups is not None:
        enrichment.runs = lookups.run(lookup_order(ips, domains))
        enrichment.unavailable = dict(lookups.unavailable)
        for domain in domains:
            _note_registration_age(domain, summary.first_timestamp, config)
    return enrichment


def _indicator_lines(indicator: IpIndicator | DomainIndicator) -> list[str]:
    """The indented detail lines under one indicator."""
    lines = []
    for note in indicator.notes:
        lines.append(f"      ! {clean_text(note)}")
    for result in indicator.lookups:
        if result.status is LookupStatus.NOT_QUERIED:
            continue
        text = result.summary or result.detail or result.status.value
        lines.append(f"      {result.provider}: {clean_text(text)}")
    return lines


def _names_line(names: set[str], limit: int = 3) -> str:
    ordered = sorted(names, key=lambda n: (len(n), n))
    shown = ", ".join(clean_text(name, 60) for name in ordered[:limit])
    extra = f", +{len(ordered) - limit} more" if len(ordered) > limit else ""
    return f"      names: {shown}{extra}"


def render_enrichment_text(enrichment: Enrichment, *, limit: int = 10) -> str:
    """Terminal section, most relevant indicators first.

    Forced to ASCII at the end: registry records routinely contain accented
    names, and a character the Windows console codepage cannot encode would
    crash the run after the analysis had already succeeded.
    """
    if not enrichment.ips and not enrichment.domains:
        return ""
    if enrichment.contacted_services:
        mode = f"online, sent to {', '.join(enrichment.contacted_services)}"
    elif enrichment.runs:
        mode = "from local cache, nothing sent this run"
    else:
        mode = "offline, nothing left this machine"
    lines = [
        "",
        f"IOC enrichment: {len(enrichment.ips) + enrichment.ips_omitted} external "
        f"IP(s), {len(enrichment.domains) + enrichment.domains_omitted} domain(s) "
        f"({mode})",
    ]
    for note in enrichment.notes:
        lines.append(f"  ! {note}")

    for indicator in enrichment.ips[:limit]:
        tags = [t for t in (
            indicator.service.name if indicator.service else None,
            indicator.address_class,
        ) if t]
        reputation = indicator.reputation["signal"]
        if reputation in (Signal.FLAGGED.value, Signal.REPORTED.value):
            tags.append(str(reputation).upper())
        lines.append(
            f"  {indicator.value:<18} to {_format_size(indicator.bytes_to):>9}"
            f"  from {_format_size(indicator.bytes_from):>9}"
            f"  ports {','.join(str(p) for p in indicator.ports[:3]) or '-'}"
            + (f"  [{'; '.join(tags)}]" if tags else "")
            + (f"  related findings {len(indicator.finding_ids)}" if indicator.finding_ids else "")
        )
        names = indicator.names | indicator.sni | indicator.http_hosts
        if names:
            lines.append(_names_line(names))
        lines.extend(_indicator_lines(indicator))
    if len(enrichment.ips) > limit:
        lines.append(f"  ... and {len(enrichment.ips) - limit} more IP(s) in the reports")

    for domain in enrichment.domains[:limit]:
        tags = [domain.service.name] if domain.service else []
        reputation = domain.reputation["signal"]
        if reputation in (Signal.FLAGGED.value, Signal.REPORTED.value):
            tags.append(str(reputation).upper())
        lines.append(
            f"  {clean_text(domain.value, 60)}"
            f"  dns {domain.dns_queries}  tls {domain.tls_sessions}"
            f"  http {domain.http_requests}"
            + (f"  [{'; '.join(tags)}]" if tags else "")
            + (f"  related findings {len(domain.finding_ids)}" if domain.finding_ids else "")
        )
        if domain.names - {domain.value}:
            lines.append(_names_line(domain.names - {domain.value}))
        lines.extend(_indicator_lines(domain))
    if len(enrichment.domains) > limit:
        lines.append(
            f"  ... and {len(enrichment.domains) - limit} more domain(s) in the reports"
        )

    for run in enrichment.runs:
        if run.stopped or run.not_queried:
            lines.append(
                f"  ! {run.name}: {run.not_queried} indicator(s) not looked up"
                + (f" ({clean_text(run.stopped)})" if run.stopped else "")
            )
    for name, reason in enrichment.unavailable.items():
        lines.append(f"  {name} not used: {reason}")
    if not enrichment.runs:
        lines.append(
            "  Add --enrich for ASN, registration and reputation data from "
            "third-party services."
        )
    return "\n".join(lines).encode("ascii", "replace").decode("ascii")
