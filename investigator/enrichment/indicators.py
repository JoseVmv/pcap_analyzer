"""What the capture itself says about each external address and domain.

Everything here is passive: it reads the aggregates the collectors already
built and needs no network.  The most valuable context usually comes from this
layer, because it is first-hand: which name this client resolved to that
address, which SNI it asked for, which URL it fetched.  A registry can say who
owns an address, but only the capture can say what this host did with it.

This module also decides what may ever leave the machine.  Only public
addresses and registrable domains are eligible for a lookup.  Full hostnames
never are, because labels under a tunnelling domain can *be* the exfiltrated
data, and a third party would be the one receiving it.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import quote

from investigator.enrichment.knowledge import (
    ServiceHint,
    address_class,
    best_name_hint,
    hint_for_ip,
)
from investigator.enrichment.providers import (
    LookupResult,
    LookupStatus,
    Signal,
    clean_text,
)
from investigator.findings import Finding
from investigator.inventory import HostKind, HostProfile, NetworkInventory, classify_ip
from investigator.protocols.dns import split_domain

if TYPE_CHECKING:
    from investigator.config import Config
    from investigator.protocols import ProtocolAnalyzers

# Names that do not exist in public DNS.  Sending them anywhere would disclose
# internal naming and could not return anything useful.
_NON_PUBLIC_TLDS = frozenset(
    {
        "arpa", "corp", "domain", "example", "home", "internal", "intranet",
        "invalid", "lan", "local", "localdomain", "localhost", "onion",
        "private", "test", "workgroup",
    }
)

# Letters, digits and hyphens in dot-separated labels.  Besides rejecting junk,
# this is what guarantees a capture-controlled name cannot alter the path of an
# API request: a crafted SNI like "x.com/../../users/me" fails here.
_PUBLIC_NAME = re.compile(
    r"(?=.{4,253}\Z)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
)

#: What a split base domain may contain before it stops being meaningful.
#: Underscores stay, so that mDNS names still group under ``_tcp.local``.
_DNS_SHAPED = re.compile(r"[a-z0-9._-]+")

_REPUTATION_ORDER = [Signal.FLAGGED, Signal.REPORTED, Signal.NO_REPORTS]


def ip_lookup_block(ip: str) -> str | None:
    """Why ``ip`` must not be looked up, or ``None`` if it may be."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "not a valid address"
    return None if address.is_global else "not a publicly routable address"


def domain_lookup_block(
    domain: str,
    *,
    names: Iterable[str] = (),
    resolved_ips: Iterable[str] = (),
    exclude: Iterable[str] = (),
) -> str | None:
    """Why ``domain`` must not be looked up, or ``None`` if it may be."""
    if not _PUBLIC_NAME.fullmatch(domain):
        return "malformed name"
    tld = domain.rsplit(".", 1)[1]
    if tld in _NON_PUBLIC_TLDS:
        return f"non-public suffix .{tld}"
    # Checked against every observed name: excluding `corp.acme.com` must also
    # hold back `acme.com`, the form that would actually be sent.
    candidates = (domain, *names)
    for suffix in exclude:
        suffix = suffix.lower().strip(".")
        if any(name == suffix or name.endswith(f".{suffix}") for name in candidates):
            return "excluded by enrich_exclude_domains"
    # Only internal answers mean an internal name, whatever its TLD looks like.
    resolved = list(resolved_ips)
    if resolved and all(classify_ip(ip) is HostKind.INTERNAL for ip in resolved):
        return "resolves only to internal addresses"
    return None


def _sample(values: Iterable[object], limit: int) -> dict[str, object]:
    """A bounded listing that keeps the true total, shortest entries first.

    Short-first puts ``www.evil.io`` ahead of two hundred random labels.
    """
    ordered = sorted({clean_text(value) for value in values}, key=lambda v: (len(v), v))
    return {"sample": ordered[:limit], "total": len(ordered)}


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


@dataclass(slots=True)
class Indicator:
    """Common shape of an observed address or domain."""

    kind: ClassVar[str]

    value: str
    finding_ids: list[str] = field(default_factory=list)
    service: ServiceHint | None = None
    notes: list[str] = field(default_factory=list)
    #: Why this indicator is never sent to a third party.
    lookup_block: str | None = None
    lookups: list[LookupResult] = field(default_factory=list)

    @property
    def reputation(self) -> dict[str, object]:
        """Worst signal any source returned, with the sources that said so.

        ``not_checked`` is a separate state from ``no_reports`` because nobody
        having been asked is very different from nobody having complained.
        """
        answers = [r for r in self.lookups if r.signal is not None]
        if not answers:
            return {"signal": "not_checked", "sources": []}
        worst = min(answers, key=lambda r: _REPUTATION_ORDER.index(r.signal))
        return {
            "signal": worst.signal.value,
            "sources": [f"{r.provider}: {r.summary}" for r in answers],
        }

    def _pivots(self) -> list[tuple[str, str]]:
        raise NotImplementedError

    def pivots(self) -> list[dict[str, str]]:
        """Links for looking this up by hand: nothing is fetched until the
        analyst clicks.  Non-public indicators get none, which also keeps
        capture-controlled junk out of URLs."""
        if self.lookup_block is not None:
            return []
        return [{"name": name, "url": url} for name, url in self._pivots()]

    def _context_parts(self) -> list[str]:
        parts = []
        if self.service is not None:
            parts.append(self.service.name)
        parts.extend(
            r.brief for r in self.lookups
            if r.brief and r.status is LookupStatus.OK
        )
        return parts

    def _common_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "value": clean_text(self.value, 253),
            "service": self.service.as_dict() if self.service else None,
            "finding_ids": self.finding_ids,
            "notes": self.notes,
            "lookup_block": self.lookup_block,
            "reputation": self.reputation,
            "lookups": [r.as_dict() for r in self.lookups],
            "pivots": self.pivots(),
        }


@dataclass(slots=True)
class IpIndicator(Indicator):
    """An external address, seen from the inside of this capture."""

    kind: ClassVar[str] = "ip"

    address_class: str | None = None
    names: set[str] = field(default_factory=set)
    sni: set[str] = field(default_factory=set)
    http_hosts: set[str] = field(default_factory=set)
    http_servers: set[str] = field(default_factory=set)
    internal_peers: set[str] = field(default_factory=set)
    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    packets: int = 0
    bytes_to: int = 0
    bytes_from: int = 0
    first_seen: float | None = None
    last_seen: float | None = None

    def _pivots(self) -> list[tuple[str, str]]:
        value = quote(self.value, safe="")
        return [
            ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{value}"),
            ("AbuseIPDB", f"https://www.abuseipdb.com/check/{value}"),
            ("Shodan", f"https://www.shodan.io/host/{value}"),
        ]

    def label(self) -> str:
        """One line for tables of other things.  Empty if there is nothing."""
        parts = []
        seen = sorted(self.names | self.sni | self.http_hosts, key=lambda n: (len(n), n))
        if seen:
            more = f" +{len(seen) - 1}" if len(seen) > 1 else ""
            parts.append(clean_text(seen[0], 80) + more)
        if self.address_class:
            parts.append(self.address_class)
        return " | ".join(parts + self._context_parts())

    def as_dict(self, limit: int) -> dict[str, object]:
        return {
            **self._common_dict(),
            "address_class": self.address_class,
            "names": _sample(self.names, limit),
            "sni": _sample(self.sni, limit),
            "http_hosts": _sample(self.http_hosts, limit),
            "http_servers": _sample(self.http_servers, limit),
            "internal_peers": _sample(self.internal_peers, limit),
            "ports": self.ports,
            "protocols": self.protocols,
            "packets": self.packets,
            "bytes_to": self.bytes_to,
            "bytes_from": self.bytes_from,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(slots=True)
class DomainIndicator(Indicator):
    """A registrable domain and everything observed under it."""

    kind: ClassVar[str] = "domain"

    names: set[str] = field(default_factory=set)
    seen_via: set[str] = field(default_factory=set)
    resolved_ips: set[str] = field(default_factory=set)
    #: Where TLS and HTTP sessions for this domain actually went, which need
    #: not match what DNS said.
    contacted_ips: set[str] = field(default_factory=set)
    clients: set[str] = field(default_factory=set)
    dns_queries: int = 0
    nxdomains: int = 0
    tls_sessions: int = 0
    http_requests: int = 0
    urls: Counter = field(default_factory=Counter)
    first_seen: float | None = None
    last_seen: float | None = None

    def touch(self, timestamp: float) -> None:
        if self.first_seen is None or timestamp < self.first_seen:
            self.first_seen = timestamp
        if self.last_seen is None or timestamp > self.last_seen:
            self.last_seen = timestamp

    @property
    def activity(self) -> int:
        return self.dns_queries + self.tls_sessions + self.http_requests

    def _pivots(self) -> list[tuple[str, str]]:
        value = quote(self.value, safe="")
        return [
            ("VirusTotal", f"https://www.virustotal.com/gui/domain/{value}"),
            ("urlscan", f"https://urlscan.io/search/#domain:{value}"),
        ]

    def label(self) -> str:
        return " | ".join(self._context_parts())

    def as_dict(self, limit: int) -> dict[str, object]:
        return {
            **self._common_dict(),
            "names": _sample(self.names, limit),
            "seen_via": sorted(self.seen_via),
            "resolved_ips": _sample(self.resolved_ips, limit),
            "contacted_ips": _sample(self.contacted_ips, limit),
            "clients": _sample(self.clients, limit),
            "dns_queries": self.dns_queries,
            "nxdomains": self.nxdomains,
            "tls_sessions": self.tls_sessions,
            "http_requests": self.http_requests,
            "urls": [
                {"url": clean_text(url), "count": count}
                for url, count in self.urls.most_common(limit)
            ],
            "url_total": len(self.urls),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


def normalise_host(raw: str) -> str | None:
    """Reduce an HTTP Host or SNI value to a bare name.

    ``None`` for an address literal: that is an address, already accounted for,
    and treating ``10.0.0.5:8080`` as a domain would make ``0.5`` a "site".
    """
    host = raw.strip().lower().rstrip(".")
    if host.startswith("["):  # bracketed IPv6 literal
        return None
    host = host.split(":", 1)[0].rstrip(".")
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


def _select_hosts(
    inventory: NetworkInventory, findings: Iterable[Finding], limit: int
) -> tuple[list[HostProfile], int]:
    """External hosts worth an entry, with how many did not make it.

    Selected before anything is built: a horizontal scan can leave 200k
    external hosts in the inventory, and the entries are the expensive part.
    """
    referenced = {
        value for finding in findings
        for value in (finding.source, finding.destination)
    }
    external = sorted(
        inventory.external_hosts,
        key=lambda h: (h.ip not in referenced, -h.total_bytes, h.ip),
    )
    return external[:limit], max(0, len(external) - limit)


def _build_ips(
    inventory: NetworkInventory,
    protocols: "ProtocolAnalyzers",
    findings: list[Finding],
    config: "Config",
) -> tuple[dict[str, IpIndicator], int]:
    hosts, omitted = _select_hosts(inventory, findings, config.enrich_max_indicators)
    ips: dict[str, IpIndicator] = {}
    for host in hosts:
        ips[host.ip] = IpIndicator(
            value=host.ip,
            names=set(protocols.dns.names_for_ip(host.ip)),
            internal_peers={
                peer for peer in host.peers
                if classify_ip(peer) is HostKind.INTERNAL
            },
            ports=[port for port, _ in host.ports_served.most_common(8)],
            protocols=[name for name, _ in host.protocols.most_common()],
            packets=host.packets_sent + host.packets_received,
            # The inventory counts from this host's point of view, so what it
            # received is what the monitored network sent to it.
            bytes_to=host.bytes_received,
            bytes_from=host.bytes_sent,
            first_seen=host.first_seen,
            last_seen=host.last_seen,
            lookup_block=ip_lookup_block(host.ip),
            address_class=address_class(host.ip),
            service=hint_for_ip(host.ip),
        )

    for hello in protocols.tls.client_hellos:
        indicator = ips.get(hello.dst_ip)
        if indicator is not None and hello.sni:
            indicator.sni.add(hello.sni)
    for request in protocols.http.requests:
        indicator = ips.get(request.dst_ip)
        if indicator is not None and request.host:
            host_name = normalise_host(request.host)
            if host_name:
                indicator.http_hosts.add(host_name)
    for response in protocols.http.responses:
        indicator = ips.get(response.src_ip)
        if indicator is not None and response.server:
            indicator.http_servers.add(response.server)

    dns_seen = protocols.dns.total_responses > 0
    for indicator in ips.values():
        if indicator.address_class == "documentation range":
            indicator.notes.append(
                "documentation range (RFC 5737/3849): never routed on the "
                "internet, so unexpected in real traffic"
            )
        # Only meaningful where DNS was visible at all; otherwise it says
        # something about the capture, and that goes in the capture-level notes.
        if dns_seen and not indicator.names:
            indicator.notes.append("no DNS answer in this capture named this address")
    return ips, omitted


def _build_domains(
    protocols: "ProtocolAnalyzers", config: "Config"
) -> tuple[dict[str, DomainIndicator], int]:
    domains: dict[str, DomainIndicator] = {}

    def domain_for(name: str) -> DomainIndicator | None:
        _, base = split_domain(name)
        if not base:
            return None
        # Splitting on dots means nothing for a crafted value: an SNI like
        # "x.com/../../users/me" would be reported as a domain "./users/me",
        # which hides what the client actually sent.
        if not _DNS_SHAPED.fullmatch(base):
            base = name
        indicator = domains.get(base)
        if indicator is None:
            indicator = domains[base] = DomainIndicator(value=base)
        return indicator

    dns = protocols.dns
    for base, stats in dns.domains.items():
        indicator = domain_for(base)
        if indicator is None:
            continue
        indicator.seen_via.add("dns")
        indicator.dns_queries = stats.queries
        indicator.nxdomains = stats.nxdomains
        indicator.clients.update(stats.clients)
    for client in dns.clients.values():
        for name in client.unique_qnames:
            indicator = domain_for(name)
            if indicator is not None:
                indicator.names.add(name)
    for name, addresses in dns.resolutions.items():
        indicator = domain_for(name)
        if indicator is not None:
            indicator.names.add(name)
            indicator.resolved_ips.update(addresses)
    for query in dns.sample_queries:
        indicator = domain_for(query.qname)
        if indicator is not None:
            indicator.touch(query.timestamp)

    for hello in protocols.tls.client_hellos:
        name = normalise_host(hello.sni) if hello.sni else None
        indicator = domain_for(name) if name else None
        if indicator is None:
            continue
        indicator.seen_via.add("tls-sni")
        indicator.names.add(name)
        indicator.tls_sessions += 1
        indicator.clients.add(hello.src_ip)
        indicator.contacted_ips.add(hello.dst_ip)
        indicator.touch(hello.timestamp)

    for request in protocols.http.requests:
        name = normalise_host(request.host) if request.host else None
        indicator = domain_for(name) if name else None
        if indicator is None:
            continue
        indicator.seen_via.add("http-host")
        indicator.names.add(name)
        indicator.http_requests += 1
        indicator.clients.add(request.src_ip)
        indicator.contacted_ips.add(request.dst_ip)
        indicator.urls[f"{request.method} http://{request.host}{request.uri}"] += 1
        indicator.touch(request.timestamp)

    for indicator in domains.values():
        indicator.lookup_block = domain_lookup_block(
            indicator.value,
            names=indicator.names,
            resolved_ips=indicator.resolved_ips,
            exclude=config.enrich_exclude_domains,
        )
        if indicator.nxdomains and not indicator.resolved_ips:
            indicator.notes.append(
                f"never resolved in this capture ({indicator.nxdomains} NXDOMAIN)"
            )
    ranked_out = max(0, len(domains) - config.enrich_max_indicators)
    return domains, ranked_out


def _link_findings(
    ips: dict[str, IpIndicator],
    domains: dict[str, DomainIndicator],
    findings: list[Finding],
) -> None:
    """Tie findings to the indicators they concern.

    A domain also collects the findings of the addresses it was resolved to or
    connected through.  That is association, not attribution: a shared CDN
    address brings in findings about its other tenants, so the report calls
    these *related* findings.
    """
    def domain_named(value: str) -> DomainIndicator | None:
        return domains.get(value) or domains.get(split_domain(value)[1])

    for finding in findings:
        for value in (finding.source, finding.destination):
            if not value:
                continue
            if value in ips:
                ips[value].finding_ids.append(finding.id)
                continue
            domain = domain_named(value)
            if domain is not None:
                domain.finding_ids.append(finding.id)
        sni = finding.metadata.get("sni")
        if isinstance(sni, str):
            domain = domain_named(sni)
            if domain is not None:
                domain.finding_ids.append(finding.id)

    for domain in domains.values():
        for address in domain.resolved_ips | domain.contacted_ips:
            linked = ips.get(address)
            if linked is not None:
                domain.finding_ids.extend(linked.finding_ids)
        domain.finding_ids = _unique(domain.finding_ids)
    for indicator in ips.values():
        indicator.finding_ids = _unique(indicator.finding_ids)


def build_indicators(
    inventory: NetworkInventory,
    protocols: "ProtocolAnalyzers",
    findings: list[Finding],
    config: "Config",
) -> tuple[list[IpIndicator], list[DomainIndicator], int, int]:
    """Ranked indicators plus how many of each kind were left out.

    Ranking puts anything tied to a finding first, so a table limit drops the
    least interesting entries; volume breaks the tie.
    """
    ips, ips_omitted = _build_ips(inventory, protocols, findings, config)
    domains, domains_omitted = _build_domains(protocols, config)
    _link_findings(ips, domains, findings)

    ranked_ips = sorted(
        ips.values(),
        key=lambda i: (not i.finding_ids, -(i.bytes_to + i.bytes_from), i.value),
    )
    ranked_domains = sorted(
        domains.values(),
        key=lambda d: (
            not d.finding_ids,
            d.lookup_block is not None,
            -d.activity,
            d.value,
        ),
    )[: config.enrich_max_indicators]
    for domain in ranked_domains:
        domain.service = best_name_hint([domain.value, *sorted(domain.names)])
    return ranked_ips, ranked_domains, ips_omitted, domains_omitted
