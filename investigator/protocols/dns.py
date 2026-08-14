"""DNS analysis.

Extracts queries/responses from the packet stream and keeps aggregates
designed for the V3 anomaly detectors:

* per-client stats (rate, NXDOMAIN counts, unique names, query timestamps);
* per-base-domain stats (unique subdomains, label lengths, label entropy -
  the raw material for DNS-tunneling heuristics);
* name -> IP resolutions and the reverse map, so later versions can ask
  "was this external IP ever resolved via DNS, and from which name?".

Importing this module registers Scapy's DNS dissector bindings (UDP/TCP 53,
mDNS...), which is what makes ``packet.getlayer(DNS)`` work during the
engine pass.
"""

from __future__ import annotations

import logging
from array import array
from collections import Counter
from dataclasses import dataclass, field

from scapy.layers.dns import DNS, DNSRR
from scapy.packet import NoPayload, Packet

from investigator.models import NetworkEvent
from investigator.stats import shannon_entropy

LOG = logging.getLogger(__name__)

QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
    65: "HTTPS", 255: "ANY",
}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

# Minimal multi-label public suffixes so "host.example.com.br" groups under
# "example.com.br" and not "com.br".  A full Public Suffix List is overkill
# for a heuristic grouping; documented limitation.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "com.br", "net.br", "org.br", "gov.br",
    "edu.br", "com.au", "net.au", "co.jp", "com.mx", "com.ar", "co.za",
    "com.cn", "com.tr",
}

_MAX_SAMPLE_QUERIES = 2_000
_MAX_UNIQUE_NAMES_PER_CLIENT = 50_000
_MAX_SUBDOMAINS_PER_DOMAIN = 20_000
_MAX_TIMESTAMPS_PER_CLIENT = 100_000


def _to_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii", errors="replace")
    return str(value)


def normalise_qname(qname: object) -> str:
    return _to_text(qname).rstrip(".").lower()


def split_domain(qname: str) -> tuple[str, str]:
    """Return ``(subdomain, base_domain)`` for a normalised name.

    ``a.b.example.com`` -> ``("a.b", "example.com")``.
    """
    labels = qname.split(".")
    if len(labels) <= 2:
        return "", qname
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        base_size = 3
    else:
        base_size = 2
    base = ".".join(labels[-base_size:])
    sub = ".".join(labels[:-base_size])
    return sub, base


def _iter_section(section: object):
    """Yield resource records from a DNS section across scapy versions
    (list in newer scapy, payload-chained packets in older ones)."""
    if section is None:
        return
    if isinstance(section, list):
        yield from section
        return
    current = section
    while current is not None and not isinstance(current, NoPayload):
        yield current
        current = getattr(current, "payload", None)


@dataclass(slots=True)
class DnsQuery:
    """One observed query (kept as a bounded sample for evidence)."""

    timestamp: float
    client_ip: str
    server_ip: str
    qname: str
    qtype: str

    def as_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "qname": self.qname,
            "qtype": self.qtype,
            "observation": "observed",
        }


@dataclass(slots=True)
class DnsClientStats:
    client_ip: str
    queries: int = 0
    responses: int = 0
    nxdomains: int = 0
    qtypes: Counter = field(default_factory=Counter)
    unique_qnames: set[str] = field(default_factory=set)
    unique_qnames_overflow: bool = False
    timestamps: array = field(default_factory=lambda: array("d"))

    def record_query(self, qname: str, qtype: str, timestamp: float) -> None:
        self.queries += 1
        self.qtypes[qtype] += 1
        if len(self.unique_qnames) < _MAX_UNIQUE_NAMES_PER_CLIENT:
            self.unique_qnames.add(qname)
        elif qname not in self.unique_qnames:
            self.unique_qnames_overflow = True
        if len(self.timestamps) < _MAX_TIMESTAMPS_PER_CLIENT:
            self.timestamps.append(timestamp)

    def as_dict(self) -> dict[str, object]:
        return {
            "client_ip": self.client_ip,
            "queries": self.queries,
            "responses": self.responses,
            "nxdomains": self.nxdomains,
            "qtypes": dict(self.qtypes.most_common()),
            "unique_qnames": len(self.unique_qnames),
            "unique_qnames_overflow": self.unique_qnames_overflow,
        }


@dataclass(slots=True)
class DomainStats:
    base_domain: str
    queries: int = 0
    nxdomains: int = 0
    clients: set[str] = field(default_factory=set)
    unique_subdomains: set[str] = field(default_factory=set)
    subdomain_overflow: bool = False
    max_label_length: int = 0
    max_entropy: float = 0.0
    entropy_sum: float = 0.0
    entropy_count: int = 0
    txt_or_null_queries: int = 0

    def record_query(self, subdomain: str, qtype: str, client_ip: str) -> None:
        self.queries += 1
        self.clients.add(client_ip)
        if qtype in ("TXT", "NULL"):
            self.txt_or_null_queries += 1
        if subdomain:
            if len(self.unique_subdomains) < _MAX_SUBDOMAINS_PER_DOMAIN:
                self.unique_subdomains.add(subdomain)
            elif subdomain not in self.unique_subdomains:
                self.subdomain_overflow = True
            longest_label = max(subdomain.split("."), key=len)
            self.max_label_length = max(self.max_label_length, len(longest_label))
            entropy = shannon_entropy(subdomain.replace(".", ""))
            self.max_entropy = max(self.max_entropy, entropy)
            self.entropy_sum += entropy
            self.entropy_count += 1

    @property
    def mean_entropy(self) -> float:
        return self.entropy_sum / self.entropy_count if self.entropy_count else 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "base_domain": self.base_domain,
            "queries": self.queries,
            "nxdomains": self.nxdomains,
            "clients": sorted(self.clients),
            "unique_subdomains": len(self.unique_subdomains),
            "subdomain_overflow": self.subdomain_overflow,
            "max_label_length": self.max_label_length,
            "max_entropy": round(self.max_entropy, 3),
            "mean_entropy": round(self.mean_entropy, 3),
            "txt_or_null_queries": self.txt_or_null_queries,
        }


class DnsAnalyzer:
    """Collector extracting DNS activity from the packet stream."""

    wants_packets = True

    def __init__(self) -> None:
        self.total_queries = 0
        self.total_responses = 0
        self.nxdomain_responses = 0
        self.rcodes: Counter = Counter()
        self.parse_errors = 0
        self.clients: dict[str, DnsClientStats] = {}
        self.domains: dict[str, DomainStats] = {}
        self.sample_queries: list[DnsQuery] = []
        # name -> IPs it resolved to; ip -> names that resolved to it
        self.resolutions: dict[str, set[str]] = {}
        self.ip_to_names: dict[str, set[str]] = {}

    # ------------------------------------------------------------- helpers

    def _client(self, ip: str) -> DnsClientStats:
        stats = self.clients.get(ip)
        if stats is None:
            stats = DnsClientStats(client_ip=ip)
            self.clients[ip] = stats
        return stats

    def _domain(self, base: str) -> DomainStats:
        stats = self.domains.get(base)
        if stats is None:
            stats = DomainStats(base_domain=base)
            self.domains[base] = stats
        return stats

    # ------------------------------------------------------------ observe

    def observe_packet(self, event: NetworkEvent, packet: Packet) -> None:
        dns = packet.getlayer(DNS)
        if dns is None or event.src_ip is None or event.dst_ip is None:
            return
        try:
            if int(dns.qr) == 0:
                self._process_query(dns, event)
            else:
                self._process_response(dns, event)
        except Exception:
            self.parse_errors += 1
            LOG.debug("failed to parse DNS message", exc_info=True)

    def _first_qname_qtype(self, dns: DNS) -> tuple[str, str] | None:
        for question in _iter_section(dns.qd):
            qname = normalise_qname(question.qname)
            qtype = QTYPE_NAMES.get(int(question.qtype), str(int(question.qtype)))
            return qname, qtype
        return None

    def _process_query(self, dns: DNS, event: NetworkEvent) -> None:
        parsed = self._first_qname_qtype(dns)
        if parsed is None:
            return
        qname, qtype = parsed
        self.total_queries += 1

        client = self._client(event.src_ip)
        client.record_query(qname, qtype, event.timestamp)

        subdomain, base = split_domain(qname)
        self._domain(base).record_query(subdomain, qtype, event.src_ip)

        if len(self.sample_queries) < _MAX_SAMPLE_QUERIES:
            self.sample_queries.append(
                DnsQuery(
                    timestamp=event.timestamp,
                    client_ip=event.src_ip,
                    server_ip=event.dst_ip,
                    qname=qname,
                    qtype=qtype,
                )
            )

    def _process_response(self, dns: DNS, event: NetworkEvent) -> None:
        self.total_responses += 1
        rcode = int(dns.rcode)
        self.rcodes[RCODE_NAMES.get(rcode, str(rcode))] += 1

        # The response's destination is the querying client.
        client = self._client(event.dst_ip)
        client.responses += 1

        parsed = self._first_qname_qtype(dns)
        qname = parsed[0] if parsed else None

        if rcode == 3:
            self.nxdomain_responses += 1
            client.nxdomains += 1
            if qname:
                _, base = split_domain(qname)
                self._domain(base).nxdomains += 1
            return

        if qname is None:
            return
        for rr in _iter_section(dns.an):
            if not isinstance(rr, DNSRR):
                continue
            rrtype = int(rr.type)
            if rrtype in (1, 28):  # A / AAAA
                address = _to_text(rr.rdata)
                self.resolutions.setdefault(qname, set()).add(address)
                self.ip_to_names.setdefault(address, set()).add(qname)

    # ------------------------------------------------------------- views

    def names_for_ip(self, ip: str) -> set[str]:
        """Names that resolved to ``ip`` in this capture (empty set = the IP
        was contacted without any observed DNS resolution)."""
        return self.ip_to_names.get(ip, set())

    def as_dict(self) -> dict[str, object]:
        top_domains = sorted(self.domains.values(), key=lambda d: -d.queries)
        return {
            "total_queries": self.total_queries,
            "total_responses": self.total_responses,
            "nxdomain_responses": self.nxdomain_responses,
            "rcodes": dict(self.rcodes.most_common()),
            "parse_errors": self.parse_errors,
            "clients": [c.as_dict() for c in self.clients.values()],
            "domains": [d.as_dict() for d in top_domains[:100]],
            "resolutions": {
                name: sorted(ips)
                for name, ips in sorted(self.resolutions.items())[:500]
            },
            "sample_queries": [q.as_dict() for q in self.sample_queries[:200]],
        }
