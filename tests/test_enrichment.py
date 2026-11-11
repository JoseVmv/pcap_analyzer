"""IOC enrichment: context for the addresses and sites in a capture.

The invariants that matter most are the ones an analyst cannot check by reading
a report: a default run sends nothing anywhere, ``--enrich`` sends only what it
says it sends, a third party's opinion never moves the risk score, and whatever
a provider or a crafted packet returns cannot break the tool or its output.
"""

from __future__ import annotations

import http.server
import json
import socket
import struct
import threading

import pytest
import synth
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from investigator.cli import run
from investigator.config import Config, load_config
from investigator.enrichment import (
    Enrichment,
    _note_registration_age,
    render_enrichment_text,
)
from investigator.enrichment.indicators import (
    DomainIndicator,
    IpIndicator,
    domain_lookup_block,
    ip_lookup_block,
    normalise_host,
)
from investigator.enrichment.knowledge import (
    ServiceHint,
    address_class,
    best_name_hint,
    hint_for_ip,
    hint_for_name,
)
from investigator.enrichment.lookups import (
    LookupCache,
    LookupRunner,
    build_lookup_runner,
    default_cache_path,
    lookup_order,
)
from investigator.enrichment.providers import (
    PROVIDERS,
    AbuseIpDbProvider,
    InternetDbProvider,
    LookupResult,
    LookupStatus,
    Provider,
    ProviderError,
    ProviderStop,
    RdapProvider,
    RipeStatProvider,
    Signal,
    VirusTotalProvider,
    _parse_date,
    build_providers,
    clean_text,
    urllib_fetch,
)
from investigator.errors import ConfigError
from investigator.parser import PcapLoader
from investigator.pipeline import analyze_capture
from investigator.reporting import build_report, render_html

CLIENT = "10.0.0.15"
RESOLVER = "10.0.0.1"
PUBLIC_IP = "93.184.216.34"
OTHER_PUBLIC_IP = "45.33.32.156"
SECRET_URI = "/invoice.pdf?token=s3cret"
TUNNEL_LABEL = "mzxw6ytboi2gk3tpobzxe33om4qgcidu"


# ----------------------------------------------------------------- capture

def _eth():
    return Ether(src=synth.MAC_A, dst=synth.MAC_B)


def dns_query(name, client=CLIENT, qtype=1, ts=synth.BASE_TS):
    pkt = _eth() / IP(src=client, dst=RESOLVER) / UDP(sport=53111, dport=53) / DNS(
        id=1, rd=1, qd=DNSQR(qname=name, qtype=qtype)
    )
    pkt.time = ts
    return pkt


def dns_answer(name, ip, client=CLIENT, ts=synth.BASE_TS + 0.1):
    pkt = _eth() / IP(src=RESOLVER, dst=client) / UDP(sport=53, dport=53111) / DNS(
        id=1, qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type=1, rdata=ip)
    )
    pkt.time = ts
    return pkt


def dns_nxdomain(name, client=CLIENT, ts=synth.BASE_TS + 0.1):
    pkt = _eth() / IP(src=RESOLVER, dst=client) / UDP(sport=53, dport=53111) / DNS(
        id=1, qr=1, rcode=3, qd=DNSQR(qname=name)
    )
    pkt.time = ts
    return pkt


def client_hello(sni):
    """Minimal ClientHello, assembled from the RFC 8446 layout."""
    name = sni.encode()
    entry = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack("!HH", 0, len(entry)) + entry
    ciphers = b"\x13\x01\x13\x02"
    body = (
        struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00"
        + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_session(sni, dst=PUBLIC_IP, ts=synth.BASE_TS + 1):
    pkt = _eth() / IP(src=CLIENT, dst=dst) / TCP(
        sport=52000, dport=443, flags="PA", seq=1
    ) / Raw(client_hello(sni))
    pkt.time = ts
    return pkt


def http_get(host, uri="/", dst=PUBLIC_IP, ts=synth.BASE_TS + 2, method="GET"):
    payload = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: t\r\n\r\n"
    pkt = _eth() / IP(src=CLIENT, dst=dst) / TCP(
        sport=52001, dport=80, flags="PA", seq=1
    ) / Raw(payload.encode())
    pkt.time = ts
    return pkt


def http_reply(server, src=PUBLIC_IP, ts=synth.BASE_TS + 3):
    payload = f"HTTP/1.1 200 OK\r\nServer: {server}\r\nContent-Length: 0\r\n\r\n"
    pkt = _eth() / IP(src=src, dst=CLIENT) / TCP(
        sport=80, dport=52001, flags="PA", seq=1
    ) / Raw(payload.encode())
    pkt.time = ts
    return pkt


def bulk(dst, segments, ts=synth.BASE_TS + 5):
    packets = []
    for i in range(segments):
        pkt = _eth() / IP(src=CLIENT, dst=dst) / TCP(
            sport=52002, dport=443, flags="PA", seq=1 + i * 1000
        ) / Raw(b"x" * 1000)
        pkt.time = ts + i * 0.01
        packets.append(pkt)
    return packets


def web_traffic():
    """A resolved site, plus everything that must never leave the machine:
    an mDNS-style name, a name resolving only internally, a URL carrying a
    token, and a tunnel whose subdomain labels are themselves the payload."""
    return [
        dns_query("www.example.org"),
        dns_answer("www.example.org", PUBLIC_IP),
        tls_session("www.example.org"),
        http_get("www.example.org", SECRET_URI),
        http_reply("nginx/1.18"),
        dns_query("printer.local"),
        dns_query("fileserver.acme-intranet.net"),
        dns_answer("fileserver.acme-intranet.net", "10.0.0.5"),
        dns_query(f"{TUNNEL_LABEL}.t.dataleak.io", qtype=16),
    ]


def analyze(tmp_path, packets, config=None, lookups=None, name="enrich.pcap"):
    path = tmp_path / name
    wrpcap(str(path), sorted(packets, key=lambda p: p.time))
    return analyze_capture(PcapLoader(path), config=config or Config(), lookups=lookups)


def ip_of(result, value):
    return next(i for i in result.enrichment.ips if i.value == value)


def domain_of(result, value):
    return next(d for d in result.enrichment.domains if d.value == value)


# ---------------------------------------------------------------- doubles

class RecordingProvider(Provider):
    """Answers everything and remembers exactly what it was asked."""

    name = "recording"
    kinds = frozenset({"ip", "domain"})
    min_interval = 0.0

    def __init__(self, signal=None, summary="context", name=None, kinds=None):
        self.calls = []
        self.signal = signal
        self.summary = summary
        if name:
            self.name = name
        if kinds:
            self.kinds = frozenset(kinds)

    def lookup(self, kind, value):
        self.calls.append((kind, value))
        return LookupResult(
            provider=self.name,
            status=LookupStatus.OK,
            summary=f"{self.summary} {value}",
            fields={"seen": value},
            signal=self.signal,
        )


class ScriptedProvider(RecordingProvider):
    """Raises or returns from a script, one step per call."""

    def __init__(self, script, **kwargs):
        super().__init__(**kwargs)
        self.script = list(script)

    def lookup(self, kind, value):
        self.calls.append((kind, value))
        step = self.script.pop(0) if self.script else None
        if isinstance(step, BaseException):
            raise step
        if isinstance(step, LookupResult):
            return step
        return LookupResult(provider=self.name, status=LookupStatus.OK, summary="ok")


class FakeTransport:
    """Canned ``(status, body)`` replies keyed by a URL substring."""

    def __init__(self, routes=None, default=(404, b"")):
        self.routes = routes or {}
        self.default = default
        self.requests = []

    def __call__(self, url, headers, follow_redirects, timeout):
        self.requests.append(
            {"url": url, "headers": dict(headers), "follow": follow_redirects}
        )
        for fragment, reply in self.routes.items():
            if fragment in url:
                if isinstance(reply, Exception):
                    raise reply
                status, body = reply
                if not isinstance(body, (bytes, bytearray)):
                    body = json.dumps(body).encode()
                return status, bytes(body)
        return self.default


def indicator_ip(value, findings=()):
    return IpIndicator(value=value, finding_ids=list(findings))


def indicator_domain(value, findings=()):
    return DomainIndicator(value=value, finding_ids=list(findings))


@pytest.fixture()
def no_network(monkeypatch):
    """Any attempt to reach the network fails the test, not just the lookup."""

    def refuse(*args, **kwargs):
        raise AssertionError(f"network access attempted: {args!r}")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


# ---------------------------------------------------------- built-in tables

class TestKnowledge:
    @pytest.mark.parametrize(
        ("ip", "operator"),
        [
            ("172.66.0.227", "Cloudflare"),
            ("151.101.176.159", "Fastly"),
            ("8.8.4.4", "Google Public DNS"),
            ("1.1.1.1", "Cloudflare DNS"),
            ("142.251.156.4", "Google"),
            ("2606:4700::1", "Cloudflare"),
        ],
    )
    def test_published_addresses_name_their_operator(self, ip, operator):
        assert hint_for_ip(ip).name == operator

    @pytest.mark.parametrize("ip", ["10.0.0.1", "93.184.216.34", "not-an-ip"])
    def test_unknown_addresses_get_no_hint(self, ip):
        assert hint_for_ip(ip) is None

    def test_google_cloud_customers_are_not_called_google(self):
        """A VM rented on Google Cloud is the customer's, not Google's."""
        assert hint_for_ip("34.64.0.1") is None

    def test_suffix_match_is_aligned_to_whole_labels(self):
        assert hint_for_name("www.google.com").name == "Google"
        assert hint_for_name("google.com").name == "Google"
        assert hint_for_name("evilgoogle.com") is None
        assert hint_for_name("google.com.evil.io") is None

    def test_most_specific_suffix_wins(self):
        hint = hint_for_name("acme.blob.core.windows.net")
        assert hint.category == "cloud-hosting"
        assert hint.commonly_abused

    def test_abused_service_is_not_hidden_behind_an_ordinary_one(self):
        hint = best_name_hint(["www.google.com", "x.duckdns.org"])
        assert hint.category == "dynamic-dns"

    def test_address_classes(self):
        assert address_class("203.0.113.66") == "documentation range"
        assert address_class("2001:db8::1") == "documentation range"
        assert address_class("192.0.0.1") == "special-purpose range"
        assert address_class("8.8.8.8") is None


# -------------------------------------------------------- what may be sent

class TestLookupEligibility:
    @pytest.mark.parametrize(
        "ip", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "203.0.113.66", "::1", "fe80::1", "x"]
    )
    def test_non_public_addresses_are_blocked(self, ip):
        assert ip_lookup_block(ip) is not None

    @pytest.mark.parametrize("ip", ["8.8.8.8", "2001:4860:4860::8888"])
    def test_public_addresses_are_allowed(self, ip):
        assert ip_lookup_block(ip) is None

    @pytest.mark.parametrize(
        "domain", ["example.org", "dataleak.io", "empresa.com.br", "xn--bcher-kva.example.com"]
    )
    def test_public_names_are_allowed(self, domain):
        assert domain_lookup_block(domain) is None

    @pytest.mark.parametrize(
        "domain",
        [
            "printer.local", "dc01.corp", "x.internal", "1.168.192.in-addr.arpa",
            "router.lan", "abc.onion", "attack.test", "foo", "_tcp.local", "",
            "1.2.3.4",
        ],
    )
    def test_names_not_in_public_dns_are_blocked(self, domain):
        assert domain_lookup_block(domain) is not None

    @pytest.mark.parametrize(
        "domain",
        [
            "x.com/../../users/me",
            "evil.com?apikey=1",
            "evil.com#frag",
            "a b.com",
            "example.org\n",
            "<script>alert(1)</script>.example.org",
            "ex%2fample.org",
            "-bad.example.org",
            "a" * 64 + ".example.org",
        ],
    )
    def test_crafted_names_cannot_become_part_of_a_request(self, domain):
        """A capture-controlled string must never alter an API path."""
        assert domain_lookup_block(domain) == "malformed name"

    def test_operator_exclusions_hold(self):
        assert domain_lookup_block("acme.com", exclude=["acme.com"]) is not None
        assert domain_lookup_block("sub.acme.com", exclude=[".acme.com"]) is not None
        assert domain_lookup_block("notacme.com", exclude=["acme.com"]) is None

    def test_exclusion_of_a_subdomain_also_holds_back_its_base(self):
        """Only the base is ever sent, so that is what the exclusion must stop."""
        block = domain_lookup_block(
            "acme.com", names=["fs.corp.acme.com"], exclude=["corp.acme.com"]
        )
        assert block is not None

    def test_name_resolving_only_internally_is_internal(self):
        assert domain_lookup_block("acme.net", resolved_ips=["10.0.0.5"]) is not None
        assert (
            domain_lookup_block("acme.net", resolved_ips=["10.0.0.5", PUBLIC_IP]) is None
        )


class TestNormaliseHost:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("WWW.Example.ORG", "www.example.org"),
            ("example.org:8080", "example.org"),
            ("example.org.", "example.org"),
            ("  example.org ", "example.org"),
            ("93.184.216.34", None),
            ("93.184.216.34:8080", None),
            ("[2001:db8::1]:443", None),
            ("", None),
        ],
    )
    def test_cases(self, raw, expected):
        assert normalise_host(raw) == expected


# ------------------------------------------------- context from the capture

class TestCaptureContext:
    def test_address_collects_what_the_capture_said_about_it(self, tmp_path):
        result = analyze(tmp_path, web_traffic())
        indicator = ip_of(result, PUBLIC_IP)
        assert indicator.names == {"www.example.org"}
        assert indicator.sni == {"www.example.org"}
        assert indicator.http_hosts == {"www.example.org"}
        assert indicator.http_servers == {"nginx/1.18"}
        assert indicator.internal_peers == {CLIENT}
        assert set(indicator.ports) == {443, 80}
        assert indicator.bytes_to > 0
        assert indicator.bytes_from > 0
        assert indicator.first_seen is not None

    def test_domain_groups_names_sources_and_urls(self, tmp_path):
        result = analyze(tmp_path, web_traffic())
        domain = domain_of(result, "example.org")
        assert domain.names == {"www.example.org"}
        assert domain.seen_via == {"dns", "tls-sni", "http-host"}
        assert domain.resolved_ips == {PUBLIC_IP}
        assert domain.contacted_ips == {PUBLIC_IP}
        assert domain.clients == {CLIENT}
        assert (domain.dns_queries, domain.tls_sessions, domain.http_requests) == (1, 1, 1)
        assert f"GET http://www.example.org{SECRET_URI}" in domain.urls

    def test_repeated_url_is_counted_once_with_its_count(self, tmp_path):
        packets = [http_get("a.example.org", "/x", ts=synth.BASE_TS + i) for i in range(3)]
        result = analyze(tmp_path, packets)
        urls = domain_of(result, "example.org").urls
        assert urls["GET http://a.example.org/x"] == 3

    def test_address_literal_in_host_header_is_not_a_domain(self, tmp_path):
        """``93.184.216.34:8080`` would otherwise produce a "site" called 34."""
        result = analyze(tmp_path, [http_get(f"{PUBLIC_IP}:8080")])
        assert result.enrichment.domains == []
        assert ip_of(result, PUBLIC_IP).http_hosts == set()

    def test_tls_session_without_dns_still_produces_a_domain(self, tmp_path):
        result = analyze(tmp_path, [tls_session("direct.example.net")])
        domain = domain_of(result, "example.net")
        assert domain.seen_via == {"tls-sni"}
        assert domain.resolved_ips == set()
        assert domain.contacted_ips == {PUBLIC_IP}

    def test_internal_hosts_are_not_indicators(self, tmp_path):
        result = analyze(tmp_path, web_traffic())
        values = {i.value for i in result.enrichment.ips}
        assert CLIENT not in values
        assert RESOLVER not in values

    def test_domain_that_never_resolved_says_so(self, tmp_path):
        packets = [dns_query("gone.example.net"), dns_nxdomain("gone.example.net")]
        result = analyze(tmp_path, packets)
        assert any("NXDOMAIN" in n for n in domain_of(result, "example.net").notes)

    def test_service_hint_reaches_the_indicators(self, tmp_path):
        packets = [
            tls_session("x.duckdns.org", dst="172.66.0.227"),
            dns_query("www.google.com"),
        ]
        result = analyze(tmp_path, packets)
        assert ip_of(result, "172.66.0.227").service.name == "Cloudflare"
        assert domain_of(result, "duckdns.org").service.commonly_abused
        assert domain_of(result, "google.com").service.name == "Google"

    def test_documentation_address_is_called_out(self, tmp_path):
        result = analyze(tmp_path, [tls_session("x.example.org", dst="203.0.113.66")])
        indicator = ip_of(result, "203.0.113.66")
        assert indicator.address_class == "documentation range"
        assert indicator.lookup_block is not None
        assert any("documentation" in n for n in indicator.notes)

    def test_crafted_name_is_shown_whole_instead_of_split(self, tmp_path):
        """"./users/me" would hide what the client actually sent."""
        crafted = "x.com/../../users/me"
        result = analyze(tmp_path, [tls_session(crafted)])
        assert [d.value for d in result.enrichment.domains] == [crafted]
        assert result.enrichment.domains[0].lookup_block == "malformed name"

    def test_mdns_names_still_group_under_their_suffix(self, tmp_path):
        packets = [dns_query("a._tcp.local"), dns_query("b._tcp.local")]
        result = analyze(tmp_path, packets)
        assert [d.value for d in result.enrichment.domains] == ["_tcp.local"]

    def test_root_query_produces_no_empty_domain(self, tmp_path):
        result = analyze(tmp_path, [dns_query("."), tls_session("x.example.org")])
        assert all(d.value for d in result.enrichment.domains)


class TestCaptureNotes:
    """No name usually means the capture could not show one."""

    def _notes(self, tmp_path, packets):
        return " ".join(analyze(tmp_path, packets).enrichment.notes)

    def test_missing_dns_is_explained(self, tmp_path):
        assert "No DNS responses" in self._notes(tmp_path, bulk(PUBLIC_IP, 3))

    def test_visible_dns_needs_no_explanation(self, tmp_path):
        assert "No DNS responses" not in self._notes(tmp_path, web_traffic())

    def test_quic_is_explained(self, tmp_path):
        pkt = _eth() / IP(src=CLIENT, dst=PUBLIC_IP) / UDP(sport=50000, dport=443) / Raw(b"q")
        pkt.time = synth.BASE_TS
        assert "QUIC" in self._notes(tmp_path, [pkt])

    def test_tls_port_without_handshake_is_explained(self, tmp_path):
        assert "ClientHello" in self._notes(tmp_path, bulk(PUBLIC_IP, 3))

    def test_parsed_handshake_needs_no_explanation(self, tmp_path):
        notes = self._notes(tmp_path, [tls_session("x.example.org")])
        assert "ClientHello" not in notes

    def test_only_internal_traffic_has_nothing_to_explain(self, tmp_path):
        pkt = _eth() / IP(src=CLIENT, dst=RESOLVER) / TCP(sport=1, dport=443)
        pkt.time = synth.BASE_TS
        assert analyze(tmp_path, [pkt]).enrichment.notes == []

    def test_address_gets_a_note_only_when_dns_was_visible(self, tmp_path):
        with_dns = analyze(tmp_path, web_traffic() + bulk(OTHER_PUBLIC_IP, 2), name="a.pcap")
        assert any("no DNS answer" in n for n in ip_of(with_dns, OTHER_PUBLIC_IP).notes)
        assert ip_of(with_dns, PUBLIC_IP).notes == []

        without_dns = analyze(tmp_path, bulk(OTHER_PUBLIC_IP, 2), name="b.pcap")
        assert ip_of(without_dns, OTHER_PUBLIC_IP).notes == []


class TestFindingLinks:
    def test_finding_reaches_its_destination(self, tmp_path):
        beacon_ip = "45.33.32.156"
        result = analyze(tmp_path, synth.beacon(server=beacon_ip, dport=4444))
        beacon = next(f for f in result.findings if f.type == "beaconing")
        assert beacon.id in ip_of(result, beacon_ip).finding_ids

    def test_dns_finding_reaches_its_domain(self, tmp_path):
        result = analyze(tmp_path, synth.dns_tunnel(base_domain="tunnel.evil.io"))
        finding = next(f for f in result.findings if f.type.startswith("dns_"))
        assert finding.id in domain_of(result, "evil.io").finding_ids

    def test_domain_inherits_findings_from_its_address(self, tmp_path):
        beacon_ip = "45.33.32.156"
        packets = synth.beacon(server=beacon_ip, dport=4444) + [
            dns_answer("c2.example.net", beacon_ip)
        ]
        result = analyze(tmp_path, packets)
        linked = ip_of(result, beacon_ip).finding_ids
        assert linked
        assert set(linked) <= set(domain_of(result, "example.net").finding_ids)

    def test_finding_ids_are_not_repeated(self, tmp_path):
        beacon_ip = "45.33.32.156"
        packets = synth.beacon(server=beacon_ip, dport=4444) + [
            dns_answer("a.example.net", beacon_ip),
            dns_answer("b.example.net", beacon_ip),
        ]
        result = analyze(tmp_path, packets)
        ids = domain_of(result, "example.net").finding_ids
        assert len(ids) == len(set(ids))


class TestRankingAndLimits:
    def _beacon_and_volume(self):
        """More bytes to one address, but too few packets to raise a finding."""
        return synth.beacon(server=OTHER_PUBLIC_IP, dport=4444) + bulk(PUBLIC_IP, 5)

    def test_finding_outranks_volume(self, tmp_path):
        result = analyze(tmp_path, self._beacon_and_volume())
        quiet = ip_of(result, PUBLIC_IP)
        noisy = ip_of(result, OTHER_PUBLIC_IP)
        assert quiet.finding_ids == []
        assert quiet.bytes_to > noisy.bytes_to
        assert result.enrichment.ips[0] is noisy

    def test_limit_keeps_the_indicator_with_a_finding_and_reports_the_rest(self, tmp_path):
        result = analyze(
            tmp_path, self._beacon_and_volume(), config=Config(enrich_max_indicators=1)
        )
        assert [i.value for i in result.enrichment.ips] == [OTHER_PUBLIC_IP]
        assert result.enrichment.ips_omitted == 1

    def test_domain_limit_is_reported(self, tmp_path):
        packets = [dns_query(f"site{i}.example{i}.org") for i in range(4)]
        result = analyze(tmp_path, packets, config=Config(enrich_max_indicators=2))
        assert len(result.enrichment.domains) == 2
        assert result.enrichment.domains_omitted == 2

    def test_listing_is_bounded_but_keeps_the_true_total(self, tmp_path):
        packets = [dns_query(f"h{i}.example.org", ts=synth.BASE_TS + i) for i in range(30)]
        result = analyze(tmp_path, packets, config=Config(enrich_max_listed=5))
        names = result.enrichment.domains[0].as_dict(5)["names"]
        assert len(names["sample"]) == 5
        assert names["total"] == 30

    def test_shortest_names_are_listed_first(self):
        """``www.evil.io`` must not be buried under random tunnel labels."""
        domain = DomainIndicator(value="evil.io")
        domain.names = {f"{'z' * 40}{i}.evil.io" for i in range(20)} | {"www.evil.io"}
        assert domain.as_dict(3)["names"]["sample"][0] == "www.evil.io"


# ----------------------------------------------------------- core invariants

class TestOfflineByDefault:
    def test_analysis_never_touches_the_network(self, tmp_path, no_network):
        result = analyze(tmp_path, web_traffic())
        report = build_report(result)
        render_html(report)
        assert report["enrichment"]["mode"] == "offline"
        assert report["enrichment"]["contacted_services"] == []
        assert report["enrichment"]["lookups_sent"] == 0

    def test_cli_never_touches_the_network(self, tmp_path, no_network, capsys):
        capture = tmp_path / "web.pcap"
        wrpcap(str(capture), sorted(web_traffic(), key=lambda p: p.time))
        assert run([str(capture), "--output-dir", str(tmp_path / "out")]) == 0
        out = capsys.readouterr().out
        assert "IOC enrichment" in out
        assert "nothing left this machine" in out
        assert "--enrich" in out

    def test_offline_report_still_says_no_external_services(self, tmp_path):
        html = render_html(build_report(analyze(tmp_path, web_traffic())))
        assert "offline analysis, no external services" in html
        assert "Online lookups were enabled" not in html

    def test_configured_providers_stay_unused_without_the_flag(self, tmp_path, no_network):
        config = Config(enrich_providers=("virustotal",))
        result = analyze(tmp_path, web_traffic(), config=config)
        assert result.enrichment.runs == []


class TestWhatLeavesTheMachine:
    def test_only_public_addresses_and_base_domains_are_sent(self, tmp_path):
        provider = RecordingProvider()
        runner = LookupRunner([provider], Config())
        analyze(tmp_path, web_traffic(), lookups=runner)
        assert set(provider.calls) == {
            ("ip", PUBLIC_IP),
            ("domain", "example.org"),
            ("domain", "dataleak.io"),
        }

    def test_sensitive_values_appear_in_no_request(self, tmp_path):
        """Checked at the transport, past all the logic above it."""
        transport = FakeTransport()
        # Long enough for RDAP's 1s pacing to reach both public domains.
        config = Config(enrich_cache_ttl_hours=0, enrich_deadline_seconds=2.5)
        runner = build_lookup_runner(
            config,
            environ={"VT_API_KEY": "k", "ABUSEIPDB_API_KEY": "k"},
            transport=transport,
        )
        analyze(tmp_path, web_traffic(), config=config, lookups=runner)
        sent = " ".join(r["url"] for r in transport.requests)
        assert PUBLIC_IP in sent
        assert "rdap.org/domain/example.org" in sent
        assert "rdap.org/domain/dataleak.io" in sent
        for forbidden in (
            "s3cret", "invoice", "www.example.org", TUNNEL_LABEL, "t.dataleak.io",
            "printer", "fileserver", "acme-intranet", CLIENT, RESOLVER,
        ):
            assert forbidden not in sent, forbidden

    def test_crafted_sni_never_reaches_a_request(self, tmp_path):
        transport = FakeTransport()
        config = Config(
            enrich_providers=("ripestat", "rdap", "internetdb"),
            enrich_cache_ttl_hours=0,
            enrich_deadline_seconds=0.2,
        )
        runner = build_lookup_runner(config, environ={}, transport=transport)
        crafted = "x.com/../../users/me"
        result = analyze(
            tmp_path, [tls_session(crafted)], config=config, lookups=runner
        )
        assert not any("users/me" in r["url"] for r in transport.requests)
        blocked = [d for d in result.enrichment.domains if "users" in d.value]
        assert blocked and blocked[0].lookup_block == "malformed name"

    def test_operator_exclusion_is_honoured(self, tmp_path):
        provider = RecordingProvider()
        config = Config(enrich_exclude_domains=("example.org",))
        runner = LookupRunner([provider], config)
        analyze(tmp_path, web_traffic(), config=config, lookups=runner)
        assert ("domain", "example.org") not in provider.calls
        assert ("ip", PUBLIC_IP) in provider.calls

    def test_blocked_indicators_say_why_and_get_no_links(self, tmp_path):
        result = analyze(tmp_path, web_traffic())
        local = domain_of(result, "printer.local").as_dict(10)
        assert "non-public" in local["lookup_block"]
        assert local["pivots"] == []
        internal = domain_of(result, "acme-intranet.net").as_dict(10)
        assert "internal" in internal["lookup_block"]


class TestScoreIsolation:
    """A third party's opinion is context, never evidence."""

    def _packets(self):
        return synth.beacon(server=PUBLIC_IP, dport=4444) + web_traffic()

    @staticmethod
    def _shape(result):
        return [(f.type, f.title, f.severity, f.confidence) for f in result.findings]

    def test_reputation_does_not_move_findings_or_risk(self, tmp_path):
        offline = analyze(tmp_path, self._packets(), name="off.pcap")
        flagged = analyze(
            tmp_path,
            self._packets(),
            name="on.pcap",
            lookups=LookupRunner(
                [RecordingProvider(signal=Signal.FLAGGED)], Config()
            ),
        )
        assert ip_of(flagged, PUBLIC_IP).reputation["signal"] == "flagged"
        assert self._shape(flagged) == self._shape(offline)
        assert flagged.risk.value == offline.risk.value
        assert flagged.risk.raw_score == offline.risk.raw_score
        assert flagged.investigation.verdict == offline.investigation.verdict
        assert flagged.investigation.conclusion == offline.investigation.conclusion


# --------------------------------------------------------------- providers

RIPE_OVERVIEW = {
    "status": "ok",
    "data": {
        "announced": True,
        "resource": "8.8.8.0/24",
        "asns": [{"asn": 15169, "holder": "GOOGLE - Google LLC"}],
    },
}
RIPE_GEO = {
    "data": {
        "located_resources": [
            {"resource": "8.8.8.8/32", "locations": [{"country": "US", "city": ""}]}
        ]
    }
}
RDAP_DOMAIN = {
    "objectClassName": "domain",
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited"],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-IANA"]],
            ],
        }
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    ],
    "nameservers": [{"ldhName": "ELLIOTT.NS.CLOUDFLARE.COM"}],
}
INTERNETDB = {
    "cpes": [],
    "hostnames": ["dns.google"],
    "ip": "8.8.8.8",
    "ports": [53, 443],
    "tags": ["pqc"],
    "vulns": ["CVE-2020-1"],
}


def vt_payload(malicious=0, suspicious=0, harmless=60, undetected=30, **attributes):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious, "suspicious": suspicious,
                    "harmless": harmless, "undetected": undetected, "timeout": 0,
                },
                "reputation": -5,
                "as_owner": "EXAMPLE-AS",
                "asn": 64500,
                "country": "BR",
                **attributes,
            }
        }
    }


def abuse_payload(score=0, reports=0, **extra):
    return {
        "data": {
            "abuseConfidenceScore": score,
            "totalReports": reports,
            "numDistinctUsers": 4,
            "lastReportedAt": "2026-10-01T00:00:00+00:00",
            "isp": "Example ISP",
            "usageType": "Data Center/Web Hosting/Transit",
            "countryCode": "BR",
            "isTor": False,
            **extra,
        }
    }


def make(provider_class, transport, api_key=None, config=None):
    return provider_class(config or Config(), transport=transport, api_key=api_key)


class TestRipeStat:
    def _provider(self, geo=(200, RIPE_GEO), overview=(200, RIPE_OVERVIEW)):
        transport = FakeTransport(
            {"maxmind-geo-lite": geo, "prefix-overview": overview}
        )
        return make(RipeStatProvider, transport), transport

    def test_reports_origin_prefix_and_country(self):
        provider, _ = self._provider()
        result = provider.lookup("ip", "8.8.8.8")
        assert result.status is LookupStatus.OK
        assert result.fields["asns"][0]["asn"] == 15169
        assert result.fields["prefix"] == "8.8.8.0/24"
        assert result.fields["country"] == "US"
        assert "AS15169 GOOGLE - Google LLC" in result.summary
        assert result.brief == "AS15169 GOOGLE - Google LLC [US]"
        assert result.signal is None

    def test_losing_geolocation_does_not_lose_the_asn(self):
        provider, _ = self._provider(geo=(500, b""))
        result = provider.lookup("ip", "8.8.8.8")
        assert result.status is LookupStatus.OK
        assert result.fields["country"] is None
        assert result.fields["asns"][0]["asn"] == 15169

    def test_anycast_falls_back_to_registration_and_says_so(self):
        """Registered in a country is a different claim from located in it."""
        anycast = {"data": {"located_resources": [{"locations": [{"country": "?"}]}]}}
        registered = {"data": {"located_resources": [{"location": "AU"}]}}
        transport = FakeTransport(
            {
                "maxmind-geo-lite": (200, anycast),
                "rir-stats-country": (200, registered),
                "prefix-overview": (200, RIPE_OVERVIEW),
            }
        )
        result = make(RipeStatProvider, transport).lookup("ip", "1.1.1.1")
        assert result.fields["country"] == "AU"
        assert result.fields["country_source"] == "registered"
        assert "[registered in AU]" in result.summary

    def test_geolocation_is_preferred_and_needs_no_second_call(self):
        provider, transport = self._provider()
        result = provider.lookup("ip", "8.8.8.8")
        assert result.fields["country_source"] == "geolocated"
        assert not any("rir-stats" in r["url"] for r in transport.requests)

    def test_unannounced_prefix_is_described(self):
        overview = (200, {"data": {"announced": False, "asns": [], "resource": "1.2.3.0/24"}})
        provider, _ = self._provider(overview=overview)
        assert "not announced" in provider.lookup("ip", "1.2.3.4").summary

    def test_multiple_origins_are_noted(self):
        overview = (
            200,
            {"data": {"asns": [{"asn": 1, "holder": "A"}, {"asn": 2, "holder": "B"}]}},
        )
        provider, _ = self._provider(overview=overview)
        assert "+1 more origin" in provider.lookup("ip", "1.2.3.4").summary

    def test_identifies_itself_and_encodes_the_address(self):
        provider, transport = self._provider()
        provider.lookup("ip", "2001:4860:4860::8888")
        url = transport.requests[0]["url"]
        assert "sourceapp=pcap-investigator" in url
        assert "2001%3A4860" in url
        assert url.startswith("https://stat.ripe.net/")


class TestRdap:
    def test_reads_registration_data(self):
        transport = FakeTransport({"rdap.org": (200, RDAP_DOMAIN)})
        result = make(RdapProvider, transport).lookup("domain", "example.com")
        assert result.fields["registered"] == "1995-08-14"
        assert result.fields["expires"] == "2027-08-13"
        assert result.fields["registrar"] == "RESERVED-IANA"
        assert result.fields["nameservers"] == ["elliott.ns.cloudflare.com"]
        assert result.brief == "registered 1995-08-14"

    def test_is_the_one_provider_that_follows_redirects(self):
        """The bootstrap answers with a redirect to the registry."""
        transport = FakeTransport({"rdap.org": (200, RDAP_DOMAIN)})
        make(RdapProvider, transport).lookup("domain", "example.com")
        assert transport.requests[0]["follow"] is True

    def test_missing_record_is_not_called_unregistered(self):
        result = make(RdapProvider, FakeTransport()).lookup("domain", "example.zz")
        assert result.status is LookupStatus.NOT_FOUND
        assert "unregistered" not in result.summary

    def test_record_without_dates_still_answers(self):
        transport = FakeTransport({"rdap.org": (200, {"objectClassName": "domain"})})
        result = make(RdapProvider, transport).lookup("domain", "example.com")
        assert result.status is LookupStatus.OK
        assert result.fields["registered"] is None
        assert result.brief == ""


class TestInternetDb:
    def test_reads_exposure(self):
        transport = FakeTransport({"internetdb": (200, INTERNETDB)})
        result = make(InternetDbProvider, transport).lookup("ip", "8.8.8.8")
        assert result.fields["ports"] == [53, 443]
        assert result.fields["vulns"] == ["CVE-2020-1"]
        assert "open ports 53, 443" in result.summary
        assert "CVE-2020-1" in result.summary

    def test_exposure_is_not_a_reputation_verdict(self):
        transport = FakeTransport({"internetdb": (200, INTERNETDB)})
        assert make(InternetDbProvider, transport).lookup("ip", "8.8.8.8").signal is None

    def test_unindexed_address(self):
        result = make(InternetDbProvider, FakeTransport()).lookup("ip", "192.0.2.1")
        assert result.status is LookupStatus.NOT_FOUND


class TestVirusTotal:
    def _lookup(self, payload, kind="ip", value="8.8.8.8", config=None):
        transport = FakeTransport({"virustotal.com": (200, payload)})
        provider = make(VirusTotalProvider, transport, api_key="SECRETKEY", config=config)
        return provider.lookup(kind, value), transport

    @pytest.mark.parametrize(
        ("malicious", "suspicious", "signal"),
        [
            (5, 0, Signal.FLAGGED),
            (3, 0, Signal.FLAGGED),
            (2, 0, Signal.REPORTED),
            (0, 1, Signal.REPORTED),
            (0, 0, Signal.NO_REPORTS),
        ],
    )
    def test_signal_follows_the_threshold(self, malicious, suspicious, signal):
        result, _ = self._lookup(vt_payload(malicious, suspicious))
        assert result.signal is signal

    def test_threshold_is_configurable(self):
        result, _ = self._lookup(vt_payload(1), config=Config(enrich_vt_flag_engines=1))
        assert result.signal is Signal.FLAGGED

    def test_no_engine_data_is_not_a_clean_bill_of_health(self):
        result, _ = self._lookup({"data": {"attributes": {}}})
        assert result.signal is None
        assert "no engine results" in result.summary

    def test_summary_states_the_ratio_and_uses_hedged_words(self):
        result, _ = self._lookup(vt_payload(5))
        assert "5 of 95 engines flagged it" in result.summary
        assert "malicious" not in result.summary.lower()
        assert result.brief == "VirusTotal 5/95 flagged"

    def test_quiet_answers_earn_no_space_in_other_tables(self):
        result, _ = self._lookup(vt_payload(0))
        assert result.brief == ""

    def test_domain_lookup_reads_registration(self):
        result, transport = self._lookup(
            vt_payload(creation_date=1106675546, categories={"a": "news", "b": "news"}),
            kind="domain",
            value="example.com",
        )
        assert "/domains/example.com" in transport.requests[0]["url"]
        assert result.fields["registered"] == "2005-01-25"
        assert result.fields["registered_ts"] == 1106675546
        assert result.fields["categories"] == ["news"]

    def test_key_travels_only_in_a_header(self):
        result, transport = self._lookup(vt_payload())
        request = transport.requests[0]
        assert request["headers"]["x-apikey"] == "SECRETKEY"
        assert "SECRETKEY" not in request["url"]
        assert "SECRETKEY" not in json.dumps(result.as_dict())

    def test_keyed_requests_never_follow_redirects(self):
        """urllib forwards headers on a redirect, API key included."""
        _, transport = self._lookup(vt_payload())
        assert transport.requests[0]["follow"] is False

    def test_unknown_indicator(self):
        provider = make(VirusTotalProvider, FakeTransport(), api_key="k")
        result = provider.lookup("ip", "8.8.8.8")
        assert result.status is LookupStatus.NOT_FOUND
        assert result.signal is None


class TestAbuseIpDb:
    def _lookup(self, payload, config=None):
        transport = FakeTransport({"abuseipdb.com": (200, payload)})
        provider = make(AbuseIpDbProvider, transport, api_key="SECRETKEY", config=config)
        return provider.lookup("ip", "8.8.8.8"), transport

    @pytest.mark.parametrize(
        ("score", "reports", "signal"),
        [
            (100, 500, Signal.FLAGGED),
            (50, 10, Signal.FLAGGED),
            (10, 2, Signal.REPORTED),
            (0, 0, Signal.NO_REPORTS),
        ],
    )
    def test_signal_follows_the_threshold(self, score, reports, signal):
        result, _ = self._lookup(abuse_payload(score, reports))
        assert result.signal is signal

    def test_reads_context(self):
        result, _ = self._lookup(abuse_payload(87, 12, isTor=True))
        assert result.fields["isp"] == "Example ISP"
        assert result.fields["is_tor"] is True
        assert "abuse score 87%" in result.summary
        assert "Tor exit node" in result.summary
        assert result.brief == "AbuseIPDB score 87%"

    def test_key_travels_only_in_a_header(self):
        _, transport = self._lookup(abuse_payload())
        request = transport.requests[0]
        assert request["headers"]["Key"] == "SECRETKEY"
        assert "SECRETKEY" not in request["url"]
        assert request["follow"] is False
        assert "ipAddress=8.8.8.8" in request["url"]

    def test_answer_without_a_score_is_an_error_rather_than_a_zero(self):
        transport = FakeTransport({"abuseipdb.com": (200, {"data": {}})})
        provider = make(AbuseIpDbProvider, transport, api_key="k")
        with pytest.raises(ProviderError):
            provider.lookup("ip", "8.8.8.8")


class TestProviderFailures:
    @pytest.mark.parametrize("status", [401, 403, 429])
    def test_refusal_stops_the_provider(self, status):
        transport = FakeTransport({"internetdb": (status, b"")})
        with pytest.raises(ProviderStop):
            make(InternetDbProvider, transport).lookup("ip", "8.8.8.8")

    @pytest.mark.parametrize("status", [301, 400, 422, 500, 503])
    def test_other_statuses_fail_only_this_lookup(self, status):
        transport = FakeTransport({"internetdb": (status, b"")})
        with pytest.raises(ProviderError) as excinfo:
            make(InternetDbProvider, transport).lookup("ip", "8.8.8.8")
        assert not isinstance(excinfo.value, ProviderStop)

    @pytest.mark.parametrize(
        "body", [b"<html>not json</html>", b"[1, 2]", b"\xff\xfe", b""]
    )
    def test_malformed_body_is_an_error(self, body):
        transport = FakeTransport({"internetdb": (200, body)})
        with pytest.raises(ProviderError):
            make(InternetDbProvider, transport).lookup("ip", "8.8.8.8")

    def test_network_failure_is_an_error(self):
        transport = FakeTransport({"internetdb": OSError("connection refused")})
        with pytest.raises(ProviderError, match="connection refused"):
            make(InternetDbProvider, transport).lookup("ip", "8.8.8.8")

    @pytest.mark.parametrize(
        ("provider_class", "kind", "body"),
        [
            (RipeStatProvider, "ip", {"data": "nope"}),
            (RipeStatProvider, "ip", {"data": {"asns": [1, "x", {"asn": "AS1"}], "resource": 5}}),
            (RdapProvider, "domain", {"events": "x", "entities": [1, {"roles": ["registrar"]}]}),
            (RdapProvider, "domain", {"events": [{"eventAction": 1, "eventDate": 2}], "nameservers": [3]}),
            (RdapProvider, "domain", {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn"]]]}]}),
            (InternetDbProvider, "ip", {"ports": "x", "tags": 5, "vulns": {}, "hostnames": [1]}),
            (VirusTotalProvider, "ip", {"data": []}),
            (VirusTotalProvider, "ip", {"data": {"attributes": {"last_analysis_stats": "x", "as_owner": 5}}}),
            (VirusTotalProvider, "domain", {"data": {"attributes": {"creation_date": 1e30, "categories": []}}}),
        ],
    )
    def test_wrongly_typed_answers_do_not_crash(self, provider_class, kind, body):
        """Registry and reputation data is third-party input."""
        transport = FakeTransport(default=(200, json.dumps(body).encode()))
        result = make(provider_class, transport, api_key="k").lookup(kind, "example.com")
        assert result.status is LookupStatus.OK

    def test_boolean_is_not_a_count(self):
        """``true`` must not read as one malicious engine."""
        payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": True, "harmless": 3}}}}
        transport = FakeTransport({"virustotal.com": (200, payload)})
        result = make(VirusTotalProvider, transport, api_key="k").lookup("ip", "8.8.8.8")
        assert result.fields["malicious"] == 0
        assert result.signal is Signal.NO_REPORTS


class TestCleanText:
    def test_terminal_escapes_are_removed(self):
        assert "\x1b" not in clean_text("EVIL\x1b[31mCORP\x07")

    def test_direction_overrides_are_removed(self):
        assert "‮" not in clean_text("exe.‮gnp")

    def test_newlines_cannot_fake_output_lines(self):
        assert "\n" not in clean_text("a\r\nRisk: LOW")

    def test_accents_survive(self):
        assert clean_text("Telefônica Brasil") == "Telefônica Brasil"

    def test_length_is_bounded(self):
        assert len(clean_text("x" * 1000, 50)) == 50

    def test_hostile_registry_data_is_cleaned(self):
        overview = {"data": {"asns": [{"asn": 1, "holder": "EVIL\x1b[2J\nCORP"}]}}
        transport = FakeTransport({"prefix-overview": (200, overview)})
        result = make(RipeStatProvider, transport).lookup("ip", "1.2.3.4")
        assert "\x1b" not in result.summary
        assert "\n" not in result.summary


class TestParseDate:
    @pytest.mark.parametrize(
        "raw",
        [
            "1995-08-14T04:00:00Z",
            "1995-08-14T04:00:00+00:00",
            "1995-08-14T00:00:00-04:00",
            "1995-08-14T04:00:00.0Z",
            "1995-08-14T04:00:00.1234567Z",
        ],
    )
    def test_rdap_formats(self, raw):
        """Several of these are rejected by ``fromisoformat`` on Python 3.10."""
        assert _parse_date(raw) == pytest.approx(808372800.0, abs=1)

    @pytest.mark.parametrize("raw", ["soon", "", None, 5, "2026-13-45"])
    def test_unreadable_dates(self, raw):
        assert _parse_date(raw) is None


class TestBuildProviders:
    def test_keyless_services_need_nothing(self):
        providers, unavailable = build_providers(Config(), environ={})
        assert {p.name for p in providers} == {"ripestat", "rdap", "internetdb"}
        assert set(unavailable) == {"virustotal", "abuseipdb"}
        assert "VT_API_KEY" in unavailable["virustotal"]

    def test_keys_enable_reputation_sources(self):
        environ = {"VT_API_KEY": "a", "ABUSEIPDB_API_KEY": "b"}
        providers, unavailable = build_providers(Config(), environ=environ)
        assert {p.name for p in providers} == set(PROVIDERS)
        assert unavailable == {}

    def test_empty_key_counts_as_missing(self):
        _, unavailable = build_providers(Config(), environ={"VT_API_KEY": ""})
        assert "virustotal" in unavailable

    def test_selection_is_configurable(self):
        config = Config(enrich_providers=("rdap",))
        providers, unavailable = build_providers(config, environ={})
        assert [p.name for p in providers] == ["rdap"]
        assert unavailable == {}

    def test_unknown_name_is_an_error(self):
        """A typo would silently skip a source believed to have been checked."""
        with pytest.raises(ConfigError, match="virustotl"):
            build_providers(Config(enrich_providers=("virustotl",)), environ={})

    def test_nothing_is_sent_while_building(self):
        transport = FakeTransport()
        build_lookup_runner(
            Config(enrich_cache_ttl_hours=0), environ={}, transport=transport
        )
        assert transport.requests == []


# ------------------------------------------------------------------ runner

class TestLookupOrder:
    def test_findings_come_first_and_kinds_interleave(self):
        order = lookup_order(
            [indicator_ip("1.1.1.1"), indicator_ip("2.2.2.2", ["F1"])],
            [indicator_domain("a.org"), indicator_domain("b.org")],
        )
        assert [i.value for i in order] == ["2.2.2.2", "1.1.1.1", "a.org", "b.org"]

    def test_blocked_indicators_are_left_out(self):
        blocked = indicator_domain("printer.local")
        blocked.lookup_block = "non-public suffix .local"
        assert lookup_order([], [blocked]) == []


class TestLookupRunner:
    def _ips(self, count):
        return [indicator_ip(f"1.1.1.{i}") for i in range(count)]

    def test_attaches_answers_and_counts(self):
        provider = RecordingProvider()
        ips = self._ips(2)
        runs = LookupRunner([provider], Config()).run(ips)
        assert runs[0].looked_up == 2
        assert ips[0].lookups[0].summary == "context 1.1.1.0"
        assert ips[0].lookups[0].fetched_at is not None

    def test_provider_only_sees_kinds_it_supports(self):
        provider = RecordingProvider(kinds={"domain"})
        LookupRunner([provider], Config()).run([indicator_ip("1.1.1.1"), indicator_domain("a.org")])
        assert provider.calls == [("domain", "a.org")]

    def test_budget_is_enforced_and_the_rest_reported(self):
        provider = RecordingProvider()
        ips = self._ips(4)
        runner = LookupRunner([provider], Config(enrich_max_lookups_per_provider=1))
        run = runner.run(ips)[0]
        assert len(provider.calls) == 1
        assert run.looked_up == 1
        assert run.not_queried == 3
        assert "budget" in run.stopped
        assert ips[3].lookups[0].status is LookupStatus.NOT_QUERIED
        assert "budget" in ips[3].lookups[0].detail

    def test_deadline_is_enforced_and_the_rest_reported(self):
        ticks = iter(range(0, 10_000, 100))
        provider = RecordingProvider()
        ips = self._ips(6)
        runner = LookupRunner(
            [provider],
            Config(enrich_deadline_seconds=1050.0),
            clock=lambda: float(next(ticks)),
        )
        run = runner.run(ips)[0]
        assert 0 < run.looked_up < 6
        assert run.looked_up + run.not_queried == 6
        assert "deadline" in run.stopped

    def test_refusal_stops_the_provider_at_once(self):
        provider = ScriptedProvider([ProviderStop("rate limit reached (HTTP 429)")])
        ips = self._ips(3)
        run = LookupRunner([provider], Config()).run(ips)[0]
        assert len(provider.calls) == 1
        assert run.errors == 1
        assert run.not_queried == 2
        assert "429" in run.stopped

    def test_repeated_failures_stop_the_provider(self):
        """Offline, each attempt would otherwise cost a full timeout."""
        provider = ScriptedProvider([ProviderError("down")] * 10)
        run = LookupRunner([provider], Config()).run(self._ips(10))[0]
        assert len(provider.calls) == 3
        assert run.errors == 3
        assert run.not_queried == 7
        assert "consecutive" in run.stopped

    def test_a_success_resets_the_failure_count(self):
        error = ProviderError("flaky")
        provider = ScriptedProvider([error, error, None, error, error, None])
        run = LookupRunner([provider], Config()).run(self._ips(6))[0]
        assert run.stopped is None
        assert len(provider.calls) == 6

    def test_unexpected_exception_is_contained(self):
        provider = ScriptedProvider([KeyError("surprise"), None])
        ips = self._ips(2)
        run = LookupRunner([provider], Config()).run(ips)[0]
        assert run.errors == 1
        assert ips[0].lookups[0].status is LookupStatus.ERROR
        assert ips[1].lookups[0].status is LookupStatus.OK

    def test_rate_limit_spaces_out_calls(self):
        class Paced(RecordingProvider):
            min_interval = 0.05

        provider = Paced()
        times = []
        original = provider.lookup

        def timed(kind, value):
            import time
            times.append(time.monotonic())
            return original(kind, value)

        provider.lookup = timed
        LookupRunner([provider], Config()).run(self._ips(3))
        assert times[1] - times[0] >= 0.04
        assert times[2] - times[1] >= 0.04

    def test_answers_follow_provider_order_regardless_of_finish_order(self):
        class Slow(RecordingProvider):
            min_interval = 0.02

        first = Slow(name="first")
        second = RecordingProvider(name="second")
        ips = self._ips(2)
        LookupRunner([first, second], Config()).run(ips)
        assert [r.provider for r in ips[1].lookups] == ["first", "second"]

    def test_no_providers_means_no_runs(self):
        ips = self._ips(1)
        assert LookupRunner([], Config()).run(ips) == []
        assert ips[0].lookups == []

    def test_describe_states_what_will_be_sent_and_what_will_not(self):
        runner = LookupRunner(
            [RecordingProvider()], Config(),
            unavailable={"virustotal": "set VT_API_KEY to enable"},
        )
        text = runner.describe()
        assert "recording" in text
        assert "public IPs" in text
        assert "VT_API_KEY" in text

    def test_describe_with_nothing_available(self):
        assert "offline" in LookupRunner([], Config()).describe()


class TestLookupCache:
    def _cache(self, tmp_path, ttl=3600.0, now=lambda: 1000.0):
        return LookupCache(tmp_path / "cache" / "lookups.json", ttl, now=now)

    def _result(self, status=LookupStatus.OK, fetched_at=1000.0):
        return LookupResult(
            provider="p", status=status, summary="s", brief="b",
            fields={"k": 1}, signal=Signal.FLAGGED, fetched_at=fetched_at,
        )

    def test_round_trip_through_disk(self, tmp_path):
        cache = self._cache(tmp_path)
        cache.put("ip", "8.8.8.8", self._result())
        cache.save()
        loaded = self._cache(tmp_path).get("p", "ip", "8.8.8.8")
        assert loaded.summary == "s"
        assert loaded.brief == "b"
        assert loaded.fields == {"k": 1}
        assert loaded.signal is Signal.FLAGGED
        assert loaded.cached is True

    def test_expired_answer_is_not_served_or_kept(self, tmp_path):
        cache = self._cache(tmp_path, ttl=10.0, now=lambda: 1000.0)
        cache.put("ip", "8.8.8.8", self._result(fetched_at=1000.0))
        cache.save()
        later = self._cache(tmp_path, ttl=10.0, now=lambda: 2000.0)
        assert later.get("p", "ip", "8.8.8.8") is None
        later.put("ip", "9.9.9.9", self._result(fetched_at=2000.0))
        later.save()
        data = json.loads((tmp_path / "cache" / "lookups.json").read_text("utf-8"))
        assert list(data["entries"]) == ["p|ip|9.9.9.9"]

    @pytest.mark.parametrize(
        "content",
        [
            b"{not json",
            b"\xff\xfe",
            b"[]",
            b'{"version": 999, "entries": {"p|ip|8.8.8.8": {}}}',
            b'{"version": 1, "entries": "x"}',
        ],
    )
    def test_damaged_file_is_ignored(self, tmp_path, content):
        path = tmp_path / "cache" / "lookups.json"
        path.parent.mkdir()
        path.write_bytes(content)
        assert LookupCache(path, 3600.0).get("p", "ip", "8.8.8.8") is None

    @pytest.mark.parametrize(
        "entry",
        [
            "x",
            {},
            {"fetched_at": 1000.0},
            {"fetched_at": 1000.0, "status": "bogus", "fields": {}},
            {"fetched_at": 1000.0, "status": "ok", "fields": "x"},
            {"fetched_at": 1000.0, "status": "ok", "fields": {}, "signal": "bogus"},
            {"fetched_at": True, "status": "ok", "fields": {}},
        ],
    )
    def test_malformed_entry_is_a_miss(self, tmp_path, entry):
        path = tmp_path / "cache" / "lookups.json"
        path.parent.mkdir()
        path.write_text(
            json.dumps({"version": 1, "entries": {"p|ip|8.8.8.8": entry}}), "utf-8"
        )
        cache = LookupCache(path, 3600.0, now=lambda: 1000.0)
        assert cache.get("p", "ip", "8.8.8.8") is None

    def test_unwritable_location_does_not_abort(self, tmp_path):
        blocker = tmp_path / "file"
        blocker.write_text("x")
        cache = LookupCache(blocker / "lookups.json", 3600.0)
        cache.put("ip", "8.8.8.8", self._result())
        cache.save()

    def test_save_leaves_no_temporary_files(self, tmp_path):
        cache = self._cache(tmp_path)
        cache.put("ip", "8.8.8.8", self._result())
        cache.save()
        assert [p.name for p in (tmp_path / "cache").iterdir()] == ["lookups.json"]

    def test_second_run_sends_nothing(self, tmp_path):
        config = Config()
        path = tmp_path / "lookups.json"
        first = RecordingProvider()
        LookupRunner(
            [first], config, cache=LookupCache(path, 3600.0)
        ).run([indicator_ip("8.8.8.8")])

        second = RecordingProvider()
        ip = indicator_ip("8.8.8.8")
        run = LookupRunner(
            [second], config, cache=LookupCache(path, 3600.0)
        ).run([ip])[0]
        assert second.calls == []
        assert run.looked_up == 0
        assert run.cached == 1
        assert ip.lookups[0].cached is True

    def test_interrupted_budget_continues_on_the_next_run(self, tmp_path):
        """A small free tier works through a long list across several runs."""
        config = Config(enrich_max_lookups_per_provider=1)
        path = tmp_path / "lookups.json"
        ips = ["1.1.1.1", "2.2.2.2"]

        first = RecordingProvider()
        LookupRunner([first], config, cache=LookupCache(path, 3600.0)).run(
            [indicator_ip(v) for v in ips]
        )
        second = RecordingProvider()
        run = LookupRunner([second], config, cache=LookupCache(path, 3600.0)).run(
            [indicator_ip(v) for v in ips]
        )[0]
        assert first.calls == [("ip", "1.1.1.1")]
        assert second.calls == [("ip", "2.2.2.2")]
        assert run.cached == 1

    def test_failures_are_not_cached(self, tmp_path):
        path = tmp_path / "lookups.json"
        failing = ScriptedProvider([ProviderError("down")])
        LookupRunner([failing], Config(), cache=LookupCache(path, 3600.0)).run(
            [indicator_ip("8.8.8.8")]
        )
        retry = RecordingProvider()
        LookupRunner([retry], Config(), cache=LookupCache(path, 3600.0)).run(
            [indicator_ip("8.8.8.8")]
        )
        assert retry.calls == [("ip", "8.8.8.8")]

    def test_no_record_answers_are_cached(self, tmp_path):
        path = tmp_path / "lookups.json"
        missing = LookupResult(provider="recording", status=LookupStatus.NOT_FOUND, summary="none")
        LookupRunner(
            [ScriptedProvider([missing])], Config(), cache=LookupCache(path, 3600.0)
        ).run([indicator_ip("8.8.8.8")])
        again = RecordingProvider()
        run = LookupRunner([again], Config(), cache=LookupCache(path, 3600.0)).run(
            [indicator_ip("8.8.8.8")]
        )[0]
        assert again.calls == []
        assert run.not_found == 1

    def test_api_key_never_reaches_the_cache_file(self, tmp_path):
        transport = FakeTransport({"virustotal.com": (200, vt_payload())})
        config = Config(enrich_providers=("virustotal",), enrich_cache_dir=str(tmp_path))
        runner = build_lookup_runner(
            config, environ={"VT_API_KEY": "SECRETKEY"}, transport=transport
        )
        runner.run([indicator_ip("8.8.8.8")])
        assert "SECRETKEY" not in (tmp_path / "lookups.json").read_text("utf-8")

    def test_cache_location(self, tmp_path):
        assert default_cache_path(Config(enrich_cache_ttl_hours=0)) is None
        assert (
            default_cache_path(Config(enrich_cache_dir=str(tmp_path)))
            == tmp_path / "lookups.json"
        )
        assert default_cache_path(Config()).name == "lookups.json"


class TestRegistrationAge:
    CAPTURE = 1_700_000_000.0
    DAY = 86_400.0

    def _domain(self, registered_ts):
        domain = indicator_domain("example.org")
        domain.lookups.append(
            LookupResult(
                provider="rdap", status=LookupStatus.OK,
                fields={"registered_ts": registered_ts},
            )
        )
        return domain

    def test_recent_registration_is_noted_relative_to_the_capture(self):
        domain = self._domain(self.CAPTURE - 3 * self.DAY)
        _note_registration_age(domain, self.CAPTURE, Config())
        assert domain.notes == ["registered 3 day(s) before this capture"]

    def test_old_registration_needs_no_note(self):
        domain = self._domain(self.CAPTURE - 400 * self.DAY)
        _note_registration_age(domain, self.CAPTURE, Config())
        assert domain.notes == []

    def test_threshold_is_configurable(self):
        domain = self._domain(self.CAPTURE - 3 * self.DAY)
        _note_registration_age(domain, self.CAPTURE, Config(enrich_new_domain_days=2))
        assert domain.notes == []

    def test_registration_after_the_capture_is_not_a_negative_age(self):
        domain = self._domain(self.CAPTURE + 30 * self.DAY)
        _note_registration_age(domain, self.CAPTURE, Config())
        assert "postdates" in domain.notes[0]

    def test_capture_without_timestamps_is_skipped(self):
        domain = self._domain(self.CAPTURE)
        _note_registration_age(domain, None, Config())
        assert domain.notes == []

    def test_end_to_end_uses_capture_time_rather_than_today(self, tmp_path):
        registered = synth.BASE_TS - 2 * self.DAY
        provider = ScriptedProvider(
            [
                LookupResult(
                    provider="registry", status=LookupStatus.OK,
                    fields={"registered_ts": registered},
                )
            ],
            name="registry",
            kinds={"domain"},
        )
        result = analyze(
            tmp_path, [dns_query("new.example.org")],
            lookups=LookupRunner([provider], Config()),
        )
        assert "registered 2 day(s) before this capture" in domain_of(result, "example.org").notes


class TestReputation:
    def _indicator(self, *signals):
        indicator = indicator_ip("8.8.8.8")
        for index, signal in enumerate(signals):
            indicator.lookups.append(
                LookupResult(
                    provider=f"p{index}", status=LookupStatus.OK,
                    summary="s", signal=signal,
                )
            )
        return indicator

    def test_nobody_asked_differs_from_nobody_complaining(self):
        assert self._indicator().reputation["signal"] == "not_checked"
        assert self._indicator(None).reputation["signal"] == "not_checked"
        assert self._indicator(Signal.NO_REPORTS).reputation["signal"] == "no_reports"

    def test_worst_signal_wins_and_sources_are_kept(self):
        reputation = self._indicator(Signal.NO_REPORTS, Signal.FLAGGED, Signal.REPORTED).reputation
        assert reputation["signal"] == "flagged"
        assert len(reputation["sources"]) == 3


# --------------------------------------------------------------- reporting

class TestReportOutput:
    def _online_report(self, tmp_path, provider=None, packets=None):
        runner = LookupRunner(
            [provider or RecordingProvider(signal=Signal.FLAGGED)], Config(),
            unavailable={"virustotal": "set VT_API_KEY to enable"},
        )
        return build_report(analyze(tmp_path, packets or web_traffic(), lookups=runner))

    def test_json_structure(self, tmp_path):
        section = build_report(analyze(tmp_path, web_traffic()))["enrichment"]
        json.dumps(section)  # must be JSON-ready as it stands
        assert section["mode"] == "offline"
        assert section["ip_count"] == 1
        ip = section["ips"][0]
        assert ip["value"] == PUBLIC_IP
        assert ip["names"] == {"sample": ["www.example.org"], "total": 1}
        assert ip["reputation"]["signal"] == "not_checked"
        assert {p["name"] for p in ip["pivots"]} == {"VirusTotal", "AbuseIPDB", "Shodan"}
        domains = {d["value"]: d for d in section["domains"]}
        assert domains["example.org"]["urls"][0]["count"] == 1

    def test_online_report_accounts_for_what_was_sent(self, tmp_path):
        section = self._online_report(tmp_path)["enrichment"]
        assert section["mode"] == "online"
        assert section["contacted_services"] == ["recording"]
        assert section["lookups_sent"] == 3
        assert section["flagged_count"] == 3
        assert section["unavailable_providers"]

    def test_html_has_the_section_offline(self, tmp_path):
        html = render_html(build_report(analyze(tmp_path, web_traffic())))
        assert "IOC enrichment" in html
        assert "External addresses (1)" in html
        assert "Domains (4)" in html
        assert "www.example.org" in html
        assert "not checked" in html
        assert "virustotal.com/gui/ip-address/93.184.216.34" in html

    def test_html_states_what_left_the_machine(self, tmp_path):
        html = render_html(self._online_report(tmp_path))
        assert "Online lookups were enabled" in html
        assert "3 enrichment lookup(s) sent to recording" in html
        assert "offline analysis, no external services" not in html
        assert "FLAGGED" in html
        assert "Services consulted" in html
        assert "set VT_API_KEY to enable" in html

    def test_html_from_cache_does_not_claim_anything_was_sent(self, tmp_path):
        path = tmp_path / "lookups.json"
        for attempt in ("first", "second"):
            runner = LookupRunner(
                [RecordingProvider()], Config(), cache=LookupCache(path, 3600.0)
            )
            report = build_report(
                analyze(tmp_path, web_traffic(), lookups=runner, name=f"{attempt}.pcap")
            )
        html = render_html(report)
        assert report["enrichment"]["contacted_services"] == []
        assert "nothing was sent this run" in html
        assert "offline analysis, no external services" in html
        assert "(cached)" in html

    def test_context_reaches_the_other_tables(self, tmp_path):
        provider = ScriptedProvider(
            [
                LookupResult(
                    provider="asn", status=LookupStatus.OK, summary="s",
                    brief="AS64500 EXAMPLE",
                )
            ],
            name="asn",
            kinds={"ip"},
        )
        packets = synth.beacon(server=PUBLIC_IP, dport=4444) + [
            dns_answer("c2.example.net", PUBLIC_IP)
        ]
        report = self._online_report(tmp_path, provider, packets)
        assert report["enrichment"]["labels"][PUBLIC_IP] == "c2.example.net | AS64500 EXAMPLE"
        html = render_html(report)
        assert "Destination context:" in html
        assert html.count("c2.example.net | AS64500 EXAMPLE") >= 3

    def test_findings_can_be_reached_from_the_indicator_table(self, tmp_path):
        packets = synth.beacon(server=PUBLIC_IP, dport=4444)
        report = build_report(analyze(tmp_path, packets))
        finding_id = report["enrichment"]["ips"][0]["finding_ids"][0]
        html = render_html(report)
        assert f'href="#{finding_id}"' in html
        assert f'id="{finding_id}"' in html

    def test_blocked_indicator_shows_the_reason_without_a_link(self, tmp_path):
        html = render_html(build_report(analyze(tmp_path, web_traffic())))
        assert "not sent to third parties: non-public suffix .local" in html
        assert "virustotal.com/gui/domain/printer.local" not in html

    def test_omitted_indicators_are_stated(self, tmp_path):
        packets = bulk(PUBLIC_IP, 2) + bulk(OTHER_PUBLIC_IP, 1)
        report = build_report(
            analyze(tmp_path, packets, config=Config(enrich_max_indicators=1))
        )
        assert "1 more address(es)" in render_html(report)

    def test_provider_text_is_escaped_in_html(self, tmp_path):
        evil = "<script>alert('provider')</script>"
        html = render_html(self._online_report(tmp_path, RecordingProvider(summary=evil)))
        assert evil not in html
        assert "&lt;script&gt;" in html

    def test_capture_names_are_escaped_in_html(self, tmp_path):
        evil = "<img src=x onerror=alert(1)>"
        html = render_html(
            build_report(analyze(tmp_path, [tls_session(f"{evil}.example.org")]))
        )
        assert "<img src=x" not in html
        assert "&lt;img" in html

    def test_crafted_name_cannot_break_out_of_a_pivot_link(self, tmp_path):
        result = analyze(tmp_path, [tls_session('x".onmouseover="alert(1)')])
        html = render_html(build_report(result))
        assert 'onmouseover="alert(1)' not in html

    def test_html_renders_without_an_enrichment_section(self, tmp_path):
        """Reports built by older code or other tools have no such key."""
        report = build_report(analyze(tmp_path, web_traffic()))
        report["enrichment"] = None
        html = render_html(report)
        assert "IOC enrichment" not in html
        assert "offline analysis, no external services" in html

    def test_no_external_traffic_leaves_no_section(self, tmp_path):
        pkt = _eth() / IP(src=CLIENT, dst=RESOLVER) / TCP(sport=1, dport=445)
        pkt.time = synth.BASE_TS
        report = build_report(analyze(tmp_path, [pkt]))
        assert "IOC enrichment" not in render_html(report)


class TestTerminalOutput:
    def _text(self, tmp_path, provider=None, packets=None, limit=10):
        lookups = LookupRunner([provider], Config()) if provider else None
        result = analyze(tmp_path, packets or web_traffic(), lookups=lookups)
        return render_enrichment_text(result.enrichment, limit=limit)

    def test_shows_addresses_domains_and_names(self, tmp_path):
        text = self._text(tmp_path)
        assert PUBLIC_IP in text
        assert "example.org" in text
        assert "www.example.org" in text

    def test_states_what_left_the_machine(self, tmp_path):
        assert "nothing left this machine" in self._text(tmp_path)
        assert "sent to recording" in self._text(tmp_path, RecordingProvider())

    def test_flagged_is_visible(self, tmp_path):
        assert "FLAGGED" in self._text(tmp_path, RecordingProvider(signal=Signal.FLAGGED))

    def test_limit_is_stated(self, tmp_path):
        packets = bulk(PUBLIC_IP, 2) + bulk(OTHER_PUBLIC_IP, 1)
        assert "1 more IP(s)" in self._text(tmp_path, packets=packets, limit=1)

    def test_output_is_ascii_for_any_windows_codepage(self, tmp_path):
        """Registry names are full of accents, and the CLI promises ASCII."""
        text = self._text(tmp_path, RecordingProvider(summary="Telefônica 北京"))
        text.encode("ascii")

    def test_escape_sequences_from_a_provider_are_removed(self, tmp_path):
        text = self._text(tmp_path, RecordingProvider(summary="EVIL\x1b[2J\nRisk: LOW"))
        assert "\x1b" not in text
        assert "\nRisk: LOW" not in text

    def test_escape_sequences_from_the_capture_are_removed(self, tmp_path):
        text = self._text(tmp_path, packets=[tls_session("evil\x1b[2J.example.org")])
        assert "\x1b" not in text

    def test_provider_shortfall_is_stated(self, tmp_path):
        provider = ScriptedProvider([ProviderStop("rate limit reached (HTTP 429)")])
        text = self._text(tmp_path, provider)
        assert "not looked up" in text
        assert "429" in text

    def test_empty_when_nothing_is_external(self):
        assert render_enrichment_text(Enrichment()) == ""


# --------------------------------------------------------------- transport

class _Handler(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def do_GET(self):
        status, headers, body = self.routes[self.path]
        self.server.seen.append((self.path, dict(self.headers)))
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def local_server():
    """Loopback only: the suite never leaves the machine."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


class TestTransport:
    def test_returns_status_and_body(self, local_server, monkeypatch):
        server, base = local_server
        monkeypatch.setattr(_Handler, "routes", {"/ok": (200, {}, b"hello")})
        status, body = urllib_fetch(f"{base}/ok", {"X-Test": "1"}, False, 5.0)
        assert (status, body) == (200, b"hello")
        assert server.seen[0][1]["X-Test"] == "1"

    @pytest.mark.parametrize("code", [404, 429, 500])
    def test_error_statuses_are_returned(self, local_server, monkeypatch, code):
        _, base = local_server
        monkeypatch.setattr(_Handler, "routes", {"/x": (code, {}, b"")})
        assert urllib_fetch(f"{base}/x", {}, False, 5.0)[0] == code

    def test_redirect_out_of_https_is_refused(self, local_server, monkeypatch):
        server, base = local_server
        routes = {
            "/r": (302, {"Location": f"{base}/target"}, b""),
            "/target": (200, {}, b"secret"),
        }
        monkeypatch.setattr(_Handler, "routes", routes)
        with pytest.raises(OSError, match="non-HTTPS"):
            urllib_fetch(f"{base}/r", {}, True, 5.0)
        assert [path for path, _ in server.seen] == ["/r"]

    def test_redirect_to_a_local_file_is_not_followed(self, local_server, monkeypatch):
        """urllib refuses this scheme itself, which surfaces as the 3xx status
        and then as a failed lookup: the file is never read."""
        _, base = local_server
        routes = {"/r": (302, {"Location": "file:///etc/passwd"}, b"")}
        monkeypatch.setattr(_Handler, "routes", routes)
        assert urllib_fetch(f"{base}/r", {}, True, 5.0) == (302, b"")

    def test_keyed_request_does_not_carry_its_key_through_a_redirect(
        self, local_server, monkeypatch
    ):
        """urllib forwards request headers when it follows a redirect."""
        server, base = local_server
        routes = {
            "/r": (302, {"Location": f"{base}/elsewhere"}, b""),
            "/elsewhere": (200, {}, b"x"),
        }
        monkeypatch.setattr(_Handler, "routes", routes)
        status, _ = urllib_fetch(f"{base}/r", {"x-apikey": "SECRETKEY"}, False, 5.0)
        assert status == 302
        assert [path for path, _ in server.seen] == ["/r"]

    def test_oversized_response_is_refused(self, local_server, monkeypatch):
        import investigator.enrichment.providers as providers

        _, base = local_server
        monkeypatch.setattr(providers, "_MAX_RESPONSE_BYTES", 10)
        monkeypatch.setattr(_Handler, "routes", {"/big": (200, {}, b"x" * 11)})
        with pytest.raises(ProviderError, match="larger than"):
            urllib_fetch(f"{base}/big", {}, False, 5.0)

    def test_provider_handles_a_refused_connection(self):
        """Nothing listens here: a dead service is an error, not a crash."""
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        class Dead(InternetDbProvider):
            def lookup(self, kind, value):
                return self._get_json(f"http://127.0.0.1:{port}/{value}")

        provider = Dead(Config(enrich_timeout_seconds=2.0))
        with pytest.raises(ProviderError, match="request failed"):
            provider.lookup("ip", "8.8.8.8")


# --------------------------------------------------------------------- cli

class TestCli:
    def _capture(self, tmp_path):
        capture = tmp_path / "web.pcap"
        wrpcap(str(capture), sorted(web_traffic(), key=lambda p: p.time))
        return capture

    def test_enrich_flag_runs_lookups_and_says_so(self, tmp_path, monkeypatch, capsys):
        import investigator.enrichment as enrichment

        provider = RecordingProvider(signal=Signal.REPORTED)
        monkeypatch.setattr(
            enrichment,
            "build_lookup_runner",
            lambda config: LookupRunner([provider], config),
        )
        out_dir = tmp_path / "out"
        assert run([str(self._capture(tmp_path)), "--enrich", "--output-dir", str(out_dir)]) == 0
        streams = capsys.readouterr()
        assert "public IPs and registrable domains" in streams.err
        assert "sent to recording" in streams.out
        report = json.loads((out_dir / "investigation.json").read_text("utf-8"))
        assert report["enrichment"]["mode"] == "online"
        assert report["enrichment"]["reported_count"] == 3
        assert provider.calls

    def test_enrich_without_keys_or_keyless_services_stays_offline(
        self, tmp_path, monkeypatch, capsys, no_network
    ):
        monkeypatch.delenv("VT_API_KEY", raising=False)
        config = tmp_path / "cfg.json"
        config.write_text(
            json.dumps(
                {"enrich_providers": ["virustotal"], "enrich_cache_dir": str(tmp_path / "c")}
            )
        )
        out_dir = tmp_path / "out"
        code = run(
            [str(self._capture(tmp_path)), "--enrich", "--config", str(config),
             "--output-dir", str(out_dir)]
        )
        assert code == 0
        streams = capsys.readouterr()
        assert "no provider available" in streams.err
        assert "VT_API_KEY" in streams.err
        report = json.loads((out_dir / "investigation.json").read_text("utf-8"))
        assert report["enrichment"]["mode"] == "offline"
        assert "virustotal" in report["enrichment"]["unavailable_providers"]

    def test_unknown_provider_is_a_clean_error(self, tmp_path, capsys):
        config = tmp_path / "cfg.json"
        config.write_text(json.dumps({"enrich_providers": ["virustotl"]}))
        code = run([str(self._capture(tmp_path)), "--enrich", "--config", str(config)])
        assert code == 1
        assert "virustotl" in capsys.readouterr().err

    def test_failed_lookups_do_not_change_the_exit_code(self, tmp_path, monkeypatch, capsys):
        import investigator.enrichment as enrichment

        provider = ScriptedProvider([ProviderError("down")] * 5)
        monkeypatch.setattr(
            enrichment,
            "build_lookup_runner",
            lambda config: LookupRunner([provider], config),
        )
        out_dir = tmp_path / "out"
        assert run([str(self._capture(tmp_path)), "--enrich", "--output-dir", str(out_dir)]) == 0
        assert (out_dir / "investigation.html").is_file()

    def test_help_warns_about_what_the_flag_sends(self, capsys):
        with pytest.raises(SystemExit):
            run(["--help"])
        assert "--enrich" in capsys.readouterr().out


class TestConfigFile:
    def test_settings_load_from_a_file(self, tmp_path):
        path = tmp_path / "cfg.json"
        path.write_text(
            json.dumps(
                {
                    "enrich_providers": ["rdap"],
                    "enrich_exclude_domains": ["acme.com"],
                    "enrich_deadline_seconds": 30,
                    "enrich_cache_dir": "x",
                }
            )
        )
        config = load_config(path)
        assert config.enrich_providers == ("rdap",)
        assert config.enrich_exclude_domains == ("acme.com",)
        assert config.enrich_deadline_seconds == 30.0
        assert config.enrich_cache_dir == "x"

    def test_wrongly_typed_cache_dir_is_rejected(self, tmp_path):
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"enrich_cache_dir": 5}))
        with pytest.raises(ConfigError, match="must be a string"):
            load_config(path)

    def test_service_hint_is_json_ready(self):
        assert ServiceHint("A", "cdn").as_dict() == {
            "name": "A", "category": "cdn", "commonly_abused": False,
        }
