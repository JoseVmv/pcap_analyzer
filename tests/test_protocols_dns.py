"""Tests for the DNS analyser (V2)."""

from __future__ import annotations

import pytest

from investigator.engine import run_analysis
from investigator.parser import PcapLoader
from investigator.protocols.dns import DnsAnalyzer, split_domain
from investigator.stats import shannon_entropy


class TestSplitDomain:
    def test_plain(self):
        assert split_domain("www.example.com") == ("www", "example.com")
        assert split_domain("a.b.example.com") == ("a.b", "example.com")
        assert split_domain("example.com") == ("", "example.com")
        assert split_domain("localhost") == ("", "localhost")

    def test_multi_label_suffix(self):
        assert split_domain("loja.empresa.com.br") == ("loja", "empresa.com.br")
        assert split_domain("empresa.com.br") == ("", "empresa.com.br")


class TestShannonEntropy:
    def test_bounds(self):
        assert shannon_entropy("") == 0.0
        assert shannon_entropy("aaaa") == 0.0
        # random-looking base32 label carries much more entropy than a word
        assert shannon_entropy("mzxw6ytboi2gk3tpobzxe33om4") > shannon_entropy("mail")


class TestDnsAnalyzer:
    @pytest.fixture()
    def analyzer(self, dns_pcap) -> DnsAnalyzer:
        analyzer = DnsAnalyzer()
        run_analysis(PcapLoader(dns_pcap), [analyzer])
        return analyzer

    def test_counts(self, analyzer):
        assert analyzer.total_queries == 4
        assert analyzer.total_responses == 2
        assert analyzer.nxdomain_responses == 1
        assert analyzer.parse_errors == 0
        assert analyzer.rcodes["NXDOMAIN"] == 1

    def test_client_stats(self, analyzer):
        client = analyzer.clients["10.0.0.15"]
        assert client.queries == 3
        assert client.nxdomains == 1
        assert client.qtypes["A"] == 3
        assert len(client.timestamps) == 3

        tunnel_client = analyzer.clients["10.0.0.21"]
        assert tunnel_client.qtypes["TXT"] == 1

    def test_domain_stats_and_entropy(self, analyzer):
        example = analyzer.domains["example.com"]
        assert example.queries == 2
        assert example.nxdomains == 1
        assert "www" in example.unique_subdomains

        evil = analyzer.domains["evil.io"]
        assert evil.txt_or_null_queries == 1
        assert evil.max_label_length == len("mzxw6ytboi2gk3tpobzxe33om4qgcidu")
        assert evil.max_entropy > 3.0

        # brazilian multi-label suffix grouped correctly
        assert "empresa.com.br" in analyzer.domains

    def test_resolutions(self, analyzer):
        assert analyzer.resolutions["www.example.com"] == {"203.0.113.80"}
        assert analyzer.names_for_ip("203.0.113.80") == {"www.example.com"}
        assert analyzer.names_for_ip("198.51.100.99") == set()

    def test_as_dict_shape(self, analyzer):
        data = analyzer.as_dict()
        assert data["total_queries"] == 4
        assert any(d["base_domain"] == "evil.io" for d in data["domains"])
        assert data["sample_queries"][0]["observation"] == "observed"
