"""Third-party lookup services: the online half of IOC enrichment.

Reached only through ``--enrich``.  Three rules hold for every provider, and
each one has a test:

* **Responses are untrusted input.**  Registry and reputation records are
  written by whoever registered the resource, attacker included.  Every string
  is cleaned, every field type-checked, and a malformed answer becomes a
  recorded error rather than a crash.
* **API keys stay out of everything.**  They come from the environment rather
  than the config file, which tends to get shared, and travel only in a request
  header.  Keyed requests never follow a redirect, because urllib would forward
  that header to whichever host the redirect names.
* **Nothing touches the indicator's own infrastructure.**  Every service here
  is a registry or an intelligence source.  Reverse DNS is left out on purpose:
  a PTR query reaches the nameserver of whoever owns the address, which can
  tell an attacker that their host is being looked at.

``urllib`` is used because a handful of JSON GETs does not justify a new
dependency, which is the same reasoning that keeps pandas out of ``stats.py``.
"""

from __future__ import annotations

import enum
import http.client
import json
import logging
import os
import re
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar

from investigator import __version__
from investigator.config import Config
from investigator.errors import ConfigError

LOG = logging.getLogger(__name__)

_USER_AGENT = f"pcap-investigator/{__version__}"

#: Largest response body accepted.  RDAP answers for big networks reach a few
#: hundred KiB; anything far beyond that is not a lookup answer, and it comes
#: from a server we do not control.
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024

#: ``fetch(url, headers, follow_redirects, timeout) -> (status, body)``.
#: Injected so that tests exercise every provider without a network.
Transport = Callable[[str, Mapping[str, str], bool, float], tuple[int, bytes]]


class LookupStatus(str, enum.Enum):
    OK = "ok"
    NOT_FOUND = "not_found"
    ERROR = "error"
    #: Never sent: budget, deadline or a stopped provider.  Recorded per
    #: indicator so a report can say what was left out, never silently.
    NOT_QUERIED = "not_queried"


class Signal(str, enum.Enum):
    """What a reputation source said, in words that claim no more than that."""

    FLAGGED = "flagged"
    REPORTED = "reported"
    #: Deliberately not called "clean": no reports is not evidence of safety.
    NO_REPORTS = "no_reports"


@dataclass(slots=True)
class LookupResult:
    """One provider's answer about one indicator."""

    provider: str
    status: LookupStatus
    summary: str = ""
    #: Short form for tables of other things (findings, conversations); empty
    #: when this answer does not earn a place there.
    brief: str = ""
    fields: dict[str, object] = field(default_factory=dict)
    signal: Signal | None = None
    #: Why it failed or was not sent.
    detail: str | None = None
    fetched_at: float | None = None
    cached: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "status": self.status.value,
            "summary": self.summary,
            "brief": self.brief,
            "signal": self.signal.value if self.signal else None,
            "fields": self.fields,
            "detail": self.detail,
            "fetched_at": self.fetched_at,
            "cached": self.cached,
        }

    @classmethod
    def from_cache(cls, provider: str, entry: Mapping[str, object]) -> "LookupResult":
        """Rebuild a cached answer; raises on a malformed entry."""
        signal = entry.get("signal")
        fields = entry.get("fields")
        if not isinstance(fields, dict):
            raise ValueError("cached fields must be a mapping")
        return cls(
            provider=provider,
            status=LookupStatus(entry["status"]),
            summary=str(entry.get("summary", "")),
            brief=str(entry.get("brief", "")),
            fields=fields,
            signal=Signal(signal) if signal else None,
            fetched_at=float(entry["fetched_at"]),  # type: ignore[arg-type]
            cached=True,
        )


class ProviderError(Exception):
    """This lookup failed; the next indicator may well succeed."""


class ProviderStop(ProviderError):
    """Further lookups are pointless this run: rate-limited or refused."""


def clean_text(value: object, limit: int = 200) -> str:
    """One bounded line, safe to print.

    Removes every Unicode control and format character, which covers ANSI
    escape sequences and the right-to-left overrides used to disguise a name.
    Autoescaping protects the HTML report; this protects the terminal.
    """
    text = "".join(
        " " if unicodedata.category(ch).startswith("C") else ch for ch in str(value)
    )
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _text(value: object, limit: int = 200) -> str | None:
    return clean_text(value, limit) if isinstance(value, str) and value.strip() else None


def _texts(value: object, limit: int = 10) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned = (_text(item) for item in value)
    return [item for item in cleaned if item][:limit]


def _int(value: object) -> int | None:
    # bool is an int subclass, and `true` is not a count of anything.
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _ints(value: object, limit: int = 30) -> list[int]:
    if not isinstance(value, list):
        return []
    return [item for item in value if _int(item) is not None][:limit]


def _dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _parse_date(value: object) -> float | None:
    """Epoch seconds from an RDAP date; None when it cannot be read.

    Normalised by hand because ``fromisoformat`` on Python 3.10 rejects both
    the ``Z`` suffix and fractional seconds that are not 3 or 6 digits long.
    """
    if not isinstance(value, str):
        return None
    normalised = re.sub(r"\.\d+", "", value.strip()).replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _day(epoch: float | None) -> str | None:
    """``YYYY-MM-DD`` for an epoch, or None for one no date can represent."""
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return None


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never out of TLS or onto another URL scheme."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError("refused a redirect to a non-HTTPS URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Surface a redirect as its 3xx status instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urllib_fetch(
    url: str, headers: Mapping[str, str], follow_redirects: bool, timeout: float
) -> tuple[int, bytes]:
    """The real transport.  HTTP error statuses are returned, not raised."""
    handler = _HttpsOnlyRedirects() if follow_redirects else _NoRedirects()
    opener = urllib.request.build_opener(handler)
    request = urllib.request.Request(url, headers=dict(headers))
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        exc.close()
        return exc.code, b""
    if len(body) > _MAX_RESPONSE_BYTES:
        raise ProviderError(f"response larger than {_MAX_RESPONSE_BYTES} bytes")
    return status, body


class Provider:
    """One lookup service.  Subclasses implement :meth:`lookup`."""

    name: ClassVar[str]
    #: Indicator kinds this service can answer for.
    kinds: ClassVar[frozenset[str]]
    #: Seconds between calls, taken from the service's published limit.
    min_interval: ClassVar[float] = 0.2
    #: Environment variable holding the API key; None for keyless services.
    env_key: ClassVar[str | None] = None

    def __init__(
        self,
        config: Config,
        *,
        transport: Transport = urllib_fetch,
        api_key: str | None = None,
    ) -> None:
        self._config = config
        self._transport = transport
        self._api_key = api_key

    def lookup(self, kind: str, value: str) -> LookupResult:
        raise NotImplementedError

    def _get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> dict[str, object] | None:
        """GET a JSON object; ``None`` means the service has no such record."""
        merged = {
            "User-Agent": _USER_AGENT,
            "Accept": "application/json",
            **(headers or {}),
        }
        try:
            status, body = self._transport(
                url, merged, follow_redirects, self._config.enrich_timeout_seconds
            )
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # `from None`: the chained traceback adds nothing but risk.
            raise ProviderError(f"request failed: {clean_text(exc)}") from None
        if status == 404:
            return None
        if status in (401, 403):
            raise ProviderStop(
                f"access refused (HTTP {status}): check the API key or account limits"
            )
        if status == 429:
            raise ProviderStop("rate limit reached (HTTP 429)")
        if status != 200:
            raise ProviderError(f"unexpected HTTP {status}")
        try:
            data = json.loads(body)
        except ValueError:
            raise ProviderError("response was not valid JSON") from None
        if not isinstance(data, dict):
            raise ProviderError("response was not a JSON object")
        return data

    def _result(self, status: LookupStatus = LookupStatus.OK, **values) -> LookupResult:
        return LookupResult(provider=self.name, status=status, **values)

    def _not_found(self, summary: str) -> LookupResult:
        return self._result(LookupStatus.NOT_FOUND, summary=summary)


class RipeStatProvider(Provider):
    """Routing context for an address: origin AS, prefix and geolocation.

    The registry-level RDAP record was the other candidate, but ARIN's has no
    country and none of them has an AS number, and those are what an analyst
    asks first.
    """

    name = "ripestat"
    kinds = frozenset({"ip"})

    def _call(self, data_call: str, value: str) -> dict[str, object] | None:
        query = urllib.parse.urlencode(
            {"resource": value, "sourceapp": "pcap-investigator"}
        )
        return self._get_json(f"https://stat.ripe.net/data/{data_call}/data.json?{query}")

    def _resources(self, data_call: str, value: str) -> list[object]:
        """``located_resources`` of a data call.  Country is a nice-to-have:
        losing it must not lose the ASN, so only a refusal propagates."""
        try:
            answer = self._call(data_call, value)
        except ProviderStop:
            raise
        except ProviderError as exc:
            LOG.debug("ripestat %s failed: %s", data_call, exc)
            return []
        resources = _dict(_dict(answer).get("data")).get("located_resources")
        return resources if isinstance(resources, list) else []

    def _country(self, value: str) -> tuple[str | None, str | None]:
        """A country and how it is known.

        Anycast addresses have no geolocation (the service answers ``?``), so
        registration is the fallback.  The two are labelled apart because they
        are different claims: 1.1.1.1 is registered in Australia and served
        from everywhere.
        """
        for resource in self._resources("maxmind-geo-lite", value):
            locations = _dict(resource).get("locations")
            for location in locations if isinstance(locations, list) else []:
                country = _text(_dict(location).get("country"), 8)
                if country and country.isalpha():
                    return country, "geolocated"
        for resource in self._resources("rir-stats-country", value):
            country = _text(_dict(resource).get("location"), 8)
            if country and country.isalpha():
                return country, "registered"
        return None, None

    def lookup(self, kind: str, value: str) -> LookupResult:
        answer = self._call("prefix-overview", value)
        if answer is None:
            return self._not_found("no routing data")
        data = _dict(answer.get("data"))
        asns = []
        raw_asns = data.get("asns")
        for entry in raw_asns if isinstance(raw_asns, list) else []:
            number = _int(_dict(entry).get("asn"))
            if number is not None:
                asns.append({"asn": number, "holder": _text(_dict(entry).get("holder"))})
        prefix = _text(data.get("resource"), 64)
        country, country_source = self._country(value)
        fields = {
            "asns": asns,
            "prefix": prefix,
            "announced": data.get("announced") is True,
            "country": country,
            "country_source": country_source,
        }
        if asns:
            origin = f"AS{asns[0]['asn']} {asns[0]['holder'] or ''}".strip()
            if len(asns) > 1:
                origin += f" (+{len(asns) - 1} more origin AS)"
        else:
            origin = "not announced in BGP"
        place = ""
        if country:
            place = f" [{country}]" if country_source == "geolocated" else f" [registered in {country}]"
        summary = origin + place + (f", prefix {prefix}" if prefix else "")
        return self._result(summary=summary, brief=origin + place, fields=fields)


class RdapProvider(Provider):
    """Registration data for a domain, through the rdap.org bootstrap.

    Domains only: see :class:`RipeStatProvider` for addresses.  The bootstrap
    answers with a redirect to the registry that holds the record, so this
    is the one provider allowed to follow redirects - it sends no credentials.
    """

    name = "rdap"
    kinds = frozenset({"domain"})
    # rdap.org documents 10 requests per 10 seconds per client.
    min_interval = 1.0

    @staticmethod
    def _registrar(data: dict[str, object]) -> str | None:
        entities = data.get("entities")
        for entity in entities if isinstance(entities, list) else []:
            entity = _dict(entity)
            roles = entity.get("roles")
            if not (isinstance(roles, list) and "registrar" in roles):
                continue
            card = entity.get("vcardArray")
            if not (isinstance(card, list) and len(card) == 2 and isinstance(card[1], list)):
                continue
            for prop in card[1]:
                if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                    return _text(prop[3])
        return None

    def lookup(self, kind: str, value: str) -> LookupResult:
        data = self._get_json(
            f"https://rdap.org/domain/{urllib.parse.quote(value, safe='')}",
            headers={"Accept": "application/rdap+json, application/json"},
            follow_redirects=True,
        )
        if data is None:
            # Not proof the name is unregistered: many ccTLDs publish no RDAP.
            return self._not_found("no RDAP record available")
        events: dict[str, float] = {}
        raw_events = data.get("events")
        for event in raw_events if isinstance(raw_events, list) else []:
            action = _dict(event).get("eventAction")
            moment = _parse_date(_dict(event).get("eventDate"))
            if isinstance(action, str) and moment is not None:
                events.setdefault(action, moment)
        registered_ts = events.get("registration")
        registered = _day(registered_ts)
        expires = _day(events.get("expiration"))
        registrar = self._registrar(data)
        servers = data.get("nameservers")
        fields = {
            "registered": registered,
            "registered_ts": registered_ts,
            "expires": expires,
            "registrar": registrar,
            "status": _texts(data.get("status")),
            "nameservers": [
                name.lower()
                for name in (
                    _text(_dict(server).get("ldhName"), 253)
                    for server in (servers if isinstance(servers, list) else [])
                )
                if name
            ][:6],
        }
        parts = []
        if registered:
            parts.append(f"registered {registered}")
        if expires:
            parts.append(f"expires {expires}")
        if registrar:
            parts.append(f"registrar {registrar}")
        return self._result(
            summary=", ".join(parts) or "record has no registration data",
            brief=f"registered {registered}" if registered else "",
            fields=fields,
        )


class InternetDbProvider(Provider):
    """What Shodan last saw exposed on an address.

    Its hostnames are third-party forward-DNS claims and can be plainly
    unrelated to the address, so they are kept apart from the names this
    capture actually resolved.  Free for non-commercial use only.
    """

    name = "internetdb"
    kinds = frozenset({"ip"})

    def lookup(self, kind: str, value: str) -> LookupResult:
        data = self._get_json(
            f"https://internetdb.shodan.io/{urllib.parse.quote(value, safe=':')}"
        )
        if data is None:
            return self._not_found("not indexed")
        ports = _ints(data.get("ports"))
        tags = _texts(data.get("tags"))
        vulns = _texts(data.get("vulns"), limit=50)
        fields = {
            "ports": ports,
            "tags": tags,
            "vulns": vulns,
            "hostnames": _texts(data.get("hostnames")),
            "cpes": _texts(data.get("cpes")),
        }
        parts = []
        if ports:
            parts.append("open ports " + ", ".join(str(p) for p in ports[:12]))
        if tags:
            parts.append("tags " + ", ".join(tags))
        if vulns:
            parts.append(f"{len(vulns)} known CVE(s), e.g. {vulns[0]}")
        return self._result(
            summary="; ".join(parts) or "indexed with nothing exposed", fields=fields
        )


class VirusTotalProvider(Provider):
    """Multi-engine verdicts for an address or domain.  Needs ``VT_API_KEY``."""

    name = "virustotal"
    kinds = frozenset({"ip", "domain"})
    env_key = "VT_API_KEY"
    # The free tier allows 4 requests per minute.
    min_interval = 15.0

    def lookup(self, kind: str, value: str) -> LookupResult:
        collection = "ip_addresses" if kind == "ip" else "domains"
        quoted = urllib.parse.quote(value, safe=":")
        data = self._get_json(
            f"https://www.virustotal.com/api/v3/{collection}/{quoted}",
            headers={"x-apikey": self._api_key or ""},
        )
        if data is None:
            return self._not_found("unknown to VirusTotal")
        attributes = _dict(_dict(data.get("data")).get("attributes"))
        stats = _dict(attributes.get("last_analysis_stats"))
        malicious = _int(stats.get("malicious")) or 0
        suspicious = _int(stats.get("suspicious")) or 0
        engines = sum(count for count in map(_int, stats.values()) if count is not None)
        reputation = _int(attributes.get("reputation"))
        as_owner = _text(attributes.get("as_owner"))
        asn = _int(attributes.get("asn"))
        country = _text(attributes.get("country"), 8)
        registered_ts = _int(attributes.get("creation_date"))
        registered = _day(registered_ts)
        registrar = _text(attributes.get("registrar"))
        categories = sorted(
            {
                text
                for text in map(_text, _dict(attributes.get("categories")).values())
                if text
            }
        )[:5]
        fields = {
            "malicious": malicious,
            "suspicious": suspicious,
            "engines": engines,
            "reputation": reputation,
            "as_owner": as_owner,
            "asn": asn,
            "country": country,
            "network": _text(attributes.get("network"), 64),
            "tags": _texts(attributes.get("tags")),
            "registered": registered,
            "registered_ts": registered_ts,
            "registrar": registrar,
            "categories": categories,
        }

        signal: Signal | None = None
        if engines:
            if malicious >= self._config.enrich_vt_flag_engines:
                signal = Signal.FLAGGED
            elif malicious or suspicious:
                signal = Signal.REPORTED
            else:
                signal = Signal.NO_REPORTS

        parts = [
            f"{malicious} of {engines} engines flagged it"
            + (f", {suspicious} suspicious" if suspicious else "")
            if engines
            else "no engine results"
        ]
        if reputation is not None:
            parts.append(f"community score {reputation}")
        if as_owner:
            parts.append(f"AS{asn} {as_owner}" if asn is not None else as_owner)
        if country:
            parts.append(country)
        if categories:
            parts.append("categories: " + ", ".join(categories))
        if registered:
            parts.append(f"registered {registered}")
        brief = ""
        if signal in (Signal.FLAGGED, Signal.REPORTED):
            brief = f"VirusTotal {malicious}/{engines} flagged"
        return self._result(
            summary="; ".join(parts), brief=brief, fields=fields, signal=signal
        )


class AbuseIpDbProvider(Provider):
    """Abuse reports filed against an address.  Needs ``ABUSEIPDB_API_KEY``."""

    name = "abuseipdb"
    kinds = frozenset({"ip"})
    env_key = "ABUSEIPDB_API_KEY"

    #: How far back reports count.  An address reported a year ago has often
    #: changed hands since; the API's own default is 30 days.
    _MAX_AGE_DAYS = 90

    def lookup(self, kind: str, value: str) -> LookupResult:
        query = urllib.parse.urlencode(
            {"ipAddress": value, "maxAgeInDays": self._MAX_AGE_DAYS}
        )
        data = self._get_json(
            f"https://api.abuseipdb.com/api/v2/check?{query}",
            headers={"Key": self._api_key or ""},
        )
        if data is None:
            return self._not_found("no AbuseIPDB record")
        info = _dict(data.get("data"))
        score = _int(info.get("abuseConfidenceScore"))
        if score is None:
            raise ProviderError("response had no abuse score")
        reports = _int(info.get("totalReports")) or 0
        reporters = _int(info.get("numDistinctUsers")) or 0
        last_reported = _text(info.get("lastReportedAt"), 40)
        isp = _text(info.get("isp"))
        usage = _text(info.get("usageType"))
        country = _text(info.get("countryCode"), 8)
        is_tor = info.get("isTor") is True
        fields = {
            "abuse_score": score,
            "total_reports": reports,
            "distinct_reporters": reporters,
            "last_reported": last_reported,
            "isp": isp,
            "usage_type": usage,
            "country": country,
            "domain": _text(info.get("domain"), 253),
            "is_tor": is_tor,
            "is_whitelisted": info.get("isWhitelisted") is True,
        }

        if score >= self._config.enrich_abuse_flag_score:
            signal = Signal.FLAGGED
        elif reports:
            signal = Signal.REPORTED
        else:
            signal = Signal.NO_REPORTS

        parts = [
            f"abuse score {score}%, {reports} report(s) by {reporters} user(s) "
            f"in {self._MAX_AGE_DAYS} days"
        ]
        if last_reported:
            parts.append(f"last {last_reported}")
        if isp:
            parts.append(f"ISP {isp}")
        if usage:
            parts.append(usage)
        if country:
            parts.append(country)
        if is_tor:
            parts.append("Tor exit node")
        brief = ""
        if signal in (Signal.FLAGGED, Signal.REPORTED):
            brief = f"AbuseIPDB score {score}%"
        return self._result(
            summary="; ".join(parts), brief=brief, fields=fields, signal=signal
        )


PROVIDERS: dict[str, type[Provider]] = {
    provider.name: provider
    for provider in (
        RipeStatProvider,
        RdapProvider,
        InternetDbProvider,
        VirusTotalProvider,
        AbuseIpDbProvider,
    )
}


def build_providers(
    config: Config,
    *,
    environ: Mapping[str, str] | None = None,
    transport: Transport = urllib_fetch,
) -> tuple[list[Provider], dict[str, str]]:
    """Instantiate the configured providers that can run.

    Returns the providers plus, for the ones left out, the reason.  A missing
    API key is not an error: the keyless services still provide context, and
    the report states what was not consulted.  An unknown name *is* an error,
    for the same reason an unknown setting is: a typo here would silently skip
    a source the operator believes was checked.
    """
    environ = os.environ if environ is None else environ
    providers: list[Provider] = []
    unavailable: dict[str, str] = {}
    for name in config.enrich_providers:
        provider_class = PROVIDERS.get(name)
        if provider_class is None:
            raise ConfigError(
                "enrich_providers",
                f"unknown provider {name!r} (known: {', '.join(sorted(PROVIDERS))})",
            )
        api_key = None
        if provider_class.env_key is not None:
            api_key = environ.get(provider_class.env_key)
            if not api_key:
                unavailable[name] = f"set {provider_class.env_key} to enable"
                continue
        providers.append(provider_class(config, transport=transport, api_key=api_key))
    return providers, unavailable
