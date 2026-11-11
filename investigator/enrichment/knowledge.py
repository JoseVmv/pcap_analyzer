"""Built-in knowledge about well-known internet infrastructure.

Answers "who operates this?" with no network access.  That matters most for
captures with no cleartext names at all - no DNS at the capture point, QUIC
instead of a readable ClientHello - where a bare address is all there is.

A hint names an *operator*, never a verdict.  Attackers rent the same CDNs,
clouds and file hosts as everyone else, so nothing here is a whitelist: a hint
never touches a finding's confidence or the risk score.  ``commonly_abused``
marks services that are legitimate but disproportionately convenient to an
attacker (dynamic DNS, tunnels, anonymous file drops), which is worth an
analyst's attention without being evidence of anything.

The tables are deliberately short, because every entry can go stale.  Address
ranges are limited to operators that publish theirs; AWS and Azure publish
thousands of volatile prefixes and are left to the online lookups.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ServiceHint:
    """Who operates an address or name, as far as this table can tell."""

    name: str
    category: str
    commonly_abused: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "category": self.category,
            "commonly_abused": self.commonly_abused,
        }


_GOOGLE_DNS = ServiceHint("Google Public DNS", "public-dns")
_CLOUDFLARE_DNS = ServiceHint("Cloudflare DNS", "public-dns")
_QUAD9 = ServiceHint("Quad9 DNS", "public-dns")
_OPENDNS = ServiceHint("OpenDNS", "public-dns")

_ADDRESSES: dict[str, ServiceHint] = {
    "8.8.8.8": _GOOGLE_DNS,
    "8.8.4.4": _GOOGLE_DNS,
    "2001:4860:4860::8888": _GOOGLE_DNS,
    "2001:4860:4860::8844": _GOOGLE_DNS,
    "1.1.1.1": _CLOUDFLARE_DNS,
    "1.0.0.1": _CLOUDFLARE_DNS,
    "2606:4700:4700::1111": _CLOUDFLARE_DNS,
    "2606:4700:4700::1001": _CLOUDFLARE_DNS,
    "9.9.9.9": _QUAD9,
    "149.112.112.112": _QUAD9,
    "2620:fe::fe": _QUAD9,
    "2620:fe::9": _QUAD9,
    "208.67.222.222": _OPENDNS,
    "208.67.220.220": _OPENDNS,
    "2620:119:35::35": _OPENDNS,
    "2620:119:53::53": _OPENDNS,
}

# Ranges as published by each operator, retrieved 2026-11-04:
#   cloudflare.com/ips-v4, cloudflare.com/ips-v6, api.fastly.com/public-ip-list
#   and gstatic.com/ipranges/goog.json.  The Google blocks are the ones that
#   do not overlap cloud.json: a Google Cloud customer's VM is not "Google" in
#   any sense useful to an analyst, so those prefixes are left out on purpose.
_NETWORK_TABLE: tuple[tuple[ServiceHint, tuple[str, ...]], ...] = (
    (
        ServiceHint("Cloudflare", "cdn"),
        (
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
            "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
            "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
            "2c0f:f248::/32",
        ),
    ),
    (
        ServiceHint("Fastly", "cdn"),
        (
            "23.235.32.0/20", "43.249.72.0/22", "90.98.0.0/17",
            "90.98.128.0/18", "103.244.50.0/24", "103.245.222.0/23",
            "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18",
            "140.248.128.0/17", "146.75.0.0/17", "151.101.0.0/16",
            "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20",
            "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
            "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
            "2a04:4e40::/32", "2a04:4e42::/31", "2a04:4e44::/32",
        ),
    ),
    (
        ServiceHint("Google", "major-service"),
        (
            "142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16",
            "74.125.0.0/16", "173.194.0.0/16", "216.58.192.0/19",
            "209.85.128.0/17", "64.233.160.0/19", "66.249.64.0/19",
            "108.177.0.0/17", "192.178.0.0/15", "2607:f8b0::/32",
            "2a00:1450::/32", "2800:3f0::/32", "2404:6800::/32",
            "2c0f:fb50::/32",
        ),
    ),
)

_NETWORKS = [
    (ipaddress.ip_network(cidr), hint)
    for hint, cidrs in _NETWORK_TABLE
    for cidr in cidrs
]

_DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),     # RFC 5737
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737
    ipaddress.ip_network("203.0.113.0/24"),   # RFC 5737
    ipaddress.ip_network("2001:db8::/32"),    # RFC 3849
]

_SUFFIX_TABLE: tuple[tuple[ServiceHint, tuple[str, ...]], ...] = (
    (
        ServiceHint("Google", "major-service"),
        (
            "google.com", "gstatic.com", "googleapis.com", "googlevideo.com",
            "youtube.com", "ytimg.com", "doubleclick.net", "gvt1.com",
            "gvt2.com", "google-analytics.com", "googletagmanager.com",
        ),
    ),
    (ServiceHint("Google Public DNS", "public-dns"), ("dns.google",)),
    (
        ServiceHint("Google-hosted customer content", "cloud-hosting", True),
        ("googleusercontent.com", "appspot.com", "web.app", "firebaseapp.com", "run.app"),
    ),
    (
        ServiceHint("Microsoft", "major-service"),
        (
            "microsoft.com", "microsoftonline.com", "windowsupdate.com",
            "windows.com", "office.com", "office365.com", "office.net",
            "live.com", "msn.com", "bing.com", "skype.com", "msedge.net",
            "msftconnecttest.com", "visualstudio.com",
        ),
    ),
    (
        ServiceHint("Azure-hosted customer content", "cloud-hosting", True),
        (
            "azurewebsites.net", "blob.core.windows.net", "azureedge.net",
            "cloudapp.azure.com", "trafficmanager.net",
        ),
    ),
    (
        ServiceHint("Apple", "major-service"),
        ("apple.com", "icloud.com", "mzstatic.com", "aaplimg.com", "apple-dns.net"),
    ),
    (
        ServiceHint("Meta", "major-service"),
        (
            "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com",
            "whatsapp.net", "messenger.com",
        ),
    ),
    (ServiceHint("Amazon", "major-service"), ("amazon.com", "media-amazon.com")),
    (
        ServiceHint("AWS-hosted customer content", "cloud-hosting", True),
        ("amazonaws.com", "cloudfront.net", "elasticbeanstalk.com"),
    ),
    (ServiceHint("Cloudflare", "cdn"), ("cloudflare.com",)),
    (ServiceHint("Cloudflare DNS", "public-dns"), ("cloudflare-dns.com", "one.one.one.one")),
    (
        ServiceHint("Cloudflare-hosted customer content", "cloud-hosting", True),
        ("workers.dev", "pages.dev"),
    ),
    (
        ServiceHint("Akamai", "cdn"),
        (
            "akamai.net", "akamaiedge.net", "akamaihd.net", "akamaized.net",
            "edgekey.net", "edgesuite.net",
        ),
    ),
    (ServiceHint("Fastly", "cdn"), ("fastly.net", "fastlylb.net")),
    (ServiceHint("GitHub", "code-hosting"), ("github.com", "githubassets.com")),
    (
        ServiceHint("GitHub-hosted user content", "code-hosting", True),
        ("githubusercontent.com", "github.io"),
    ),
    (ServiceHint("Linux distribution", "os-vendor"), ("ubuntu.com", "canonical.com", "debian.org", "fedoraproject.org")),
    (ServiceHint("Mozilla", "major-service"), ("mozilla.org", "mozilla.net", "firefox.com")),
    (ServiceHint("NTP pool", "time-sync"), ("pool.ntp.org",)),
    (
        ServiceHint("Messaging service", "messaging", True),
        ("discord.com", "discordapp.com", "telegram.org", "t.me"),
    ),
    (
        ServiceHint("Dynamic DNS", "dynamic-dns", True),
        (
            "duckdns.org", "no-ip.com", "no-ip.org", "noip.com", "ddns.net",
            "hopto.org", "zapto.org", "sytes.net", "serveftp.com", "myftp.org",
            "dynu.com", "afraid.org", "mooo.com", "dyndns.org",
        ),
    ),
    (
        ServiceHint("Tunnelling service", "tunnel", True),
        (
            "ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com",
            "serveo.net", "localhost.run", "loca.lt", "localtunnel.me",
            "pinggy.io", "portmap.io",
        ),
    ),
    (
        ServiceHint("File or paste sharing", "file-sharing", True),
        (
            "pastebin.com", "paste.ee", "hastebin.com", "transfer.sh", "file.io",
            "gofile.io", "mega.nz", "mediafire.com", "anonfiles.com", "temp.sh",
            "catbox.moe", "0x0.st", "dropboxusercontent.com",
        ),
    ),
    (
        ServiceHint("URL shortener", "url-shortener", True),
        ("bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "t.co", "rb.gy", "ow.ly", "goo.gl"),
    ),
    # Asking the internet for your own public address is routine for some
    # software and an equally routine first step for an implant.
    (
        ServiceHint("Public-IP lookup service", "ip-lookup", True),
        (
            "ipinfo.io", "ipify.org", "ifconfig.me", "icanhazip.com",
            "checkip.amazonaws.com", "ip-api.com", "myexternalip.com",
            "whatismyipaddress.com",
        ),
    ),
)

_SUFFIXES: dict[str, ServiceHint] = {
    suffix: hint for hint, suffixes in _SUFFIX_TABLE for suffix in suffixes
}


def hint_for_ip(ip: str) -> ServiceHint | None:
    """The operator of ``ip``, if it is a published address or range."""
    exact = _ADDRESSES.get(ip)
    if exact is not None:
        return exact
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for network, hint in _NETWORKS:
        # ``in`` is False across IP versions rather than an error.
        if address in network:
            return hint
    return None


def hint_for_name(name: str) -> ServiceHint | None:
    """The operator of ``name``, by label-aligned suffix.

    Whole labels are compared so that ``evilgoogle.com`` is not Google, and
    the walk runs from the longest suffix so that the customer-hosting entry
    ``blob.core.windows.net`` beats any broader one.  This reads the name
    only: a hostile client can always *claim* ``www.google.com`` in an SNI.
    """
    labels = name.lower().rstrip(".").split(".")
    for start in range(len(labels)):
        hint = _SUFFIXES.get(".".join(labels[start:]))
        if hint is not None:
            return hint
    return None


def best_name_hint(names: Iterable[str]) -> ServiceHint | None:
    """One hint for several names, preferring what needs more attention.

    A base domain can hold an ordinary service next to something an analyst
    should not have hidden from them, so a commonly abused hint wins.
    """
    best: ServiceHint | None = None
    for name in names:
        hint = hint_for_name(name)
        if hint is None:
            continue
        if hint.commonly_abused:
            return hint
        best = best or hint
    return best


def address_class(ip: str) -> str | None:
    """Short description of an address outside the public unicast space."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "not a valid address"
    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        return "documentation range"
    if not address.is_global:
        return "special-purpose range"
    return None
