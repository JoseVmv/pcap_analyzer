"""Central, tunable configuration.

Every threshold a detector uses and every weight the risk score uses lives
here, never hard-coded at the point of use.  This is a core requirement of
the project: the output must be *explainable and adjustable*.  A finding can
then honestly say "flagged because X exceeded threshold T (config
``dns_label_len``)", and an operator can retune one number without editing
detector logic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path

from investigator.errors import ConfigError

try:  # tomllib is stdlib from 3.11; the project supports 3.10 as well
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - depends on the interpreter
    tomllib = None  # type: ignore[assignment]

# Ports whose periodic / fan-in behaviour is legitimately service-like.
# Used to *reduce confidence*, never to hard-whitelist: a beacon to port 53
# is less alarming, not impossible.
COMMON_SERVICE_PORTS: frozenset[int] = frozenset(
    {
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 135, 137, 138,
        139, 143, 161, 162, 389, 443, 445, 465, 514, 587, 636, 993, 995,
        1433, 1521, 3306, 3389, 5060, 5061, 5353, 5432, 8080, 8443,
    }
)

# Ports commonly used by administration / file sharing - lateral-movement
# relevant (V5).
ADMIN_PORTS: frozenset[int] = frozenset(
    {22, 23, 135, 139, 445, 3389, 5985, 5986, 5900, 1433, 3306}
)

# Ports whose protocols are *inherently* periodic (time sync, name
# resolution, DHCP renewal, NetBIOS).  A regular beacon to one of these is
# very likely benign infrastructure chatter, so it gets the strongest
# confidence penalty of all.
PERIODIC_INFRA_PORTS: frozenset[int] = frozenset({53, 67, 68, 123, 137, 138, 5353})

DEFAULT_WEIGHTS: dict[str, float] = {
    "port_scan_vertical": 15.0,
    "port_scan_horizontal": 15.0,
    "host_discovery": 10.0,
    "dns_tunneling": 20.0,
    "dns_anomaly": 10.0,
    "beaconing": 25.0,
    "http_beaconing": 22.0,
    "http_anomaly": 6.0,
    "rare_destination": 10.0,
    "unusual_port": 8.0,
    # A burst is a volume observation, not an attack stage - weighted low.
    "traffic_burst": 5.0,
    # Tiered transfer assessment: weight grows with how much corroborating
    # evidence the tier required.
    "large_transfer": 3.0,
    "outbound_data_transfer": 10.0,
    "potential_exfiltration_indicator": 20.0,
    "data_exfiltration": 20.0,   # legacy type name, kept for compatibility
    "lateral_movement": 18.0,
    # Link-layer integrity: a contested address is a strong, cheap signal,
    # and it undermines the trustworthiness of everything above it.
    "arp_spoofing": 22.0,
    "arp_mac_flooding": 12.0,
    # ICMP used as a carrier rather than as a diagnostic.
    "icmp_tunneling": 20.0,
    "icmp_sweep": 8.0,
    # TLS metadata anomalies (handshake is cleartext even when the body
    # is not, so these are observations, never payload claims).
    "tls_no_sni": 8.0,
    "tls_unresolved_sni": 14.0,
    "tls_legacy_version": 6.0,
    "tls_rare_fingerprint": 12.0,
}


@dataclass
class Config:
    """All tunables.  Instantiate with overrides: ``Config(beacon_min_events=8)``."""

    # -- port scanning ----------------------------------------------------
    scan_min_ports_vertical: int = 15
    scan_min_hosts_horizontal: int = 10
    scan_unestablished_ratio: float = 0.5

    # -- DNS anomalies (combine >= dns_min_signals before firing) ---------
    dns_min_queries_for_domain: int = 8
    dns_entropy_high: float = 3.8         # bits/char over the whole subdomain
    dns_entropy_mean: float = 3.2
    dns_label_len: int = 30
    dns_unique_subdomains: int = 40
    dns_nxdomain_ratio: float = 0.4
    dns_min_signals: int = 2

    # -- rare external destinations ---------------------------------------
    rare_max_internal_hosts: int = 1
    rare_min_packets: int = 6
    rare_max_findings: int = 25

    # -- unusual ports ----------------------------------------------------
    unusual_port_max_global_flows: int = 2
    unusual_port_max_findings: int = 25

    # -- traffic bursts ---------------------------------------------------
    burst_target_buckets: int = 240
    burst_sigma: float = 5.0
    burst_min_bucket_bytes: int = 50_000
    burst_max_findings: int = 10

    # -- beaconing --------------------------------------------------------
    beacon_min_events: int = 6
    beacon_regular_cv: float = 0.15       # coefficient of variation: regular
    beacon_jitter_cv: float = 0.35        # up to here: jittered, lower conf
    beacon_min_interval: float = 1.0      # ignore sub-second chatter
    beacon_strong_duration: float = 300.0 # persisted >= 5 min -> confidence up
    beacon_common_port_penalty: float = 0.20   # common service port
    beacon_infra_port_penalty: float = 0.50    # inherently periodic protocol

    # -- outbound data transfer (tiered assessment) -----------------------
    # Tier 1 (large_transfer): volume above this floor.
    transfer_min_bytes: int = 1_000_000   # 1 MB outbound floor to consider
    # Tier 2 (outbound_data_transfer): also upload-dominant.
    transfer_out_in_ratio: float = 3.0    # sent >> received
    # Tier 3 (potential_exfiltration_indicator): also corroborated by at
    # least this many independent indicators beyond volume and direction.
    exfil_min_indicators: int = 2
    exfil_baseline_multiple: float = 5.0  # vs median internal host upload
    exfil_min_uploads: int = 3            # repeated HTTP POST/PUT requests
    exfil_low_response_ratio: float = 20.0  # sent/received considered "low reply"

    # -- HTTP anomaly analysis --------------------------------------------
    http_min_requests_for_pattern: int = 5
    http_beacon_cv: float = 0.25          # request-interval regularity
    http_low_response_ratio: float = 10.0
    #: User-Agent substrings whose age/shape makes them contextually odd.
    #: Never proof of anything - they raise a *contextual* flag only.
    http_legacy_agents: tuple[str, ...] = (
        "MSIE", "Windows NT 5.", "Windows NT 6.0", "Windows NT 6.1",
        "Windows NT 6.2", "Windows NT 6.3", "Trident/", "Firefox/3",
        "Firefox/4", "Chrome/4", "Chrome/5", "Java/1.", "python-requests",
        "curl/", "Wget/", "WinHTTP", "Mozilla/4.",
    )

    # -- lateral movement (V5) --------------------------------------------
    lateral_min_targets: int = 3          # internal hosts reached on admin ports

    # -- ARP integrity (V8) -----------------------------------------------
    #: Frames a MAC must send claiming an IP before the claim is weighed.
    #: One stray frame is noise; a poisoner repeats itself to keep caches
    #: warm.
    arp_min_claims: int = 2
    #: Seconds two MACs must claim the same IP *simultaneously* before the
    #: overlap is treated as corroboration.  A sequential handover (DHCP
    #: reassignment, replaced NIC) produces no overlap at all.
    arp_conflict_min_overlap: float = 1.0
    #: One MAC answering for at least this many distinct IPs.  Routers doing
    #: proxy ARP legitimately do this, so it carries low confidence.
    arp_mac_many_ips: int = 5
    arp_conflict_base_confidence: float = 0.45
    arp_overlap_bonus: float = 0.25       # claims coexisted in time
    arp_gratuitous_bonus: float = 0.10    # unprompted announcements
    arp_ether_mismatch_bonus: float = 0.15  # Ether.src != ARP.hwsrc

    # -- ICMP anomalies (V8) ----------------------------------------------
    icmp_min_echo_packets: int = 10       # below this there is no shape
    #: Mean echo payload above this is beyond what ping implementations
    #: emit (Windows 32 B, Linux 56 B); carrying data needs room.
    icmp_large_payload: int = 128
    #: Fraction of echoes that differ from the channel's most common size.
    #: A ping is 0.0 by construction; a carrier varies.
    icmp_size_variability: float = 0.30
    icmp_min_tunnel_bytes: int = 10_000   # total payload floor
    icmp_sweep_min_targets: int = 15      # distinct hosts pinged
    icmp_tunnel_base_confidence: float = 0.40
    icmp_variability_bonus: float = 0.20
    icmp_volume_bonus: float = 0.15

    # -- TLS metadata anomalies (V8) --------------------------------------
    #: Handshake versions that a current client should not be negotiating.
    tls_legacy_versions: tuple[str, ...] = ("SSL 3.0", "TLS 1.0", "TLS 1.1")
    #: ClientHellos a client must send before its fingerprint is compared
    #: against the rest of the capture.
    tls_min_hellos_for_pattern: int = 3
    #: A fingerprint used by at most this many clients counts as rare
    #: *within this capture* - never against an external list.
    tls_rare_fingerprint_max_clients: int = 1
    #: Distinct destinations one fingerprint must reach before "same TLS
    #: stack, many endpoints" is worth reporting.
    tls_rare_fingerprint_min_destinations: int = 3
    tls_max_findings: int = 25
    tls_no_sni_confidence: float = 0.45
    tls_unresolved_sni_confidence: float = 0.55
    tls_legacy_version_confidence: float = 0.60
    tls_rare_fingerprint_confidence: float = 0.40

    # -- risk scoring (V7) ------------------------------------------------
    weights: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_WEIGHTS)
    )
    score_cap: float = 100.0
    correlation_bonus: float = 15.0       # added when a chain correlates

    def weight_for(self, finding_type: str) -> float:
        return self.weights.get(finding_type, 5.0)

    @classmethod
    def from_mapping(
        cls, values: dict[str, object], *, source: Path | str = "<mapping>"
    ) -> "Config":
        """Build a config from a mapping, validating names and types.

        An unknown key is rejected rather than ignored.  A silently dropped
        typo would leave the operator believing a threshold had been
        retuned while the tool kept using the default - the exact failure
        mode that makes tuning untrustworthy.

        ``weights`` is merged into the defaults instead of replacing them,
        so a file that adjusts one weight does not have to restate all of
        them (and does not lose the ones added in later versions).
        """
        known = {f.name: f for f in fields(cls)}
        kwargs: dict[str, object] = {}

        for key, value in values.items():
            spec = known.get(key)
            if spec is None:
                suggestion = _closest_name(key, known)
                raise ConfigError(
                    source,
                    f"unknown setting {key!r}"
                    + (f" (did you mean {suggestion!r}?)" if suggestion else ""),
                )
            if key == "weights":
                if not isinstance(value, dict):
                    raise ConfigError(
                        source, "'weights' must be a table of name -> number"
                    )
                merged = dict(DEFAULT_WEIGHTS)
                for name, weight in value.items():
                    if not isinstance(weight, (int, float)) or isinstance(
                        weight, bool
                    ):
                        raise ConfigError(
                            source,
                            f"weight {name!r} must be a number, got "
                            f"{type(weight).__name__}",
                        )
                    merged[name] = float(weight)
                kwargs[key] = merged
                continue
            kwargs[key] = _coerce(key, value, spec.type, source)

        return cls(**kwargs)  # type: ignore[arg-type]


def _coerce(key: str, value: object, declared: object, source: Path | str) -> object:
    """Convert one config value to the type its field declares.

    ``from __future__ import annotations`` turns every annotation into a
    string, so the declared type is matched by name.
    """
    declared = str(declared)
    if declared.startswith("tuple"):
        if not isinstance(value, (list, tuple)):
            raise ConfigError(source, f"{key!r} must be a list of strings")
        return tuple(str(item) for item in value)
    if declared.startswith("int"):
        # bool is an int subclass; accepting it here would let `true` set a
        # threshold to 1 without complaint.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(
                source, f"{key!r} must be an integer, got {type(value).__name__}"
            )
        return value
    if declared.startswith("float"):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(
                source, f"{key!r} must be a number, got {type(value).__name__}"
            )
        return float(value)
    return value


def _closest_name(key: str, known: dict[str, object]) -> str | None:
    """Best-effort 'did you mean' for a mistyped setting name."""
    import difflib

    matches = difflib.get_close_matches(key, list(known), n=1, cutoff=0.7)
    return matches[0] if matches else None


def load_config(path: Path | str) -> Config:
    """Load a :class:`Config` from a TOML or JSON file.

    Both formats are accepted so the feature works on every supported
    interpreter: ``tomllib`` only became stdlib in Python 3.11, and adding a
    TOML backport as a dependency for a handful of thresholds would not pay
    for itself.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(path, f"cannot read the file: {exc}") from exc

    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            values = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConfigError(path, f"invalid JSON: {exc}") from exc
    elif suffix == ".toml":
        if tomllib is None:
            raise ConfigError(
                path,
                "TOML needs Python 3.11 or newer; use a .json file instead",
            )
        try:
            values = tomllib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(path, f"invalid TOML: {exc}") from exc
    else:
        raise ConfigError(
            path, f"unsupported extension {suffix or '(none)'} - use .toml or .json"
        )

    if not isinstance(values, dict):
        raise ConfigError(path, "the top level must be a table of settings")
    return Config.from_mapping(values, source=path)
