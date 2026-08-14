"""Central, tunable configuration.

Every threshold a detector uses and every weight the risk score uses lives
here, never hard-coded at the point of use.  This is a core requirement of
the project: the output must be *explainable and adjustable*.  A finding can
then honestly say "flagged because X exceeded threshold T (config
``dns_label_len``)", and an operator can retune one number without editing
detector logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

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

    # -- risk scoring (V7) ------------------------------------------------
    weights: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_WEIGHTS)
    )
    score_cap: float = 100.0
    correlation_bonus: float = 15.0       # added when a chain correlates

    def weight_for(self, finding_type: str) -> float:
        return self.weights.get(finding_type, 5.0)
