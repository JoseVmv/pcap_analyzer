"""Recommended investigation steps, derived from what was actually found.

Two rules govern this module:

1. **Every recommendation is tied to an indicator that was observed.**  No
   generic checklist: if no DNS anomaly was found, no DNS-review step is
   emitted.  A recommendation the evidence does not justify wastes an
   analyst's time and implies a finding that was never made.
2. **Nothing destructive, nothing automated.**  Steps are investigative -
   inspect, review, correlate, acquire.  Containment decisions (isolating a
   host, blocking a destination) belong to a human with organisational
   context this tool does not have.
"""

from __future__ import annotations

from dataclasses import dataclass

from investigator.findings import Finding


@dataclass(slots=True)
class Recommendation:
    """One suggested next step, with the indicator that motivated it."""

    step: str
    rationale: str
    triggered_by: list[str]  # finding types that produced this step

    def as_dict(self) -> dict[str, object]:
        return {
            "step": self.step,
            "rationale": self.rationale,
            "triggered_by": self.triggered_by,
        }


# Each rule: finding types -> (step template, rationale).  ``{host}`` is
# substituted with the primary suspect when one exists.
_RULES: list[tuple[tuple[str, ...], str, str]] = [
    (
        ("port_scan_vertical", "port_scan_horizontal", "host_discovery"),
        "Identify the process on {host} responsible for the scanning activity.",
        "Scanning behaviour was observed from this host; the responsible process "
        "distinguishes an authorised vulnerability scanner from unexpected activity.",
    ),
    (
        ("beaconing", "http_beaconing"),
        "Correlate the periodic connections from {host} with running processes and "
        "scheduled tasks at the matching timestamps.",
        "Periodic communication was observed. Matching it to a process or scheduled "
        "job is what separates an update agent from an unwanted channel.",
    ),
    (
        ("beaconing", "http_beaconing", "rare_destination"),
        "Compare the observed external destinations against known-good "
        "infrastructure and threat intelligence.",
        "External destinations were contacted that are uncommon in this capture; "
        "reputation and ownership context is not available from packet data.",
    ),
    (
        ("dns_anomaly", "dns_tunneling"),
        "Review DNS cache and resolver logs on {host} for the flagged domain.",
        "Anomalous DNS query patterns were observed; resolver history shows whether "
        "the queries persist and which process issued them.",
    ),
    (
        ("http_beaconing", "http_anomaly"),
        "Inspect the application or browser activity on {host} that generated the "
        "observed HTTP requests.",
        "HTTP characteristics (client identity, request pattern) were anomalous in "
        "context; the originating application resolves the ambiguity.",
    ),
    (
        ("outbound_data_transfer", "potential_exfiltration_indicator",
         "large_transfer", "data_exfiltration"),
        "Examine outbound request payloads and identify what data left the host, "
        "using proxy, DLP or endpoint telemetry where available.",
        "An outbound-dominant transfer was observed, but packet data does not "
        "reveal payload content; only host or proxy telemetry can establish what "
        "was sent.",
    ),
    (
        ("lateral_movement",),
        "Review authentication logs on the internal hosts contacted by {host}.",
        "Successful administrative sessions to multiple internal hosts were "
        "observed; authentication logs show whether the access was legitimate.",
    ),
    (
        ("unusual_port",),
        "Determine which service is listening on the non-standard ports observed.",
        "Sessions on uncommon ports were observed; identifying the service "
        "distinguishes a custom application from a hidden channel.",
    ),
]

# Always-applicable closing steps, emitted only when something was found.
_GENERAL: list[tuple[str, str]] = [
    (
        "Acquire endpoint telemetry from {host} (running processes, network "
        "connections, persistence entries) if it is available.",
        "Network evidence alone cannot establish process attribution, execution or "
        "intent; endpoint data is what closes that gap.",
    ),
    (
        "Preserve this capture and the generated reports as investigation "
        "artefacts before making changes to the host.",
        "Remediation destroys volatile evidence; preserving the source data keeps "
        "the analysis reproducible.",
    ),
]


def build_recommendations(
    findings: list[Finding], primary_suspect: str | None
) -> list[Recommendation]:
    """Derive investigation steps from the finding types actually present."""
    if not findings:
        return []

    present = {f.type for f in findings}
    host = primary_suspect or "the affected host"
    recommendations: list[Recommendation] = []
    seen_steps: set[str] = set()

    for types, template, rationale in _RULES:
        matched = sorted(present.intersection(types))
        if not matched:
            continue
        step = template.format(host=host)
        if step in seen_steps:
            continue
        seen_steps.add(step)
        recommendations.append(
            Recommendation(step=step, rationale=rationale, triggered_by=matched)
        )

    for template, rationale in _GENERAL:
        step = template.format(host=host)
        if step in seen_steps:
            continue
        seen_steps.add(step)
        recommendations.append(
            Recommendation(step=step, rationale=rationale, triggered_by=["general"])
        )

    return recommendations


def render_recommendations_text(recommendations: list[Recommendation]) -> str:
    if not recommendations:
        return ""
    lines = ["", "Recommended investigation steps:"]
    for index, recommendation in enumerate(recommendations, start=1):
        lines.append(f"  {index}. {recommendation.step}")
    return "\n".join(lines)
