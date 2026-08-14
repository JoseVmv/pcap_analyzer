"""DNS anomaly detection, with an emphasis on *not* over-claiming.

The rule the project sets is explicit: never call something DNS tunneling on
a single characteristic.  So this detector evaluates several independent
signals per base domain - subdomain entropy, label length, unique-subdomain
cardinality, NXDOMAIN ratio, TXT/NULL usage - and only reports when at least
``dns_min_signals`` of them are present together.  Each contributing signal
becomes one Evidence item, so the report shows exactly which combination
triggered, and confidence scales with how many and how strong they are.
"""

from __future__ import annotations

from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.protocols.dns import DomainStats


class DnsAnomalyDetector(Detector):
    name = "dns_anomaly"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        findings: list[Finding] = []
        for domain in ctx.dns.domains.values():
            if domain.queries < cfg.dns_min_queries_for_domain:
                continue
            finding = self._evaluate_domain(ctx, domain)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate_domain(self, ctx: DetectionContext, domain: DomainStats):
        cfg = ctx.config
        signals: list[tuple[str, dict, float]] = []  # (summary, data, strength)

        if domain.max_entropy >= cfg.dns_entropy_high:
            strength = min(1.0, (domain.max_entropy - cfg.dns_entropy_high) / 1.0 + 0.6)
            signals.append((
                f"high subdomain entropy (max {domain.max_entropy:.2f} bits/char, "
                f"mean {domain.mean_entropy:.2f})",
                {"max_entropy": domain.max_entropy, "mean_entropy": domain.mean_entropy},
                strength,
            ))
        elif domain.mean_entropy >= cfg.dns_entropy_mean:
            signals.append((
                f"elevated mean subdomain entropy ({domain.mean_entropy:.2f} bits/char)",
                {"mean_entropy": domain.mean_entropy},
                0.4,
            ))

        if domain.max_label_length >= cfg.dns_label_len:
            signals.append((
                f"very long DNS label ({domain.max_label_length} chars)",
                {"max_label_length": domain.max_label_length},
                min(1.0, domain.max_label_length / 63.0),
            ))

        if len(domain.unique_subdomains) >= cfg.dns_unique_subdomains:
            signals.append((
                f"{len(domain.unique_subdomains)} unique subdomains under one domain",
                {"unique_subdomains": len(domain.unique_subdomains)},
                min(1.0, len(domain.unique_subdomains) / (cfg.dns_unique_subdomains * 4)),
            ))

        nx_ratio = domain.nxdomains / domain.queries if domain.queries else 0.0
        if nx_ratio >= cfg.dns_nxdomain_ratio:
            signals.append((
                f"high NXDOMAIN ratio ({domain.nxdomains}/{domain.queries} = "
                f"{nx_ratio:.0%})",
                {"nxdomain_ratio": round(nx_ratio, 3)},
                nx_ratio,
            ))

        if domain.txt_or_null_queries > 0:
            signals.append((
                f"{domain.txt_or_null_queries} TXT/NULL queries (data-carrying "
                f"record types)",
                {"txt_or_null_queries": domain.txt_or_null_queries},
                0.5,
            ))

        if len(signals) < cfg.dns_min_signals:
            return None

        # Confidence: blend of signal count and average strength.
        avg_strength = sum(s[2] for s in signals) / len(signals)
        coverage = min(1.0, len(signals) / 4.0)
        confidence = min(0.95, 0.35 + 0.35 * coverage + 0.3 * avg_strength)

        looks_like_tunnel = (
            len(signals) >= 3
            and any("entropy" in s[0] for s in signals)
            and (
                any("label" in s[0] for s in signals)
                or any("unique subdomains" in s[0] for s in signals)
            )
        )
        if looks_like_tunnel:
            ftype, label = "dns_tunneling", "Possible DNS tunneling / exfiltration"
        else:
            ftype, label = "dns_anomaly", "Unusual DNS behaviour"

        finding = Finding(
            type=ftype,
            title=f"{label}: {domain.base_domain}",
            severity=Severity.from_confidence(confidence, Severity.HIGH),
            confidence=confidence,
            explanation=(
                f"Queries for {domain.base_domain} combine {len(signals)} independent "
                f"anomaly signals (listed below). No single signal is conclusive, but "
                f"their combination is consistent with "
                + ("automated data transfer over DNS" if looks_like_tunnel
                   else "abnormal DNS usage")
                + f". {domain.queries} queries from {len(domain.clients)} client(s)."
            ),
            source=sorted(domain.clients)[0] if domain.clients else None,
            destination=domain.base_domain,
            metadata={
                "base_domain": domain.base_domain,
                "clients": sorted(domain.clients),
                "signal_count": len(signals),
                "queries": domain.queries,
            },
        )
        for summary, data, _strength in signals:
            finding.add(summary, **data)
        return finding
