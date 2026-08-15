"""TLS metadata anomalies - what the handshake reveals before encryption.

TLS hides payloads, not handshakes.  The ClientHello is sent in the clear
and states which host the client wants, which protocol versions it accepts
and, through the ordering of its cipher and extension lists, which
implementation produced it.  All four signals below read only that
cleartext preamble; nothing is decrypted and no payload claim is made.

The four signals
----------------
* **No SNI to an external destination.**  Every modern client announces the
  hostname it wants, because shared hosting requires it.  Omitting it means
  the client already knows exactly which endpoint it is reaching.

* **SNI that was never resolved in this capture.**  The client asked for a
  hostname that no observed DNS response ever mapped to that address.  That
  is the shape of a hard-coded address with a plausible-looking name
  attached, and of domain fronting.  Only evaluated when DNS *was* observed
  in the capture - otherwise the absence proves nothing about the client.

* **Legacy protocol versions.**  A current client negotiating TLS 1.0 or
  SSL 3.0 is either very old software or something that does not care to
  blend in.

* **A rare fingerprint reaching many destinations.**  Fingerprint rarity is
  measured *within this capture only* (see :meth:`TlsAnalyzer.rare_fingerprints`);
  there is no external corpus and no blocklist, in keeping with the rule
  that the baseline always comes from the traffic at hand.
"""

from __future__ import annotations

from collections import defaultdict

from investigator.detectors.base import DetectionContext, Detector
from investigator.findings import Finding, Severity
from investigator.inventory import HostKind


class TlsAnomalyDetector(Detector):
    """Reads the cleartext TLS handshake for metadata-level anomalies."""

    name = "tls_anomaly"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._missing_sni(ctx))
        findings.extend(self._unresolved_sni(ctx))
        findings.extend(self._legacy_versions(ctx))
        findings.extend(self._rare_fingerprints(ctx))
        return findings[: ctx.config.tls_max_findings]

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _is_external(ctx: DetectionContext, ip: str) -> bool:
        host = ctx.inventory.hosts.get(ip)
        return host is not None and host.kind is HostKind.EXTERNAL

    # ------------------------------------------------------------ signals

    def _missing_sni(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        pairs: dict[tuple[str, str], list] = defaultdict(list)
        for hello in ctx.tls.client_hellos:
            if hello.sni:
                continue
            if not self._is_external(ctx, hello.dst_ip):
                continue
            pairs[(hello.src_ip, hello.dst_ip)].append(hello)

        findings: list[Finding] = []
        for (src, dst), hellos in pairs.items():
            times = [h.timestamp for h in hellos]
            finding = Finding(
                type="tls_no_sni",
                title=f"TLS without SNI: {src} -> {dst}",
                severity=Severity.MEDIUM,
                confidence=cfg.tls_no_sni_confidence,
                explanation=(
                    f"{src} opened {len(hellos)} TLS session(s) to {dst} without "
                    f"sending a Server Name Indication. Clients normally announce "
                    f"the hostname they want, because shared hosting cannot serve "
                    f"the right certificate without it - omitting it indicates the "
                    f"client already knew precisely which endpoint it was reaching."
                ),
                source=src,
                destination=dst,
                timestamp=min(times),
                start_time=min(times),
                end_time=max(times),
                tactic="Command & Control",
                interpretation=(
                    "Connecting to a bare address with no hostname is common in "
                    "software configured with a hard-coded endpoint, which "
                    "includes both internal tooling and remote-access implants."
                ),
                limitations=(
                    "Direct-to-IP connections are routine for monitoring agents, "
                    "certificate checks, some mobile SDKs and any client talking "
                    "to a dedicated host. Absence of SNI is not evidence of "
                    "malice on its own."
                ),
                metadata={"hello_count": len(hellos)},
            )
            finding.add(
                f"{len(hellos)} ClientHello(s) to {dst} carried no SNI extension",
                hello_count=len(hellos),
            )
            findings.append(finding)
        return findings

    def _unresolved_sni(self, ctx: DetectionContext) -> list[Finding]:
        """SNI naming a host that no observed DNS answer tied to this IP.

        Guarded by ``total_responses``: in a capture where DNS was never
        recorded (split horizon, DoH, resolver outside the capture point)
        every single session would look unresolved, which would say
        something about the capture rather than about the client.
        """
        cfg = ctx.config
        dns = ctx.dns
        if dns.total_responses == 0:
            return []

        pairs: dict[tuple[str, str, str], list] = defaultdict(list)
        for hello in ctx.tls.client_hellos:
            if not hello.sni:
                continue
            if not self._is_external(ctx, hello.dst_ip):
                continue
            names = dns.names_for_ip(hello.dst_ip)
            if hello.sni in names:
                continue  # resolution observed and consistent
            if any(hello.sni.endswith("." + name) or name.endswith("." + hello.sni)
                   for name in names):
                continue  # same zone, CNAME-style indirection
            pairs[(hello.src_ip, hello.dst_ip, hello.sni)].append(hello)

        findings: list[Finding] = []
        for (src, dst, sni), hellos in pairs.items():
            resolved = sorted(dns.names_for_ip(dst))
            times = [h.timestamp for h in hellos]
            # A destination that DNS did resolve - to a *different* name -
            # is a stronger signal than one never named at all.
            contradicted = bool(resolved)
            confidence = cfg.tls_unresolved_sni_confidence + (
                0.10 if contradicted else 0.0
            )
            finding = Finding(
                type="tls_unresolved_sni",
                title=f"TLS SNI without matching DNS resolution: {sni}",
                severity=Severity.HIGH if contradicted else Severity.MEDIUM,
                confidence=min(0.85, confidence),
                explanation=(
                    f"{src} requested \"{sni}\" from {dst}, but no DNS response in "
                    f"this capture mapped that name to that address."
                    + (
                        f" DNS did resolve this address, to a different name "
                        f"({', '.join(resolved[:3])})."
                        if contradicted
                        else " This address was never named by DNS at all."
                    )
                    + " The client therefore reached the address without an "
                    "observed lookup that would justify it."
                ),
                source=src,
                destination=dst,
                timestamp=min(times),
                start_time=min(times),
                end_time=max(times),
                tactic="Command & Control",
                interpretation=(
                    "A hostname presented to an address that DNS never tied to it "
                    "is consistent with a hard-coded endpoint carrying a "
                    "plausible-looking name, and with domain fronting, where the "
                    "visible name and the real destination deliberately differ."
                ),
                limitations=(
                    "A resolution cached before the capture started, a lookup made "
                    "over encrypted DNS, a resolver sitting outside the capture "
                    "point, or a CDN answering for many names all produce this "
                    "same observation without anything being wrong."
                ),
                metadata={
                    "sni": sni,
                    "hello_count": len(hellos),
                    "dns_names_for_ip": resolved[:10],
                    "contradicted": contradicted,
                },
            )
            finding.add(
                f"SNI \"{sni}\" requested from {dst} in {len(hellos)} session(s)",
                sni=sni, hello_count=len(hellos),
            )
            if contradicted:
                finding.add(
                    f"DNS resolved {dst} to {', '.join(resolved[:5])} - never to "
                    f"\"{sni}\"",
                    resolved_names=resolved[:10],
                )
            else:
                finding.add(
                    f"no DNS response in this capture resolved to {dst}",
                    dns_responses_seen=dns.total_responses,
                )
            findings.append(finding)
        return findings

    def _legacy_versions(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        legacy = set(cfg.tls_legacy_versions)
        pairs: dict[tuple[str, str, str], list] = defaultdict(list)
        for hello in ctx.tls.client_hellos:
            # A hello that offers modern versions via supported_versions is
            # a TLS 1.3 client using a legacy record version by design, not
            # an old client - RFC 8446 requires exactly that.
            offered = set(hello.supported_versions) or {hello.legacy_version}
            if offered - legacy:
                continue
            version = sorted(offered)[0]
            pairs[(hello.src_ip, hello.dst_ip, version)].append(hello)

        findings: list[Finding] = []
        for (src, dst, version), hellos in pairs.items():
            times = [h.timestamp for h in hellos]
            finding = Finding(
                type="tls_legacy_version",
                title=f"Legacy TLS version offered: {version} ({src} -> {dst})",
                severity=Severity.LOW,
                confidence=cfg.tls_legacy_version_confidence,
                explanation=(
                    f"{src} offered only {version} in {len(hellos)} handshake(s) "
                    f"with {dst}. Current clients negotiate TLS 1.2 or 1.3; "
                    f"offering nothing newer points to outdated software or to a "
                    f"client that implements TLS minimally."
                ),
                source=src,
                destination=dst,
                timestamp=min(times),
                start_time=min(times),
                end_time=max(times),
                interpretation=(
                    "Obsolete protocol versions widen the attack surface and are "
                    "characteristic of both unpatched software and hand-rolled "
                    "TLS clients."
                ),
                limitations=(
                    "Legacy embedded devices, printers, industrial equipment and "
                    "old management tools legitimately speak these versions. This "
                    "is a hygiene observation, not an indicator of compromise."
                ),
                metadata={"version": version, "hello_count": len(hellos)},
            )
            finding.add(
                f"{len(hellos)} handshake(s) offering only {version}",
                version=version, hello_count=len(hellos),
            )
            findings.append(finding)
        return findings

    def _rare_fingerprints(self, ctx: DetectionContext) -> list[Finding]:
        cfg = ctx.config
        tls = ctx.tls
        findings: list[Finding] = []

        for fingerprint in tls.rare_fingerprints(cfg.tls_rare_fingerprint_max_clients):
            clients = tls.ja3_clients.get(fingerprint, set())
            destinations = tls.ja3_destinations.get(fingerprint, set())
            hellos = tls.ja3_counter.get(fingerprint, 0)
            if hellos < cfg.tls_min_hellos_for_pattern:
                continue
            if len(destinations) < cfg.tls_rare_fingerprint_min_destinations:
                continue
            external = [d for d in destinations if self._is_external(ctx, d)]
            if not external:
                continue

            src = sorted(clients)[0]
            total_fingerprints = len(tls.ja3_clients)
            finding = Finding(
                type="tls_rare_fingerprint",
                title=f"Uncommon TLS client fingerprint from {src}",
                severity=Severity.MEDIUM,
                confidence=cfg.tls_rare_fingerprint_confidence,
                explanation=(
                    f"{src} produced a TLS fingerprint ({fingerprint[:16]}...) that "
                    f"no other host in this capture used, across {hellos} handshakes "
                    f"to {len(external)} external destination(s). The fingerprint is "
                    f"derived from the ordering of the offered ciphers, extensions "
                    f"and curves, which is decided by the client's TLS library - so "
                    f"it identifies the software making the connection, not the "
                    f"content of it."
                ),
                source=src,
                timestamp=None,
                tactic="Command & Control",
                interpretation=(
                    "One TLS implementation, unique on this network, reaching "
                    "several external endpoints is consistent with a purpose-built "
                    "client rather than with the browsers and updaters the rest of "
                    "the hosts run."
                ),
                limitations=(
                    "Rarity is measured only against the other clients in this "
                    "capture; a single unusual-but-legitimate application produces "
                    "the same result. The fingerprint identifies an implementation, "
                    "never a specific program, and it is not compared against any "
                    "external database."
                ),
                metadata={
                    "fingerprint": fingerprint,
                    "hellos": hellos,
                    "clients": sorted(clients),
                    "destination_count": len(destinations),
                    "external_destinations": sorted(external)[:10],
                    "distinct_fingerprints_in_capture": total_fingerprints,
                },
            )
            finding.add(
                f"fingerprint {fingerprint[:16]}... used by {len(clients)} host of "
                f"{total_fingerprints} distinct fingerprint(s) observed",
                fingerprint=fingerprint,
                clients=sorted(clients),
            )
            finding.add(
                f"{hellos} handshakes to {len(external)} external destination(s)",
                hellos=hellos, external_destinations=sorted(external)[:10],
            )
            findings.append(finding)
        return findings