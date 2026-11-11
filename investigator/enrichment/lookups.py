"""Running the online lookups: order, budget, deadline and local cache.

Free tiers are small (VirusTotal allows 4 requests a minute) and a capture can
hold hundreds of indicators, so not everything gets looked up.  What matters is
which ones do and that the report says which did not:

* indicators tied to a finding go first;
* each provider runs in its own thread at its own pace, so the slowest service
  does not hold back the others, while one service never sees parallel calls;
* whatever does not fit the budget or the deadline is recorded as not queried;
* answers are cached, so a second run skips what it already knows and continues
  down the list instead of leaking the same indicators again.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path

from investigator.config import Config
from investigator.enrichment.indicators import DomainIndicator, Indicator, IpIndicator
from investigator.enrichment.providers import (
    LookupResult,
    LookupStatus,
    Provider,
    ProviderError,
    ProviderStop,
    Transport,
    build_providers,
    clean_text,
    urllib_fetch,
)

LOG = logging.getLogger(__name__)

_CACHE_VERSION = 1

#: Failures in a row before a provider is given up on for this run.  With no
#: connectivity, each attempt would otherwise cost a full timeout.
_MAX_CONSECUTIVE_FAILURES = 3

_CACHEABLE = (LookupStatus.OK, LookupStatus.NOT_FOUND)


class LookupCache:
    """Answers kept on disk between runs, as a single JSON file.

    It lives in the user's cache directory rather than the report folder: it
    accumulates indicators across investigations, and a report folder is the
    thing that gets zipped up and sent to someone.  Losing it costs only
    repeated lookups, so a damaged file is ignored instead of aborting a run.
    """

    def __init__(
        self,
        path: Path,
        ttl_seconds: float,
        *,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._path = path
        self._ttl = ttl_seconds
        self._now = now
        self._lock = threading.Lock()
        self._dirty = False
        self._entries: dict[str, dict[str, object]] = self._load()

    def _load(self) -> dict[str, dict[str, object]]:
        try:
            data = json.loads(self._path.read_bytes())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            LOG.warning("ignoring unreadable lookup cache %s: %s", self._path, exc)
            return {}
        if not isinstance(data, dict) or data.get("version") != _CACHE_VERSION:
            return {}
        entries = data.get("entries")
        return entries if isinstance(entries, dict) else {}

    @staticmethod
    def _key(provider: str, kind: str, value: str) -> str:
        return f"{provider}|{kind}|{value}"

    def _is_fresh(self, entry: object) -> bool:
        if not isinstance(entry, dict):
            return False
        fetched_at = entry.get("fetched_at")
        return (
            isinstance(fetched_at, (int, float))
            and not isinstance(fetched_at, bool)
            and self._now() - fetched_at < self._ttl
        )

    def get(self, provider: str, kind: str, value: str) -> LookupResult | None:
        with self._lock:
            entry = self._entries.get(self._key(provider, kind, value))
        if not self._is_fresh(entry):
            return None
        try:
            return LookupResult.from_cache(provider, entry)  # type: ignore[arg-type]
        except (KeyError, TypeError, ValueError):
            return None

    def put(self, kind: str, value: str, result: LookupResult) -> None:
        entry = result.as_dict()
        for transient in ("provider", "cached", "detail"):
            entry.pop(transient)
        with self._lock:
            self._entries[self._key(result.provider, kind, value)] = entry
            self._dirty = True

    def save(self) -> None:
        """Atomic write, so an interrupted run cannot truncate the file."""
        with self._lock:
            if not self._dirty:
                return
            entries = {
                key: entry
                for key, entry in self._entries.items()
                if self._is_fresh(entry)
            }
            self._dirty = False
        temp_name = None
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # mkstemp creates the file readable by this user only, which suits
            # a list of what has been investigated.
            handle, temp_name = tempfile.mkstemp(
                dir=self._path.parent, prefix=".lookups-", suffix=".tmp"
            )
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump({"version": _CACHE_VERSION, "entries": entries}, stream)
            os.replace(temp_name, self._path)
        except OSError as exc:
            LOG.warning("could not save lookup cache %s: %s", self._path, exc)
            if temp_name is not None:
                Path(temp_name).unlink(missing_ok=True)


@dataclass(slots=True)
class ProviderRun:
    """What one provider did during this run."""

    name: str
    #: Requests attempted, failures included, because a failed request may
    #: still have reached the service.  This is what "was sent" means.
    looked_up: int = 0
    cached: int = 0
    not_found: int = 0
    errors: int = 0
    not_queried: int = 0
    #: Why it stopped before the end of its queue, when it did.
    stopped: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "looked_up": self.looked_up,
            "cached": self.cached,
            "not_found": self.not_found,
            "errors": self.errors,
            "not_queried": self.not_queried,
            "stopped": self.stopped,
        }


def lookup_order(
    ips: Sequence[IpIndicator], domains: Sequence[DomainIndicator]
) -> list[Indicator]:
    """Eligible indicators, most useful first.

    Both inputs are already ranked.  They are interleaved so a small budget is
    not spent entirely on one kind, then anything tied to a finding moves up
    (the sort is stable, so ranking survives inside each group).
    """
    merged = [
        indicator
        for pair in zip_longest(ips, domains)
        for indicator in pair
        if indicator is not None and indicator.lookup_block is None
    ]
    return sorted(merged, key=lambda indicator: not indicator.finding_ids)


class LookupRunner:
    """Runs every provider over the indicators it can answer for."""

    def __init__(
        self,
        providers: Sequence[Provider],
        config: Config,
        *,
        cache: LookupCache | None = None,
        unavailable: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.providers = list(providers)
        self.unavailable = dict(unavailable or {})
        self._config = config
        self._cache = cache
        self._clock = clock

    def describe(self) -> str:
        """Plain statement of what is about to leave this machine."""
        lines = []
        if self.providers:
            names = ", ".join(provider.name for provider in self.providers)
            lines.append(
                f"enrichment: looking up public IPs and registrable domains in: "
                f"{names} (up to {self._config.enrich_deadline_seconds:.0f}s)"
            )
        else:
            lines.append("enrichment: no provider available, staying offline")
        for name, reason in self.unavailable.items():
            lines.append(f"enrichment: {name} not used ({reason})")
        return "\n".join(lines)

    def run(self, indicators: Iterable[Indicator]) -> list[ProviderRun]:
        """Attach each provider's answers to the indicators, in provider order
        so the report does not depend on which thread finished first."""
        if not self.providers:
            return []
        queue = list(indicators)
        deadline = self._clock() + self._config.enrich_deadline_seconds
        stop = threading.Event()
        try:
            with ThreadPoolExecutor(
                max_workers=len(self.providers), thread_name_prefix="enrich"
            ) as pool:
                futures = [
                    pool.submit(self._run_provider, provider, queue, deadline, stop)
                    for provider in self.providers
                ]
                try:
                    outcomes = [future.result() for future in futures]
                except KeyboardInterrupt:
                    stop.set()
                    raise
        finally:
            if self._cache is not None:
                self._cache.save()

        runs: list[ProviderRun] = []
        for run, results in outcomes:
            runs.append(run)
            for indicator, result in results:
                indicator.lookups.append(result)
            LOG.info("enrichment: %s", run.as_dict())
        return runs

    def _run_provider(
        self,
        provider: Provider,
        queue: Sequence[Indicator],
        deadline: float,
        stop: threading.Event,
    ) -> tuple[ProviderRun, list[tuple[Indicator, LookupResult]]]:
        run = ProviderRun(provider.name)
        results: list[tuple[Indicator, LookupResult]] = []
        pending: list[Indicator] = []
        for indicator in queue:
            if indicator.kind not in provider.kinds:
                continue
            cached = None
            if self._cache is not None:
                cached = self._cache.get(provider.name, indicator.kind, indicator.value)
            if cached is None:
                pending.append(indicator)
                continue
            run.cached += 1
            run.not_found += cached.status is LookupStatus.NOT_FOUND
            results.append((indicator, cached))

        failures = 0
        next_call = self._clock()
        for indicator in pending:
            if run.stopped is None:
                run.stopped = self._reason_to_stop(run, next_call, deadline, stop)
            if run.stopped is not None:
                run.not_queried += 1
                results.append(
                    (
                        indicator,
                        LookupResult(
                            provider=provider.name,
                            status=LookupStatus.NOT_QUERIED,
                            detail=run.stopped,
                        ),
                    )
                )
                continue

            next_call = self._clock() + provider.min_interval
            run.looked_up += 1
            # The catch-all is deliberate: providers parse hostile data from
            # outside this project, and the capture's own results must survive
            # whatever comes back.
            try:
                result = provider.lookup(indicator.kind, indicator.value)
            except ProviderStop as exc:
                run.stopped = clean_text(exc)
                result = self._failure(provider, run.stopped)
            except ProviderError as exc:
                result = self._failure(provider, clean_text(exc))
            except Exception:
                LOG.debug("unexpected %s failure", provider.name, exc_info=True)
                result = self._failure(provider, "unexpected response format")
            result.fetched_at = time.time()
            results.append((indicator, result))

            if result.status is LookupStatus.ERROR:
                run.errors += 1
                failures += 1
                if run.stopped is None and failures >= _MAX_CONSECUTIVE_FAILURES:
                    run.stopped = (
                        f"gave up after {failures} consecutive failures: {result.detail}"
                    )
                continue
            failures = 0
            run.not_found += result.status is LookupStatus.NOT_FOUND
            if self._cache is not None and result.status in _CACHEABLE:
                self._cache.put(indicator.kind, indicator.value, result)
        return run, results

    def _reason_to_stop(
        self,
        run: ProviderRun,
        next_call: float,
        deadline: float,
        stop: threading.Event,
    ) -> str | None:
        """Wait out the rate limit, or say why no further call may be made."""
        budget = self._config.enrich_max_lookups_per_provider
        if run.looked_up >= budget:
            return f"lookup budget of {budget} reached"
        wait = max(0.0, next_call - self._clock())
        if self._clock() + wait >= deadline:
            return (
                f"deadline of {self._config.enrich_deadline_seconds:.0f}s reached"
            )
        if stop.wait(wait):
            return "interrupted"
        return None

    @staticmethod
    def _failure(provider: Provider, detail: str) -> LookupResult:
        return LookupResult(
            provider=provider.name, status=LookupStatus.ERROR, detail=detail
        )


def default_cache_path(config: Config) -> Path | None:
    """Where answers are kept; ``None`` when caching is off."""
    if config.enrich_cache_ttl_hours <= 0:
        return None
    if config.enrich_cache_dir:
        return Path(config.enrich_cache_dir) / "lookups.json"
    try:
        return Path.home() / ".cache" / "pcap-investigator" / "lookups.json"
    except RuntimeError:  # no resolvable home directory
        return None


def build_lookup_runner(
    config: Config,
    *,
    environ: Mapping[str, str] | None = None,
    transport: Transport = urllib_fetch,
) -> LookupRunner:
    """A runner for the configured providers.  Nothing is sent until ``run``."""
    providers, unavailable = build_providers(
        config, environ=environ, transport=transport
    )
    path = default_cache_path(config)
    cache = None
    if path is not None:
        cache = LookupCache(path, config.enrich_cache_ttl_hours * 3600.0)
    return LookupRunner(providers, config, cache=cache, unavailable=unavailable)
