"""Curated, bounded host-side Web service availability evidence."""

from __future__ import annotations

import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol, Sequence
from urllib.parse import urlsplit

from manager.component_registry import ComponentRegistry


API_VERSION = "fortifylab.io/v1alpha1"
STATES = frozenset(
    {
        "reachable",
        "degraded",
        "tls-warning",
        "dns-mismatch",
        "unreachable",
        "not-configured",
        "unknown",
    }
)


@dataclass(frozen=True)
class ObservedRoute:
    """Sanitized ingress metadata; never accepts a caller-supplied URL."""

    endpoint_id: str
    host: str
    tls: bool
    addresses: tuple[str, ...] = ()


class RouteObserver(Protocol):
    def observed_routes(self) -> Sequence[ObservedRoute]: ...


class UnavailableRouteObserver:
    def observed_routes(self) -> Sequence[ObservedRoute]:
        return ()


@dataclass(frozen=True)
class ProbeEvidence:
    state: str
    dns: str
    tls: str
    http: str
    latency_ms: int
    summary: str

    def __post_init__(self) -> None:
        if self.state not in STATES:
            raise ValueError("unsupported availability state")


class AvailabilityProbe(Protocol):
    def probe(self, route: ObservedRoute) -> ProbeEvidence: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HostAvailabilityProbe:
    """Perform DNS and HTTPS/HTTP checks without credentials or response bodies."""

    def __init__(self, *, timeout_seconds: float = 1.5) -> None:
        self._timeout = min(max(float(timeout_seconds), 0.1), 10.0)
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            urllib.request.HTTPHandler(),
            _NoRedirect(),
        )

    def probe(self, route: ObservedRoute) -> ProbeEvidence:
        started = time.monotonic()
        try:
            resolver = ThreadPoolExecutor(max_workers=1)
            future = resolver.submit(
                socket.getaddrinfo,
                route.host,
                443 if route.tls else 80,
                0,
                socket.SOCK_STREAM,
            )
            try:
                records = future.result(timeout=self._timeout)
            finally:
                resolver.shutdown(wait=False, cancel_futures=True)
            resolved = {record[4][0] for record in records}
        except (OSError, UnicodeError, FutureTimeout):
            return self._result(
                started, "unreachable", "failed", "not-attempted",
                "not-attempted", "DNS resolution failed",
            )
        if route.addresses and resolved.isdisjoint(route.addresses):
            return self._result(
                started, "dns-mismatch", "mismatch", "not-attempted",
                "not-attempted", "DNS does not resolve to an observed ingress address",
            )

        url = f"{'https' if route.tls else 'http'}://{route.host}/"
        request = urllib.request.Request(
            url,
            headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"},
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
        except urllib.error.URLError as error:
            reason = error.reason
            if isinstance(reason, ssl.SSLError):
                return self._result(
                    started, "tls-warning", "resolved", "warning",
                    "not-attempted", "TLS certificate validation failed",
                )
            return self._result(
                started, "unreachable", "resolved",
                "failed" if route.tls else "not-configured",
                "unreachable", "The service did not accept an HTTP connection",
            )
        except (OSError, TimeoutError, ssl.SSLError):
            return self._result(
                started, "unreachable", "resolved",
                "failed" if route.tls else "not-configured",
                "unreachable", "The service did not accept an HTTP connection",
            )

        tls = "valid" if route.tls else "not-configured"
        if 300 <= status < 400:
            return self._result(
                started, "degraded", "resolved", tls, f"redirect-{status}",
                "The service returned a redirect; redirects are not followed",
            )
        if status >= 500:
            return self._result(
                started, "degraded", "resolved", tls, f"status-{status}",
                "The service returned a server error",
            )
        return self._result(
            started, "reachable", "resolved", tls, f"status-{status}",
            "The service returned an HTTP response",
        )

    @staticmethod
    def _result(started, state, dns, tls, http, summary) -> ProbeEvidence:
        return ProbeEvidence(
            state, dns, tls, http,
            max(0, round((time.monotonic() - started) * 1000)), summary,
        )


class AvailabilityMonitor:
    """Cache due probes with bounded concurrency, backoff, jitter, and history."""

    def __init__(
        self,
        registry: ComponentRegistry,
        routes: RouteObserver | None = None,
        probe: AvailabilityProbe | None = None,
        *,
        interval_seconds: float = 30.0,
        max_backoff_seconds: float = 300.0,
        max_concurrency: int = 4,
        history_limit: int = 12,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._registry = registry
        self._routes = routes or UnavailableRouteObserver()
        self._probe = probe or HostAvailabilityProbe()
        self._interval = min(max(float(interval_seconds), 5.0), 300.0)
        self._max_backoff = min(
            max(float(max_backoff_seconds), self._interval), 900.0
        )
        self._concurrency = min(max(int(max_concurrency), 1), 8)
        self._history_limit = min(max(int(history_limit), 1), 48)
        self._clock = clock
        self._wall_clock = wall_clock
        self._lock = threading.Lock()
        self._results: dict[str, dict] = {}
        self._history: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self._history_limit)
        )
        self._failures: dict[str, int] = defaultdict(int)
        self._next_due: dict[str, float] = defaultdict(float)
        self._polling: set[str] = set()

    def document(self) -> dict:
        now = self._clock()
        approved = self._approved_routes()
        route_observation_failed = approved is None
        routes = approved or {}
        with self._lock:
            due = [
                route for route in routes.values()
                if now >= self._next_due[route.endpoint_id]
                and route.endpoint_id not in self._polling
            ]
            self._polling.update(route.endpoint_id for route in due)
        if due:
            try:
                with ThreadPoolExecutor(max_workers=self._concurrency) as executor:
                    evidence = list(executor.map(self._safe_probe, due))
                with self._lock:
                    for route, result in zip(due, evidence):
                        self._record(route, result, now)
            finally:
                with self._lock:
                    self._polling.difference_update(
                        route.endpoint_id for route in due
                    )

        items = []
        with self._lock:
            for endpoint in self._endpoints():
                endpoint_id = endpoint["id"]
                route = routes.get(endpoint_id)
                result = self._results.get(endpoint_id)
                if route_observation_failed:
                    result = self._unknown(endpoint)
                elif route is None:
                    result = self._not_configured(endpoint)
                elif result is None:
                    result = self._unknown(endpoint, route)
                items.append(
                    {
                        **result,
                        "history": list(self._history[endpoint_id]),
                    }
                )
        return {
            "apiVersion": API_VERSION,
            "kind": "ServiceAvailability",
            "scope": "manager-host",
            "items": items,
            "notice": (
                "Manager-host reachability does not prove reachability from an "
                "operator workstation or AWS network path."
            ),
        }

    def _approved_routes(self) -> dict[str, ObservedRoute] | None:
        endpoints = {item["id"]: item for item in self._endpoints()}
        try:
            observed = list(self._routes.observed_routes())
        except Exception:
            return None
        manager = next(
            (
                item for item in observed
                if item.endpoint_id == "manager"
                and self._valid_host(item.host, "lab")
            ),
            None,
        )
        if manager is None:
            return {}
        domain = manager.host.split(".", 1)[1]
        approved: dict[str, ObservedRoute] = {}
        for route in observed:
            endpoint = endpoints.get(route.endpoint_id)
            if (
                endpoint is None
                or route.endpoint_id in approved
                or not route.tls
                or not self._valid_host(route.host, endpoint["hostLabel"])
                or route.host.split(".", 1)[1] != domain
            ):
                continue
            approved[route.endpoint_id] = route
        return approved

    def _endpoints(self) -> list[dict]:
        endpoints = [
            {
                "id": "manager",
                "componentId": "manager",
                "displayName": "Fortify Lab Manager",
                "hostLabel": "lab",
            }
        ]
        for component_id in self._registry.component_ids:
            component = self._registry.component(component_id)
            web = component.get("web")
            if web:
                endpoints.append(
                    {
                        "id": component_id,
                        "componentId": component_id,
                        "displayName": component["displayName"],
                        "hostLabel": web["hostLabel"],
                    }
                )
        return endpoints

    @staticmethod
    def _valid_host(host: str, label: str) -> bool:
        try:
            parsed = urlsplit(f"https://{host}/")
            return (
                parsed.hostname == host
                and host == host.lower()
                and host.startswith(f"{label}.")
                and len(host) <= 253
                and all(
                    part and len(part) <= 63
                    and part[0].isalnum() and part[-1].isalnum()
                    and all(char.isalnum() or char == "-" for char in part)
                    for part in host.split(".")
                )
            )
        except ValueError:
            return False

    def _safe_probe(self, route: ObservedRoute) -> ProbeEvidence:
        try:
            return self._probe.probe(route)
        except Exception:
            return ProbeEvidence(
                "unknown", "unknown", "unknown", "unknown", 0,
                "Availability evidence could not be collected",
            )

    def _record(self, route: ObservedRoute, result: ProbeEvidence, now: float) -> None:
        endpoint = next(item for item in self._endpoints() if item["id"] == route.endpoint_id)
        checked = self._wall_clock().astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        if result.state == "reachable":
            self._failures[route.endpoint_id] = 0
        else:
            self._failures[route.endpoint_id] += 1
        multiplier = 2 ** min(self._failures[route.endpoint_id], 4)
        jitter = 0.9 + (sum(route.endpoint_id.encode()) % 21) / 100
        delay = min(
            self._max_backoff,
            self._interval * (1 if result.state == "reachable" else multiplier),
        )
        self._next_due[route.endpoint_id] = now + delay * jitter
        self._results[route.endpoint_id] = {
            "id": route.endpoint_id,
            "componentId": endpoint["componentId"],
            "displayName": endpoint["displayName"],
            "url": f"https://{route.host}/",
            "state": result.state,
            "dns": result.dns,
            "tls": result.tls,
            "http": result.http,
            "latencyMs": result.latency_ms,
            "checkedAt": checked,
            "summary": result.summary,
            "applicationHealthIndependent": True,
        }
        self._history[route.endpoint_id].appendleft(
            {"state": result.state, "checkedAt": checked, "latencyMs": result.latency_ms}
        )

    @staticmethod
    def _not_configured(endpoint: dict) -> dict:
        return {
            "id": endpoint["id"],
            "componentId": endpoint["componentId"],
            "displayName": endpoint["displayName"],
            "url": None,
            "state": "not-configured",
            "dns": "not-attempted",
            "tls": "not-attempted",
            "http": "not-attempted",
            "latencyMs": None,
            "checkedAt": None,
            "summary": "No approved observed ingress route is configured",
            "applicationHealthIndependent": True,
        }

    @staticmethod
    def _unknown(endpoint: dict, route: ObservedRoute | None = None) -> dict:
        return {
            **AvailabilityMonitor._not_configured(endpoint),
            "url": f"https://{route.host}/" if route else None,
            "state": "unknown",
            "summary": (
                "The approved route has not been checked"
                if route
                else "Ingress route evidence could not be collected"
            ),
        }
