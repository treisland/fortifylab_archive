"""Versioned read-only WSGI API for manager dashboard read models."""

from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any, Callable, Iterable, Protocol

from manager.component_inventory import ClusterObserver, ComponentInventory
from manager.helm_release_evidence import ProtectedHelmSnapshot
from manager.availability import AvailabilityMonitor
from manager.component_registry import ComponentRegistry, RegistryError
from manager.health import HealthEngine, HealthProbe
from manager.preflight import PreflightEngine, PreflightProbe


COMPONENTS_PATH = "/api/v1alpha1/components"
HEALTH_PATH = "/api/v1alpha1/health"
PREFLIGHT_PATH = "/api/v1alpha1/preflight"
HISTORY_PATH = "/api/v1alpha1/history"
PROFILE_PATH = "/api/v1alpha1/platform-profile"
AVAILABILITY_PATH = "/api/v1alpha1/availability"


class HistoryReader(Protocol):
    """Read sanitized manager-owned history, newest record first."""

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return at most ``limit`` already-sanitized records."""


class EmptyHistoryReader:
    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        return []


class ManagerAPI:
    """Serve the stable component inventory contract without mutation routes."""

    def __init__(
        self,
        registry_loader: Callable[[], ComponentRegistry] = ComponentRegistry.load,
        observer: ClusterObserver | None = None,
        health_probe: HealthProbe | None = None,
        preflight_probe: PreflightProbe | None = None,
        preflight_capability_provider: Callable[[], dict[str, Any]] | None = None,
        history_reader: HistoryReader | None = None,
        availability_monitor: AvailabilityMonitor | None = None,
        helm_evidence: ProtectedHelmSnapshot | None = None,
    ) -> None:
        self._registry_loader = registry_loader
        self._observer = observer
        self._health_probe = health_probe
        self._preflight_probe = preflight_probe
        self._preflight_capability_provider = preflight_capability_provider
        self._history_reader = history_reader or EmptyHistoryReader()
        self._availability_monitor = availability_monitor
        self._helm_evidence = helm_evidence

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        if path not in {
            COMPONENTS_PATH,
            HEALTH_PATH,
            PREFLIGHT_PATH,
            HISTORY_PATH,
            PROFILE_PATH,
            AVAILABILITY_PATH,
        }:
            return self._response(
                start_response,
                HTTPStatus.NOT_FOUND,
                {"code": "NOT_FOUND", "message": "resource not found"},
                method,
            )
        if method not in {"GET", "HEAD"}:
            return self._response(
                start_response,
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"code": "METHOD_NOT_ALLOWED", "message": "method not allowed"},
                method,
                (("Allow", "GET, HEAD"),),
            )
        try:
            if path == HISTORY_PATH:
                document = {
                    "apiVersion": "fortifylab.io/v1alpha1",
                    "kind": "OperationHistory",
                    "items": self._history_reader.recent(20),
                }
            elif path == AVAILABILITY_PATH and self._availability_monitor is not None:
                document = self._availability_monitor.document()
            else:
                registry = self._registry_loader()
            if path == AVAILABILITY_PATH and self._availability_monitor is None:
                document = AvailabilityMonitor(registry).document()
            elif path == HEALTH_PATH:
                document = HealthEngine(registry, self._health_probe).document()
            elif path == PREFLIGHT_PATH:
                document = PreflightEngine(
                    registry, self._preflight_probe,
                    capability_provider=self._preflight_capability_provider,
                ).document()
            elif path == PROFILE_PATH:
                document = registry.profile.public_document()
            elif path == COMPONENTS_PATH:
                document = ComponentInventory(
                    registry, self._observer, self._helm_evidence
                ).document()
        except (RegistryError, RuntimeError, ValueError, TypeError):
            return self._response(
                start_response,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "code": (
                        "READ_MODEL_UNAVAILABLE"
                        if path == HISTORY_PATH
                        else "REGISTRY_UNAVAILABLE"
                    ),
                    "message": (
                        "operation history is unavailable"
                        if path == HISTORY_PATH
                        else "service availability is unavailable"
                        if path == AVAILABILITY_PATH
                        else "health read model is unavailable"
                        if path == HEALTH_PATH
                        else (
                            "preflight read model is unavailable"
                            if path == PREFLIGHT_PATH
                            else "platform profile is unavailable"
                            if path == PROFILE_PATH
                            else "component inventory is unavailable"
                        )
                    ),
                },
                method,
            )
        return self._response(start_response, HTTPStatus.OK, document, method)

    @staticmethod
    def _response(
        start_response: Callable,
        status: HTTPStatus,
        document: dict,
        method: str,
        extra_headers: tuple[tuple[str, str], ...] = (),
    ) -> Iterable[bytes]:
        body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
        headers = (
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            *extra_headers,
        )
        start_response(f"{status.value} {status.phrase}", list(headers))
        return (b"",) if method == "HEAD" else (body,)
