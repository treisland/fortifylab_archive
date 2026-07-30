"""Versioned read-only WSGI API for manager dashboard read models."""

from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any, Callable, Iterable, Protocol

from manager.component_inventory import ClusterObserver, ComponentInventory
from manager.component_registry import ComponentRegistry, RegistryError
from manager.health import HealthEngine, HealthProbe
from manager.preflight import PreflightEngine, PreflightProbe


COMPONENTS_PATH = "/api/v1alpha1/components"
HEALTH_PATH = "/api/v1alpha1/health"
PREFLIGHT_PATH = "/api/v1alpha1/preflight"
HISTORY_PATH = "/api/v1alpha1/history"


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
        history_reader: HistoryReader | None = None,
    ) -> None:
        self._registry_loader = registry_loader
        self._observer = observer
        self._health_probe = health_probe
        self._preflight_probe = preflight_probe
        self._history_reader = history_reader or EmptyHistoryReader()

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        if path not in {COMPONENTS_PATH, HEALTH_PATH, PREFLIGHT_PATH, HISTORY_PATH}:
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
            else:
                registry = self._registry_loader()
            if path == HEALTH_PATH:
                document = HealthEngine(registry, self._health_probe).document()
            elif path == PREFLIGHT_PATH:
                document = PreflightEngine(registry, self._preflight_probe).document()
            elif path == COMPONENTS_PATH:
                document = ComponentInventory(registry, self._observer).document()
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
                        else "health read model is unavailable"
                        if path == HEALTH_PATH
                        else (
                            "preflight read model is unavailable"
                            if path == PREFLIGHT_PATH
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
