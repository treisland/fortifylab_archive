"""Minimal read-only WSGI API for manager component inventory."""

from __future__ import annotations

import json
from http import HTTPStatus
from typing import Callable, Iterable

from manager.component_inventory import ClusterObserver, ComponentInventory
from manager.component_registry import ComponentRegistry, RegistryError
from manager.health import HealthEngine, HealthProbe


COMPONENTS_PATH = "/api/v1alpha1/components"
HEALTH_PATH = "/api/v1alpha1/health"


class ManagerAPI:
    """Serve the stable component inventory contract without mutation routes."""

    def __init__(
        self,
        registry_loader: Callable[[], ComponentRegistry] = ComponentRegistry.load,
        observer: ClusterObserver | None = None,
        health_probe: HealthProbe | None = None,
    ) -> None:
        self._registry_loader = registry_loader
        self._observer = observer
        self._health_probe = health_probe

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        if path not in {COMPONENTS_PATH, HEALTH_PATH}:
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
            registry = self._registry_loader()
            document = (
                HealthEngine(registry, self._health_probe).document()
                if path == HEALTH_PATH
                else ComponentInventory(registry, self._observer).document()
            )
        except RegistryError:
            return self._response(
                start_response,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "code": "REGISTRY_UNAVAILABLE",
                    "message": (
                        "health read model is unavailable"
                        if path == HEALTH_PATH
                        else "component inventory is unavailable"
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
