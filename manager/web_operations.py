"""Authenticated HTTP transport for shared typed lifecycle services."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Any, Callable, Iterable

from manager.authorization import (
    APPROVAL_REQUIRED,
    HIGH_RISK_CONFIRMATION,
    ActorIdentity,
    AuthorizationError,
    AuthorizationService,
    OperationPlan,
)
from manager.dashboard import WebIdentity
from manager.operation_engine import (
    TERMINAL_STATES,
    OperationEngine,
    OperationError,
    OperationNotFound,
    OperationStore,
)


MAX_BODY = 16_384
COLLECTION = "/api/v1alpha1/operations"
PLANS = COLLECTION + "/plans"
APPROVALS = "/api/v1alpha1/approvals"


class WebOperationAPI:
    """Map same-origin identities to bounded engine and approval methods."""

    def __init__(
        self,
        engine: OperationEngine,
        store: OperationStore,
        authorization: AuthorizationService,
        state_provider: Callable[[tuple[str, ...]], dict[str, str]],
    ) -> None:
        self._engine = engine
        self._store = store
        self._authorization = authorization
        self._state_provider = state_provider

    def __call__(
        self, environ: dict, start_response: Callable, web: WebIdentity
    ) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        identity = ActorIdentity(
            actor=f"web:{web.username}",
            source="web",
            session_id=web.session_id,
            authenticated_at=datetime.fromtimestamp(
                web.authenticated_at, tz=timezone.utc
            ),
        )
        try:
            if path == PLANS and method == "POST":
                request = self._body(environ)
                return self._json(start_response, HTTPStatus.OK, self._plan(request))
            if path == APPROVALS and method == "POST":
                request = self._body(environ)
                plan = self._operation_plan(request)
                approval = self._authorization.request(plan, identity)
                return self._json(start_response, HTTPStatus.CREATED, approval)
            if path.startswith(APPROVALS + "/") and path.endswith("/approve") and method == "POST":
                approval_id = path[len(APPROVALS) + 1 : -len("/approve")]
                request = self._body(environ)
                approval = self._authorization.approve(
                    approval_id, identity, confirmation=request.get("confirmation")
                )
                return self._json(start_response, HTTPStatus.OK, approval)
            if path == COLLECTION and method == "POST":
                request = self._body(environ)
                document = self._engine.submit_async(
                    request.get("operation"),
                    request.get("components"),
                    actor=identity.actor,
                    identity=identity,
                    approval_id=request.get("approvalId"),
                )
                return self._json(start_response, HTTPStatus.ACCEPTED, self._detail(document))
            if path.startswith(COLLECTION + "/"):
                return self._member(path, method, environ, start_response, identity)
        except (OperationError, AuthorizationError, ValueError, TypeError, json.JSONDecodeError) as error:
            status = HTTPStatus.NOT_FOUND if isinstance(error, OperationNotFound) else (
                HTTPStatus.CONFLICT if isinstance(error, AuthorizationError) else
                HTTPStatus.BAD_REQUEST
            )
            return self._json(
                start_response,
                status,
                {"code": getattr(error, "code", "INVALID_REQUEST"), "message": str(error)},
            )
        return self._json(
            start_response,
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"code": "METHOD_NOT_ALLOWED", "message": "method not allowed"},
            (("Allow", "GET, POST"),),
        )

    def _member(self, path, method, environ, start_response, identity):
        suffix = path[len(COLLECTION) + 1 :]
        operation_id, _, action = suffix.partition("/")
        if not operation_id:
            raise OperationNotFound("operation was not found")
        if method == "GET" and not action:
            return self._json(start_response, HTTPStatus.OK, self._detail(self._store.get(operation_id)))
        if method == "POST" and action == "cancel":
            document = self._engine.cancel(
                operation_id, actor=identity.actor, identity=identity
            )
            return self._json(start_response, HTTPStatus.ACCEPTED, self._detail(document))
        if method == "POST" and action == "retry":
            request = self._body(environ)
            document = self._engine.retry_async(
                operation_id,
                actor=identity.actor,
                identity=identity,
                approval_id=request.get("approvalId"),
            )
            return self._json(start_response, HTTPStatus.ACCEPTED, self._detail(document))
        raise ValueError("unsupported operation action")

    def _plan(self, request: dict[str, Any]) -> dict[str, Any]:
        plan = self._engine.plan(request.get("operation"), request.get("components"))
        current = self._state_provider(tuple(plan["components"]))
        authorization_plan = OperationPlan(
            plan["operation"], tuple(plan["components"]), current
        )
        requested = set(plan["requestedTargets"])
        dependencies = [item for item in plan["components"] if item not in requested]
        return {
            "apiVersion": "fortifylab.io/v1alpha1",
            "kind": "LifecyclePlan",
            **plan,
            "risk": authorization_plan.risk,
            "approvalRequired": authorization_plan.risk in APPROVAL_REQUIRED,
            "dependencyImpact": dependencies,
            "destructive": plan["operation"] in {"uninstall", "delete-data"},
            "deletesData": plan["operation"] == "delete-data",
        }

    def _operation_plan(self, request: dict[str, Any]) -> OperationPlan:
        plan = self._plan(request)
        if not plan["approvalRequired"]:
            raise AuthorizationError("operation does not require approval")
        targets = tuple(plan["components"])
        return OperationPlan(
            plan["operation"], targets, self._state_provider(targets)
        )

    def _detail(self, document: dict[str, Any]) -> dict[str, Any]:
        result = dict(document)
        result["events"] = self._store.events(document["id"])
        result["terminal"] = document["state"] in TERMINAL_STATES
        result["completionHealth"] = (
            "verified" if document["state"] == "succeeded" else "not-verified"
        )
        return result

    @staticmethod
    def _body(environ: dict) -> dict[str, Any]:
        try:
            length = int(environ.get("CONTENT_LENGTH", "0"))
        except ValueError as error:
            raise ValueError("request body is invalid") from error
        if length < 2 or length > MAX_BODY:
            raise ValueError("request body is invalid")
        document = json.loads(environ["wsgi.input"].read(length))
        if not isinstance(document, dict):
            raise ValueError("request body must be an object")
        forbidden = {"command", "path", "environment", "secret", "value"}
        if forbidden.intersection(document):
            raise ValueError("request contains unsupported fields")
        return document

    @staticmethod
    def _json(start_response, status, document, extra=()):
        body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
        headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            *extra,
        ]
        start_response(f"{status.value} {status.phrase}", headers)
        return (body,)
