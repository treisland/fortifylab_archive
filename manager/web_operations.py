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
from manager.backup_restore import RecoveryError, RecoveryService
from manager.profile_upgrade import ProfileUpgradeService, UpgradeError


MAX_BODY = 16_384
COLLECTION = "/api/v1alpha1/operations"
PLANS = COLLECTION + "/plans"
APPROVALS = "/api/v1alpha1/approvals"
CLEAN_INSTALL = "/api/v1alpha1/clean-install"
RECOVERY = "/api/v1alpha1/recovery"
PROFILE_UPGRADES = "/api/v1alpha1/profile-upgrades"


class WebOperationAPI:
    """Map same-origin identities to bounded engine and approval methods."""

    def __init__(
        self,
        engine: OperationEngine,
        store: OperationStore,
        authorization: AuthorizationService,
        state_provider: Callable[[tuple[str, ...]], dict[str, str]],
        recovery: RecoveryService | None = None,
        profile_upgrades: ProfileUpgradeService | None = None,
    ) -> None:
        self._engine = engine
        self._store = store
        self._authorization = authorization
        self._state_provider = state_provider
        self._recovery = recovery
        self._profile_upgrades = profile_upgrades

    def __call__(
        self, environ: dict, start_response: Callable, web: WebIdentity
    ) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "")
        identity = ActorIdentity(
            actor=f"{web.source}:{web.username}",
            source=web.source,
            session_id=web.session_id,
            authenticated_at=datetime.fromtimestamp(
                web.authenticated_at, tz=timezone.utc
            ),
        )
        try:
            if path.startswith(PROFILE_UPGRADES):
                return self._profile_upgrade_request(
                    path, method, environ, start_response, identity
                )
            if path.startswith(RECOVERY):
                return self._recovery_request(
                    path, method, environ, start_response, identity
                )
            if path == CLEAN_INSTALL + "/plan" and method == "POST":
                self._body(environ)
                plan = self._engine.clean_install_plan()
                plan["workflow"] = "clean-install"
                return self._json(start_response, HTTPStatus.OK, plan)
            if path == CLEAN_INSTALL and method == "POST":
                self._body(environ)
                document = self._engine.submit_clean_install_async(
                    actor=identity.actor, identity=identity
                )
                return self._json(
                    start_response, HTTPStatus.ACCEPTED, self._detail(document)
                )
            if path == PLANS and method == "POST":
                request = self._body(environ)
                return self._json(start_response, HTTPStatus.OK, self._plan(request))
            if path == APPROVALS and method == "POST":
                request = self._body(environ)
                plan = self._operation_plan(request)
                approval = self._authorization.request(plan, identity)
                return self._json(
                    start_response, HTTPStatus.CREATED, self._approval(approval)
                )
            if path.startswith(APPROVALS + "/") and path.endswith("/approve") and method == "POST":
                approval_id = path[len(APPROVALS) + 1 : -len("/approve")]
                request = self._body(environ)
                approval = self._authorization.approve(
                    approval_id, identity, confirmation=request.get("confirmation")
                )
                return self._json(
                    start_response, HTTPStatus.OK, self._approval(approval)
                )
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
        except (OperationError, RecoveryError, UpgradeError, AuthorizationError, ValueError, TypeError, json.JSONDecodeError) as error:
            status = HTTPStatus.NOT_FOUND if isinstance(error, OperationNotFound) else (
                HTTPStatus.CONFLICT if isinstance(error, AuthorizationError) else
                HTTPStatus.BAD_REQUEST
            )
            return self._json(
                start_response,
                status,
                self._error(
                    getattr(error, "code", "INVALID_REQUEST"), str(error)
                ),
            )
        return self._json(
            start_response,
            HTTPStatus.METHOD_NOT_ALLOWED,
            self._error("METHOD_NOT_ALLOWED", "method not allowed"),
            (("Allow", "GET, POST"),),
        )

    def _profile_upgrade_request(
        self, path, method, environ, start_response, identity
    ):
        if self._profile_upgrades is None:
            raise UpgradeError("profile upgrades are not configured")
        if path == PROFILE_UPGRADES + "/plans" and method == "POST":
            request = self._body(environ)
            if set(request) != {"targetProfileId"}:
                raise ValueError("profile upgrade plan request is invalid")
            return self._json(
                start_response, HTTPStatus.OK,
                self._profile_upgrades.plan(request["targetProfileId"]),
            )
        if path == PROFILE_UPGRADES and method == "POST":
            request = self._body(environ)
            if set(request) != {"planId", "confirmation"}:
                raise ValueError("profile upgrade request is invalid")
            operation = self._profile_upgrades.submit(
                request["planId"], identity=identity,
                confirmation=request["confirmation"],
            )
            return self._json(start_response, HTTPStatus.ACCEPTED, operation)
        prefix = PROFILE_UPGRADES + "/"
        if path.startswith(prefix):
            suffix = path[len(prefix):]
            operation_id, _, action = suffix.partition("/")
            if method == "GET" and not action:
                return self._json(
                    start_response, HTTPStatus.OK,
                    self._profile_upgrades.get(operation_id),
                )
            if method == "POST" and action == "cancel":
                self._body(environ)
                return self._json(
                    start_response, HTTPStatus.ACCEPTED,
                    self._profile_upgrades.cancel(operation_id),
                )
        raise ValueError("unsupported profile upgrade action")

    def _recovery_request(self, path, method, environ, start_response, identity):
        if self._recovery is None:
            raise RecoveryError("backup and restore are not configured")
        if path == RECOVERY + "/backup/plan" and method == "POST":
            self._body(environ)
            return self._json(start_response, HTTPStatus.OK, self._recovery.backup_plan())
        if path == RECOVERY + "/backups" and method == "POST":
            self._body(environ)
            document = self._recovery.submit_backup(actor=identity.actor)
            return self._json(start_response, HTTPStatus.ACCEPTED, document)
        if path == RECOVERY + "/restore/plan" and method == "POST":
            request = self._body(environ)
            return self._json(
                start_response, HTTPStatus.OK,
                self._recovery.restore_plan(request.get("backupId")),
            )
        if path == RECOVERY + "/restores" and method == "POST":
            request = self._body(environ)
            document = self._recovery.submit_restore(
                request.get("backupId"),
                actor=identity.actor,
                confirmation=request.get("confirmation"),
            )
            return self._json(start_response, HTTPStatus.ACCEPTED, document)
        prefix = RECOVERY + "/operations/"
        if path.startswith(prefix):
            suffix = path[len(prefix):]
            operation_id, _, action = suffix.partition("/")
            if method == "GET" and not action:
                return self._json(
                    start_response, HTTPStatus.OK,
                    self._recovery.store.operation(operation_id),
                )
            if method == "POST" and action == "cancel":
                self._body(environ)
                return self._json(
                    start_response, HTTPStatus.ACCEPTED,
                    self._recovery.cancel(operation_id),
                )
        raise ValueError("unsupported recovery action")

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
            "recoveryBoundary": max(
                (step["recoveryClass"] for step in plan["steps"]),
                key={
                    "reversible": 0,
                    "compensating-action": 1,
                    "restore-required": 2,
                    "irreversible": 3,
                }.__getitem__,
            ),
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
    def _approval(document: dict[str, Any]) -> dict[str, Any]:
        return {
            "apiVersion": "fortifylab.io/v1alpha1",
            "kind": "LifecycleApproval",
            **document,
        }

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

    @staticmethod
    def _error(code: str, message: str) -> dict[str, str]:
        return {
            "apiVersion": "fortifylab.io/v1alpha1",
            "kind": "Error",
            "code": code,
            "message": message,
        }
