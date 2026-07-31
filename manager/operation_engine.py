"""Typed, dependency-aware lifecycle execution for registry components."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from manager.authorization import ActorIdentity, AuthorizationService, OperationPlan
from manager.component_registry import ComponentRegistry, RegistryError
from manager.record_store import sanitize_record


START_OPERATIONS = frozenset({"install", "configure", "start", "upgrade"})
STOP_OPERATIONS = frozenset({"stop", "uninstall", "delete-data"})
REQUEST_OPERATIONS = START_OPERATIONS | STOP_OPERATIONS | {"restart"}
TERMINAL_STATES = frozenset(
    {"succeeded", "failed", "timed-out", "cancelled", "interrupted"}
)
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
RECOVERY_CLASS_BY_OPERATION = {
    "install": "compensating-action",
    "configure": "reversible",
    "start": "reversible",
    "stop": "reversible",
    "restart": "reversible",
    "upgrade": "restore-required",
    "uninstall": "compensating-action",
    "delete-data": "irreversible",
}


class OperationError(RuntimeError):
    """A sanitized lifecycle request or execution failure."""

    code = "OPERATION_FAILED"


class InvalidOperation(OperationError):
    code = "INVALID_OPERATION"


class DependencyBlocked(OperationError):
    code = "DEPENDENCY_BLOCKED"


class OperationConflict(OperationError):
    code = "OPERATION_CONFLICT"


class OperationNotFound(OperationError):
    code = "OPERATION_NOT_FOUND"


class PreflightBlocked(OperationError):
    code = "PREFLIGHT_BLOCKED"


class ExistingInstallation(OperationError):
    code = "EXISTING_INSTALLATION"


class StepTimedOut(OperationError):
    code = "OPERATION_TIMEOUT"


class StepCancelled(OperationError):
    code = "OPERATION_CANCELLED"


@dataclass(frozen=True)
class Step:
    component_id: str
    operation: str
    adapter: str
    timeout_seconds: float
    verify: tuple[str, ...]
    max_attempts: int
    recovery_class: str = "reversible"


class OperationAdapter(Protocol):
    def execute(
        self, step: Step, *, deadline: float, cancelled: Callable[[], bool]
    ) -> None:
        """Execute one registry-resolved step without accepting request arguments."""


class HealthVerifier(Protocol):
    def verify(
        self,
        component_id: str,
        check_id: str,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> bool:
        """Return whether one registry allow-listed postcondition is satisfied."""


class OperationStore:
    """Durable current state and sanitized events for lifecycle operations."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.connection = sqlite3.connect(
            self.path, timeout=30, isolation_level=None, check_same_thread=False
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS lifecycle_operations ("
            "id TEXT PRIMARY KEY, state TEXT NOT NULL, payload TEXT NOT NULL)"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS lifecycle_events ("
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL,"
            "payload TEXT NOT NULL)"
        )
        self.connection.execute(
            "UPDATE lifecycle_operations SET state = 'interrupted', "
            "payload = json_set(payload, '$.state', 'interrupted', "
            "'$.error', 'Manager restarted before the operation completed', "
            "'$.updatedAt', ?) WHERE state IN ('queued','running','cancelling')",
            (_timestamp(),),
        )
        for row in self.connection.execute(
            "SELECT id, payload FROM lifecycle_operations WHERE state='interrupted'"
        ):
            document = json.loads(row["payload"])
            if not document.get("recovery", {}).get("required"):
                self._set_interrupted_recovery(document)
                self.connection.execute(
                    "UPDATE lifecycle_operations SET payload=? WHERE id=?",
                    (_payload(document), row["id"]),
                )
                self.event(row["id"], {
                    "type": "manager-restarted",
                    "at": document["updatedAt"],
                })

    def close(self) -> None:
        self.connection.close()

    def create(self, document: dict[str, Any]) -> None:
        payload = _payload(document)
        self.connection.execute(
            "INSERT INTO lifecycle_operations VALUES (?, ?, ?)",
            (document["id"], document["state"], payload),
        )

    def update(self, document: dict[str, Any]) -> None:
        self.connection.execute(
            "UPDATE lifecycle_operations SET state = ?, payload = ? WHERE id = ?",
            (document["state"], _payload(document), document["id"]),
        )

    def get(self, operation_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT payload FROM lifecycle_operations WHERE id = ?", (operation_id,)
        ).fetchone()
        if row is None:
            raise OperationNotFound("operation was not found")
        return json.loads(row["payload"])

    def events(self, operation_id: str) -> list[dict[str, Any]]:
        return [
            json.loads(row["payload"])
            for row in self.connection.execute(
                "SELECT payload FROM lifecycle_events WHERE operation_id = ? "
                "ORDER BY sequence",
                (operation_id,),
            )
        ]

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT payload FROM lifecycle_operations ORDER BY "
            "json_extract(payload, '$.updatedAt') DESC LIMIT ?",
            (max(0, min(limit, 100)),),
        )
        return [json.loads(row["payload"]) for row in rows]

    def event(self, operation_id: str, event: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO lifecycle_events(operation_id, payload) VALUES (?, ?)",
            (operation_id, _payload(event)),
        )

    def active_components(self) -> set[str]:
        active: set[str] = set()
        for row in self.connection.execute(
            "SELECT payload FROM lifecycle_operations "
            "WHERE state IN ('queued','running','cancelling')"
        ):
            active.update(json.loads(row["payload"])["components"])
        return active

    @staticmethod
    def _set_interrupted_recovery(document: dict[str, Any]) -> None:
        operation = (document.get("currentStep") or {}).get(
            "operation", document.get("operation")
        )
        boundary = RECOVERY_CLASS_BY_OPERATION.get(operation, "irreversible")
        document["recovery"] = {
            "required": True,
            "boundary": boundary,
            "nextAction": (
                "Review retained evidence and authoritative health before retrying; "
                "a Manager restart does not prove rollback."
            ),
        }


class OperationEngine:
    """Build and execute bounded lifecycle plans from the component registry."""

    def __init__(
        self,
        registry: ComponentRegistry,
        store: OperationStore,
        adapter: OperationAdapter,
        verifier: HealthVerifier,
        *,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        max_attempts: int = 2,
        max_step_timeout: float = 3600,
        authorization: AuthorizationService | None = None,
        state_provider: Callable[[tuple[str, ...]], dict[str, str]] | None = None,
        preflight_provider: Callable[[], dict[str, Any]] | None = None,
        footprint_provider: Callable[[tuple[str, ...]], dict[str, str]] | None = None,
    ) -> None:
        if max_attempts < 1 or max_step_timeout <= 0:
            raise ValueError("operation bounds must be positive")
        self._registry = registry
        self._store = store
        self._adapter = adapter
        self._verifier = verifier
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic
        self._max_attempts = max_attempts
        self._max_step_timeout = max_step_timeout
        self._authorization = authorization
        self._state_provider = state_provider
        self._preflight_provider = preflight_provider
        self._footprint_provider = footprint_provider
        self._cancelled: set[str] = set()
        self._lock = threading.RLock()

    def submit(
        self,
        operation: str,
        component_ids: list[str] | tuple[str, ...],
        *,
        actor: str,
        retry_of: str | None = None,
        identity: ActorIdentity | None = None,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        document, steps = self._prepare(
            operation, component_ids, actor=actor, retry_of=retry_of,
            identity=identity, approval_id=approval_id,
        )
        self._run(document, steps)
        return self._store.get(document["id"])

    def submit_async(
        self,
        operation: str,
        component_ids: list[str] | tuple[str, ...],
        *,
        actor: str,
        retry_of: str | None = None,
        identity: ActorIdentity | None = None,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Durably queue an exact operation before background execution."""
        document, steps = self._prepare(
            operation, component_ids, actor=actor, retry_of=retry_of,
            identity=identity, approval_id=approval_id,
        )
        threading.Thread(target=self._run, args=(document, steps), daemon=True).start()
        return self._store.get(document["id"])

    def clean_install_plan(self) -> dict[str, Any]:
        """Return fresh, read-only evidence for the full verified-profile install."""
        if self._preflight_provider is None or self._footprint_provider is None:
            raise PreflightBlocked("clean-install observation is unavailable")
        components = self._registry.dependency_order()
        try:
            preflight = self._preflight_provider()
            footprint = self._footprint_provider(components)
        except Exception as error:
            raise PreflightBlocked("clean-install evidence is unavailable") from error
        if set(footprint) != set(components):
            raise PreflightBlocked("clean-install footprint evidence is incomplete")
        existing = sorted(
            component for component, state in footprint.items() if state != "absent"
        )
        plan = self.plan("install", components)
        return {
            "apiVersion": "fortifylab.io/v1alpha1",
            "kind": "CleanInstallPlan",
            "profile": {
                "id": self._registry.profile.id,
                "maturity": self._registry.profile.maturity,
            },
            "ready": bool(preflight.get("ready")) and not existing,
            "preflight": preflight,
            "existingComponents": existing,
            **plan,
        }

    def submit_clean_install_async(
        self, *, actor: str, identity: ActorIdentity | None = None
    ) -> dict[str, Any]:
        plan = self.clean_install_plan()
        if not plan["preflight"].get("ready"):
            raise PreflightBlocked("deployment preflight has blocking checks")
        if plan["existingComponents"]:
            raise ExistingInstallation(
                "existing installation or retained data requires operator review"
            )
        document, steps = self._prepare(
            "install", tuple(plan["requestedTargets"]), actor=actor, retry_of=None,
            identity=identity, approval_id=None, workflow="clean-install",
        )
        threading.Thread(target=self._run, args=(document, steps), daemon=True).start()
        return self._store.get(document["id"])

    def _prepare(
        self,
        operation: str,
        component_ids: list[str] | tuple[str, ...],
        *,
        actor: str,
        retry_of: str | None,
        identity: ActorIdentity | None,
        approval_id: str | None,
        workflow: str | None = None,
    ) -> tuple[dict[str, Any], tuple[Step, ...]]:
        if operation not in REQUEST_OPERATIONS:
            raise InvalidOperation("operation is not an allowed lifecycle action")
        components = tuple(dict.fromkeys(component_ids))
        if (
            not components
            or any(not isinstance(item, str) or not IDENTIFIER.fullmatch(item) for item in components)
            or not actor
            or len(actor) > 128
        ):
            raise InvalidOperation("components and actor are required")
        steps = self._plan(operation, components)
        affected = tuple(dict.fromkeys(step.component_id for step in steps))
        with self._lock:
            conflict = self._store.active_components().intersection(affected)
            if conflict:
                raise OperationConflict(
                    "another operation is active for an affected component"
                )
            if self._authorization is not None:
                if identity is None or identity.actor != actor or self._state_provider is None:
                    raise InvalidOperation(
                        "authenticated identity and current-state provider are required"
                    )
                try:
                    current_state = self._state_provider(affected)
                except Exception as error:
                    raise OperationError("current target state is unavailable") from error
                plan = OperationPlan(operation, affected, current_state)
                self._authorization.authorize(
                    plan,
                    identity,
                    approval_id=approval_id,
                    state_provider=lambda: self._state_provider(affected),
                )
            now = _timestamp(self._clock())
            document: dict[str, Any] = {
                "apiVersion": "fortifylab.io/v1alpha1",
                "kind": "LifecycleOperation",
                "id": str(uuid.uuid4()),
                "operation": operation,
                "components": list(affected),
                "requestedTargets": list(components),
                "actor": actor,
                "state": "queued",
                "createdAt": now,
                "updatedAt": now,
                "currentStep": None,
                "completedSteps": 0,
                "totalSteps": len(steps),
                "retryOf": retry_of,
                "error": None,
                "recovery": {
                    "required": False,
                    "boundary": _plan_recovery_boundary(steps),
                    "nextAction": None,
                },
            }
            if workflow is not None:
                document["workflow"] = workflow
                document["profileId"] = self._registry.profile.id
            self._store.create(document)
        return document, steps

    def plan(
        self,
        operation: str,
        component_ids: list[str] | tuple[str, ...],
    ) -> dict[str, Any]:
        """Return the same registry-resolved plan used by execution."""
        if operation not in REQUEST_OPERATIONS:
            raise InvalidOperation("operation is not an allowed lifecycle action")
        components = tuple(dict.fromkeys(component_ids))
        if not components or any(
            not isinstance(item, str) or not IDENTIFIER.fullmatch(item)
            for item in components
        ):
            raise InvalidOperation("components are required")
        steps = self._plan(operation, components)
        affected = tuple(dict.fromkeys(step.component_id for step in steps))
        return {
            "operation": operation,
            "requestedTargets": list(components),
            "components": list(affected),
            "steps": [
                {
                    "number": number,
                    "component": step.component_id,
                    "operation": step.operation,
                    "timeoutSeconds": step.timeout_seconds,
                    "maxAttempts": step.max_attempts,
                    "verificationChecks": list(step.verify),
                    "recoveryClass": step.recovery_class,
                }
                for number, step in enumerate(steps, 1)
            ],
        }

    def retry(
        self,
        operation_id: str,
        *,
        actor: str,
        identity: ActorIdentity | None = None,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        previous = self._store.get(operation_id)
        if previous["state"] not in TERMINAL_STATES - {"succeeded", "cancelled"}:
            raise InvalidOperation("only a failed, timed-out, or interrupted operation can retry")
        return self.submit(
            previous["operation"],
            previous["requestedTargets"],
            actor=actor,
            retry_of=operation_id,
            identity=identity,
            approval_id=approval_id,
        )

    def retry_async(
        self,
        operation_id: str,
        *,
        actor: str,
        identity: ActorIdentity | None = None,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        previous = self._store.get(operation_id)
        if previous["state"] not in TERMINAL_STATES - {"succeeded", "cancelled"}:
            raise InvalidOperation("only a failed, timed-out, or interrupted operation can retry")
        if previous.get("workflow") == "clean-install":
            if self._preflight_provider is None:
                raise PreflightBlocked("clean-install preflight is unavailable")
            try:
                preflight = self._preflight_provider()
            except Exception as error:
                raise PreflightBlocked("clean-install preflight is unavailable") from error
            if not preflight.get("ready"):
                raise PreflightBlocked("deployment preflight has blocking checks")
            completed = {
                (event.get("component"), event.get("operation"))
                for event in self._store.events(operation_id)
                if event.get("type") in {"step-succeeded", "step-resumed"}
            }
            document, steps = self._prepare(
                previous["operation"], previous["requestedTargets"], actor=actor,
                retry_of=operation_id, identity=identity, approval_id=approval_id,
                workflow="clean-install",
            )
            remaining = tuple(
                step for step in steps
                if (step.component_id, step.operation) not in completed
            )
            document["completedSteps"] = len(steps) - len(remaining)
            self._store.update(document)
            for step in steps:
                if (step.component_id, step.operation) in completed:
                    self._store.event(
                        document["id"],
                        {
                            "type": "step-resumed",
                            "component": step.component_id,
                            "operation": step.operation,
                            "at": _timestamp(self._clock()),
                        },
                    )
            threading.Thread(
                target=self._run, args=(document, remaining), daemon=True
            ).start()
            return self._store.get(document["id"])
        return self.submit_async(
            previous["operation"], previous["requestedTargets"], actor=actor,
            retry_of=operation_id, identity=identity, approval_id=approval_id,
        )

    def cancel(
        self,
        operation_id: str,
        *,
        actor: str,
        identity: ActorIdentity | None = None,
    ) -> dict[str, Any]:
        if not actor:
            raise InvalidOperation("actor is required")
        if self._authorization is not None and (
            identity is None or identity.actor != actor
        ):
            raise InvalidOperation("authenticated identity is required")
        with self._lock:
            document = self._store.get(operation_id)
            if document["state"] in TERMINAL_STATES:
                return document
            self._cancelled.add(operation_id)
            document["state"] = "cancelling"
            document["updatedAt"] = _timestamp(self._clock())
            self._store.update(document)
            self._store.event(
                operation_id,
                {"type": "cancellation-requested", "actor": actor, "at": document["updatedAt"]},
            )
            return document

    def _plan(self, operation: str, requested: tuple[str, ...]) -> tuple[Step, ...]:
        for component_id in requested:
            self._registry.component(component_id)
        if operation == "restart":
            stop = self._ordered_steps("stop", requested, include_dependencies=False)
            start = self._ordered_steps("start", requested, include_dependencies=True)
            return stop + start
        return self._ordered_steps(
            operation, requested, include_dependencies=operation in START_OPERATIONS
        )

    def _ordered_steps(
        self, operation: str, requested: tuple[str, ...], *, include_dependencies: bool
    ) -> tuple[Step, ...]:
        if include_dependencies:
            ordered = list(self._registry.dependency_order(requested))
        else:
            selected = set(requested)
            missing_consumers = [
                component_id
                for component_id in self._registry.component_ids
                if component_id not in selected
                and selected.intersection(
                    self._transitive_dependencies(component_id)
                )
            ]
            if missing_consumers:
                raise DependencyBlocked(
                    "dependent components must be included before this operation"
                )
            ordered = [
                item
                for item in reversed(self._registry.dependency_order(requested))
                if item in selected
            ]
        return tuple(self._step(component_id, operation) for component_id in ordered)

    def _transitive_dependencies(self, component_id: str) -> set[str]:
        return set(self._registry.dependency_order([component_id])) - {component_id}

    def _step(self, component_id: str, operation: str) -> Step:
        capabilities = {
            item["id"]: item
            for item in self._registry.lifecycle_operations(component_id)
        }
        capability = capabilities.get(operation)
        if capability is None:
            raise InvalidOperation(
                f"{component_id} does not declare the requested operation"
            )
        timeout = min(float(capability["timeoutSeconds"]), self._max_step_timeout)
        if timeout <= 0:
            raise RegistryError("operation timeout is not bounded")
        return Step(
            component_id=component_id,
            operation=operation,
            adapter=capability["adapter"],
            timeout_seconds=timeout,
            verify=tuple(capability["verify"]),
            max_attempts=self._max_attempts if capability["idempotent"] else 1,
            recovery_class=RECOVERY_CLASS_BY_OPERATION[operation],
        )

    def _run(self, document: dict[str, Any], steps: tuple[Step, ...]) -> None:
        operation_id = document["id"]
        document["state"] = "running"
        self._save(document)
        try:
            first = document["completedSteps"] + 1
            for index, step in enumerate(steps, first):
                document["currentStep"] = {
                    "number": index,
                    "component": step.component_id,
                    "operation": step.operation,
                    "attempt": 0,
                }
                self._save(document)
                self._execute_step(operation_id, document, step)
                document["completedSteps"] = index
                self._save(document)
            document["state"] = "succeeded"
            document["currentStep"] = None
            document["error"] = None
        except StepCancelled:
            document["state"] = "cancelled"
            document["error"] = "Operation was cancelled"
            self._set_recovery(document)
        except StepTimedOut:
            document["state"] = "timed-out"
            document["error"] = "A step exceeded its bounded deadline"
            self._set_recovery(document)
        except Exception:
            document["state"] = "failed"
            document["error"] = "A lifecycle step failed; inspect sanitized events"
            self._set_recovery(document)
        finally:
            self._cancelled.discard(operation_id)
            self._save(document)

    def _execute_step(
        self, operation_id: str, document: dict[str, Any], step: Step
    ) -> None:
        for attempt in range(1, step.max_attempts + 1):
            document["currentStep"]["attempt"] = attempt
            self._save(document)
            deadline = self._monotonic() + step.timeout_seconds
            cancelled = lambda: operation_id in self._cancelled
            try:
                self._check_boundary(deadline, cancelled)
                self._adapter.execute(step, deadline=deadline, cancelled=cancelled)
                for check_id in step.verify:
                    self._check_boundary(deadline, cancelled)
                    if not self._verifier.verify(
                        step.component_id,
                        check_id,
                        deadline=deadline,
                        cancelled=cancelled,
                    ):
                        raise OperationError("post-operation health verification failed")
                self._store.event(
                    operation_id,
                    {
                        "type": "step-succeeded",
                        "component": step.component_id,
                        "operation": step.operation,
                        "attempt": attempt,
                        "at": _timestamp(self._clock()),
                    },
                )
                return
            except (StepCancelled, StepTimedOut):
                raise
            except Exception:
                self._store.event(
                    operation_id,
                    {
                        "type": "attempt-failed",
                        "component": step.component_id,
                        "operation": step.operation,
                        "attempt": attempt,
                        "retrying": attempt < step.max_attempts,
                        "at": _timestamp(self._clock()),
                    },
                )
                if attempt == step.max_attempts:
                    raise

    def _check_boundary(
        self, deadline: float, cancelled: Callable[[], bool]
    ) -> None:
        if cancelled():
            raise StepCancelled()
        if self._monotonic() >= deadline:
            raise StepTimedOut()

    def _save(self, document: dict[str, Any]) -> None:
        document["updatedAt"] = _timestamp(self._clock())
        self._store.update(document)

    @staticmethod
    def _set_recovery(document: dict[str, Any]) -> None:
        current = document.get("currentStep") or {}
        recovery_class = RECOVERY_CLASS_BY_OPERATION.get(
            current.get("operation", document["operation"]), "irreversible"
        )
        document["recovery"] = {
            "required": True,
            "boundary": recovery_class,
            "nextAction": {
                "reversible": "Review evidence and retry the idempotent action or apply its declared inverse.",
                "compensating-action": "Review completed steps and run the documented compensating action.",
                "restore-required": "Do not claim Helm rollback; restore and verify the bound backup before retrying.",
                "irreversible": "Stop automation and follow the documented manual recovery procedure.",
            }[recovery_class],
        }


def _timestamp(value: datetime | None = None) -> str:
    return (value or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")


def _payload(document: dict[str, Any]) -> str:
    return json.dumps(
        sanitize_record(document), sort_keys=True, separators=(",", ":")
    )


def _plan_recovery_boundary(steps: tuple[Step, ...]) -> str:
    precedence = {
        "reversible": 0,
        "compensating-action": 1,
        "restore-required": 2,
        "irreversible": 3,
    }
    return max(
        (step.recovery_class for step in steps),
        key=precedence.__getitem__,
    )
