"""Authorized, write-only secret replacement orchestration.

The service deliberately has no Kubernetes implementation.  Runtime composition
must provide a protected-store adapter that consumes secret material without
returning it.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from manager.authorization import ActorIdentity, AuthorizationService, OperationPlan
from manager.component_registry import ComponentRegistry
from manager.record_store import sanitize_record


SOURCE_TYPES = frozenset({"external-path", "upload", "kubernetes-secret", "generated"})
NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
CONFIRM_SSC_KEY = "REPLACE SSC SECRET.KEY AFTER VERIFIED BACKUP"


class SecretWorkflowError(RuntimeError):
    """A sanitized secret workflow failure."""

    code = "SECRET_UPDATE_FAILED"


class InvalidSecretRequest(SecretWorkflowError):
    code = "INVALID_SECRET_REQUEST"


class SecretUpdateConflict(SecretWorkflowError):
    code = "SECRET_UPDATE_CONFLICT"


class SecretUpdateNotFound(SecretWorkflowError):
    code = "SECRET_UPDATE_NOT_FOUND"


@dataclass(frozen=True)
class SecretSource:
    """Ephemeral input accepted at the write-only boundary."""

    source_type: str
    value: bytes | str | None = None
    key: str | None = None

    @classmethod
    def external_path(cls, path: str) -> "SecretSource":
        return cls("external-path", path)

    @classmethod
    def upload(cls, content: bytes) -> "SecretSource":
        return cls("upload", content)

    @classmethod
    def kubernetes_secret(cls, name: str, key: str) -> "SecretSource":
        return cls("kubernetes-secret", name, key)

    @classmethod
    def generated(cls) -> "SecretSource":
        return cls("generated")


@dataclass(frozen=True)
class SecretTarget:
    component_id: str
    secret_id: str
    kubernetes_secret: str
    classification: str
    consumers: tuple[str, ...]

    @property
    def identifier(self) -> str:
        return f"{self.component_id}/{self.secret_id}"

    @property
    def is_ssc_key(self) -> bool:
        return self.component_id == "ssc" and self.secret_id == "ssc-material"


class SecretAdapter(Protocol):
    """Protected store boundary; implementations must never log source data."""

    def replace(
        self,
        target: SecretTarget,
        source: SecretSource,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> str | None:
        """Atomically replace/reference material and return an opaque revision."""

    def rollback(
        self,
        target: SecretTarget,
        previous_revision: str,
        *,
        deadline: float,
    ) -> None:
        """Restore an adapter-owned revision without revealing its value."""


class ConsumerController(Protocol):
    def restart(
        self,
        component_id: str,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> None: ...

    def healthy(
        self,
        component_id: str,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> bool: ...


class SecretOperationStore:
    """Metadata-only durable state. Secret source values are never accepted."""

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
            "CREATE TABLE IF NOT EXISTS secret_operations ("
            "id TEXT PRIMARY KEY, state TEXT NOT NULL, payload TEXT NOT NULL)"
        )
        self.connection.execute(
            "UPDATE secret_operations SET state='interrupted', "
            "payload=json_set(payload, '$.state', 'interrupted', "
            "'$.error', 'Manager restarted before secret update completion', "
            "'$.recovery', 'Inspect consumer health and submit a new replacement', "
            "'$.updatedAt', ?) WHERE state IN ('applying','restarting','verifying','rolling-back')",
            (_timestamp(),),
        )
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        self.connection.close()

    def create(self, document: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO secret_operations VALUES (?, ?, ?)",
            (document["id"], document["state"], _payload(document)),
        )

    def update(self, document: dict[str, Any]) -> None:
        self.connection.execute(
            "UPDATE secret_operations SET state=?, payload=? WHERE id=?",
            (document["state"], _payload(document), document["id"]),
        )

    def get(self, operation_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT payload FROM secret_operations WHERE id=?", (operation_id,)
        ).fetchone()
        if row is None:
            raise SecretUpdateNotFound("secret update was not found")
        return json.loads(row["payload"])

    def active_target(self, target: str) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM secret_operations WHERE state IN "
            "('applying','restarting','verifying','rolling-back') "
            "AND json_extract(payload, '$.target')=? LIMIT 1",
            (target,),
        ).fetchone() is not None


class SecretWorkflow:
    """Plan and execute one bounded write-only replacement."""

    def __init__(
        self,
        registry: ComponentRegistry,
        store: SecretOperationStore,
        adapter: SecretAdapter,
        consumers: ConsumerController,
        authorization: AuthorizationService,
        *,
        allowed_external_roots: tuple[str | Path, ...],
        monotonic: Callable[[], float] = time.monotonic,
        timeout_seconds: float = 900,
        max_upload_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        if timeout_seconds <= 0 or max_upload_bytes < 1:
            raise ValueError("secret workflow bounds must be positive")
        self._registry = registry
        self._store = store
        self._adapter = adapter
        self._consumers = consumers
        self._authorization = authorization
        self._roots = tuple(Path(root).resolve(strict=True) for root in allowed_external_roots)
        self._monotonic = monotonic
        self._timeout = min(float(timeout_seconds), 3600)
        self._max_upload = max_upload_bytes
        self._cancelled: set[str] = set()
        self._lock = threading.RLock()

    def plan(self, component_id: str, secret_id: str, source_type: str) -> dict[str, Any]:
        target = self._target(component_id, secret_id)
        if source_type not in SOURCE_TYPES:
            raise InvalidSecretRequest("secret source type is not allowed")
        disruptive = bool(target.consumers)
        rollback = (
            "adapter-revision"
            if source_type in {"external-path", "upload", "generated"}
            else "restore-reference"
        )
        return {
            "target": target.identifier,
            "classification": target.classification,
            "sourceType": source_type,
            "consumers": list(target.consumers),
            "restartRequired": disruptive,
            "expectedInterruption": "consumer restart" if disruptive else "none",
            "rollbackBoundary": rollback,
            "persistentDataBackupRequired": target.is_ssc_key,
            "healthVerificationRequired": bool(target.consumers),
        }

    def request_approval(
        self,
        component_id: str,
        secret_id: str,
        source_type: str,
        *,
        identity: ActorIdentity,
    ) -> dict[str, Any]:
        """Create a high-risk approval bound to target, state, and source class."""

        target = self._target(component_id, secret_id)
        self.plan(component_id, secret_id, source_type)
        return self._authorization.request(
            self._authorization_plan(target, source_type), identity
        )

    def replace(
        self,
        component_id: str,
        secret_id: str,
        source: SecretSource,
        *,
        identity: ActorIdentity,
        approval_id: str,
        ssc_confirmation: str | None = None,
        backup_verified: bool = False,
    ) -> dict[str, Any]:
        target = self._target(component_id, secret_id)
        source = self._validate_source(target, source)
        impact = self.plan(component_id, secret_id, source.source_type)
        if target.is_ssc_key and (
            ssc_confirmation != CONFIRM_SSC_KEY or not backup_verified
        ):
            raise InvalidSecretRequest(
                "SSC secret.key replacement requires verified persistent-data backup "
                "and typed confirmation"
            )
        operation_plan = self._authorization_plan(target, source.source_type)
        self._authorization.authorize(
            operation_plan,
            identity,
            approval_id=approval_id,
            state_provider=lambda: self._authorization_plan(
                target, source.source_type
            ).current_state,
        )
        with self._lock:
            if self._store.active_target(target.identifier):
                raise SecretUpdateConflict("another update is active for this secret")
            now = _timestamp()
            document = {
                "apiVersion": "fortifylab.io/v1alpha1",
                "kind": "SecretUpdate",
                "id": str(uuid.uuid4()),
                "target": target.identifier,
                "actor": identity.actor,
                "sourceType": source.source_type,
                "state": "applying",
                "createdAt": now,
                "updatedAt": now,
                "impact": impact,
                "restartedConsumers": [],
                "error": None,
                "recovery": None,
            }
            self._store.create(document)
        deadline = self._monotonic() + self._timeout
        previous_revision: str | None = None
        try:
            previous_revision = self._adapter.replace(
                target, source, deadline=deadline,
                cancelled=lambda: document["id"] in self._cancelled,
            )
            for consumer in target.consumers:
                self._check_deadline(deadline, document)
                document["state"] = "restarting"
                self._save(document)
                self._consumers.restart(
                    consumer, deadline=deadline,
                    cancelled=lambda: document["id"] in self._cancelled,
                )
                document["restartedConsumers"].append(consumer)
                document["state"] = "verifying"
                self._save(document)
                if not self._consumers.healthy(
                    consumer, deadline=deadline,
                    cancelled=lambda: document["id"] in self._cancelled,
                ):
                    raise SecretWorkflowError("consumer health verification failed")
            document["state"] = "succeeded"
        except Exception as error:
            document["error"] = _safe_error(error)
            document["state"] = "failed"
            document["recovery"] = (
                "Restore the authoritative source and submit a new replacement"
            )
            if previous_revision:
                try:
                    document["state"] = "rolling-back"
                    self._save(document)
                    self._adapter.rollback(target, previous_revision, deadline=deadline)
                    document["state"] = "rolled-back"
                    document["recovery"] = "Previous adapter revision restored; verify consumers"
                except Exception:
                    document["state"] = "recovery-required"
                    document["recovery"] = (
                        "Automatic rollback failed; restore the authoritative source "
                        "and verify every consumer"
                    )
        finally:
            self._cancelled.discard(document["id"])
            self._save(document)
        return self._store.get(document["id"])

    def cancel(self, operation_id: str, *, identity: ActorIdentity) -> dict[str, Any]:
        document = self._store.get(operation_id)
        if document["actor"] != identity.actor:
            raise InvalidSecretRequest("authenticated actor does not own this update")
        if document["state"] not in {"applying", "restarting", "verifying"}:
            raise InvalidSecretRequest("secret update is not cancellable")
        self._cancelled.add(operation_id)
        return document

    def _target(self, component_id: str, secret_id: str) -> SecretTarget:
        try:
            component = self._registry.component(component_id)
        except Exception as error:
            raise InvalidSecretRequest("secret target is not declared") from error
        item = next((value for value in component["secrets"] if value["id"] == secret_id), None)
        if item is None:
            raise InvalidSecretRequest("secret target is not declared")
        consumers = tuple(
            component_id
            for component_id in self._registry.component_ids
            for value in (self._registry.component(component_id),)
            if any(
                secret["kubernetesSecret"] == item["kubernetesSecret"]
                for secret in value["secrets"]
            )
        )
        return SecretTarget(
            component_id, secret_id, item["kubernetesSecret"],
            item["classification"], consumers,
        )

    def _validate_source(self, target: SecretTarget, source: SecretSource) -> SecretSource:
        if source.source_type not in SOURCE_TYPES:
            raise InvalidSecretRequest("secret source type is not allowed")
        if source.source_type == "upload":
            if not isinstance(source.value, bytes) or not 0 < len(source.value) <= self._max_upload:
                raise InvalidSecretRequest("uploaded secret has an invalid size")
        elif source.source_type == "external-path":
            if not isinstance(source.value, str):
                raise InvalidSecretRequest("external secret path is invalid")
            try:
                candidate = Path(source.value)
                resolved = candidate.resolve(strict=True)
                info = candidate.lstat()
                allowed = any(resolved.is_relative_to(root) for root in self._roots)
                if (
                    not allowed or stat.S_ISLNK(info.st_mode) or not resolved.is_file()
                    or resolved.stat().st_mode & 0o077
                ):
                    raise OSError
            except (OSError, RuntimeError, ValueError):
                raise InvalidSecretRequest(
                    "external secret file is outside allowed roots, unsafe, or unreadable"
                ) from None
            source = SecretSource.external_path(str(resolved))
        elif source.source_type == "kubernetes-secret":
            if (
                not isinstance(source.value, str) or not source.key
                or not NAME.fullmatch(source.value) or not NAME.fullmatch(source.key)
            ):
                raise InvalidSecretRequest("Kubernetes Secret reference is invalid")
        elif source.source_type == "generated":
            if source.value is not None or source.key is not None:
                raise InvalidSecretRequest("generated source accepts no value")
            if target.classification not in {"credential", "token", "key"} or target.is_ssc_key:
                raise InvalidSecretRequest("generation is not allowed for this secret")
        return source

    def _current_state(self, target: SecretTarget) -> str:
        # Deliberately metadata-only: current content/revision is adapter-owned.
        try:
            row = self._store.connection.execute(
                "SELECT state FROM secret_operations "
                "WHERE json_extract(payload, '$.target')=? ORDER BY rowid DESC LIMIT 1",
                (target.identifier,),
            ).fetchone()
            return row["state"] if row else "unmanaged"
        except sqlite3.Error as error:
            raise SecretWorkflowError("secret metadata state is unavailable") from error

    def _authorization_plan(
        self, target: SecretTarget, source_type: str
    ) -> OperationPlan:
        return OperationPlan(
            "replace-secret",
            (target.identifier,),
            {
                target.identifier: self._current_state(target),
                "sourceType": source_type,
            },
        )

    def _check_deadline(self, deadline: float, document: dict[str, Any]) -> None:
        if document["id"] in self._cancelled:
            raise SecretWorkflowError("secret update was cancelled")
        if self._monotonic() >= deadline:
            raise SecretWorkflowError("secret update timed out")

    def _save(self, document: dict[str, Any]) -> None:
        document["updatedAt"] = _timestamp()
        self._store.update(document)


def _safe_error(error: Exception) -> str:
    if isinstance(error, SecretWorkflowError) and str(error):
        return str(error)
    return "secret update failed"


def _timestamp(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")


def _payload(document: dict[str, Any]) -> str:
    clean = sanitize_record(document)
    return json.dumps(clean, sort_keys=True, separators=(",", ":"))
