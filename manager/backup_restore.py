"""Durable, profile-bound orchestration for verified platform recovery."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import socket
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol


API_VERSION = "fortifylab.io/v1alpha1"
BACKUP_SCOPES = (
    "manager-state",
    "configuration-metadata",
    "mysql-ssc",
    "ssc-secret-key",
    "postgresql-dast",
)
RESTORE_CONFIRMATION = "RESTORE VERIFIED PLATFORM BACKUP"
TERMINAL_STATES = frozenset(
    {"succeeded", "failed", "interrupted", "cancelled"}
)


class RecoveryError(RuntimeError):
    """A sanitized recovery failure."""

    code = "RECOVERY_FAILED"


class IncompatibleBackup(RecoveryError):
    code = "INCOMPATIBLE_PROFILE"


class IncompleteArtifact(RecoveryError):
    code = "INCOMPLETE_ARTIFACT"


@dataclass(frozen=True)
class Destination:
    """Public metadata for an operator-configured protected destination."""

    id: str
    storage_class: str
    retention_days: int

    def __post_init__(self) -> None:
        if (
            not self.id
            or len(self.id) > 64
            or not all(character.isalnum() or character in ".-" for character in self.id)
            or self.storage_class not in {"local-protected", "removable", "object"}
            or not 1 <= self.retention_days <= 3650
        ):
            raise ValueError("backup destination metadata is invalid")

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "class": self.storage_class,
            "retentionDays": self.retention_days,
        }


class RecoveryAdapter(Protocol):
    """Fixed-action privileged boundary; values and paths never cross outward."""

    def backup(self, backup_id: str, scope: str, cancelled: Callable[[], bool]) -> dict[str, Any]:
        ...

    def restore(self, backup_id: str, scope: str, cancelled: Callable[[], bool]) -> dict[str, Any]:
        ...

    def verify(self, backup_id: str, checks: tuple[str, ...]) -> list[dict[str, str]]:
        ...


class UnixRecoveryAdapter:
    """Protected fixed-action client for the credential-bearing recovery helper."""

    _MAX_RESPONSE = 16_384

    def __init__(self, socket_path: Path, *, timeout_seconds: float = 3600) -> None:
        self._path = socket_path
        self._timeout = timeout_seconds

    def backup(self, backup_id: str, scope: str, cancelled: Callable[[], bool]) -> dict[str, Any]:
        return self._request("backup", backup_id, scope)

    def restore(self, backup_id: str, scope: str, cancelled: Callable[[], bool]) -> dict[str, Any]:
        return self._request("restore", backup_id, scope)

    def verify(self, backup_id: str, checks: tuple[str, ...]) -> list[dict[str, str]]:
        result = self._request("verify", backup_id, None, checks)
        evidence = result.get("evidence")
        if not isinstance(evidence, list):
            raise RecoveryError("recovery helper returned invalid verification evidence")
        return evidence

    def _request(
        self, action: str, backup_id: str, scope: str | None,
        checks: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        try:
            mode = self._path.stat().st_mode
            if not stat.S_ISSOCK(mode) or mode & 0o007:
                raise RecoveryError("recovery helper socket is not protected")
            request = {
                "apiVersion": API_VERSION,
                "kind": "RecoveryHelperRequest",
                "action": action,
                "backupId": backup_id,
                "scope": scope,
                "checks": list(checks),
            }
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout)
                connection.connect(str(self._path))
                connection.sendall(_encode(request).encode() + b"\n")
                response = b""
                while not response.endswith(b"\n"):
                    chunk = connection.recv(self._MAX_RESPONSE + 1 - len(response))
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > self._MAX_RESPONSE:
                        raise RecoveryError("recovery helper response is invalid")
            document = json.loads(response)
            if (
                not isinstance(document, dict)
                or document.get("apiVersion") != API_VERSION
                or document.get("kind") != "RecoveryHelperResult"
                or document.get("state") != "succeeded"
            ):
                raise RecoveryError("recovery helper did not complete the fixed action")
            return document
        except RecoveryError:
            raise
        except (OSError, TimeoutError, ValueError, json.JSONDecodeError) as error:
            raise RecoveryError("recovery helper is unavailable or returned invalid data") from error

class RecoveryStore:
    """Transactional operation and immutable artifact metadata."""

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
            "CREATE TABLE IF NOT EXISTS recovery_operations ("
            "id TEXT PRIMARY KEY, state TEXT NOT NULL, payload TEXT NOT NULL)"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS recovery_artifacts ("
            "id TEXT PRIMARY KEY, complete INTEGER NOT NULL, payload TEXT NOT NULL)"
        )
        self.connection.execute(
            "UPDATE recovery_operations SET state='interrupted', "
            "payload=json_set(payload, '$.state', 'interrupted', "
            "'$.error', 'Manager restarted before recovery completed', "
            "'$.updatedAt', ?) WHERE state IN ('queued','running','verifying')",
            (_now(),),
        )
        self._lock = threading.RLock()

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def put_operation(self, document: dict[str, Any]) -> None:
        payload = _encode(document)
        with self._lock:
            self.connection.execute(
                "INSERT OR REPLACE INTO recovery_operations VALUES (?, ?, ?)",
                (document["id"], document["state"], payload),
            )

    def operation(self, operation_id: str) -> dict[str, Any]:
        with self._lock:
            row = self.connection.execute(
                "SELECT payload FROM recovery_operations WHERE id=?", (operation_id,)
            ).fetchone()
        if row is None:
            raise RecoveryError("recovery operation was not found")
        return json.loads(row["payload"])

    def put_artifact(self, document: dict[str, Any], *, complete: bool) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT OR REPLACE INTO recovery_artifacts VALUES (?, ?, ?)",
                (document["id"], int(complete), _encode(document)),
            )

    def artifact(self, backup_id: str, *, require_complete: bool = True) -> dict[str, Any]:
        with self._lock:
            row = self.connection.execute(
                "SELECT complete,payload FROM recovery_artifacts WHERE id=?", (backup_id,)
            ).fetchone()
        if row is None or (require_complete and not row["complete"]):
            raise IncompleteArtifact("backup artifact is unavailable or incomplete")
        return json.loads(row["payload"])


class RecoveryService:
    """Plan and execute non-idempotent backups and strongly confirmed restores."""

    def __init__(
        self,
        store: RecoveryStore,
        adapter: RecoveryAdapter,
        *,
        profile_id: str,
        destination: Destination,
    ) -> None:
        self.store = store
        self.adapter = adapter
        self.profile_id = profile_id
        self.destination = destination
        self._cancelled: set[str] = set()
        self._lock = threading.RLock()
        self._workers: set[threading.Thread] = set()

    def backup_plan(self) -> dict[str, Any]:
        return {
            "apiVersion": API_VERSION,
            "kind": "BackupPlan",
            "profileId": self.profile_id,
            "scope": list(BACKUP_SCOPES),
            "consistency": {
                "manager-state": "SQLite online snapshot",
                "configuration-metadata": "atomic metadata snapshot",
                "mysql-ssc": "application-quiesced logical database backup",
                "ssc-secret-key": "preserved protected Secret entry",
                "postgresql-dast": "application-quiesced logical database backup",
            },
            "estimatedImpact": "Fortify applications are read-only or unavailable while database snapshots are captured",
            "destination": self.destination.public(),
            "retention": {
                "days": self.destination.retention_days,
                "independentOfUninstallAndDataDeletion": True,
            },
            "secretValuesExposed": False,
        }

    def restore_plan(self, backup_id: str) -> dict[str, Any]:
        artifact = self.store.artifact(backup_id)
        compatible = artifact["profileId"] == self.profile_id
        return {
            "apiVersion": API_VERSION,
            "kind": "RestorePlan",
            "backupId": backup_id,
            "artifactProfileId": artifact["profileId"],
            "currentProfileId": self.profile_id,
            "compatible": compatible,
            "blockedReason": None if compatible else "platform profile does not match",
            "scope": artifact["scope"],
            "estimatedImpact": "All covered applications are unavailable during restore and verification",
            "confirmation": RESTORE_CONFIRMATION,
        }

    def submit_backup(self, *, actor: str) -> dict[str, Any]:
        backup_id = "backup-" + uuid.uuid4().hex
        document = self._new_operation("backup", backup_id, actor)
        self.store.put_operation(document)
        self._start_worker(self._run_backup, document["id"], backup_id)
        return document

    def submit_restore(
        self, backup_id: str, *, actor: str, confirmation: str | None
    ) -> dict[str, Any]:
        if confirmation != RESTORE_CONFIRMATION:
            raise RecoveryError("restore requires the exact typed confirmation")
        plan = self.restore_plan(backup_id)
        if not plan["compatible"]:
            raise IncompatibleBackup("backup platform profile is incompatible")
        document = self._new_operation("restore", backup_id, actor)
        self.store.put_operation(document)
        self._start_worker(self._run_restore, document["id"], backup_id)
        return document

    def wait_for_idle(self, timeout_seconds: float = 10.0) -> bool:
        """Bound shutdown/tests without closing SQLite under active workers."""
        deadline = time.monotonic() + max(0.0, min(float(timeout_seconds), 3600.0))
        while True:
            with self._lock:
                workers = tuple(self._workers)
            if not workers:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            workers[0].join(remaining)

    def _start_worker(self, target: Callable[..., None], *args: str) -> None:
        def run() -> None:
            try:
                target(*args)
            finally:
                with self._lock:
                    self._workers.discard(threading.current_thread())

        worker = threading.Thread(target=run, daemon=True)
        with self._lock:
            self._workers.add(worker)
        worker.start()

    def cancel(self, operation_id: str) -> dict[str, Any]:
        document = self.store.operation(operation_id)
        if document["state"] in TERMINAL_STATES:
            return document
        with self._lock:
            self._cancelled.add(operation_id)
        document["cancellationRequested"] = True
        self._save(document)
        return document

    def _new_operation(self, action: str, backup_id: str, actor: str) -> dict[str, Any]:
        now = _now()
        return {
            "apiVersion": API_VERSION,
            "kind": "RecoveryOperation",
            "id": "recovery-" + uuid.uuid4().hex,
            "action": action,
            "backupId": backup_id,
            "profileId": self.profile_id,
            "actor": actor[:128],
            "state": "queued",
            "currentScope": None,
            "completedScopes": [],
            "cancellationRequested": False,
            "createdAt": now,
            "updatedAt": now,
            "evidence": [],
            "error": None,
        }

    def _run_backup(self, operation_id: str, backup_id: str) -> None:
        operation = self.store.operation(operation_id)
        artifact = {
            "apiVersion": API_VERSION,
            "kind": "PlatformBackup",
            "id": backup_id,
            "profileId": self.profile_id,
            "scope": list(BACKUP_SCOPES),
            "destination": self.destination.public(),
            "createdAt": operation["createdAt"],
            "checksums": {},
        }
        self.store.put_artifact(artifact, complete=False)
        try:
            operation["state"] = "running"
            self._save(operation)
            for scope in BACKUP_SCOPES:
                self._check_cancelled(operation_id)
                operation["currentScope"] = scope
                self._save(operation)
                result = self.adapter.backup(
                    backup_id, scope, lambda: self._is_cancelled(operation_id)
                )
                digest = result.get("checksum")
                if not isinstance(digest, str) or not digest.startswith("sha256:"):
                    raise IncompleteArtifact("backup scope did not produce a checksum")
                artifact["checksums"][scope] = digest
                operation["completedScopes"].append(scope)
                self._save(operation)
            artifact["manifestDigest"] = "sha256:" + hashlib.sha256(
                _encode(artifact).encode()
            ).hexdigest()
            self.store.put_artifact(artifact, complete=True)
            operation["state"] = "succeeded"
        except Exception as error:  # adapter failures are deliberately sanitized
            operation["state"] = "cancelled" if self._is_cancelled(operation_id) else "failed"
            operation["error"] = (
                "backup cancelled at a safe boundary"
                if operation["state"] == "cancelled"
                else _safe_error(error, "backup failed; incomplete artifact cannot be restored")
            )
        finally:
            operation["currentScope"] = None
            self._save(operation)

    def _run_restore(self, operation_id: str, backup_id: str) -> None:
        operation = self.store.operation(operation_id)
        try:
            artifact = self.store.artifact(backup_id)
            if artifact["profileId"] != self.profile_id:
                raise IncompatibleBackup("backup platform profile is incompatible")
            operation["state"] = "running"
            self._save(operation)
            for scope in reversed(BACKUP_SCOPES):
                self._check_cancelled(operation_id)
                operation["currentScope"] = scope
                self._save(operation)
                self.adapter.restore(
                    backup_id, scope, lambda: self._is_cancelled(operation_id)
                )
                operation["completedScopes"].append(scope)
                self._save(operation)
            operation["state"] = "verifying"
            self._save(operation)
            evidence = self.adapter.verify(
                backup_id,
                ("manager-readiness", "mysql-query", "ssc-readiness", "postgresql-query", "dast-readiness", "ssc-secret-key-match"),
            )
            if not evidence or any(item.get("state") != "passed" for item in evidence):
                raise RecoveryError("application-level recovery verification failed")
            operation["evidence"] = _sanitize_evidence(evidence)
            operation["state"] = "succeeded"
        except Exception as error:
            operation["state"] = "cancelled" if self._is_cancelled(operation_id) else "failed"
            operation["error"] = (
                "restore cancelled at a safe boundary; applications require verification"
                if operation["state"] == "cancelled"
                else _safe_error(error, "restore failed; follow the recovery plan")
            )
        finally:
            operation["currentScope"] = None
            self._save(operation)

    def _save(self, document: dict[str, Any]) -> None:
        document["updatedAt"] = _now()
        self.store.put_operation(document)

    def _is_cancelled(self, operation_id: str) -> bool:
        with self._lock:
            return operation_id in self._cancelled

    def _check_cancelled(self, operation_id: str) -> None:
        if self._is_cancelled(operation_id):
            raise RecoveryError("operation cancelled")


def _sanitize_evidence(items: list[dict[str, str]]) -> list[dict[str, str]]:
    allowed = {"check", "state", "code"}
    return [
        {key: str(value)[:128] for key, value in item.items() if key in allowed}
        for item in items
    ]


def _safe_error(error: Exception, fallback: str) -> str:
    return str(error) if isinstance(error, RecoveryError) else fallback


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _encode(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))
