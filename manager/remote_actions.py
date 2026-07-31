"""Provider-neutral, policy-bounded remote lifecycle and recovery actions."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from manager.authorization import (
    RISK_BY_OPERATION,
    ActorIdentity,
    AuthorizationError,
    AuthorizationService,
    OperationPlan,
)
from manager.communications import MAX_MESSAGE, Action, Message
from manager.operation_engine import (
    RECOVERY_CLASS_BY_OPERATION,
    OperationEngine,
    OperationStore,
    TERMINAL_STATES,
)


REMOTE_APPROVABLE_RISKS = frozenset({"disruptive"})
WEB_ONLY_OPERATIONS = frozenset(
    {"uninstall", "delete-data", "restore-database", "replace-secret"}
)
REMOTE_ACTIONS = frozenset(
    {"approve", "reject", "acknowledge", "retry", "cancel", "pause"}
)


class RemoteActionError(RuntimeError):
    """A sanitized, fail-closed remote action error."""


class RemoteActionUnavailable(RemoteActionError):
    """Authoritative manager state could not be read or changed."""


@dataclass(frozen=True)
class OpaqueAction:
    token: str


class IncidentPort(Protocol):
    def acknowledge(self, incident_id: str, *, actor: str) -> Mapping[str, Any]: ...


class AutomationPort(Protocol):
    def pause(self, *, actor: str) -> Mapping[str, Any]: ...


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class RemoteActionStore:
    """Immutable plan snapshots and transactional opaque callback capabilities."""

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
            "CREATE TABLE IF NOT EXISTS remote_plans ("
            "id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload TEXT NOT NULL)"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS remote_callbacks ("
            "token_hash TEXT PRIMARY KEY, state TEXT NOT NULL, actor TEXT NOT NULL,"
            "session_id TEXT NOT NULL, action TEXT NOT NULL, reference_id TEXT NOT NULL,"
            "expires_at TEXT NOT NULL)"
        )
        self._lock = threading.RLock()

    def close(self) -> None:
        self.connection.close()

    def save_plan(self, document: Mapping[str, Any]) -> None:
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
        self.connection.execute(
            "INSERT INTO remote_plans(id, digest, payload) VALUES (?, ?, ?)",
            (document["id"], document["planDigest"], payload),
        )

    def plan(self, plan_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT payload FROM remote_plans WHERE id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            raise RemoteActionError("remote plan was not found")
        return json.loads(row["payload"])

    def issue(
        self,
        action: str,
        reference_id: str,
        identity: ActorIdentity,
        expires_at: datetime,
    ) -> OpaqueAction:
        if action not in REMOTE_ACTIONS:
            raise ValueError("unsupported remote action")
        token = secrets.token_urlsafe(18)
        self.connection.execute(
            "INSERT INTO remote_callbacks VALUES (?, 'pending', ?, ?, ?, ?, ?)",
            (
                self._hash(token),
                identity.actor,
                identity.session_id,
                action,
                reference_id,
                _timestamp(expires_at),
            ),
        )
        return OpaqueAction(token)

    def begin(
        self, token: str, identity: ActorIdentity, now: datetime
    ) -> tuple[str, str]:
        token_hash = self._hash(token)
        with self._lock:
            row = self.connection.execute(
                "SELECT * FROM remote_callbacks WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if row is None:
                raise RemoteActionError("action is invalid or expired")
            if row["actor"] != identity.actor or row["session_id"] != identity.session_id:
                raise RemoteActionError("action identity does not match")
            if row["state"] != "pending":
                raise RemoteActionError("action was already used")
            if now >= _datetime(row["expires_at"]):
                self.connection.execute(
                    "UPDATE remote_callbacks SET state = 'expired' WHERE token_hash = ?",
                    (token_hash,),
                )
                raise RemoteActionError("action is invalid or expired")
            changed = self.connection.execute(
                "UPDATE remote_callbacks SET state = 'executing' "
                "WHERE token_hash = ? AND state = 'pending'",
                (token_hash,),
            )
            if changed.rowcount != 1:
                raise RemoteActionError("action was already used")
            return row["action"], row["reference_id"]

    def finish(self, token: str, *, retryable: bool) -> None:
        state = "pending" if retryable else "consumed"
        self.connection.execute(
            "UPDATE remote_callbacks SET state = ? "
            "WHERE token_hash = ? AND state = 'executing'",
            (state, self._hash(token)),
        )

    @staticmethod
    def _hash(token: str) -> str:
        if not token or len(token) > 48:
            raise RemoteActionError("action is invalid or expired")
        return hashlib.sha256(token.encode()).hexdigest()


class RemoteActionService:
    """Create immutable mobile plans and execute only typed manager mutations."""

    def __init__(
        self,
        store: RemoteActionStore,
        authorization: AuthorizationService,
        engine: OperationEngine,
        operations: OperationStore,
        state_provider: Callable[[tuple[str, ...]], Mapping[str, str]],
        web_base_url: str,
        *,
        incident_port: IncidentPort | None = None,
        automation_port: AutomationPort | None = None,
        clock: Callable[[], datetime] | None = None,
        callback_ttl: timedelta = timedelta(minutes=10),
    ) -> None:
        parsed = urllib.parse.urlsplit(web_base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Web UI base URL must be HTTP(S)")
        self._store = store
        self._authorization = authorization
        self._engine = engine
        self._operations = operations
        self._state_provider = state_provider
        self._web_base = web_base_url.rstrip("/")
        self._incident_port = incident_port
        self._automation_port = automation_port
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ttl = callback_ttl

    def lifecycle_plan(
        self, operation: str, targets: tuple[str, ...], identity: ActorIdentity
    ) -> Message:
        resolved = self._engine.plan(operation, targets)
        affected = tuple(resolved["components"])
        current = dict(self._state_provider(affected))
        policy_plan = OperationPlan(operation, affected, current)
        if (
            policy_plan.risk not in REMOTE_APPROVABLE_RISKS
            or operation in WEB_ONLY_OPERATIONS
            or (operation == "upgrade")
        ):
            raise RemoteActionError(
                "this operation requires stronger confirmation in the Web UI"
            )
        approval = self._authorization.request(policy_plan, identity)
        timeout = sum(float(step["timeoutSeconds"]) for step in resolved["steps"])
        requested = set(resolved["requestedTargets"])
        dependencies = [item for item in affected if item not in requested]
        rollback_class = max(
            (
                step.get(
                    "recoveryClass",
                    RECOVERY_CLASS_BY_OPERATION.get(
                        step.get("operation", operation), "irreversible"
                    ),
                )
                for step in resolved["steps"]
            ),
            key={
                "reversible": 0,
                "compensating-action": 1,
                "restore-required": 2,
                "irreversible": 3,
            }.__getitem__,
        )
        rollback = (
            f"{rollback_class}; cancellation is best-effort and completed mutations "
            "are retained as recovery evidence."
        )
        snapshot = {
            "id": approval["id"],
            "operation": operation,
            "requestedTargets": list(targets),
            "components": list(affected),
            "dependencyImpact": dependencies,
            "currentState": current,
            "timeoutSeconds": timeout,
            "rollbackBoundary": rollback,
            "recoveryClass": rollback_class,
            "planDigest": policy_plan.digest,
            "expiresAt": approval["expiresAt"],
        }
        self._store.save_plan(snapshot)
        expires = _datetime(approval["expiresAt"])
        approve = self._store.issue("approve", approval["id"], identity, expires)
        reject = self._store.issue("reject", approval["id"], identity, expires)
        impact = (
            ", ".join(dependencies) if dependencies else "requested components only"
        )
        digest_ref = policy_plan.digest.split(":", 1)[1][:12]
        text = (
            f"Lifecycle plan: {operation} {', '.join(targets)}\n"
            f"Impact: {impact}\n"
            f"Timeout: {int(timeout)} seconds\n"
            f"Rollback boundary: {rollback}\n"
            f"Plan digest: {digest_ref}\n"
            f"Expires: {approval['expiresAt']}\n"
            f"Review in Web UI: {self._web_base}/operations/plans/{approval['id']}"
        )
        return Message(
            text[:MAX_MESSAGE],
            (
                Action("Approve", approve),  # type: ignore[arg-type]
                Action("Reject", reject),  # type: ignore[arg-type]
            ),
            f"plan:{approval['id']}",
        )

    def recovery_actions(
        self,
        *,
        incident_id: str | None = None,
        operation_id: str | None = None,
        identity: ActorIdentity,
    ) -> tuple[Action, ...]:
        now = self._now()
        expires = now + self._ttl
        actions: list[Action] = []
        if incident_id:
            actions.append(
                Action(
                    "Acknowledge",
                    self._store.issue("acknowledge", incident_id, identity, expires),
                )  # type: ignore[arg-type]
            )
        if operation_id:
            document = self._operations.get(operation_id)
            if (
                document["state"] in TERMINAL_STATES - {"succeeded", "cancelled"}
                and RISK_BY_OPERATION.get(document.get("operation")) == "routine"
            ):
                actions.append(
                    Action(
                        "Safe retry",
                        self._store.issue("retry", operation_id, identity, expires),
                    )  # type: ignore[arg-type]
                )
            elif document["state"] not in TERMINAL_STATES:
                actions.append(
                    Action(
                        "Cancel",
                        self._store.issue("cancel", operation_id, identity, expires),
                    )  # type: ignore[arg-type]
                )
        if self._automation_port is not None:
            actions.append(
                Action(
                    "Pause automation",
                    self._store.issue("pause", "automation", identity, expires),
                )  # type: ignore[arg-type]
            )
        return tuple(actions)

    def recovery_notification(
        self, message: Message, event: Mapping[str, Any], identity: ActorIdentity
    ) -> Message:
        """Attach state-eligible recovery controls to a sanitized notification."""
        incident_id = event.get("incidentId")
        operation_id = event.get("operationId")
        actions = self.recovery_actions(
            incident_id=incident_id if isinstance(incident_id, str) else None,
            operation_id=operation_id if isinstance(operation_id, str) else None,
            identity=identity,
        )
        return Message(message.text, actions, message.replace_key)

    def execute(self, token: str, identity: ActorIdentity) -> Message:
        action, reference = self._store.begin(token, identity, self._now())
        retryable = False
        try:
            if action == "approve":
                plan = self._store.plan(reference)
                approval = self._authorization.approval(reference)
                if approval["state"] == "pending":
                    approval = self._authorization.approve(reference, identity)
                elif approval["state"] != "approved":
                    raise RemoteActionError("approval is no longer usable")
                operation = self._engine.submit_async(
                    plan["operation"],
                    tuple(plan["requestedTargets"]),
                    actor=identity.actor,
                    identity=identity,
                    approval_id=approval["id"],
                )
                text = (
                    f"Operation queued: {operation['id']}\n"
                    f"Open Web UI: {self._web_base}/operations/{operation['id']}"
                )
            elif action == "reject":
                self._authorization.revoke(reference, identity)
                text = f"Plan rejected.\nOpen Web UI: {self._web_base}/operations"
            elif action == "retry":
                operation = self._engine.retry_async(
                    reference, actor=identity.actor, identity=identity
                )
                text = (
                    f"Retry queued: {operation['id']}\n"
                    f"Open Web UI: {self._web_base}/operations/{operation['id']}"
                )
            elif action == "cancel":
                operation = self._engine.cancel(
                    reference, actor=identity.actor, identity=identity
                )
                text = (
                    f"Cancellation requested: {operation['id']}\n"
                    f"Open Web UI: {self._web_base}/operations/{operation['id']}"
                )
            elif action == "acknowledge" and self._incident_port is not None:
                self._incident_port.acknowledge(reference, actor=identity.actor)
                text = (
                    f"Incident acknowledged.\n"
                    f"Open Web UI: {self._web_base}/incidents/{reference}"
                )
            elif action == "pause" and self._automation_port is not None:
                self._automation_port.pause(actor=identity.actor)
                text = f"Automation paused.\nOpen Web UI: {self._web_base}/automation"
            else:
                raise RemoteActionError("action is not available")
        except (OSError, TimeoutError, RemoteActionUnavailable):
            retryable = True
            raise RemoteActionUnavailable(
                "manager is unavailable; authoritative state was not changed"
            ) from None
        except (AuthorizationError, ValueError, RuntimeError) as error:
            raise RemoteActionError(str(error)) from None
        finally:
            self._store.finish(token, retryable=retryable)
        return Message(text[:MAX_MESSAGE])

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("remote action clock must be timezone-aware")
        return now.astimezone(timezone.utc)
