"""Local identities and single-use risk-based lifecycle approvals."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


RISK_BY_OPERATION = {
    "install": "routine",
    "configure": "routine",
    "start": "routine",
    "stop": "disruptive",
    "restart": "disruptive",
    "upgrade": "high",
    "uninstall": "high",
    "delete-data": "high",
    "replace-secret": "high",
}
APPROVAL_REQUIRED = frozenset({"disruptive", "high"})
HIGH_RISK_SOURCES = frozenset({"local-cli", "web"})
HIGH_RISK_CONFIRMATION = "AUTHORIZE HIGH-RISK OPERATION"


class AuthorizationError(RuntimeError):
    """A sanitized authorization failure which always fails closed."""

    code = "AUTHORIZATION_DENIED"


class ApprovalUnavailable(AuthorizationError):
    code = "APPROVAL_PROVIDER_UNAVAILABLE"


@dataclass(frozen=True)
class ActorIdentity:
    """Authenticated local actor and bounded session/channel provenance."""

    actor: str
    source: str
    session_id: str
    authenticated_at: datetime

    def __post_init__(self) -> None:
        if (
            not self.actor
            or len(self.actor) > 128
            or self.source not in {"local-cli", "web", "telegram"}
            or not self.session_id
            or len(self.session_id) > 128
            or self.authenticated_at.tzinfo is None
        ):
            raise ValueError("identity is incomplete or unsupported")


@dataclass(frozen=True)
class OperationPlan:
    operation: str
    targets: tuple[str, ...]
    current_state: Mapping[str, str]

    @property
    def risk(self) -> str:
        try:
            return RISK_BY_OPERATION[self.operation]
        except KeyError as error:
            raise AuthorizationError("operation has no authorization policy") from error

    @property
    def digest(self) -> str:
        document = {
            "operation": self.operation,
            "targets": list(self.targets),
            "currentState": dict(sorted(self.current_state.items())),
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(payload).hexdigest()


class ApprovalStore:
    """Transactional approval and audit history; no credentials are persisted."""

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
            "CREATE TABLE IF NOT EXISTS operation_approvals ("
            "id TEXT PRIMARY KEY, state TEXT NOT NULL, payload TEXT NOT NULL)"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS authorization_audit ("
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,"
            "approval_id TEXT, action TEXT NOT NULL, actor TEXT NOT NULL,"
            "outcome TEXT NOT NULL, reason TEXT NOT NULL)"
        )
        self._lock = threading.RLock()

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def available(self) -> bool:
        """Check the approval ledger through its serialized database boundary."""
        with self._lock:
            return self.connection.execute("SELECT 1").fetchone() is not None

    def approval(self, approval_id: str) -> dict[str, Any]:
        with self._lock:
            row = self.connection.execute(
                "SELECT payload FROM operation_approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            raise AuthorizationError("approval was not found")
        return json.loads(row["payload"])

    def audit(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(row)
                for row in self.connection.execute(
                    "SELECT at, approval_id, action, actor, outcome, reason "
                    "FROM authorization_audit ORDER BY sequence"
                )
            ]

    def insert(self, document: dict[str, Any]) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT INTO operation_approvals VALUES (?, ?, ?)",
                (document["id"], document["state"], _payload(document)),
            )

    def transition(
        self, approval_id: str, expected: str, state: str, document: dict[str, Any]
    ) -> bool:
        with self._lock:
            cursor = self.connection.execute(
                "UPDATE operation_approvals SET state = ?, payload = ? "
                "WHERE id = ? AND state = ?",
                (state, _payload(document), approval_id, expected),
            )
            return cursor.rowcount == 1

    def record(
        self, at: str, approval_id: str | None, action: str, actor: str,
        outcome: str, reason: str,
    ) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT INTO authorization_audit("
                "at, approval_id, action, actor, outcome, reason"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (at, approval_id, action, actor, outcome, reason),
            )


class AuthorizationService:
    """One policy and ledger shared by every manager mutation adapter."""

    def __init__(
        self,
        store: ApprovalStore,
        *,
        clock: Callable[[], datetime] | None = None,
        approval_ttl: timedelta = timedelta(minutes=10),
        reauthentication_age: timedelta = timedelta(minutes=5),
    ) -> None:
        self._store = store
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ttl = approval_ttl
        self._reauthentication_age = reauthentication_age

    def request(self, plan: OperationPlan, identity: ActorIdentity) -> dict[str, Any]:
        now = self._now()
        document = {
            "id": str(uuid.uuid4()),
            "state": "pending",
            "singleUse": True,
            "actor": identity.actor,
            "source": identity.source,
            "sessionId": identity.session_id,
            "risk": plan.risk,
            "operation": plan.operation,
            "targets": list(plan.targets),
            "planDigest": plan.digest,
            "createdAt": _timestamp(now),
            "expiresAt": _timestamp(now + self._ttl),
            "decidedAt": None,
            "consumedAt": None,
            "revokedAt": None,
        }
        self._store.insert(document)
        self._audit(document["id"], "request", identity.actor, "accepted", plan.risk)
        return document

    def approval(self, approval_id: str) -> dict[str, Any]:
        """Return one authorization record for trusted manager adapters."""
        return self._store.approval(approval_id)

    def approve(
        self,
        approval_id: str,
        identity: ActorIdentity,
        *,
        confirmation: str | None = None,
    ) -> dict[str, Any]:
        document = self._store.approval(approval_id)
        now = self._now()
        reason = self._decision_reason(document, identity, now, confirmation)
        if reason:
            self._audit(approval_id, "approve", identity.actor, "denied", reason)
            raise AuthorizationError(reason)
        document["state"] = "approved"
        document["decidedAt"] = _timestamp(now)
        if not self._store.transition(approval_id, "pending", "approved", document):
            self._audit(approval_id, "approve", identity.actor, "denied", "not pending")
            raise AuthorizationError("approval is no longer pending")
        self._audit(approval_id, "approve", identity.actor, "accepted", document["risk"])
        return document

    def revoke(self, approval_id: str, identity: ActorIdentity) -> dict[str, Any]:
        document = self._store.approval(approval_id)
        if document["actor"] != identity.actor:
            self._audit(approval_id, "revoke", identity.actor, "denied", "actor mismatch")
            raise AuthorizationError("approval actor does not match")
        previous = document["state"]
        if previous not in {"pending", "approved"}:
            raise AuthorizationError("approval can no longer be revoked")
        document["state"] = "revoked"
        document["revokedAt"] = _timestamp(self._now())
        if not self._store.transition(approval_id, previous, "revoked", document):
            raise AuthorizationError("approval state changed concurrently")
        self._audit(approval_id, "revoke", identity.actor, "accepted", "revoked")
        return document

    def authorize(
        self,
        plan: OperationPlan,
        identity: ActorIdentity,
        *,
        approval_id: str | None = None,
        state_provider: Callable[[], Mapping[str, str]] | None = None,
    ) -> None:
        if plan.risk not in APPROVAL_REQUIRED:
            self._audit(None, "authorize", identity.actor, "accepted", plan.risk)
            return
        if approval_id is None:
            self._audit(None, "authorize", identity.actor, "denied", "approval required")
            raise AuthorizationError("operation requires approval")
        document = self._store.approval(approval_id)
        try:
            current_state = state_provider() if state_provider else plan.current_state
        except Exception as error:
            self._audit(approval_id, "authorize", identity.actor, "denied", "state unavailable")
            raise ApprovalUnavailable("current target state is unavailable") from error
        current = OperationPlan(plan.operation, plan.targets, current_state)
        reason = self._consumption_reason(document, current, identity, self._now())
        if reason:
            self._audit(approval_id, "authorize", identity.actor, "denied", reason)
            raise AuthorizationError(reason)
        document["state"] = "consumed"
        document["consumedAt"] = _timestamp(self._now())
        if not self._store.transition(approval_id, "approved", "consumed", document):
            self._audit(approval_id, "authorize", identity.actor, "denied", "replay")
            raise AuthorizationError("approval was already consumed or changed")
        self._audit(approval_id, "authorize", identity.actor, "accepted", plan.risk)

    def _decision_reason(
        self, document: dict[str, Any], identity: ActorIdentity,
        now: datetime, confirmation: str | None,
    ) -> str | None:
        if document["state"] != "pending":
            return "approval is no longer pending"
        if now >= _datetime(document["expiresAt"]):
            return "approval has expired"
        if document["actor"] != identity.actor or document["sessionId"] != identity.session_id:
            return "approval actor or session does not match"
        if document["risk"] == "high":
            if identity.source not in HIGH_RISK_SOURCES:
                return "high-risk approval requires local CLI or Web UI"
            if now - identity.authenticated_at > self._reauthentication_age:
                return "high-risk approval requires fresh authentication"
            if confirmation != HIGH_RISK_CONFIRMATION:
                return "high-risk confirmation did not match"
        return None

    @staticmethod
    def _consumption_reason(
        document: dict[str, Any], plan: OperationPlan,
        identity: ActorIdentity, now: datetime,
    ) -> str | None:
        if document["state"] != "approved":
            return "approval is not approved"
        if now >= _datetime(document["expiresAt"]):
            return "approval has expired"
        if document["actor"] != identity.actor or document["sessionId"] != identity.session_id:
            return "approval actor or session does not match"
        if document["source"] != identity.source:
            return "approval source does not match"
        if document["planDigest"] != plan.digest:
            return "operation plan or current state changed"
        return None

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("authorization clock must be timezone-aware")
        return now.astimezone(timezone.utc)

    def _audit(
        self, approval_id: str | None, action: str, actor: str,
        outcome: str, reason: str,
    ) -> None:
        self._store.record(
            _timestamp(self._now()), approval_id, action, actor, outcome, reason
        )


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _payload(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))
