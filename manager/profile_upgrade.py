"""Profile-aware, evidence-bound upgrade planning and execution."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

from manager.authorization import ActorIdentity
from manager.component_registry import ComponentRegistry
from manager.platform_profiles import PlatformProfile, PlatformProfileError


API_VERSION = "fortifylab.io/v1alpha1"
TERMINAL_STATES = frozenset(
    {"succeeded", "failed", "cancelled", "timed-out", "interrupted"}
)
STRONG_SOURCES = frozenset({"web", "local-cli"})


class UpgradeError(RuntimeError):
    code = "UPGRADE_BLOCKED"


class StaleUpgradePlan(UpgradeError):
    code = "STALE_UPGRADE_PLAN"


class UpgradeExecutionError(UpgradeError):
    code = "UPGRADE_FAILED"


class UpgradeAdapter(Protocol):
    def upgrade(
        self, component: str, version: dict[str, Any], *,
        deadline: float, cancelled: Callable[[], bool],
    ) -> None: ...


class UpgradeVerifier(Protocol):
    def verify_layer(
        self, component: str, *, deadline: float,
        cancelled: Callable[[], bool],
    ) -> bool: ...


class UpgradeStore:
    """Durable plans and operations; unfinished execution becomes interrupted."""

    def __init__(self, path: str = ":memory:") -> None:
        self.connection = sqlite3.connect(
            path, timeout=30, isolation_level=None, check_same_thread=False
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS profile_upgrades ("
            "id TEXT PRIMARY KEY, kind TEXT NOT NULL, state TEXT, payload TEXT NOT NULL)"
        )
        self.connection.execute(
            "UPDATE profile_upgrades SET state='interrupted', "
            "payload=json_set(payload, '$.state', 'interrupted', "
            "'$.error', 'Manager restarted before profile upgrade completed') "
            "WHERE state IN ('queued','running','cancelling')"
        )
        self._lock = threading.RLock()

    def put(self, document: dict[str, Any]) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT OR REPLACE INTO profile_upgrades VALUES (?, ?, ?, ?)",
                (
                    document["id"], document["kind"], document.get("state"),
                    json.dumps(document, sort_keys=True, separators=(",", ":")),
                ),
            )

    def get(self, document_id: str) -> dict[str, Any]:
        with self._lock:
            row = self.connection.execute(
                "SELECT payload FROM profile_upgrades WHERE id=?", (document_id,)
            ).fetchone()
        if row is None:
            raise UpgradeError("upgrade plan or operation was not found")
        return json.loads(row["payload"])

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def consume_plan(self, plan_id: str) -> bool:
        with self._lock:
            cursor = self.connection.execute(
                "UPDATE profile_upgrades SET state='consumed', "
                "payload=json_set(payload, '$.state', 'consumed') "
                "WHERE id=? AND kind='ProfileUpgradePlan' AND state IS NULL",
                (plan_id,),
            )
            return cursor.rowcount == 1


class ProfileUpgradeService:
    """Plan only declared profile paths and execute an unchanged approved snapshot."""

    def __init__(
        self,
        registry: ComponentRegistry,
        store: UpgradeStore,
        adapter: UpgradeAdapter,
        verifier: UpgradeVerifier,
        *,
        profile_loader: Callable[[str], PlatformProfile] = PlatformProfile.load,
        observation_provider: Callable[[], dict[str, Any]],
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        plan_ttl: timedelta = timedelta(minutes=10),
        confirmation_age: timedelta = timedelta(minutes=5),
    ) -> None:
        self._registry = registry
        self._store = store
        self._adapter = adapter
        self._verifier = verifier
        self._load = profile_loader
        self._observe = observation_provider
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic
        self._ttl = plan_ttl
        self._confirmation_age = confirmation_age
        self._cancelled: set[str] = set()

    def plan(self, target_profile_id: str) -> dict[str, Any]:
        source = self._registry.profile
        try:
            target = self._load(target_profile_id)
        except PlatformProfileError as error:
            raise UpgradeError("target platform profile is unavailable or invalid") from error
        if target.id == source.id or target.maturity == "unsupported":
            raise UpgradeError("source and target platform profiles are not an allowed transition")
        if (
            target.maturity not in {"validated", "recommended"}
            or target.document["evidence"]["level"] != "licensed-live"
        ):
            raise UpgradeError("target profile transition lacks licensed-live validation")
        transition = self._transition(target, source.id)
        observed = self._validated_observation(source, target, transition)
        changed = [
            component for component in self._registry.dependency_order()
            if source.component_version(component) != target.component_version(component)
        ]
        if not changed:
            raise UpgradeError("target platform profile has no component version changes")
        dependency_impact = list(self._registry.dependency_order())
        migrations = transition["migrations"]
        rollback = _rollback_class(migrations)
        now = self._now()
        body = {
            "sourceProfile": {"id": source.id, "versions": _versions(source)},
            "targetProfile": {"id": target.id, "versions": _versions(target)},
            "components": changed,
            "dependencyImpact": dependency_impact,
            "capacity": observed["capacity"],
            "currentHealth": observed["health"],
            "dependencyState": observed["dependencies"],
            "backupEvidence": observed.get("backup"),
            "migration": {
                "required": bool(migrations),
                "items": migrations,
                "rollback": rollback,
                "recovery": transition["recovery"],
            },
            "expectedDowntime": transition["expectedDowntime"],
            "timeoutSeconds": transition["timeoutSeconds"],
        }
        digest = _digest(body)
        plan = {
            "apiVersion": API_VERSION,
            "kind": "ProfileUpgradePlan",
            "id": "upgrade-plan-" + uuid.uuid4().hex,
            **body,
            "planDigest": digest,
            "ready": True,
            "createdAt": _timestamp(now),
            "expiresAt": _timestamp(now + self._ttl),
            "confirmation": f"UPGRADE {source.id} TO {target.id} {digest}",
        }
        self._store.put(plan)
        return plan

    def submit(
        self, plan_id: str, *, identity: ActorIdentity, confirmation: str | None
    ) -> dict[str, Any]:
        plan = self._store.get(plan_id)
        now = self._now()
        if plan.get("kind") != "ProfileUpgradePlan":
            raise UpgradeError("upgrade plan is invalid")
        if identity.source not in STRONG_SOURCES:
            raise UpgradeError("profile upgrades require Web UI or local CLI confirmation")
        if now - identity.authenticated_at.astimezone(timezone.utc) > self._confirmation_age:
            raise UpgradeError("profile upgrade requires fresh authentication")
        if confirmation != plan["confirmation"]:
            raise UpgradeError("profile upgrade confirmation did not match")
        if now >= _datetime(plan["expiresAt"]):
            raise StaleUpgradePlan("upgrade plan has expired")
        target = self._load(plan["targetProfile"]["id"])
        transition = self._transition(target, self._registry.profile.id)
        observed = self._validated_observation(self._registry.profile, target, transition)
        fresh_body = {
            "sourceProfile": {
                "id": self._registry.profile.id,
                "versions": _versions(self._registry.profile),
            },
            "targetProfile": {"id": target.id, "versions": _versions(target)},
            "components": plan["components"],
            "dependencyImpact": list(self._registry.dependency_order()),
            "capacity": observed["capacity"],
            "currentHealth": observed["health"],
            "dependencyState": observed["dependencies"],
            "backupEvidence": observed.get("backup"),
            "migration": plan["migration"],
            "expectedDowntime": transition["expectedDowntime"],
            "timeoutSeconds": transition["timeoutSeconds"],
        }
        if _digest(fresh_body) != plan["planDigest"]:
            raise StaleUpgradePlan("profile versions, state, capacity, health, dependencies, or backup evidence changed")
        if not self._store.consume_plan(plan_id):
            raise StaleUpgradePlan("upgrade plan was already consumed or changed")
        operation = {
            "apiVersion": API_VERSION,
            "kind": "ProfileUpgradeOperation",
            "id": "upgrade-" + uuid.uuid4().hex,
            "planId": plan_id,
            "planDigest": plan["planDigest"],
            "sourceProfileId": plan["sourceProfile"]["id"],
            "targetProfileId": plan["targetProfile"]["id"],
            "actor": identity.actor,
            "confirmationSource": identity.source,
            "state": "queued",
            "currentComponent": None,
            "completedComponents": [],
            "error": None,
            "createdAt": _timestamp(now),
            "updatedAt": _timestamp(now),
            "rollback": plan["migration"]["rollback"],
        }
        self._store.put(operation)
        threading.Thread(
            target=self._run, args=(operation["id"], plan, target), daemon=True
        ).start()
        return operation

    def cancel(self, operation_id: str) -> dict[str, Any]:
        operation = self._store.get(operation_id)
        if operation["state"] not in TERMINAL_STATES:
            self._cancelled.add(operation_id)
            operation["state"] = "cancelling"
            operation["updatedAt"] = _timestamp(self._now())
            self._store.put(operation)
        return operation

    def get(self, document_id: str) -> dict[str, Any]:
        return self._store.get(document_id)

    def _run(
        self, operation_id: str, plan: dict[str, Any], target: PlatformProfile
    ) -> None:
        operation = self._store.get(operation_id)
        operation["state"] = "running"
        self._save(operation)
        deadline = self._monotonic() + plan["timeoutSeconds"]
        cancelled = lambda: operation_id in self._cancelled
        try:
            for component in plan["dependencyImpact"]:
                if cancelled():
                    operation["state"] = "cancelled"
                    return
                operation["currentComponent"] = component
                self._save(operation)
                if component in plan["components"]:
                    self._adapter.upgrade(
                        component, target.component_version(component),
                        deadline=deadline, cancelled=cancelled,
                    )
                if self._monotonic() >= deadline:
                    operation["state"] = "timed-out"
                    operation["error"] = "profile upgrade exceeded its bounded timeout"
                    return
                if not self._verifier.verify_layer(
                    component, deadline=deadline, cancelled=cancelled
                ):
                    raise UpgradeExecutionError(
                        f"health verification failed for {component}"
                    )
                operation["completedComponents"].append(component)
                self._save(operation)
            operation["state"] = "succeeded"
            operation["currentComponent"] = None
        except Exception:
            operation["state"] = "failed"
            operation["error"] = (
                "upgrade failed; inspect component health and follow the plan recovery boundary"
            )
        finally:
            self._cancelled.discard(operation_id)
            self._save(operation)

    def _validated_observation(
        self, source: PlatformProfile, target: PlatformProfile,
        transition: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            observed = self._observe()
        except Exception as error:
            raise UpgradeError("current platform evidence is unavailable") from error
        if observed.get("profileId") != source.id:
            raise UpgradeError("observed source profile does not match")
        if observed.get("versions") != _versions(source):
            raise UpgradeError("observed component versions drift from the source profile")
        capacity = observed.get("capacity", {})
        if any(capacity.get(key, -1) < value for key, value in target.document["capacity"].items()):
            raise UpgradeError("available capacity does not satisfy the target profile")
        health = observed.get("health", {})
        if health.get("state") != "healthy":
            raise UpgradeError("current platform health is not ready for upgrade")
        dependencies = observed.get("dependencies", {})
        if set(dependencies) != set(self._registry.component_ids) or any(
            state != "ready" for state in dependencies.values()
        ):
            raise UpgradeError("component dependency state is incomplete or unhealthy")
        if transition["backupRequired"]:
            backup = observed.get("backup")
            if (
                not isinstance(backup, dict)
                or backup.get("profileId") != source.id
                or not backup.get("complete")
                or not backup.get("verified")
            ):
                raise UpgradeError("a complete verified source-profile backup is required")
        return observed

    @staticmethod
    def _transition(target: PlatformProfile, source_id: str) -> dict[str, Any]:
        upgrade = target.document["upgrade"]
        if source_id not in upgrade["allowedSources"]:
            raise UpgradeError("target profile does not allow the source profile")
        matches = [
            item for item in upgrade.get("transitions", [])
            if item["source"] == source_id
        ]
        if len(matches) != 1:
            raise UpgradeError("target profile lacks one explicit tested transition")
        return matches[0]

    def _save(self, operation: dict[str, Any]) -> None:
        operation["updatedAt"] = _timestamp(self._now())
        self._store.put(operation)

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("upgrade clock must be timezone-aware")
        return value.astimezone(timezone.utc)


def _versions(profile: PlatformProfile) -> dict[str, Any]:
    return {
        component: profile.component_version(component)
        for component in sorted(profile.document["components"])
    }


def _rollback_class(migrations: list[dict[str, Any]]) -> str:
    limitations = {item["rollback"] for item in migrations}
    if "forward-only" in limitations:
        return "forward-only"
    if "restore-required" in limitations:
        return "restore-required"
    return "reversible"


def _digest(document: dict[str, Any]) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _copy(document: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(document))


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
