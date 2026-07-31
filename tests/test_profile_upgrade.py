"""Profile-aware upgrade gates, drift, recovery, and execution tests."""

from __future__ import annotations

import copy
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from manager.authorization import ActorIdentity
from manager.component_registry import ComponentRegistry
from manager.platform_profiles import PlatformProfile
from manager.profile_upgrade import (
    ProfileUpgradeService,
    StaleUpgradePlan,
    UpgradeError,
    UpgradeStore,
)


class Adapter:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fail = False
        self.block = False

    def upgrade(self, component, version, *, deadline, cancelled):
        self.calls.append(component)
        if self.fail:
            raise RuntimeError("database details must not escape")
        while self.block and not cancelled():
            time.sleep(0.001)


class Verifier:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fail: str | None = None

    def verify_layer(self, component, *, deadline, cancelled):
        self.calls.append(component)
        return component != self.fail


class ProfileUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.registry = ComponentRegistry.load()
        source = self.registry.profile
        document = copy.deepcopy(source.document)
        document["id"] = "fortify-24.4-eval.2"
        document["maturity"] = "validated"
        document["evidence"]["level"] = "licensed-live"
        document["cleanInstall"]["status"] = "passed"
        document["components"]["mysql"]["chart"] = "9.20.0"
        document["components"]["ssc"]["chart"] = "24.4.2-2"
        document["upgrade"] = {
            "allowedSources": [source.id],
            "forwardMigration": "Use the declared tested transition.",
            "transitions": [{
                "source": source.id,
                "timeoutSeconds": 600,
                "expectedDowntime": "Up to ten minutes",
                "backupRequired": True,
                "migrations": [{
                    "component": "ssc",
                    "kind": "database",
                    "rollback": "restore-required",
                    "summary": "SSC schema migration",
                }],
                "recovery": "Do not use Helm rollback; restore the verified backup.",
            }],
        }
        self.target = PlatformProfile(document, Path("fixture.json"))
        self.now = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
        self.observed = {
            "profileId": source.id,
            "versions": {
                component: source.component_version(component)
                for component in sorted(source.document["components"])
            },
            "capacity": {"cpuCores": 8, "memoryGiB": 32, "storageGiB": 100},
            "health": {"state": "healthy", "evidenceId": "health-1"},
            "dependencies": {
                component: "ready" for component in self.registry.component_ids
            },
            "backup": {
                "id": "backup-" + "1" * 32,
                "profileId": source.id,
                "complete": True,
                "verified": True,
                "manifestDigest": "sha256:" + "2" * 64,
            },
        }
        self.adapter = Adapter()
        self.verifier = Verifier()
        self.store = UpgradeStore()
        self.service = ProfileUpgradeService(
            self.registry, self.store, self.adapter, self.verifier,
            profile_loader=lambda profile_id: self.target,
            observation_provider=lambda: copy.deepcopy(self.observed),
            clock=lambda: self.now,
        )

    def tearDown(self):
        self.store.close()

    def identity(self, source="web", age=timedelta()) -> ActorIdentity:
        return ActorIdentity("web:operator", source, "session-1", self.now - age)

    def completed(self, operation_id):
        for _ in range(1000):
            result = self.service.get(operation_id)
            if result["state"] in {
                "succeeded", "failed", "cancelled", "timed-out"
            }:
                return result
            time.sleep(0.001)
        self.fail("upgrade did not complete")

    def test_plan_binds_profiles_capacity_health_dependencies_backup_and_migration(self):
        plan = self.service.plan(self.target.id)
        self.assertTrue(plan["ready"])
        self.assertEqual(plan["migration"]["rollback"], "restore-required")
        self.assertEqual(plan["backupEvidence"]["id"], "backup-" + "1" * 32)
        self.assertEqual(plan["timeoutSeconds"], 600)
        self.assertIn("mysql", plan["components"])
        self.assertIn("ssc", plan["components"])
        self.assertIn(plan["planDigest"], plan["confirmation"])

    def test_stale_plan_and_version_drift_are_rejected_before_mutation(self):
        plan = self.service.plan(self.target.id)
        self.observed["health"]["evidenceId"] = "health-2"
        with self.assertRaises(StaleUpgradePlan):
            self.service.submit(
                plan["id"], identity=self.identity(),
                confirmation=plan["confirmation"],
            )
        self.assertEqual(self.adapter.calls, [])

        self.observed["health"]["evidenceId"] = "health-1"
        self.observed["versions"]["mysql"]["chart"] = "drift"
        with self.assertRaises(UpgradeError):
            self.service.plan(self.target.id)

    def test_insufficient_capacity_and_missing_backup_fail_closed(self):
        self.observed["capacity"]["memoryGiB"] = 1
        with self.assertRaisesRegex(UpgradeError, "capacity"):
            self.service.plan(self.target.id)
        self.observed["capacity"]["memoryGiB"] = 32
        self.observed["backup"]["verified"] = False
        with self.assertRaisesRegex(UpgradeError, "backup"):
            self.service.plan(self.target.id)

    def test_migration_requires_fresh_strong_non_telegram_confirmation(self):
        plan = self.service.plan(self.target.id)
        for identity in (
            self.identity("telegram"),
            self.identity(age=timedelta(minutes=6)),
        ):
            with self.assertRaises(UpgradeError):
                self.service.submit(
                    plan["id"], identity=identity,
                    confirmation=plan["confirmation"],
                )
        with self.assertRaises(UpgradeError):
            self.service.submit(
                plan["id"], identity=self.identity(), confirmation="yes"
            )
        self.assertEqual(self.adapter.calls, [])

    def test_success_verifies_every_dependency_layer_and_final_health(self):
        plan = self.service.plan(self.target.id)
        operation = self.service.submit(
            plan["id"], identity=self.identity(),
            confirmation=plan["confirmation"],
        )
        result = self.completed(operation["id"])
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(
            self.verifier.calls, list(self.registry.dependency_order())
        )
        self.assertEqual(result["completedComponents"], self.verifier.calls)
        with self.assertRaises(StaleUpgradePlan):
            self.service.submit(
                plan["id"], identity=self.identity(),
                confirmation=plan["confirmation"],
            )

    def test_failed_migration_is_sanitized_and_stops_later_layers(self):
        self.adapter.fail = True
        plan = self.service.plan(self.target.id)
        operation = self.service.submit(
            plan["id"], identity=self.identity(),
            confirmation=plan["confirmation"],
        )
        result = self.completed(operation["id"])
        self.assertEqual(result["state"], "failed")
        self.assertNotIn("database details", result["error"])
        self.assertEqual(result["rollback"], "restore-required")

    def test_restart_marks_incomplete_upgrade_interrupted(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "upgrade.sqlite3")
            first = UpgradeStore(database)
            first.put({
                "id": "upgrade-incomplete",
                "kind": "ProfileUpgradeOperation",
                "state": "running",
                "error": None,
            })
            first.close()
            second = UpgradeStore(database)
            recovered = second.get("upgrade-incomplete")
            self.assertEqual(recovered["state"], "interrupted")
            self.assertIn("restarted", recovered["error"])
            second.close()

    def test_interruption_is_explicitly_cancelled_without_claiming_rollback(self):
        self.adapter.block = True
        plan = self.service.plan(self.target.id)
        operation = self.service.submit(
            plan["id"], identity=self.identity(),
            confirmation=plan["confirmation"],
        )
        for _ in range(1000):
            if self.adapter.calls:
                break
            time.sleep(0.001)
        self.service.cancel(operation["id"])
        result = self.completed(operation["id"])
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(result["rollback"], "restore-required")


if __name__ == "__main__":
    unittest.main()
