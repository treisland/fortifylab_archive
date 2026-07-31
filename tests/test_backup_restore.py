"""Release-gate coverage for component-aware verified recovery."""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from manager.backup_restore import (
    BACKUP_SCOPES,
    RESTORE_CONFIRMATION,
    Destination,
    IncompatibleBackup,
    IncompleteArtifact,
    RecoveryError,
    RecoveryService,
    RecoveryStore,
    UnixRecoveryAdapter,
)


class FakeAdapter:
    def __init__(self) -> None:
        self.calls = []
        self.fail_backup = None
        self.fail_restore = None
        self.verification_state = "passed"

    def backup(self, backup_id, scope, cancelled):
        self.calls.append(("backup", scope))
        if scope == self.fail_backup:
            raise RuntimeError("/protected/path and password must not escape")
        return {"checksum": "sha256:" + scope.replace("-", "")}

    def restore(self, backup_id, scope, cancelled):
        self.calls.append(("restore", scope))
        if scope == self.fail_restore:
            raise RuntimeError("database said secret-value")
        return {"state": "succeeded"}

    def verify(self, backup_id, checks):
        self.calls.append(("verify", checks))
        return [
            {
                "check": check,
                "state": self.verification_state,
                "code": "OK",
                "protectedPath": "/not/exposed",
                "detail": "credential",
            }
            for check in checks
        ]


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "recovery.sqlite3"
        self.store = RecoveryStore(self.path)
        self.adapter = FakeAdapter()
        self.service = RecoveryService(
            self.store,
            self.adapter,
            profile_id="fortify-24.4-eval.1",
            destination=Destination("primary", "local-protected", 30),
        )

    def tearDown(self):
        self.assertTrue(self.service.wait_for_idle(2))
        self.store.close()
        self.temp.cleanup()

    def completed(self, operation_id):
        for _ in range(200):
            document = self.store.operation(operation_id)
            if document["state"] in {"succeeded", "failed", "cancelled", "interrupted"}:
                return document
            time.sleep(0.005)
        self.fail("recovery operation did not complete")

    def backup(self):
        operation = self.service.submit_backup(actor="local-cli:operator")
        completed = self.completed(operation["id"])
        self.assertEqual(completed["state"], "succeeded")
        return completed["backupId"]

    def test_plan_covers_required_state_without_values_or_paths(self):
        plan = self.service.backup_plan()
        self.assertEqual(tuple(plan["scope"]), BACKUP_SCOPES)
        self.assertIn("SQLite", plan["consistency"]["manager-state"])
        self.assertIn("logical database", plan["consistency"]["mysql-ssc"])
        self.assertEqual(plan["destination"]["id"], "primary")
        self.assertTrue(plan["retention"]["independentOfUninstallAndDataDeletion"])
        rendered = str(plan)
        self.assertNotIn("/var/", rendered)
        self.assertNotIn("/etc/", rendered)
        self.assertFalse(plan["secretValuesExposed"])

    def test_successful_backup_and_verified_recovery(self):
        backup_id = self.backup()
        artifact = self.store.artifact(backup_id)
        self.assertEqual(set(artifact["checksums"]), set(BACKUP_SCOPES))
        operation = self.service.submit_restore(
            backup_id, actor="web:operator", confirmation=RESTORE_CONFIRMATION
        )
        restored = self.completed(operation["id"])
        self.assertEqual(restored["state"], "succeeded")
        self.assertEqual(
            [scope for action, scope in self.adapter.calls if action == "restore"],
            list(reversed(BACKUP_SCOPES)),
        )
        self.assertTrue(restored["evidence"])
        self.assertEqual(set(restored["evidence"][0]), {"check", "state", "code"})

    def test_incomplete_artifact_from_failed_backup_cannot_restore(self):
        self.adapter.fail_backup = "mysql-ssc"
        operation = self.service.submit_backup(actor="local-cli:operator")
        failed = self.completed(operation["id"])
        self.assertEqual(failed["state"], "failed")
        self.assertNotIn("protected", failed["error"])
        with self.assertRaises(IncompleteArtifact):
            self.store.artifact(failed["backupId"])
        with self.assertRaises(IncompleteArtifact):
            self.service.submit_restore(
                failed["backupId"], actor="web:operator",
                confirmation=RESTORE_CONFIRMATION,
            )

    def test_wrong_profile_is_visible_in_plan_and_blocked(self):
        backup_id = self.backup()
        other = RecoveryService(
            self.store, self.adapter, profile_id="fortify-25.1",
            destination=Destination("primary", "local-protected", 30),
        )
        plan = other.restore_plan(backup_id)
        self.assertFalse(plan["compatible"])
        with self.assertRaises(IncompatibleBackup):
            other.submit_restore(
                backup_id, actor="local-cli:operator",
                confirmation=RESTORE_CONFIRMATION,
            )

    def test_restore_requires_exact_confirmation_and_records_safe_failure(self):
        backup_id = self.backup()
        with self.assertRaisesRegex(RecoveryError, "exact typed"):
            self.service.submit_restore(
                backup_id, actor="web:operator", confirmation="yes"
            )
        self.adapter.fail_restore = "postgresql-dast"
        operation = self.service.submit_restore(
            backup_id, actor="web:operator", confirmation=RESTORE_CONFIRMATION
        )
        failed = self.completed(operation["id"])
        self.assertEqual(failed["state"], "failed")
        self.assertNotIn("secret-value", failed["error"])
        self.assertIn("follow the recovery plan", failed["error"])

    def test_application_verification_failure_fails_restore(self):
        backup_id = self.backup()
        self.adapter.verification_state = "failed"
        operation = self.service.submit_restore(
            backup_id, actor="web:operator", confirmation=RESTORE_CONFIRMATION
        )
        failed = self.completed(operation["id"])
        self.assertEqual(failed["state"], "failed")
        self.assertIn("verification failed", failed["error"])

    def test_wait_for_idle_is_bounded_and_prevents_store_close_races(self):
        release = threading.Event()
        original = self.adapter.backup

        def blocked(*args):
            release.wait(1)
            return original(*args)

        self.adapter.backup = blocked
        self.service.submit_backup(actor="local-cli:operator")
        self.assertFalse(self.service.wait_for_idle(0.01))
        release.set()
        self.assertTrue(self.service.wait_for_idle(2))

    def test_restart_marks_active_operation_interrupted(self):
        document = self.service._new_operation(
            "backup", "backup-interrupted", "local-cli:operator"
        )
        document["state"] = "running"
        self.store.put_operation(document)
        self.store.close()
        self.store = RecoveryStore(self.path)
        interrupted = self.store.operation(document["id"])
        self.assertEqual(interrupted["state"], "interrupted")
        self.assertIn("Manager restarted", interrupted["error"])

    def test_unix_adapter_restore_and_verify_use_only_fixed_identifiers(self):
        adapter = UnixRecoveryAdapter(Path("/protected/helper.sock"))
        reply = (
            b'{"apiVersion":"fortifylab.io/v1alpha1",'
            b'"kind":"RecoveryHelperResult","state":"succeeded",'
            b'"evidence":[{"check":"ssc-readiness","state":"passed","code":"OK"}]}\n'
        )
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.recv.side_effect = [reply, reply]
        with (
            patch.object(Path, "stat") as path_stat,
            patch("manager.backup_restore.socket.socket", return_value=connection),
        ):
            path_stat.return_value.st_mode = 0o140660
            adapter.restore("backup-" + "a" * 32, "mysql-ssc", lambda: False)
            evidence = adapter.verify(
                "backup-" + "a" * 32, ("ssc-readiness",)
            )
        self.assertEqual(evidence[0]["state"], "passed")
        requests = b"".join(call.args[0] for call in connection.sendall.call_args_list)
        self.assertIn(b'"action":"restore"', requests)
        self.assertIn(b'"action":"verify"', requests)
        self.assertNotIn(b'"path"', requests)
        self.assertNotIn(b'"secret"', requests)


if __name__ == "__main__":
    unittest.main()
