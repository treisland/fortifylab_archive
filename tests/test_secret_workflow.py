"""Write-only secret replacement and recovery regression coverage."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from manager.authorization import (
    HIGH_RISK_CONFIRMATION,
    ActorIdentity,
    ApprovalStore,
    AuthorizationService,
    AuthorizationError,
    OperationPlan,
)
from manager.component_registry import ComponentRegistry
from manager.secret_workflow import (
    CONFIRM_SSC_KEY,
    InvalidSecretRequest,
    SecretOperationStore,
    SecretSource,
    SecretWorkflow,
)


class RecordingAdapter:
    def __init__(self) -> None:
        self.sources: list[SecretSource] = []
        self.rolled_back: list[str] = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = False

    def replace(self, target, source, *, deadline, cancelled):
        self.sources.append(source)
        self.entered.set()
        if self.block:
            self.release.wait(1)
            if cancelled():
                raise RuntimeError("sensitive adapter detail")
        return "opaque-previous-revision"

    def rollback(self, target, previous_revision, *, deadline):
        self.rolled_back.append(previous_revision)


class RecordingConsumers:
    def __init__(self) -> None:
        self.restarted: list[str] = []
        self.fail_health = False

    def restart(self, component_id, *, deadline, cancelled):
        self.restarted.append(component_id)

    def healthy(self, component_id, *, deadline, cancelled):
        return not self.fail_health


class SecretWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "approved"
        self.root.mkdir(mode=0o700)
        self.store = SecretOperationStore(Path(self.temp.name) / "secret-ops.db")
        self.approvals = ApprovalStore(Path(self.temp.name) / "approvals.db")
        self.auth = AuthorizationService(self.approvals)
        self.identity = ActorIdentity(
            "local:operator", "web", "session-1", datetime.now(timezone.utc)
        )
        self.adapter = RecordingAdapter()
        self.consumers = RecordingConsumers()
        self.workflow = SecretWorkflow(
            ComponentRegistry.load(),
            self.store,
            self.adapter,
            self.consumers,
            self.auth,
            allowed_external_roots=(self.root,),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.approvals.close()
        self.temp.cleanup()

    def approval(self, target: str, source_type: str = "upload") -> str:
        component_id, secret_id = target.split("/")
        approval = self.workflow.request_approval(
            component_id, secret_id, source_type, identity=self.identity
        )
        self.auth.approve(
            approval["id"], self.identity, confirmation=HIGH_RISK_CONFIRMATION
        )
        return approval["id"]

    def test_upload_replacement_returns_and_persists_metadata_only(self) -> None:
        marker = b"unique-sensitive-upload-marker"
        result = self.workflow.replace(
            "scancentral-sast",
            "controller-token",
            SecretSource.upload(marker),
            identity=self.identity,
            approval_id=self.approval("scancentral-sast/controller-token"),
        )

        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(result["sourceType"], "upload")
        self.assertNotIn("value", json.dumps(result))
        self.assertNotIn(marker, Path(self.store.path).read_bytes())
        self.assertEqual(self.adapter.sources[0].value, marker)
        self.assertIn("scancentral-sast", result["restartedConsumers"])
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "registry/schemas/secret-update.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)

    def test_invalid_sources_fail_before_authorization_or_adapter(self) -> None:
        outside = Path(self.temp.name) / "outside"
        outside.write_text("not-a-real-secret", encoding="utf-8")
        outside.chmod(0o600)
        with self.assertRaisesRegex(InvalidSecretRequest, "outside allowed roots"):
            self.workflow.replace(
                "scancentral-sast", "controller-token",
                SecretSource.external_path(str(outside)),
                identity=self.identity, approval_id="unused",
            )
        with self.assertRaises(InvalidSecretRequest):
            self.workflow.replace(
                "scancentral-sast", "controller-token",
                SecretSource.kubernetes_secret("../../bad", "token"),
                identity=self.identity, approval_id="unused",
            )
        self.assertEqual(self.adapter.sources, [])

    def test_external_path_and_existing_secret_references_are_supported(self) -> None:
        protected = self.root / "license"
        protected.write_text("synthetic-license-material", encoding="utf-8")
        protected.chmod(0o600)
        path_result = self.workflow.replace(
            "scancentral-sast", "fortify-license",
            SecretSource.external_path(str(protected)),
            identity=self.identity,
            approval_id=self.approval(
                "scancentral-sast/fortify-license", "external-path"
            ),
        )
        self.assertEqual(path_result["state"], "succeeded")
        self.assertNotIn(str(protected), json.dumps(path_result))

        target = "mysql/root-password"
        ref_result = self.workflow.replace(
            "mysql", "root-password",
            SecretSource.kubernetes_secret("managed-database", "password"),
            identity=self.identity,
            approval_id=self.approval(target, "kubernetes-secret"),
        )
        self.assertEqual(ref_result["sourceType"], "kubernetes-secret")

    def test_generated_values_are_policy_limited_and_never_returned(self) -> None:
        result = self.workflow.replace(
            "scancentral-sast", "controller-token", SecretSource.generated(),
            identity=self.identity,
            approval_id=self.approval(
                "scancentral-sast/controller-token", "generated"
            ),
        )
        self.assertEqual(result["state"], "succeeded")
        with self.assertRaisesRegex(InvalidSecretRequest, "not allowed"):
            self.workflow.replace(
                "scancentral-sast", "fortify-license", SecretSource.generated(),
                identity=self.identity, approval_id="unused",
            )

    def test_approval_is_bound_to_source_class(self) -> None:
        approval_id = self.approval(
            "scancentral-sast/controller-token", "generated"
        )
        with self.assertRaisesRegex(AuthorizationError, "plan or current state changed"):
            self.workflow.replace(
                "scancentral-sast", "controller-token",
                SecretSource.upload(b"not-approved-for-upload"),
                identity=self.identity, approval_id=approval_id,
            )
        self.assertEqual(self.adapter.sources, [])

    def test_restart_failure_rolls_back_opaque_revision(self) -> None:
        self.consumers.fail_health = True
        result = self.workflow.replace(
            "mysql", "root-password", SecretSource.upload(b"replacement"),
            identity=self.identity,
            approval_id=self.approval("mysql/root-password"),
        )
        self.assertEqual(result["state"], "rolled-back")
        self.assertEqual(self.adapter.rolled_back, ["opaque-previous-revision"])
        self.assertNotIn("replacement", json.dumps(result))

    def test_ssc_key_requires_backup_confirmation_and_cannot_be_generated(self) -> None:
        with self.assertRaisesRegex(InvalidSecretRequest, "verified persistent-data backup"):
            self.workflow.replace(
                "ssc", "ssc-material", SecretSource.upload(b"replacement-key"),
                identity=self.identity, approval_id="unused",
            )
        result = self.workflow.replace(
            "ssc", "ssc-material", SecretSource.upload(b"replacement-key"),
            identity=self.identity,
            approval_id=self.approval("ssc/ssc-material"),
            backup_verified=True, ssc_confirmation=CONFIRM_SSC_KEY,
        )
        self.assertEqual(result["state"], "succeeded")
        self.assertTrue(result["impact"]["persistentDataBackupRequired"])
        with self.assertRaises(InvalidSecretRequest):
            self.workflow.replace(
                "ssc", "ssc-material", SecretSource.generated(),
                identity=self.identity, approval_id="unused",
                backup_verified=True, ssc_confirmation=CONFIRM_SSC_KEY,
            )

    def test_telegram_cannot_authorize_secret_replacement(self) -> None:
        telegram = ActorIdentity(
            "local:operator", "telegram", "telegram-1", datetime.now(timezone.utc)
        )
        plan = OperationPlan(
            "replace-secret", ("mysql/root-password",),
            {"mysql/root-password": "unmanaged", "sourceType": "upload"},
        )
        approval = self.auth.request(plan, telegram)
        with self.assertRaisesRegex(AuthorizationError, "local CLI or Web UI"):
            self.auth.approve(
                approval["id"], telegram, confirmation=HIGH_RISK_CONFIRMATION
            )

    def test_interrupted_update_is_fenced_and_requires_resubmission(self) -> None:
        self.store.create(
            {
                "id": "incomplete", "state": "applying",
                "target": "mysql/root-password",
                "updatedAt": "2026-01-01T00:00:00Z",
            }
        )
        self.store.close()
        self.store = SecretOperationStore(Path(self.temp.name) / "secret-ops.db")
        recovered = self.store.get("incomplete")
        self.assertEqual(recovered["state"], "interrupted")
        self.assertIn("submit a new replacement", recovered["recovery"])
        self.assertNotIn("value", recovered)


if __name__ == "__main__":
    unittest.main()
