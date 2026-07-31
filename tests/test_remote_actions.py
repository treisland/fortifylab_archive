"""Remote lifecycle approval and recovery safety regression coverage."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from manager.authorization import (
    ActorIdentity,
    ApprovalStore,
    AuthorizationService,
    OperationPlan,
)
from manager.remote_actions import (
    RemoteActionError,
    RemoteActionService,
    RemoteActionStore,
    RemoteActionUnavailable,
)
from manager.telegram_observer import PrivateTelegramObserver
from manager.communications import ReadModelService


class FakeOperations:
    def __init__(self, state="failed"):
        self.document = {
            "id": "11111111-1111-4111-8111-111111111111",
            "operation": "start",
            "requestedTargets": ["ssc"],
            "state": state,
        }

    def get(self, operation_id):
        if operation_id != self.document["id"]:
            raise RuntimeError("operation was not found")
        return dict(self.document)


class FakeEngine:
    def __init__(self, authorization, state):
        self.authorization = authorization
        self.state = state
        self.calls = []
        self.unavailable = False

    def plan(self, operation, targets):
        return {
            "operation": operation,
            "requestedTargets": list(targets),
            "components": list(targets),
            "steps": [
                {
                    "number": 1,
                    "component": targets[0],
                    "operation": operation,
                    "timeoutSeconds": 300,
                    "maxAttempts": 1,
                    "verificationChecks": ["healthy"],
                }
            ],
        }

    def submit_async(
        self, operation, targets, *, actor, identity, approval_id=None, retry_of=None
    ):
        if self.unavailable:
            raise RemoteActionUnavailable("synthetic manager outage")
        plan = OperationPlan(operation, tuple(targets), dict(self.state))
        self.authorization.authorize(
            plan,
            identity,
            approval_id=approval_id,
            state_provider=lambda: dict(self.state),
        )
        self.calls.append(("submit", operation, tuple(targets), actor))
        return {"id": "22222222-2222-4222-8222-222222222222", "state": "queued"}

    def retry_async(self, operation_id, *, actor, identity, approval_id=None):
        self.calls.append(("retry", operation_id, actor))
        return {"id": "33333333-3333-4333-8333-333333333333", "state": "queued"}

    def cancel(self, operation_id, *, actor, identity):
        self.calls.append(("cancel", operation_id, actor))
        return {"id": operation_id, "state": "cancelling"}


class FakeIncident:
    def __init__(self):
        self.calls = []

    def acknowledge(self, incident_id, *, actor):
        self.calls.append((incident_id, actor))
        return {"state": "acknowledged"}


class FakeAutomation:
    def __init__(self):
        self.calls = []

    def pause(self, *, actor):
        self.calls.append(actor)
        return {"state": "paused"}


class FakeTelegram:
    def __init__(self):
        self.messages = []
        self.answers = []

    def send(self, text, markup=None):
        self.messages.append((text, markup))

    def answer_callback(self, callback_id, text):
        self.answers.append((callback_id, text))


class EmptyManager:
    def read(self, resource, *, page=1, page_size=10):
        return {"items": [], "freshness": {"state": "fresh"}, "observedAt": "now"}


class RemoteActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
        root = Path(self.temp.name)
        self.approvals = ApprovalStore(root / "approval.sqlite3")
        self.authorization = AuthorizationService(
            self.approvals, clock=lambda: self.now
        )
        self.callbacks = RemoteActionStore(root / "remote.sqlite3")
        self.state = {"ssc": "running"}
        self.engine = FakeEngine(self.authorization, self.state)
        self.operations = FakeOperations()
        self.incidents = FakeIncident()
        self.automation = FakeAutomation()
        self.service = RemoteActionService(
            self.callbacks,
            self.authorization,
            self.engine,
            self.operations,
            lambda targets: {target: self.state[target] for target in targets},
            "https://manager.example",
            incident_port=self.incidents,
            automation_port=self.automation,
            clock=lambda: self.now,
        )
        self.identity = ActorIdentity(
            "telegram:7", "telegram", "private-chat:11", self.now
        )

    def tearDown(self):
        self.callbacks.close()
        self.approvals.close()
        self.temp.cleanup()

    @staticmethod
    def token(message, label):
        action = next(item for item in message.actions if item.label == label)
        return action.command.token

    def test_plan_is_immutable_bounded_and_contains_required_safety_summary(self):
        message = self.service.lifecycle_plan("stop", ("ssc",), self.identity)
        approval_id = message.replace_key.split(":", 1)[1]
        snapshot = self.callbacks.plan(approval_id)
        self.assertEqual(snapshot["timeoutSeconds"], 300)
        self.assertEqual(snapshot["currentState"], {"ssc": "running"})
        self.assertTrue(snapshot["planDigest"].startswith("sha256:"))
        for text in ("Impact:", "Timeout:", "Rollback boundary:", "Plan digest:"):
            self.assertIn(text, message.text)
        self.state["ssc"] = "stopped"
        self.assertEqual(
            self.callbacks.plan(approval_id)["currentState"], {"ssc": "running"}
        )

    def test_high_risk_and_upgrade_plans_require_web_ui(self):
        for operation in ("uninstall", "delete-data", "upgrade"):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(RemoteActionError, "Web UI"):
                    self.service.lifecycle_plan(operation, ("ssc",), self.identity)

    def test_stale_plan_health_change_fails_and_callback_cannot_replay(self):
        message = self.service.lifecycle_plan("stop", ("ssc",), self.identity)
        token = self.token(message, "Approve")
        self.state["ssc"] = "stopped"
        with self.assertRaisesRegex(RemoteActionError, "current state changed"):
            self.service.execute(token, self.identity)
        with self.assertRaisesRegex(RemoteActionError, "already used"):
            self.service.execute(token, self.identity)
        self.assertEqual(self.engine.calls, [])

    def test_approval_executes_once_and_is_identity_bound(self):
        message = self.service.lifecycle_plan("stop", ("ssc",), self.identity)
        token = self.token(message, "Approve")
        intruder = ActorIdentity(
            "telegram:9", "telegram", "private-chat:11", self.now
        )
        with self.assertRaisesRegex(RemoteActionError, "identity"):
            self.service.execute(token, intruder)
        response = self.service.execute(token, self.identity)
        self.assertIn("Operation queued", response.text)
        with self.assertRaisesRegex(RemoteActionError, "already used"):
            self.service.execute(token, self.identity)
        self.assertEqual(len(self.engine.calls), 1)

    def test_reject_revokes_plan_without_starting_operation(self):
        message = self.service.lifecycle_plan("stop", ("ssc",), self.identity)
        response = self.service.execute(
            self.token(message, "Reject"), self.identity
        )
        approval_id = message.replace_key.split(":", 1)[1]
        self.assertIn("Plan rejected", response.text)
        self.assertEqual(self.approvals.approval(approval_id)["state"], "revoked")
        self.assertEqual(self.engine.calls, [])

    def test_manager_outage_preserves_approval_and_allows_safe_retry(self):
        message = self.service.lifecycle_plan("stop", ("ssc",), self.identity)
        token = self.token(message, "Approve")
        self.engine.unavailable = True
        with self.assertRaises(RemoteActionUnavailable):
            self.service.execute(token, self.identity)
        approval_id = message.replace_key.split(":", 1)[1]
        self.assertEqual(self.approvals.approval(approval_id)["state"], "approved")
        self.engine.unavailable = False
        response = self.service.execute(token, self.identity)
        self.assertIn("Operation queued", response.text)

    def test_expired_callback_and_recovery_actions(self):
        message = self.service.lifecycle_plan("stop", ("ssc",), self.identity)
        self.now += timedelta(minutes=11)
        with self.assertRaisesRegex(RemoteActionError, "expired"):
            self.service.execute(self.token(message, "Approve"), self.identity)

        self.now -= timedelta(minutes=11)
        actions = self.service.recovery_actions(
            incident_id="incident-1",
            operation_id=self.operations.document["id"],
            identity=self.identity,
        )
        by_label = {item.label: item.command.token for item in actions}
        self.service.execute(by_label["Acknowledge"], self.identity)
        self.service.execute(by_label["Safe retry"], self.identity)
        self.service.execute(by_label["Pause automation"], self.identity)
        self.assertEqual(self.incidents.calls, [("incident-1", "telegram:7")])
        self.assertEqual(self.engine.calls[-1][0], "retry")
        self.assertEqual(self.automation.calls, ["telegram:7"])

    def test_recovery_notification_carries_applicable_actions_and_deep_link(self):
        base = ReadModelService(
            EmptyManager(), "https://manager.example"
        ).recovery(
            {
                "type": "health.recovered",
                "subject": {"id": "ssc", "displayName": "SSC"},
                "summary": "Checks pass",
                "occurredAt": "2026-07-31T12:00:00Z",
            }
        )
        notification = self.service.recovery_notification(
            base,
            {
                "incidentId": "incident-1",
                "operationId": self.operations.document["id"],
            },
            self.identity,
        )
        self.assertIn("Open Web UI:", notification.text)
        self.assertEqual(
            {action.label for action in notification.actions},
            {"Acknowledge", "Safe retry", "Pause automation"},
        )

    def test_active_operation_offers_cancel(self):
        self.operations.document["state"] = "running"
        actions = self.service.recovery_actions(
            operation_id=self.operations.document["id"], identity=self.identity
        )
        token = next(item.command.token for item in actions if item.label == "Cancel")
        self.service.execute(token, self.identity)
        self.assertEqual(self.engine.calls[-1][0], "cancel")

    def test_telegram_rejects_unauthorized_callback_before_manager_action(self):
        message = self.service.lifecycle_plan("stop", ("ssc",), self.identity)
        token = self.token(message, "Approve")
        telegram = FakeTelegram()
        adapter = PrivateTelegramObserver(
            ReadModelService(EmptyManager(), "https://manager.example"),
            telegram,
            allowed_user="7",
            allowed_chat="11",
            actions=self.service,
            clock=lambda: self.now,
        )
        update = {
            "callback_query": {
                "id": "cb-1",
                "data": f"act:{token}",
                "from": {"id": 99},
                "message": {"chat": {"id": 11, "type": "private"}},
            }
        }
        self.assertFalse(adapter.handle(update))
        self.assertEqual(self.engine.calls, [])
        self.assertEqual(telegram.answers, [])

    def test_telegram_callback_data_contains_only_opaque_reference(self):
        message = self.service.lifecycle_plan("stop", ("ssc",), self.identity)
        telegram = FakeTelegram()
        adapter = PrivateTelegramObserver(
            ReadModelService(EmptyManager(), "https://manager.example"),
            telegram,
            allowed_user="7",
            allowed_chat="11",
            actions=self.service,
            clock=lambda: self.now,
        )
        adapter._send(message)
        markup = json.loads(telegram.messages[0][1])
        values = [
            button["callback_data"] for button in markup["inline_keyboard"][0]
        ]
        self.assertTrue(all(value.startswith("act:") for value in values))
        self.assertTrue(all(len(value.encode()) <= 64 for value in values))
        self.assertNotIn("ssc", json.dumps(values))


if __name__ == "__main__":
    unittest.main()
