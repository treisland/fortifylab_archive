"""Risk policy, approval binding, and replay regression coverage."""

from __future__ import annotations

import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from manager.authorization import (
    HIGH_RISK_CONFIRMATION,
    ActorIdentity,
    ApprovalStore,
    ApprovalUnavailable,
    AuthorizationError,
    AuthorizationService,
    OperationPlan,
)


class AuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.now = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
        self.store = ApprovalStore(Path(self.temp.name) / "approvals.sqlite3")
        self.service = AuthorizationService(
            self.store, clock=lambda: self.now, approval_ttl=timedelta(minutes=10)
        )
        self.web = ActorIdentity("local:operator", "web", "session-1", self.now)
        self.telegram = ActorIdentity(
            "local:operator", "telegram", "telegram-session", self.now
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    @staticmethod
    def plan(operation: str = "stop", state: str = "running") -> OperationPlan:
        return OperationPlan(operation, ("ssc",), {"ssc": state})

    def approved(self, plan: OperationPlan | None = None) -> tuple[OperationPlan, str]:
        plan = plan or self.plan()
        approval = self.service.request(plan, self.web)
        self.service.approve(approval["id"], self.web)
        return plan, approval["id"]

    def test_unauthenticated_or_wrong_actor_cannot_approve_or_consume(self) -> None:
        plan = self.plan()
        approval = self.service.request(plan, self.web)
        intruder = ActorIdentity("local:other", "web", "session-2", self.now)
        with self.assertRaisesRegex(AuthorizationError, "actor or session"):
            self.service.approve(approval["id"], intruder)
        self.service.approve(approval["id"], self.web)
        with self.assertRaisesRegex(AuthorizationError, "actor or session"):
            self.service.authorize(plan, intruder, approval_id=approval["id"])

    def test_expired_approval_fails_closed(self) -> None:
        plan = self.plan()
        approval = self.service.request(plan, self.web)
        self.now += timedelta(minutes=11)
        with self.assertRaisesRegex(AuthorizationError, "expired"):
            self.service.approve(approval["id"], self.web)

    def test_plan_or_current_state_change_invalidates_approval(self) -> None:
        plan, approval_id = self.approved()
        with self.assertRaisesRegex(AuthorizationError, "plan or current state changed"):
            self.service.authorize(
                plan,
                self.web,
                approval_id=approval_id,
                state_provider=lambda: {"ssc": "stopped"},
            )

    def test_consumption_is_single_use_and_audited(self) -> None:
        plan, approval_id = self.approved()
        self.service.authorize(plan, self.web, approval_id=approval_id)
        with self.assertRaises(AuthorizationError):
            self.service.authorize(plan, self.web, approval_id=approval_id)
        self.assertEqual(self.store.approval(approval_id)["state"], "consumed")
        outcomes = [(row["action"], row["outcome"]) for row in self.store.audit()]
        self.assertIn(("authorize", "accepted"), outcomes)
        self.assertIn(("authorize", "denied"), outcomes)

    def test_only_one_concurrent_approval_decision_wins(self) -> None:
        approval = self.service.request(self.plan(), self.web)
        outcomes: list[str] = []

        def decide() -> None:
            try:
                self.service.approve(approval["id"], self.web)
                outcomes.append("approved")
            except AuthorizationError:
                outcomes.append("denied")

        workers = [threading.Thread(target=decide) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertCountEqual(outcomes, ["approved", "denied"])

    def test_provider_outage_does_not_consume_approval(self) -> None:
        plan, approval_id = self.approved()

        def unavailable() -> dict[str, str]:
            raise RuntimeError("synthetic outage")

        with self.assertRaises(ApprovalUnavailable):
            self.service.authorize(
                plan, self.web, approval_id=approval_id, state_provider=unavailable
            )
        self.assertEqual(self.store.approval(approval_id)["state"], "approved")

    def test_high_risk_cannot_be_downgraded_by_telegram(self) -> None:
        plan = self.plan("delete-data")
        approval = self.service.request(plan, self.telegram)
        with self.assertRaisesRegex(AuthorizationError, "local CLI or Web UI"):
            self.service.approve(
                approval["id"],
                self.telegram,
                confirmation=HIGH_RISK_CONFIRMATION,
            )

    def test_high_risk_requires_fresh_strong_confirmation(self) -> None:
        plan = self.plan("upgrade")
        approval = self.service.request(plan, self.web)
        with self.assertRaisesRegex(AuthorizationError, "confirmation"):
            self.service.approve(approval["id"], self.web)
        self.service.approve(
            approval["id"], self.web, confirmation=HIGH_RISK_CONFIRMATION
        )

        stale = ActorIdentity(
            "local:operator", "local-cli", "terminal-1",
            self.now - timedelta(minutes=6),
        )
        approval = self.service.request(plan, stale)
        with self.assertRaisesRegex(AuthorizationError, "fresh authentication"):
            self.service.approve(
                approval["id"], stale, confirmation=HIGH_RISK_CONFIRMATION
            )

    def test_revocation_prevents_use(self) -> None:
        plan, approval_id = self.approved()
        self.service.revoke(approval_id, self.web)
        with self.assertRaisesRegex(AuthorizationError, "not approved"):
            self.service.authorize(plan, self.web, approval_id=approval_id)

    def test_routine_operation_needs_identity_but_not_approval(self) -> None:
        self.service.authorize(self.plan("start"), self.web)
        self.assertEqual(self.store.audit()[-1]["reason"], "routine")


if __name__ == "__main__":
    unittest.main()
