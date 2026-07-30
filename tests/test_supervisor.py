from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "supervisor"))

from fortify_supervisor import (  # noqa: E402
    Config,
    Store,
    Supervisor,
    SupervisorError,
    checks_state,
)


def passing_pr(number: int = 12, sha: str = "abc123") -> dict[str, Any]:
    return {
        "number": number,
        "state": "OPEN",
        "isDraft": True,
        "headRefOid": sha,
        "headRefName": f"agent/issue-{number}",
        "mergeable": "MERGEABLE",
        "mergeStateStatus": "CLEAN",
        "reviewDecision": "",
        "statusCheckRollup": [
            {"name": "repository", "status": "COMPLETED", "conclusion": "SUCCESS"},
            {"name": "secrets", "status": "COMPLETED", "conclusion": "SUCCESS"},
        ],
        "url": f"https://github.test/pull/{number}",
        "mergedAt": None,
    }


class FakeGitHub:
    def __init__(self) -> None:
        self.pr = passing_pr()
        self.discovered: list[dict[str, Any]] = [self.pr]
        self.merges: list[tuple[int, str]] = []
        self.readied: list[int] = []
        self.issue: dict[str, Any] | None = {
            "number": 2,
            "title": "Architecture decisions",
            "url": "https://github.test/issues/2",
        }

    def pull_request(self, number: int) -> dict[str, Any]:
        assert number == int(self.pr["number"])
        return dict(self.pr)

    def discover_pull_requests(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self.discovered]

    def merge(self, number: int, head_sha: str) -> None:
        self.merges.append((number, head_sha))

    def ready(self, number: int) -> None:
        self.readied.append(number)
        self.pr["isDraft"] = False
        self.pr["mergeStateStatus"] = "CLEAN"

    def next_issue(self, milestone: str) -> dict[str, Any] | None:
        assert milestone == "0.1 — Evaluation Foundation"
        return self.issue


class FakeTelegram:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def updates(self, offset: int, timeout: int) -> list[dict[str, Any]]:
        return []

    def send(self, message: str) -> None:
        self.messages.append(message)


class SupervisorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.clock = [1_000.0]
        self.user_file = root / "user"
        self.chat_file = root / "chat"
        self.token_file = root / "token"
        for path, value in (
            (self.user_file, "101"),
            (self.chat_file, "202"),
            (self.token_file, "test-token"),
        ):
            path.write_text(value, encoding="utf-8")
            path.chmod(0o600)
        self.config = Config(
            repository="treisland/fortifylab",
            milestone="0.1 — Evaluation Foundation",
            state_file=root / "state" / "supervisor.db",
            telegram_token_file=self.token_file,
            telegram_user_file=self.user_file,
            telegram_chat_file=self.chat_file,
            approval_ttl_seconds=60,
        )
        self.store = Store(self.config.state_file, now=lambda: self.clock[0])
        self.github = FakeGitHub()
        self.telegram = FakeTelegram()
        self.supervisor = Supervisor(
            self.config, self.store, self.github, self.telegram
        )

    def tearDown(self) -> None:
        self.store.connection.close()
        self.temporary.cleanup()

    def test_checks_state(self) -> None:
        self.assertEqual(checks_state(passing_pr()), "passed")
        pr = passing_pr()
        pr["statusCheckRollup"][0]["status"] = "IN_PROGRESS"
        self.assertEqual(checks_state(pr), "pending")
        pr = passing_pr()
        pr["statusCheckRollup"][0]["conclusion"] = "FAILURE"
        self.assertEqual(checks_state(pr), "failed")

    def test_unauthorized_and_group_commands_are_ignored(self) -> None:
        self.supervisor.handle_update(
            {
                "message": {
                    "text": "/pause",
                    "from": {"id": 999},
                    "chat": {"id": 202, "type": "private"},
                }
            }
        )
        self.supervisor.handle_update(
            {
                "message": {
                    "text": "/pause",
                    "from": {"id": 101},
                    "chat": {"id": 202, "type": "group"},
                }
            }
        )
        self.assertEqual(self.store.get("paused", "false"), "false")
        self.assertEqual(self.telegram.messages, [])

    def test_merge_approval_is_single_use(self) -> None:
        payload = {
            "repository": self.config.repository,
            "pull_request": 12,
            "head_sha": "abc123",
        }
        approval = self.store.create_approval("merge_pr", payload, 60)
        response = self.supervisor.approve(approval["id"], "101")
        self.assertIn("merge approved", response)
        self.assertEqual(self.github.readied, [12])
        self.assertEqual(self.github.merges, [(12, "abc123")])
        with self.assertRaisesRegex(SupervisorError, "already approved"):
            self.supervisor.approve(approval["id"], "101")

    def test_approve_command_resolves_current_approval(self) -> None:
        payload = {
            "repository": self.config.repository,
            "pull_request": 12,
            "head_sha": "abc123",
        }
        self.store.create_approval("merge_pr", payload, 60)
        response = self.supervisor.handle_command("/approve", "101")
        self.assertIn("merge approved", response)
        self.assertEqual(self.github.merges, [(12, "abc123")])

    def test_changed_head_rejects_approval(self) -> None:
        payload = {
            "repository": self.config.repository,
            "pull_request": 12,
            "head_sha": "old-sha",
        }
        approval = self.store.create_approval("merge_pr", payload, 60)
        with self.assertRaisesRegex(SupervisorError, "head changed"):
            self.supervisor.approve(approval["id"], "101")
        self.assertEqual(self.github.merges, [])
        self.assertEqual(self.store.approval(approval["id"])["state"], "pending")

    def test_expired_approval_fails_closed(self) -> None:
        payload = {
            "repository": self.config.repository,
            "pull_request": 12,
            "head_sha": "abc123",
        }
        approval = self.store.create_approval("merge_pr", payload, 60)
        self.clock[0] += 61
        with self.assertRaisesRegex(SupervisorError, "expired"):
            self.supervisor.approve(approval["id"], "101")
        self.assertEqual(self.github.merges, [])

    def test_monitor_deduplicates_merge_approval(self) -> None:
        self.supervisor.monitor_once()
        self.supervisor.monitor_once()
        approvals = self.store.connection.execute(
            "SELECT COUNT(*) AS count FROM approvals"
        ).fetchone()["count"]
        self.assertEqual(approvals, 1)
        self.assertEqual(len(self.telegram.messages), 1)
        self.assertIn("Approve: /approve", self.telegram.messages[0])

    def test_merged_pr_queues_next_issue_once(self) -> None:
        self.store.set("current_pr", "12")
        self.github.pr["state"] = "MERGED"
        self.github.pr["mergedAt"] = "2026-07-30T00:00:00Z"
        self.supervisor.monitor_once()
        self.github.discovered = []
        self.supervisor.monitor_once()
        self.assertEqual(self.store.get("current_issue"), "2")
        self.assertEqual(
            len([message for message in self.telegram.messages if "Queued issue" in message]),
            1,
        )

    def test_reject_command_records_reason(self) -> None:
        payload = {
            "repository": self.config.repository,
            "pull_request": 12,
            "head_sha": "abc123",
        }
        approval = self.store.create_approval("merge_pr", payload, 60)
        response = self.supervisor.handle_command(
            f"/reject {approval['id']} needs changes", "101"
        )
        self.assertIn("rejected", response)
        row = self.store.approval(approval["id"])
        self.assertEqual(row["state"], "rejected")
        self.assertEqual(row["reason"], "needs changes")

    def test_reject_command_resolves_current_approval(self) -> None:
        payload = {
            "repository": self.config.repository,
            "pull_request": 12,
            "head_sha": "abc123",
        }
        approval = self.store.create_approval("merge_pr", payload, 60)
        response = self.supervisor.handle_command("/reject needs changes", "101")
        self.assertIn("rejected", response)
        row = self.store.approval(approval["id"])
        self.assertEqual(row["state"], "rejected")
        self.assertEqual(row["reason"], "needs changes")

    def test_implicit_approval_rejects_ambiguity(self) -> None:
        self.store.create_approval(
            "merge_pr",
            {
                "repository": self.config.repository,
                "pull_request": 12,
                "head_sha": "abc123",
            },
            60,
        )
        self.store.create_approval(
            "merge_pr",
            {
                "repository": self.config.repository,
                "pull_request": 13,
                "head_sha": "def456",
            },
            60,
        )
        with self.assertRaisesRegex(SupervisorError, "Multiple approvals"):
            self.supervisor.handle_command("/approve", "101")


if __name__ == "__main__":
    unittest.main()
