from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "supervisor"))

from fortify_supervisor import (  # noqa: E402
    Config,
    GitHub,
    InlineAction,
    MessageReference,
    Store,
    Supervisor,
    SupervisorError,
    checks_state,
)


class GitHubTest(unittest.TestCase):
    def test_close_issue_accepts_native_closure_race(self) -> None:
        responses = iter(
            [
                subprocess.CompletedProcess([], 0, '{"state":"open"}', ""),
                subprocess.CompletedProcess(
                    [], 1, "", "gh: Validation Failed (HTTP 422)"
                ),
                subprocess.CompletedProcess([], 0, '{"state":"closed"}', ""),
            ]
        )

        def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return next(responses)

        GitHub("treisland/fortifylab", run=run).close_issue(5)


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
        self.closed_issues: list[int] = []
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

    def close_issue(self, number: int) -> None:
        self.closed_issues.append(number)

    def next_issue(
        self, milestone: str, excluded: set[int] | None = None
    ) -> dict[str, Any] | None:
        assert milestone == "0.1 — Evaluation Foundation"
        if self.issue and int(self.issue["number"]) in (excluded or set()):
            return None
        return self.issue


class FakeTelegram:
    def __init__(self) -> None:
        self.messages: list[str] = []
        self.actions: list[tuple[InlineAction, ...]] = []
        self.edits: list[tuple[MessageReference, str, tuple[InlineAction, ...]]] = []
        self.callback_answers: list[tuple[str, str]] = []
        self.fail_edits = False

    def updates(self, offset: int, timeout: int) -> list[dict[str, Any]]:
        return []

    def send(
        self, message: str, actions: tuple[InlineAction, ...] = ()
    ) -> MessageReference:
        self.messages.append(message)
        self.actions.append(actions)
        return MessageReference(str(len(self.messages)))

    def edit(
        self,
        reference: MessageReference,
        message: str,
        actions: tuple[InlineAction, ...] = (),
    ) -> None:
        if self.fail_edits:
            raise SupervisorError("Telegram edit failed")
        self.edits.append((reference, message, actions))

    def answer_callback(self, callback_id: str, message: str) -> None:
        self.callback_answers.append((callback_id, message))


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
        self.assertEqual(self.github.closed_issues, [12])
        self.assertEqual(self.store.get("current_issue"), "2")
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

    def test_final_approval_reports_completed_queue(self) -> None:
        self.github.issue = None
        payload = {
            "repository": self.config.repository,
            "pull_request": 12,
            "head_sha": "abc123",
        }
        self.store.create_approval("merge_pr", payload, 60)
        response = self.supervisor.handle_command("/approve", "101")
        self.assertIn("Milestone 0.1 — Evaluation Foundation is complete", response)
        self.assertNotIn("next issue was selected", response)

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
        self.assertEqual(
            [action.label for action in self.telegram.actions[0]],
            ["Approve", "Reject", "Details", "Pause"],
        )
        for action in self.telegram.actions[0]:
            self.assertNotIn("apr-", action.token)
            self.assertNotIn("/", action.token)

    def test_monitor_supersedes_approval_after_head_change(self) -> None:
        self.supervisor.monitor_once()
        first = self.store.pending_approvals("merge_pr")[0]
        self.github.pr["headRefOid"] = "new-sha"
        self.supervisor.monitor_once()
        self.assertEqual(self.store.approval(first["id"])["state"], "superseded")
        pending = self.store.pending_approvals("merge_pr")
        self.assertEqual(len(pending), 1)
        self.assertEqual(json.loads(pending[0]["payload"])["head_sha"], "new-sha")

    def test_merged_pr_queues_next_issue_once(self) -> None:
        self.store.set("current_pr", "12")
        self.github.pr["state"] = "MERGED"
        self.github.pr["mergedAt"] = "2026-07-30T00:00:00Z"
        self.supervisor.monitor_once()
        self.github.discovered = []
        self.supervisor.monitor_once()
        self.assertEqual(self.store.get("current_issue"), "2")
        self.assertEqual(self.github.closed_issues, [12])
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

    def callback_update(self, token: str, callback_id: str = "cb-1") -> dict[str, Any]:
        return {
            "callback_query": {
                "id": callback_id,
                "data": token,
                "from": {"id": 101},
                "message": {
                    "message_id": 44,
                    "chat": {"id": 202, "type": "private"},
                },
            }
        }

    def action_token(self, label: str) -> str:
        self.supervisor.monitor_once()
        return next(
            action.token
            for action in self.telegram.actions[-1]
            if action.label == label
        )

    def test_inline_approval_consumes_token_and_edits_card(self) -> None:
        token = self.action_token("Approve")
        self.supervisor.handle_update(self.callback_update(token))
        self.assertEqual(self.github.merges, [(12, "abc123")])
        self.assertIn("merge approved", self.telegram.callback_answers[-1][1])
        self.assertEqual(self.telegram.edits[-1][0].message_id, "44")
        event = self.store.connection.execute(
            "SELECT payload FROM events WHERE kind = 'pull_request.merge_approved'"
        ).fetchone()
        self.assertNotIn("approval_id", json.loads(event["payload"]))

    def test_inline_rejection_is_single_use(self) -> None:
        token = self.action_token("Reject")
        self.supervisor.handle_update(self.callback_update(token))
        self.supervisor.handle_update(self.callback_update(token, "cb-2"))
        self.assertIn("rejected", self.telegram.callback_answers[0][1])
        self.assertIn("already used", self.telegram.callback_answers[1][1])

    def test_expired_callback_fails_closed(self) -> None:
        token = self.action_token("Approve")
        self.clock[0] += 61
        self.supervisor.handle_update(self.callback_update(token))
        self.assertEqual(self.github.merges, [])
        self.assertIn("expired", self.telegram.callback_answers[-1][1])

    def test_callback_revalidates_changed_head(self) -> None:
        token = self.action_token("Approve")
        self.github.pr["headRefOid"] = "changed"
        self.supervisor.handle_update(self.callback_update(token))
        self.assertEqual(self.github.merges, [])
        self.assertIn("head changed", self.telegram.callback_answers[-1][1])

    def test_callback_revalidates_checks_and_merge_state(self) -> None:
        token = self.action_token("Approve")
        self.github.pr["statusCheckRollup"][0]["conclusion"] = "FAILURE"
        self.supervisor.handle_update(self.callback_update(token))
        self.assertIn("checks are not passing", self.telegram.callback_answers[-1][1])
        self.github.pr["statusCheckRollup"][0]["conclusion"] = "SUCCESS"
        self.github.pr["mergeStateStatus"] = "DIRTY"
        self.supervisor.handle_update(self.callback_update(token, "cb-2"))
        self.assertIn("merge state is DIRTY", self.telegram.callback_answers[-1][1])

    def test_duplicate_callback_delivery_merges_once(self) -> None:
        token = self.action_token("Approve")
        update = self.callback_update(token)
        self.supervisor.handle_update(update)
        self.supervisor.handle_update(update)
        self.assertEqual(self.github.merges, [(12, "abc123")])
        self.assertIn("already used", self.telegram.callback_answers[-1][1])

    def test_unauthorized_callback_is_ignored(self) -> None:
        token = self.action_token("Pause")
        update = self.callback_update(token)
        update["callback_query"]["from"]["id"] = 999
        self.supervisor.handle_update(update)
        self.assertEqual(self.store.get("paused", "false"), "false")
        self.assertEqual(self.telegram.callback_answers, [])

    def test_telegram_edit_failure_keeps_decision_and_audits_failure(self) -> None:
        token = self.action_token("Reject")
        self.telegram.fail_edits = True
        self.supervisor.handle_update(self.callback_update(token))
        approval = self.store.pending_approvals("merge_pr")
        self.assertEqual(approval, [])
        event = self.store.connection.execute(
            "SELECT payload FROM events "
            "WHERE kind = 'communications.message_edit_failed'"
        ).fetchone()
        self.assertEqual(
            json.loads(event["payload"]),
            {"outcome": "failed", "provider": "telegram"},
        )

    def test_existing_status_card_is_edited_in_place(self) -> None:
        self.store.set("status_message_id", "77")
        self.supervisor.monitor_once()
        self.assertEqual(self.telegram.messages, [])
        self.assertEqual(self.telegram.edits[0][0].message_id, "77")
        self.assertIn(self.config.milestone, self.telegram.edits[0][1])


if __name__ == "__main__":
    unittest.main()
