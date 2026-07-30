from __future__ import annotations

import dataclasses
import datetime
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
    NotificationPreferences,
    Store,
    Supervisor,
    SupervisorError,
    checks_state,
    sanitize_diagnostics,
)
from workflow_status import heartbeat_interval, render_stall  # noqa: E402


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

    def test_next_issue_prioritizes_queue_next_then_number(self) -> None:
        issues = [
            {"number": 22, "title": "Health", "url": "", "labels": []},
            {
                "number": 31,
                "title": "Telegram recovery",
                "url": "",
                "labels": [{"name": "queue:next"}],
            },
            {
                "number": 30,
                "title": "Telegram approvals",
                "url": "",
                "labels": [{"name": "queue:next"}],
            },
        ]

        def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, json.dumps(issues), "")

        issue = GitHub("treisland/fortifylab", run=run).next_issue("0.2")
        self.assertIsNotNone(issue)
        self.assertEqual(issue["number"], 30)


class ConfigTest(unittest.TestCase):
    def test_notification_preferences_require_protected_external_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_file = root / "supervisor.toml"
            for name in ("token", "user", "chat"):
                path = root / name
                path.write_text(name, encoding="utf-8")
                path.chmod(0o600)
            config_file.write_text(
                f"""
[supervisor]
repository = "owner/repository"
milestone = "test"
state_file = "{root / 'state.db'}"
telegram_token_file = "{root / 'token'}"
telegram_user_file = "{root / 'user'}"
telegram_chat_file = "{root / 'chat'}"

[notifications]
mode = "failures"
quiet_start = "22:00"
quiet_end = "07:00"
timezone = "UTC"
retry_stages = ["checks"]
rejection_reasons = ["changes-required"]
""",
                encoding="utf-8",
            )
            config_file.chmod(0o644)
            with self.assertRaisesRegex(SupervisorError, "group/world"):
                Config.load(config_file)
            config_file.chmod(0o600)
            config = Config.load(config_file)
            self.assertEqual(config.notifications.mode, "failures")


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
        self.created_issues: list[tuple[str, str]] = []
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

    def create_failure_issue(self, title: str, body: str) -> str:
        self.created_issues.append((title, body))
        return "https://github.test/issues/99"

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
        self.fail_sends = False

    def updates(self, offset: int, timeout: int) -> list[dict[str, Any]]:
        return []

    def send(
        self, message: str, actions: tuple[InlineAction, ...] = ()
    ) -> MessageReference:
        if self.fail_sends:
            raise SupervisorError("Telegram send failed")
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
        self.root = root
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
            notifications=NotificationPreferences(retry_stages=("checks",)),
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

    def test_maintenance_merge_does_not_advance_issue_queue(self) -> None:
        self.github.pr["headRefName"] = "maintenance/supervisor-installer"
        payload = {
            "repository": self.config.repository,
            "pull_request": 12,
            "head_sha": "abc123",
        }
        self.store.create_approval("merge_pr", payload, 60)
        response = self.supervisor.handle_command("/approve", "101")
        self.assertIn("maintenance PR did not advance", response)
        self.assertEqual(self.store.get("current_issue"), "")
        self.assertEqual(self.github.closed_issues, [])

    def test_paused_supervisor_does_not_start_next_issue_after_merge(self) -> None:
        self.store.set("paused", "true")
        payload = {
            "repository": self.config.repository,
            "pull_request": 12,
            "head_sha": "abc123",
        }
        self.store.create_approval("merge_pr", payload, 60)
        response = self.supervisor.handle_command("/approve", "101")
        self.assertIn("supervisor is paused", response)
        self.assertEqual(self.store.get("current_issue"), "")
        self.assertEqual(self.github.closed_issues, [12])

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
        self.assertEqual(len(self.telegram.messages), 3)
        self.assertEqual(
            [action.label for action in self.telegram.actions[-1]],
            [
                "Approve",
                "Reject",
                "Status",
                "Details",
                "Refresh",
                "Unwatch",
                "Pause",
            ],
        )
        for action in self.telegram.actions[-1]:
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
            f"/reject {approval['id']} changes-required", "101"
        )
        self.assertIn("rejected", response)
        row = self.store.approval(approval["id"])
        self.assertEqual(row["state"], "rejected")
        self.assertEqual(row["reason"], "changes-required")

    def test_reject_command_resolves_current_approval(self) -> None:
        payload = {
            "repository": self.config.repository,
            "pull_request": 12,
            "head_sha": "abc123",
        }
        approval = self.store.create_approval("merge_pr", payload, 60)
        response = self.supervisor.handle_command("/reject changes-required", "101")
        self.assertIn("rejected", response)
        row = self.store.approval(approval["id"])
        self.assertEqual(row["state"], "rejected")
        self.assertEqual(row["reason"], "changes-required")

    def test_rejection_reason_must_be_predefined(self) -> None:
        self.store.create_approval(
            "merge_pr",
            {
                "repository": self.config.repository,
                "pull_request": 12,
                "head_sha": "abc123",
            },
            60,
        )
        with self.assertRaisesRegex(SupervisorError, "Choose a rejection reason"):
            self.supervisor.handle_command("/reject free-form", "101")

    def test_quiet_hours_defer_and_digest_rolls_over(self) -> None:
        self.config = dataclasses.replace(
            self.config,
            notifications=NotificationPreferences(
                quiet_start="00:00",
                quiet_end="01:00",
                timezone="UTC",
                digest_hour=1,
            ),
        )
        self.clock[0] = 1_800.0  # 1970-01-01 00:30 UTC
        self.supervisor = Supervisor(
            self.config, self.store, self.github, self.telegram
        )
        self.supervisor.notify_once("quiet-1", "test.info", "deferred", {})
        self.assertEqual(self.telegram.messages, [])
        self.clock[0] = 90_000.0  # next day, after the digest boundary
        self.supervisor.deliver_digest()
        self.assertIn("Fortify SDLC digest", self.telegram.messages[0])

    def test_duplicate_events_edit_one_notification(self) -> None:
        self.supervisor.notify_once("duplicate-1", "test.failure", "failed", {}, "failure")
        self.supervisor.notify_once("duplicate-1", "test.failure", "failed", {}, "failure")
        self.assertEqual(len(self.telegram.messages), 1)
        self.assertEqual(len(self.telegram.edits), 1)
        self.assertIn("Occurrences: 2", self.telegram.edits[0][1])

    def test_transient_delivery_failure_never_advances_and_retries(self) -> None:
        self.telegram.fail_sends = True
        self.supervisor.notify_once("transient-1", "test.failure", "failed", {}, "failure")
        self.assertEqual(self.store.get("paused", "false"), "false")
        self.assertEqual(self.github.merges, [])
        row = self.store.connection.execute(
            "SELECT state FROM notifications WHERE fingerprint = 'transient-1'"
        ).fetchone()
        self.assertEqual(row["state"], "pending")
        self.telegram.fail_sends = False
        self.supervisor.notify_once("transient-1", "test.failure", "failed", {}, "failure")
        self.assertEqual(self.telegram.messages, ["failed\nOccurrences: 2"])

    def write_heartbeat(
        self,
        *,
        elapsed: int = 0,
        phase: str = "implementing",
        health: str = "active",
        revision: int = 1,
        activity_age: int = 0,
    ) -> None:
        root = self.root / "runner-heartbeats"
        root.mkdir(exist_ok=True)
        started = self.clock[0] - elapsed
        activity = self.clock[0] - activity_age
        stamp = lambda value: datetime.datetime.fromtimestamp(  # noqa: E731
            value, datetime.timezone.utc
        ).isoformat().replace("+00:00", "Z")
        (root / "issue-2.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "issue": 2,
                    "milestone": self.config.milestone,
                    "writer_id": "a" * 32,
                    "generation": 1,
                    "revision": revision,
                    "phase": phase,
                    "phase_started_at": stamp(started),
                    "started_at": stamp(started),
                    "total_elapsed_seconds": elapsed,
                    "last_activity_at": stamp(activity),
                    "runner_health": health,
                    "changed_file_count": 3,
                    "validation_state": "running",
                    "pr_reference": None,
                    "next_expected_transition": "testing",
                    "last_completed_safe_step": "repository inspection",
                }
            ),
            encoding="utf-8",
        )
        self.config = dataclasses.replace(self.config, heartbeat_root=root)
        self.store.set("current_issue", "2")
        self.store.set("current_issue_title", "Detailed workflow cards")
        self.supervisor = Supervisor(
            self.config, self.store, self.github, self.telegram
        )

    def test_adaptive_heartbeat_intervals(self) -> None:
        self.assertEqual(heartbeat_interval(599), 600)
        self.assertEqual(heartbeat_interval(600), 900)
        self.assertEqual(heartbeat_interval(3599), 900)
        self.assertEqual(heartbeat_interval(3600), 1800)

    def test_start_and_ten_minute_heartbeat_are_real_notifications(self) -> None:
        self.clock[0] = 10_000
        self.write_heartbeat(elapsed=600)
        self.supervisor.monitor_runner()
        self.assertEqual(len(self.telegram.messages), 2)
        self.assertIn("Work started", self.telegram.messages[0])
        self.assertIn("Changed files: 3", self.telegram.messages[1])

    def test_restart_deduplicates_heartbeat_delivery(self) -> None:
        self.clock[0] = 10_000
        self.write_heartbeat(elapsed=600)
        self.supervisor.monitor_runner()
        delivered = len(self.telegram.messages)
        restarted = Supervisor(self.config, self.store, self.github, self.telegram)
        restarted.monitor_runner()
        self.assertEqual(len(self.telegram.messages), delivered)

    def test_quiet_hours_suppress_routine_but_not_stall(self) -> None:
        self.clock[0] = 1_800
        self.write_heartbeat(elapsed=900, health="stalled", activity_age=900)
        self.config = dataclasses.replace(
            self.config,
            notifications=NotificationPreferences(
                quiet_start="00:00", quiet_end="01:00", timezone="UTC"
            ),
        )
        self.supervisor = Supervisor(
            self.config, self.store, self.github, self.telegram
        )
        self.supervisor.monitor_runner()
        self.assertEqual(len(self.telegram.messages), 3)
        self.assertTrue(any("stalled" in item for item in self.telegram.messages))

    def test_stall_recovery_and_no_output_evidence(self) -> None:
        self.clock[0] = 10_000
        self.write_heartbeat(elapsed=1800, health="stalled", activity_age=1800)
        self.supervisor.monitor_runner()
        self.assertTrue(
            any(
                "Last safe step: repository inspection" in item
                for item in self.telegram.messages
            )
        )
        self.write_heartbeat(
            elapsed=1810, health="active", activity_age=0, revision=2
        )
        self.supervisor.monitor_runner()
        self.assertTrue(any("recovered" in item for item in self.telegram.messages))

    def test_stop_requires_second_identity_bound_confirmation(self) -> None:
        calls: list[list[str]] = []

        def run(command: list[str], **kwargs: Any) -> None:
            calls.append(command)

        self.config = dataclasses.replace(
            self.config, runner_stop_command=("/bin/true",)
        )
        self.store.set("current_issue", "2")
        self.supervisor = Supervisor(
            self.config, self.store, self.github, self.telegram, run=run
        )
        stop = next(
            action.token
            for action in self.supervisor.workflow_actions()
            if action.label == "Stop"
        )
        outcome = self.supervisor.execute_callback(stop, "101")
        confirm = outcome.split(":", 1)[1]
        with self.assertRaisesRegex(SupervisorError, "another identity"):
            self.supervisor.execute_callback(confirm, "999")
        self.assertEqual(calls, [])
        self.supervisor.execute_callback(confirm, "101")
        self.assertEqual(calls, [["/bin/true", "2"]])
        event = self.store.connection.execute(
            "SELECT kind FROM events WHERE kind = 'runner.stop_requested'"
        ).fetchone()
        self.assertIsNotNone(event)

    def test_retry_requires_allowlisted_stage_and_matching_failure(self) -> None:
        self.supervisor.notify_once(
            "checks-1",
            "test.failure",
            "checks failed",
            {"stage": "checks"},
            "failure",
        )
        self.assertIn(
            "Retry requested",
            self.supervisor.handle_command("/retry checks", "101"),
        )
        with self.assertRaisesRegex(SupervisorError, "not allowed"):
            self.supervisor.handle_command("/retry deploy", "101")

    def test_github_issue_action_is_sanitized_and_idempotent(self) -> None:
        self.supervisor.notify_once(
            "checks-issue-1",
            "test.failure",
            "checks failed",
            {"stage": "checks", "raw_logs": "excluded"},
            "failure",
        )
        response = self.supervisor.handle_command(
            "/issue checks-issue-1", "101"
        )
        self.assertIn("issue created", response)
        self.assertEqual(len(self.github.created_issues), 1)
        title, body = self.github.created_issues[0]
        self.assertIn("checks", title)
        self.assertNotIn("raw_logs", body)
        self.assertIn("intentionally excluded", body)
        duplicate = self.supervisor.handle_command(
            "/issue checks-issue-1", "101"
        )
        self.assertIn("already created", duplicate)
        self.assertEqual(len(self.github.created_issues), 1)
        event = self.store.connection.execute(
            "SELECT payload FROM events "
            "WHERE kind = 'recovery.github_issue_created'"
        ).fetchone()
        self.assertEqual(
            json.loads(event["payload"]),
            {
                "actor": "101",
                "fingerprint": "checks-issue-1",
                "url": "https://github.test/issues/99",
            },
        )
        self.assertEqual(self.github.closed_issues, [])

    def test_diagnostics_are_bounded_and_sanitized(self) -> None:
        sanitized = sanitize_diagnostics(
            {
                "stage": "checks",
                "raw_logs": "do not send",
                "config_path": "/home/operator/.config/private",
                "message": "password=hidden " + ("x" * 300),
            }
        )
        self.assertNotIn("raw_logs", sanitized)
        self.assertNotIn("/home/", json.dumps(sanitized))
        self.assertNotIn("hidden", json.dumps(sanitized))
        self.assertLessEqual(len(sanitized["message"]), 120)

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

    def test_details_callback_sends_visible_message(self) -> None:
        token = self.action_token("Details")
        self.supervisor.handle_update(self.callback_update(token))
        self.assertIn("PR / CI: #12", self.telegram.messages[-1])
        self.assertIn("Checks: passed", self.telegram.messages[-1])
        self.assertIn("https://github.test/pull/12", self.telegram.messages[-1])
        self.assertEqual(self.telegram.callback_answers[-1][1], "Details sent")
        self.assertEqual(self.telegram.edits, [])

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
        self.assertTrue(
            any("PR #12 created" in message for message in self.telegram.messages)
        )
        approval_message = next(
            index
            for index, message in enumerate(self.telegram.messages)
            if "PR #12 is ready for operator approval" in message
        )
        self.assertEqual(
            [action.label for action in self.telegram.actions[approval_message]],
            ["Approve", "Reject", "Status", "Details", "Refresh", "Unwatch", "Pause"],
        )
        self.assertEqual(self.telegram.edits[0][0].message_id, "77")
        self.assertIn(self.config.milestone, self.telegram.edits[0][1])

    def test_approval_notification_retries_with_actions_after_provider_failure(
        self,
    ) -> None:
        self.store.set("status_message_id", "77")
        self.telegram.fail_sends = True
        self.supervisor.monitor_once()
        fingerprint = "pr:12:approval-ready:abc123"
        self.assertEqual(self.store.notification(fingerprint)["state"], "pending")

        self.telegram.fail_sends = False
        self.supervisor.monitor_once()
        approval_message = next(
            index
            for index, message in enumerate(self.telegram.messages)
            if "PR #12 is ready for operator approval" in message
        )
        self.assertEqual(
            [action.label for action in self.telegram.actions[approval_message]][:2],
            ["Approve", "Reject"],
        )
        self.assertEqual(self.store.notification(fingerprint)["state"], "delivered")

        delivered = len(self.telegram.messages)
        restarted = Supervisor(self.config, self.store, self.github, self.telegram)
        restarted.monitor_once()
        self.assertEqual(len(self.telegram.messages), delivered)

    def test_implicit_approval_prefers_current_pull_request(self) -> None:
        stale = self.store.create_approval(
            "merge_pr",
            {
                "repository": self.config.repository,
                "pull_request": 13,
                "head_sha": "def456",
            },
            60,
        )
        current = self.store.create_approval(
            "merge_pr",
            {
                "repository": self.config.repository,
                "pull_request": 12,
                "head_sha": "abc123",
            },
            60,
        )
        self.store.set("current_pr", "12")
        response = self.supervisor.handle_command("/approve", "101")
        self.assertIn("merge approved", response)
        self.assertEqual(self.store.approval(current["id"])["state"], "approved")
        self.assertEqual(self.store.approval(stale["id"])["state"], "pending")

    def test_merged_pr_supersedes_its_pending_approvals(self) -> None:
        approval = self.store.create_approval(
            "merge_pr",
            {
                "repository": self.config.repository,
                "pull_request": 12,
                "head_sha": "abc123",
            },
            60,
        )
        self.github.pr["state"] = "MERGED"
        self.github.pr["mergedAt"] = "2026-07-30T00:00:00Z"
        self.supervisor.complete_merged_pull_request(self.github.pr)
        row = self.store.approval(approval["id"])
        self.assertEqual(row["state"], "superseded")
        self.assertEqual(row["reason"], "pull request merged")


if __name__ == "__main__":
    unittest.main()
