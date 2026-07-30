#!/usr/bin/env python3
"""Durable Telegram and GitHub supervisor for the Fortify SDLC loop."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import secrets
import shlex
import sqlite3
import stat
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Protocol


class SupervisorError(RuntimeError):
    """Expected, user-actionable supervisor failure."""


@dataclasses.dataclass(frozen=True)
class Config:
    repository: str
    milestone: str
    state_file: Path
    telegram_token_file: Path
    telegram_user_file: Path
    telegram_chat_file: Path
    poll_seconds: int = 120
    approval_ttl_seconds: int = 3600
    runner_command: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: Path) -> "Config":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        values = data.get("supervisor", {})
        required = (
            "repository",
            "milestone",
            "state_file",
            "telegram_token_file",
            "telegram_user_file",
            "telegram_chat_file",
        )
        missing = [key for key in required if not values.get(key)]
        if missing:
            raise SupervisorError(
                f"Missing supervisor configuration: {', '.join(missing)}"
            )
        config = cls(
            repository=str(values["repository"]),
            milestone=str(values["milestone"]),
            state_file=Path(values["state_file"]).expanduser(),
            telegram_token_file=Path(values["telegram_token_file"]).expanduser(),
            telegram_user_file=Path(values["telegram_user_file"]).expanduser(),
            telegram_chat_file=Path(values["telegram_chat_file"]).expanduser(),
            poll_seconds=max(15, int(values.get("poll_seconds", 120))),
            approval_ttl_seconds=max(
                60, int(values.get("approval_ttl_seconds", 3600))
            ),
            runner_command=tuple(str(item) for item in values.get("runner_command", [])),
        )
        if config.runner_command:
            validate_runner(config.runner_command[0])
        return config


def validate_protected_file(path: Path, label: str) -> None:
    if not path.exists():
        raise SupervisorError(f"{label} is not configured: {path}")
    if path.is_symlink() or not path.is_file():
        raise SupervisorError(f"{label} must be a regular non-symlink file")
    details = path.stat()
    if details.st_uid != os.getuid():
        raise SupervisorError(f"{label} must be owned by the service user")
    mode = stat.S_IMODE(details.st_mode)
    if mode & 0o077:
        raise SupervisorError(f"{label} must not be group/world accessible ({mode:o})")


def read_protected(path: Path, label: str) -> str:
    validate_protected_file(path, label)
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise SupervisorError(f"{label} is empty")
    return value


def validate_runner(command: str) -> None:
    path = Path(command)
    if not path.is_absolute():
        raise SupervisorError("runner_command executable must use an absolute path")
    validate_protected_file(path, "Runner executable")
    if not os.access(path, os.X_OK):
        raise SupervisorError("Runner executable is not executable")


class Store:
    def __init__(self, path: Path, now: Callable[[], float] = time.time):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        self.connection = sqlite3.connect(path)
        path.chmod(0o600)
        self.connection.row_factory = sqlite3.Row
        self.now = now
        self.connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                payload TEXT NOT NULL,
                plan_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                decided_at INTEGER,
                decided_by TEXT,
                reason TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        self.connection.commit()

    def get(self, key: str, default: str = "") -> str:
        row = self.connection.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return str(row["value"]) if row else default

    def set(self, key: str, value: str) -> None:
        self.connection.execute(
            """
            INSERT INTO settings(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        self.connection.commit()

    def event(self, fingerprint: str, kind: str, payload: dict[str, Any]) -> bool:
        try:
            self.connection.execute(
                "INSERT INTO events(fingerprint, kind, payload, created_at) VALUES(?, ?, ?, ?)",
                (
                    fingerprint,
                    kind,
                    json.dumps(payload, sort_keys=True),
                    int(self.now()),
                ),
            )
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def create_approval(
        self, action: str, payload: dict[str, Any], ttl: int
    ) -> sqlite3.Row:
        normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        approval_id = f"apr-{secrets.token_hex(4)}"
        created = int(self.now())
        self.connection.execute(
            """
            INSERT INTO approvals(
                id, action, payload, plan_digest, state, created_at, expires_at
            ) VALUES(?, ?, ?, ?, 'pending', ?, ?)
            """,
            (approval_id, action, normalized, digest, created, created + ttl),
        )
        self.connection.commit()
        return self.approval(approval_id)

    def approval(self, approval_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM approvals WHERE id = ?", (approval_id,)
        ).fetchone()
        if not row:
            raise SupervisorError(f"Unknown approval: {approval_id}")
        return row

    def pending_approval(
        self, action: str, payload: dict[str, Any]
    ) -> sqlite3.Row | None:
        normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        return self.connection.execute(
            """
            SELECT * FROM approvals
            WHERE action = ? AND plan_digest = ? AND state = 'pending'
              AND expires_at > ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (action, digest, int(self.now())),
        ).fetchone()

    def decide(
        self, approval_id: str, state: str, actor: str, reason: str = ""
    ) -> sqlite3.Row:
        row = self.approval(approval_id)
        if row["state"] != "pending":
            raise SupervisorError(
                f"Approval {approval_id} is already {row['state']}"
            )
        if int(row["expires_at"]) <= int(self.now()):
            self.connection.execute(
                "UPDATE approvals SET state = 'expired' WHERE id = ?",
                (approval_id,),
            )
            self.connection.commit()
            raise SupervisorError(f"Approval {approval_id} has expired")
        self.connection.execute(
            """
            UPDATE approvals
            SET state = ?, decided_at = ?, decided_by = ?, reason = ?
            WHERE id = ?
            """,
            (state, int(self.now()), actor, reason, approval_id),
        )
        self.connection.commit()
        return self.approval(approval_id)


class GitHubPort(Protocol):
    def pull_request(self, number: int) -> dict[str, Any]: ...
    def discover_pull_requests(self) -> list[dict[str, Any]]: ...
    def ready(self, number: int) -> None: ...
    def merge(self, number: int, head_sha: str) -> None: ...
    def next_issue(self, milestone: str) -> dict[str, Any] | None: ...


class GitHub:
    PR_FIELDS = (
        "number,state,isDraft,headRefOid,headRefName,mergeable,mergeStateStatus,"
        "reviewDecision,statusCheckRollup,url,mergedAt"
    )

    def __init__(
        self,
        repository: str,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ):
        self.repository = repository
        self.run = run

    def _json(self, arguments: list[str]) -> Any:
        result = self.run(
            ["gh", *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            message = result.stderr.strip() or "GitHub CLI request failed"
            raise SupervisorError(message)
        return json.loads(result.stdout)

    def pull_request(self, number: int) -> dict[str, Any]:
        return self._json(
            [
                "pr",
                "view",
                str(number),
                "--repo",
                self.repository,
                "--json",
                self.PR_FIELDS,
            ]
        )

    def discover_pull_requests(self) -> list[dict[str, Any]]:
        return self._json(
            [
                "pr",
                "list",
                "--repo",
                self.repository,
                "--state",
                "open",
                "--limit",
                "20",
                "--json",
                self.PR_FIELDS,
            ]
        )

    def merge(self, number: int, head_sha: str) -> None:
        owner, repository = self.repository.split("/", 1)
        result = self.run(
            [
                "gh",
                "api",
                "--method",
                "PUT",
                f"repos/{owner}/{repository}/pulls/{number}/merge",
                "-f",
                "merge_method=squash",
                "-f",
                f"sha={head_sha}",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise SupervisorError(result.stderr.strip() or "GitHub merge failed")
        response = json.loads(result.stdout)
        if not response.get("merged"):
            raise SupervisorError(response.get("message", "GitHub declined the merge"))

    def ready(self, number: int) -> None:
        result = self.run(
            ["gh", "pr", "ready", str(number), "--repo", self.repository],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise SupervisorError(
                result.stderr.strip() or "Could not mark pull request ready"
            )

    def next_issue(self, milestone: str) -> dict[str, Any] | None:
        issues = self._json(
            [
                "issue",
                "list",
                "--repo",
                self.repository,
                "--milestone",
                milestone,
                "--state",
                "open",
                "--limit",
                "100",
                "--json",
                "number,title,url,labels",
            ]
        )
        eligible = []
        for issue in issues:
            labels = {item["name"] for item in issue.get("labels", [])}
            if "automated-observation" not in labels and "needs-triage" not in labels:
                eligible.append(issue)
        return min(eligible, key=lambda item: int(item["number"])) if eligible else None


class TelegramPort(Protocol):
    def updates(self, offset: int, timeout: int) -> list[dict[str, Any]]: ...
    def send(self, message: str) -> None: ...


class Telegram:
    def __init__(self, config: Config):
        self.token_file = config.telegram_token_file
        self.chat_id = read_protected(config.telegram_chat_file, "Telegram chat ID")

    def _api(self, method: str, parameters: dict[str, Any]) -> Any:
        token = read_protected(self.token_file, "Telegram bot token")
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/{method}",
            data=urllib.parse.urlencode(parameters).encode(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=35) as response:
                result = json.load(response)
        except urllib.error.URLError as error:
            raise SupervisorError(f"Telegram unavailable: {error.reason}") from error
        if not result.get("ok"):
            raise SupervisorError(
                result.get("description", "Telegram request failed")
            )
        return result["result"]

    def updates(self, offset: int, timeout: int) -> list[dict[str, Any]]:
        return self._api(
            "getUpdates", {"offset": offset, "timeout": max(1, min(timeout, 30))}
        )

    def send(self, message: str) -> None:
        self._api("sendMessage", {"chat_id": self.chat_id, "text": message})


def checks_state(pr: dict[str, Any]) -> str:
    checks = pr.get("statusCheckRollup") or []
    if not checks:
        return "pending"
    pending = False
    for check in checks:
        status = str(check.get("status") or "").upper()
        conclusion = str(check.get("conclusion") or "").upper()
        if status != "COMPLETED":
            pending = True
        elif conclusion not in {"SUCCESS", "NEUTRAL", "SKIPPED"}:
            return "failed"
    return "pending" if pending else "passed"


class Supervisor:
    def __init__(
        self,
        config: Config,
        store: Store,
        github: GitHubPort,
        telegram: TelegramPort,
        run: Callable[..., subprocess.Popen[Any]] = subprocess.Popen,
    ):
        self.config = config
        self.store = store
        self.github = github
        self.telegram = telegram
        self.run = run
        self.allowed_user = read_protected(
            config.telegram_user_file, "Telegram user ID"
        )
        self.allowed_chat = read_protected(
            config.telegram_chat_file, "Telegram chat ID"
        )

    def status_text(self) -> str:
        paused = self.store.get("paused", "false") == "true"
        pr = self.store.get("current_pr", "none")
        issue = self.store.get("current_issue", "none")
        return (
            "Fortify SDLC Supervisor\n"
            f"State: {'paused' if paused else 'running'}\n"
            f"Tracked PR: {pr}\n"
            f"Queued issue: {issue}"
        )

    def authorized_message(self, update: dict[str, Any]) -> dict[str, Any] | None:
        message = update.get("message")
        if not message:
            return None
        sender = message.get("from") or {}
        chat = message.get("chat") or {}
        if (
            chat.get("type") != "private"
            or str(sender.get("id")) != self.allowed_user
            or str(chat.get("id")) != self.allowed_chat
        ):
            return None
        return message

    def handle_update(self, update: dict[str, Any]) -> None:
        message = self.authorized_message(update)
        if not message:
            return
        text = str(message.get("text") or "").strip()
        if not text.startswith("/"):
            return
        actor = str((message.get("from") or {}).get("id"))
        try:
            response = self.handle_command(text, actor)
        except SupervisorError as error:
            response = f"❌ {error}"
        self.telegram.send(response)

    def handle_command(self, text: str, actor: str) -> str:
        parts = shlex.split(text)
        command = parts[0].split("@", 1)[0].lower()
        if command == "/status":
            return self.status_text()
        if command == "/pr":
            number = self.store.get("current_pr")
            if not number:
                return "No pull request is currently tracked."
            pr = self.github.pull_request(int(number))
            return (
                f"PR #{number}: {pr['state']}\n"
                f"Checks: {checks_state(pr)}\n"
                f"Merge: {pr.get('mergeStateStatus', 'unknown')}\n"
                f"{pr.get('url', '')}"
            )
        if command == "/pause":
            self.store.set("paused", "true")
            self.store.event(
                f"command:pause:{int(self.store.now())}",
                "supervisor.paused",
                {"actor": actor},
            )
            return "⏸ Supervisor paused. Monitoring continues; no new work will start."
        if command == "/continue":
            self.store.set("paused", "false")
            self.store.event(
                f"command:continue:{int(self.store.now())}",
                "supervisor.continued",
                {"actor": actor},
            )
            return "▶️ Supervisor resumed."
        if command == "/approve":
            if len(parts) != 2:
                raise SupervisorError("Usage: /approve <approval-id>")
            return self.approve(parts[1], actor)
        if command == "/reject":
            if len(parts) < 2:
                raise SupervisorError("Usage: /reject <approval-id> [reason]")
            reason = " ".join(parts[2:])
            self.store.decide(parts[1], "rejected", actor, reason)
            return f"Approval {parts[1]} rejected."
        if command == "/help":
            return (
                "/status\n/pr\n/approve <id>\n/reject <id> [reason]\n"
                "/pause\n/continue\n/help"
            )
        raise SupervisorError("Unknown command. Use /help.")

    def approve(self, approval_id: str, actor: str) -> str:
        row = self.store.approval(approval_id)
        if row["action"] != "merge_pr":
            raise SupervisorError("Unsupported approval action")
        payload = json.loads(row["payload"])
        pr = self.github.pull_request(int(payload["pull_request"]))
        self.verify_merge_plan(pr, payload, allow_draft=True)
        self.store.decide(approval_id, "approved", actor)
        try:
            if pr.get("isDraft"):
                self.github.ready(int(payload["pull_request"]))
                pr = self.github.pull_request(int(payload["pull_request"]))
                self.verify_merge_plan(pr, payload)
            self.github.merge(int(payload["pull_request"]), payload["head_sha"])
        except Exception:
            self.store.set("last_error", f"Merge failed for PR #{payload['pull_request']}")
            raise
        self.store.event(
            f"approval:{approval_id}:merge",
            "pull_request.merge_approved",
            {"approval_id": approval_id, "pull_request": payload["pull_request"]},
        )
        return f"✅ PR #{payload['pull_request']} merge approved and submitted."

    @staticmethod
    def verify_merge_plan(
        pr: dict[str, Any], payload: dict[str, Any], allow_draft: bool = False
    ) -> None:
        if str(pr.get("headRefOid")) != str(payload["head_sha"]):
            raise SupervisorError("PR head changed; request a new approval")
        if pr.get("state") != "OPEN":
            raise SupervisorError("PR is no longer open")
        if checks_state(pr) != "passed":
            raise SupervisorError("PR checks are not passing")
        if pr.get("mergeable") != "MERGEABLE":
            raise SupervisorError("PR is not mergeable")
        if pr.get("isDraft") and not allow_draft:
            raise SupervisorError("PR is still a draft")
        allowed_states = {"CLEAN", "UNSTABLE"}
        if allow_draft and pr.get("isDraft"):
            allowed_states.add("BLOCKED")
        if pr.get("mergeStateStatus") not in allowed_states:
            raise SupervisorError(
                f"PR merge state is {pr.get('mergeStateStatus', 'unknown')}"
            )

    def monitor_once(self) -> None:
        if self.store.get("paused", "false") == "true":
            return
        number = self.store.get("current_pr")
        if not number:
            candidates = [
                item
                for item in self.github.discover_pull_requests()
                if str(item.get("headRefName", "")).startswith("agent/")
            ]
            if len(candidates) == 1:
                number = str(candidates[0]["number"])
                self.store.set("current_pr", number)
            elif len(candidates) > 1:
                self.notify_once(
                    "pr:ambiguous",
                    "supervisor.attention",
                    "⚠ Multiple agent PRs are open; track one explicitly.",
                    {"count": len(candidates)},
                )
                return
            else:
                return
        pr = self.github.pull_request(int(number))
        state = str(pr.get("state"))
        sha = str(pr.get("headRefOid") or "")
        if state == "MERGED" or pr.get("mergedAt"):
            if self.store.event(
                f"pr:{number}:merged:{sha}",
                "pull_request.merged",
                {"pull_request": int(number), "head_sha": sha},
            ):
                self.telegram.send(f"✅ PR #{number} merged. Selecting next issue.")
                self.store.set("current_pr", "")
                self.queue_next_issue()
            return
        if state == "CLOSED":
            if self.store.event(
                f"pr:{number}:closed:{sha}",
                "pull_request.closed",
                {"pull_request": int(number), "head_sha": sha},
            ):
                self.telegram.send(
                    f"🛑 PR #{number} closed without merge. Work is paused."
                )
                self.store.set("paused", "true")
            return
        review = str(pr.get("reviewDecision") or "")
        if review == "CHANGES_REQUESTED":
            self.notify_once(
                f"pr:{number}:changes:{sha}",
                "pull_request.changes_requested",
                f"📝 Changes requested on PR #{number}.",
                {"pull_request": int(number), "head_sha": sha},
            )
            return
        check_state = checks_state(pr)
        if check_state == "failed":
            self.notify_once(
                f"pr:{number}:checks-failed:{sha}",
                "pull_request.checks_failed",
                f"❌ Checks failed on PR #{number}.",
                {"pull_request": int(number), "head_sha": sha},
            )
            return
        if check_state != "passed" or pr.get("mergeable") != "MERGEABLE":
            return
        payload = {
            "repository": self.config.repository,
            "pull_request": int(number),
            "head_sha": sha,
        }
        approval = self.store.pending_approval("merge_pr", payload)
        if approval is None:
            approval = self.store.create_approval(
                "merge_pr", payload, self.config.approval_ttl_seconds
            )
            self.telegram.send(
                f"✅ PR #{number} is passing and mergeable.\n"
                f"Approve: /approve {approval['id']}\n"
                f"Reject: /reject {approval['id']} <reason>\n"
                f"Expires: {approval['expires_at']}"
            )

    def notify_once(
        self,
        fingerprint: str,
        kind: str,
        message: str,
        payload: dict[str, Any],
    ) -> None:
        if self.store.event(fingerprint, kind, payload):
            self.telegram.send(message)

    def queue_next_issue(self) -> None:
        issue = self.github.next_issue(self.config.milestone)
        if not issue:
            self.telegram.send(
                f"🎉 No eligible issues remain in {self.config.milestone}."
            )
            return
        number = str(issue["number"])
        self.store.set("current_issue", number)
        self.telegram.send(
            f"▶️ Queued issue #{number}: {issue['title']}\n{issue.get('url', '')}"
        )
        if self.config.runner_command:
            command = [*self.config.runner_command, number]
            self.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            self.store.event(
                f"issue:{number}:runner-started",
                "runner.started",
                {"issue": int(number)},
            )


def build(config_path: Path) -> tuple[Config, Store, Supervisor]:
    config = Config.load(config_path)
    store = Store(config.state_file)
    github = GitHub(config.repository)
    telegram = Telegram(config)
    supervisor = Supervisor(config, store, github, telegram)
    return config, store, supervisor


def command_line() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path.home()
        / ".config"
        / "fortify-lab-manager"
        / "supervisor.toml",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("status")
    commands.add_parser("monitor-once")
    commands.add_parser("telegram-once")
    commands.add_parser("telegram-loop")
    track = commands.add_parser("track-pr")
    track.add_argument("number", type=int)
    return parser


def main() -> int:
    arguments = command_line().parse_args()
    try:
        config, store, supervisor = build(arguments.config)
        if arguments.command == "init":
            print(f"Initialized supervisor state at {config.state_file}")
        elif arguments.command == "status":
            print(supervisor.status_text())
        elif arguments.command == "track-pr":
            store.set("current_pr", str(arguments.number))
            print(f"Tracking PR #{arguments.number}")
        elif arguments.command == "monitor-once":
            supervisor.monitor_once()
        elif arguments.command == "telegram-once":
            offset = int(store.get("telegram_offset", "0"))
            for update in supervisor.telegram.updates(offset, 1):
                offset = max(offset, int(update["update_id"]) + 1)
                supervisor.handle_update(update)
                store.set("telegram_offset", str(offset))
        elif arguments.command == "telegram-loop":
            while True:
                try:
                    offset = int(store.get("telegram_offset", "0"))
                    updates = supervisor.telegram.updates(offset, 25)
                    for update in updates:
                        offset = max(offset, int(update["update_id"]) + 1)
                        supervisor.handle_update(update)
                        store.set("telegram_offset", str(offset))
                except SupervisorError as error:
                    print(f"Supervisor warning: {error}", file=sys.stderr)
                    time.sleep(5)
        return 0
    except (SupervisorError, OSError, sqlite3.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
