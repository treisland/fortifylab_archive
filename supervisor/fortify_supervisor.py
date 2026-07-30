#!/usr/bin/env python3
"""Durable Telegram and GitHub supervisor for the Fortify SDLC loop."""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import re
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
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class SupervisorError(RuntimeError):
    """Expected, user-actionable supervisor failure."""


@dataclasses.dataclass(frozen=True)
class InlineAction:
    """Provider-neutral contextual action rendered by a communications adapter."""

    label: str
    token: str


@dataclasses.dataclass(frozen=True)
class MessageReference:
    """Opaque provider message reference used only for later replacement."""

    message_id: str


@dataclasses.dataclass(frozen=True)
class NotificationPreferences:
    """Externally configured delivery policy; never authoritative workflow state."""

    mode: str = "all"
    quiet_start: str = ""
    quiet_end: str = ""
    timezone: str = "UTC"
    digest_hour: int = 8
    digest_minute: int = 0
    retry_stages: tuple[str, ...] = ()
    rejection_reasons: tuple[str, ...] = (
        "changes-required",
        "security-concern",
        "tests-incomplete",
        "out-of-scope",
    )

    def __post_init__(self) -> None:
        if self.mode not in {"all", "failures"}:
            raise SupervisorError("notification_mode must be 'all' or 'failures'")
        if bool(self.quiet_start) != bool(self.quiet_end):
            raise SupervisorError("quiet_start and quiet_end must be configured together")
        for label, value in (
            ("quiet_start", self.quiet_start),
            ("quiet_end", self.quiet_end),
        ):
            if value and not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
                raise SupervisorError(f"{label} must use HH:MM")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as error:
            raise SupervisorError(f"Unknown notification timezone: {self.timezone}") from error
        if not 0 <= self.digest_hour <= 23 or not 0 <= self.digest_minute <= 59:
            raise SupervisorError("digest time is invalid")
        if len(set(self.retry_stages)) != len(self.retry_stages):
            raise SupervisorError("retry_stages contains duplicates")
        if not self.rejection_reasons:
            raise SupervisorError("at least one rejection reason is required")
        for reason in self.rejection_reasons:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", reason):
                raise SupervisorError("rejection reasons must be predefined slugs")

    def quiet(self, timestamp: float) -> bool:
        if not self.quiet_start:
            return False
        current = datetime.datetime.fromtimestamp(
            timestamp, datetime.timezone.utc
        ).astimezone(ZoneInfo(self.timezone))
        minute = current.hour * 60 + current.minute
        start_hour, start_minute = (int(value) for value in self.quiet_start.split(":"))
        end_hour, end_minute = (int(value) for value in self.quiet_end.split(":"))
        start = start_hour * 60 + start_minute
        end = end_hour * 60 + end_minute
        if start == end:
            return True
        return start <= minute < end if start < end else minute >= start or minute < end

    def digest_bucket(self, timestamp: float) -> str:
        local = datetime.datetime.fromtimestamp(
            timestamp, datetime.timezone.utc
        ).astimezone(ZoneInfo(self.timezone))
        boundary = local.replace(
            hour=self.digest_hour, minute=self.digest_minute, second=0, microsecond=0
        )
        if local < boundary:
            boundary -= datetime.timedelta(days=1)
        return boundary.date().isoformat()


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
    notifications: NotificationPreferences = NotificationPreferences()

    @classmethod
    def load(cls, path: Path) -> "Config":
        validate_protected_file(path, "Supervisor configuration")
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        values = data.get("supervisor", {})
        notification_values = data.get("notifications", {})
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
            notifications=NotificationPreferences(
                mode=str(notification_values.get("mode", "all")),
                quiet_start=str(notification_values.get("quiet_start", "")),
                quiet_end=str(notification_values.get("quiet_end", "")),
                timezone=str(notification_values.get("timezone", "UTC")),
                digest_hour=int(notification_values.get("digest_hour", 8)),
                digest_minute=int(notification_values.get("digest_minute", 0)),
                retry_stages=tuple(
                    str(item) for item in notification_values.get("retry_stages", [])
                ),
                rejection_reasons=tuple(
                    str(item)
                    for item in notification_values.get(
                        "rejection_reasons",
                        [
                            "changes-required",
                            "security-concern",
                            "tests-incomplete",
                            "out-of-scope",
                        ],
                    )
                ),
            ),
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
            CREATE TABLE IF NOT EXISTS callback_tokens (
                token_hash TEXT PRIMARY KEY,
                approval_id TEXT,
                action TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed_at INTEGER,
                consumed_by TEXT,
                FOREIGN KEY(approval_id) REFERENCES approvals(id)
            );
            CREATE TABLE IF NOT EXISTS notifications (
                fingerprint TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                payload TEXT NOT NULL,
                digest_bucket TEXT,
                state TEXT NOT NULL,
                message_id TEXT,
                occurrences INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL
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

    def has_event(self, fingerprint: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM events WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return row is not None

    def upsert_notification(
        self,
        fingerprint: str,
        kind: str,
        severity: str,
        message: str,
        payload: dict[str, Any],
        state: str,
        digest_bucket: str | None,
    ) -> tuple[sqlite3.Row, bool]:
        existing = self.connection.execute(
            "SELECT * FROM notifications WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        now = int(self.now())
        if existing:
            self.connection.execute(
                """
                UPDATE notifications
                SET message = ?, payload = ?, occurrences = occurrences + 1,
                    updated_at = ?
                WHERE fingerprint = ?
                """,
                (message, json.dumps(payload, sort_keys=True), now, fingerprint),
            )
            self.connection.commit()
            return (
                self.connection.execute(
                    "SELECT * FROM notifications WHERE fingerprint = ?",
                    (fingerprint,),
                ).fetchone(),
                False,
            )
        self.connection.execute(
            """
            INSERT INTO notifications(
                fingerprint, kind, severity, message, payload, digest_bucket,
                state, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint,
                kind,
                severity,
                message,
                json.dumps(payload, sort_keys=True),
                digest_bucket,
                state,
                now,
            ),
        )
        self.connection.commit()
        return (
            self.connection.execute(
                "SELECT * FROM notifications WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone(),
            True,
        )

    def mark_notification(
        self, fingerprint: str, state: str, message_id: str | None = None
    ) -> None:
        self.connection.execute(
            """
            UPDATE notifications SET state = ?, message_id = COALESCE(?, message_id),
                updated_at = ? WHERE fingerprint = ?
            """,
            (state, message_id, int(self.now()), fingerprint),
        )
        self.connection.commit()

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

    def pending_approvals(self, action: str) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                """
                SELECT * FROM approvals
                WHERE action = ? AND state = 'pending' AND expires_at > ?
                ORDER BY created_at DESC
                """,
                (action, int(self.now())),
            ).fetchall()
        )

    def supersede_merge_approvals(self, pull_request: int, head_sha: str) -> int:
        superseded = 0
        for row in self.pending_approvals("merge_pr"):
            payload = json.loads(row["payload"])
            if (
                int(payload.get("pull_request", -1)) == pull_request
                and str(payload.get("head_sha")) != head_sha
            ):
                self.connection.execute(
                    """
                    UPDATE approvals
                    SET state = 'superseded', decided_at = ?,
                        reason = 'pull request head changed'
                    WHERE id = ?
                    """,
                    (int(self.now()), row["id"]),
                )
                superseded += 1
        if superseded:
            self.connection.commit()
        return superseded

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

    def create_callback_token(
        self, action: str, ttl: int, approval_id: str | None = None
    ) -> str:
        token = secrets.token_urlsafe(24)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        created = int(self.now())
        self.connection.execute(
            """
            INSERT INTO callback_tokens(
                token_hash, approval_id, action, created_at, expires_at
            ) VALUES(?, ?, ?, ?, ?)
            """,
            (token_hash, approval_id, action, created, created + ttl),
        )
        self.connection.commit()
        return token

    def consume_callback_token(self, token: str, actor: str) -> sqlite3.Row:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = int(self.now())
        with self.connection:
            row = self.connection.execute(
                "SELECT * FROM callback_tokens WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if not row:
                raise SupervisorError("This action is invalid or no longer available")
            if row["consumed_at"] is not None:
                raise SupervisorError("This action was already used")
            if int(row["expires_at"]) <= now:
                raise SupervisorError("This action has expired")
            changed = self.connection.execute(
                """
                UPDATE callback_tokens
                SET consumed_at = ?, consumed_by = ?
                WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?
                """,
                (now, actor, token_hash, now),
            ).rowcount
            if changed != 1:
                raise SupervisorError("This action was already used")
        return self.connection.execute(
            "SELECT * FROM callback_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()


class GitHubPort(Protocol):
    def pull_request(self, number: int) -> dict[str, Any]: ...
    def discover_pull_requests(self) -> list[dict[str, Any]]: ...
    def ready(self, number: int) -> None: ...
    def merge(self, number: int, head_sha: str) -> None: ...
    def close_issue(self, number: int) -> None: ...
    def create_failure_issue(self, title: str, body: str) -> str: ...
    def next_issue(
        self, milestone: str, excluded: set[int] | None = None
    ) -> dict[str, Any] | None: ...


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

    def close_issue(self, number: int) -> None:
        owner, repository = self.repository.split("/", 1)
        endpoint = f"repos/{owner}/{repository}/issues/{number}"
        if self._json(["api", endpoint]).get("state") == "closed":
            return
        result = self.run(
            [
                "gh",
                "api",
                "--method",
                "PATCH",
                endpoint,
                "-f",
                "state=closed",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            # A PR with `Closes #N` can close the issue between the GET and
            # PATCH. Treat that concurrent native closure as success.
            if self._json(["api", endpoint]).get("state") == "closed":
                return
            raise SupervisorError(
                result.stderr.strip() or f"Could not close issue #{number}"
            )

    def create_failure_issue(self, title: str, body: str) -> str:
        result = self.run(
            [
                "gh",
                "issue",
                "create",
                "--repo",
                self.repository,
                "--title",
                title[:120],
                "--body",
                body[:2000],
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise SupervisorError(
                result.stderr.strip() or "Could not create sanitized failure issue"
            )
        return result.stdout.strip()

    def next_issue(
        self, milestone: str, excluded: set[int] | None = None
    ) -> dict[str, Any] | None:
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
        excluded = excluded or set()
        for issue in issues:
            labels = {item["name"] for item in issue.get("labels", [])}
            if (
                int(issue["number"]) not in excluded
                and "automated-observation" not in labels
                and "needs-triage" not in labels
            ):
                eligible.append(issue)
        return min(eligible, key=lambda item: int(item["number"])) if eligible else None


class TelegramPort(Protocol):
    def updates(self, offset: int, timeout: int) -> list[dict[str, Any]]: ...
    def send(
        self, message: str, actions: tuple[InlineAction, ...] = ()
    ) -> MessageReference: ...
    def edit(
        self,
        reference: MessageReference,
        message: str,
        actions: tuple[InlineAction, ...] = (),
    ) -> None: ...
    def answer_callback(self, callback_id: str, message: str) -> None: ...


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

    @staticmethod
    def _markup(actions: tuple[InlineAction, ...]) -> str:
        return json.dumps(
            {
                "inline_keyboard": [
                    [
                        {
                            "text": action.label,
                            "callback_data": action.token,
                        }
                        for action in actions
                    ]
                ]
            },
            separators=(",", ":"),
        )

    def send(
        self, message: str, actions: tuple[InlineAction, ...] = ()
    ) -> MessageReference:
        parameters: dict[str, Any] = {"chat_id": self.chat_id, "text": message}
        if actions:
            parameters["reply_markup"] = self._markup(actions)
        result = self._api("sendMessage", parameters)
        return MessageReference(str(result["message_id"]))

    def edit(
        self,
        reference: MessageReference,
        message: str,
        actions: tuple[InlineAction, ...] = (),
    ) -> None:
        parameters: dict[str, Any] = {
            "chat_id": self.chat_id,
            "message_id": reference.message_id,
            "text": message,
            "reply_markup": self._markup(actions),
        }
        self._api("editMessageText", parameters)

    def answer_callback(self, callback_id: str, message: str) -> None:
        self._api(
            "answerCallbackQuery",
            {"callback_query_id": callback_id, "text": message[:200]},
        )

    def register_commands(self) -> None:
        commands = [
            {"command": "status", "description": "Show supervisor status"},
            {"command": "pr", "description": "Show the tracked pull request"},
            {"command": "approve", "description": "Approve the pending PR merge"},
            {"command": "reject", "description": "Reject the pending PR merge"},
            {"command": "retry", "description": "Retry an allowlisted failed stage"},
            {"command": "issue", "description": "Request an issue for a failure"},
            {"command": "pause", "description": "Pause new automated work"},
            {"command": "continue", "description": "Resume automated work"},
            {"command": "help", "description": "Show available commands"},
        ]
        self._api(
            "setMyCommands",
            {
                "commands": json.dumps(commands, separators=(",", ":")),
                "scope": json.dumps(
                    {"type": "all_private_chats"}, separators=(",", ":")
                ),
            },
        )


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


def sanitize_diagnostics(value: Any, limit: int = 120) -> Any:
    """Return bounded scalar diagnostics without logs, paths, or secret-like data."""

    forbidden_keys = {
        "log",
        "logs",
        "raw",
        "path",
        "token",
        "secret",
        "credential",
        "authorization",
    }
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:12]:
            normalized = str(key).lower().replace("_", "-")
            if any(forbidden in normalized for forbidden in forbidden_keys):
                continue
            result[str(key)[:40]] = sanitize_diagnostics(item, limit)
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize_diagnostics(item, limit) for item in list(value)[:8]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = re.sub(r"(?i)(bearer|token|password|secret)\s*[:= ]\s*\S+", r"\1=[redacted]", text)
    text = re.sub(r"(?:/home|/etc|/var|/run|~)/\S+", "[protected-path]", text)
    return text[:limit]


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
        runner = self.store.get("runner_state", "idle")
        return (
            f"Fortify SDLC Workflow — {self.config.milestone}\n"
            f"State: {'paused' if paused else 'running'}\n"
            f"Issue: {issue or 'none'}\n"
            f"Runner: {runner}\n"
            f"PR: {pr or 'none'}"
        )

    def authorized_message(
        self, update: dict[str, Any], callback: bool = False
    ) -> dict[str, Any] | None:
        envelope = update.get("callback_query") if callback else update
        message = (envelope or {}).get("message")
        if not message:
            return None
        sender = (
            (envelope or {}).get("from") if callback else message.get("from")
        ) or {}
        chat = message.get("chat") or {}
        if (
            chat.get("type") != "private"
            or str(sender.get("id")) != self.allowed_user
            or str(chat.get("id")) != self.allowed_chat
        ):
            return None
        return message

    def handle_update(self, update: dict[str, Any]) -> None:
        if update.get("callback_query"):
            self.handle_callback(update)
            return
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

    def handle_callback(self, update: dict[str, Any]) -> None:
        callback = update.get("callback_query") or {}
        message = self.authorized_message(update, callback=True)
        if not message:
            return
        callback_id = str(callback.get("id") or "")
        token = str(callback.get("data") or "")
        actor = str((callback.get("from") or {}).get("id"))
        reference = MessageReference(str(message.get("message_id") or ""))
        try:
            outcome = self.execute_callback(token, actor)
            if not outcome.startswith("PR #"):
                try:
                    self.telegram.edit(reference, self.status_text())
                except SupervisorError:
                    self.store.event(
                        f"callback-edit:{hashlib.sha256(token.encode()).hexdigest()}",
                        "communications.message_edit_failed",
                        {"provider": "telegram", "outcome": "failed"},
                    )
            self.telegram.answer_callback(callback_id, outcome)
        except SupervisorError as error:
            self.telegram.answer_callback(callback_id, f"❌ {error}")

    def execute_callback(self, token: str, actor: str) -> str:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = self.store.connection.execute(
            "SELECT * FROM callback_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if not row:
            raise SupervisorError("This action is invalid or no longer available")
        approval_id = str(row["approval_id"] or "")
        approval = self.store.approval(approval_id)
        payload = json.loads(approval["payload"])
        pr = self.github.pull_request(int(payload["pull_request"]))
        self.verify_merge_plan(pr, payload, allow_draft=True)
        action = str(self.store.consume_callback_token(token, actor)["action"])
        if action == "approve":
            return self.approve(approval_id, actor)
        if action == "reject":
            self.store.decide(
                approval_id,
                "rejected",
                actor,
                self.config.notifications.rejection_reasons[0],
            )
            self.store.event(
                f"approval:{approval_id}:rejected",
                "pull_request.merge_rejected",
                {"pull_request": int(payload["pull_request"]), "actor": actor},
            )
            return "PR merge rejected"
        if action == "pause":
            self.store.set("paused", "true")
            self.store.event(
                f"callback:{approval_id}:paused",
                "supervisor.paused",
                {"actor": actor, "pull_request": int(payload["pull_request"])},
            )
            return "Supervisor paused"
        if action == "details":
            return (
                f"PR #{payload['pull_request']}: checks passed; "
                f"merge state {pr.get('mergeStateStatus', 'unknown')}"
            )
        raise SupervisorError("Unsupported callback action")

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
            if len(parts) > 2:
                raise SupervisorError("Usage: /approve [approval-id]")
            approval_id = (
                parts[1]
                if len(parts) == 2
                else self.current_approval_id("merge_pr")
            )
            return self.approve(approval_id, actor)
        if command == "/reject":
            explicit_id = len(parts) > 1 and parts[1].startswith("apr-")
            approval_id = (
                parts[1] if explicit_id else self.current_approval_id("merge_pr")
            )
            reason = " ".join(parts[2:] if explicit_id else parts[1:])
            if reason not in self.config.notifications.rejection_reasons:
                allowed = ", ".join(self.config.notifications.rejection_reasons)
                raise SupervisorError(f"Choose a rejection reason: {allowed}")
            self.store.decide(approval_id, "rejected", actor, reason)
            return "Pending PR merge rejected."
        if command == "/retry":
            if len(parts) != 2:
                raise SupervisorError("Usage: /retry <stage>")
            stage = parts[1]
            if stage not in self.config.notifications.retry_stages:
                raise SupervisorError("Retry is not allowed for this stage")
            row = self.store.connection.execute(
                """
                SELECT fingerprint FROM notifications
                WHERE severity = 'failure' AND json_extract(payload, '$.stage') = ?
                ORDER BY updated_at DESC LIMIT 1
                """,
                (stage,),
            ).fetchone()
            if not row:
                raise SupervisorError("No failed notification exists for this stage")
            self.store.event(
                f"retry:{row['fingerprint']}:{int(self.store.now())}",
                "recovery.retry_requested",
                {"actor": actor, "fingerprint": row["fingerprint"], "stage": stage},
            )
            return f"Retry requested for idempotent stage {stage}."
        if command == "/issue":
            if len(parts) != 2:
                raise SupervisorError("Usage: /issue <failure-fingerprint>")
            fingerprint = parts[1]
            row = self.store.connection.execute(
                "SELECT * FROM notifications WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if not row or row["severity"] != "failure":
                raise SupervisorError("Unknown failure notification")
            event_fingerprint = f"issue-request:{fingerprint}"
            if self.store.has_event(event_fingerprint):
                return "A GitHub issue was already created for this failure."
            payload = json.loads(row["payload"])
            stage = str(payload.get("stage", "unknown"))[:40]
            code = str(payload.get("code", row["kind"]))[:80]
            title = f"Automated SDLC failure: {stage} / {code}"
            body = (
                "A sanitized Fortify Lab Manager supervisor failure needs "
                "operator investigation.\n\n"
                f"- Fingerprint: `{fingerprint[:160]}`\n"
                f"- Stage: `{stage}`\n"
                f"- Code: `{code}`\n"
                f"- Occurrences: {int(row['occurrences'])}\n\n"
                "Raw logs, protected paths, credentials, and configuration "
                "values are intentionally excluded."
            )
            url = self.github.create_failure_issue(title, body)
            self.store.event(
                event_fingerprint,
                "recovery.github_issue_created",
                {"actor": actor, "fingerprint": fingerprint, "url": url},
            )
            return f"Sanitized GitHub issue created: {url}"
        if command == "/help":
            return (
                "/status\n/pr\n/approve\n/reject <predefined-reason>\n"
                "/retry <idempotent-stage>\n/issue <failure-fingerprint>\n"
                "/pause\n/continue\n/help"
            )
        raise SupervisorError("Unknown command. Use /help.")

    def current_approval_id(self, action: str) -> str:
        approvals = self.store.pending_approvals(action)
        if not approvals:
            raise SupervisorError("No pending PR approval")
        if len(approvals) > 1:
            raise SupervisorError(
                "Multiple approvals are pending; use /approve <approval-id> "
                "or /reject <approval-id> [reason]"
            )
        return str(approvals[0]["id"])

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
            {"pull_request": payload["pull_request"], "actor": actor},
        )
        next_issue = self.complete_merged_pull_request(pr)
        if next_issue is None:
            return (
                f"✅ PR #{payload['pull_request']} merge approved and completed. "
                f"Milestone {self.config.milestone} is complete."
            )
        return (
            f"✅ PR #{payload['pull_request']} merge approved and completed; "
            f"issue #{next_issue['number']} was started."
        )

    def complete_merged_pull_request(
        self, pr: dict[str, Any]
    ) -> dict[str, Any] | None:
        number = int(pr["number"])
        sha = str(pr.get("headRefOid") or "")
        branch = str(pr.get("headRefName") or "")
        match = re.fullmatch(r"agent/issue-(\d+)", branch)
        issue_number = int(match.group(1)) if match else None
        fingerprint = f"pr:{number}:completed:{sha}"

        if self.store.has_event(fingerprint):
            return None

        if issue_number is not None:
            self.github.close_issue(issue_number)

        self.notify_once(
            f"pr:{number}:merged-notice:{sha}",
            "pull_request.merged_notice",
            f"✅ PR #{number} merged. Selecting next issue.",
            {"pull_request": number, "head_sha": sha},
        )
        if issue_number is not None and self.store.get("current_issue") == str(
            issue_number
        ):
            self.store.set("current_issue", "")
        next_issue = self.queue_next_issue(issue_number)
        self.store.set("current_pr", "")
        self.store.event(
            fingerprint,
            "pull_request.merged",
            {
                "pull_request": number,
                "head_sha": sha,
                "issue": issue_number,
            },
        )
        return next_issue

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
        self.deliver_digest()
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
                    severity="failure",
                )
                return
            else:
                return
        pr = self.github.pull_request(int(number))
        state = str(pr.get("state"))
        sha = str(pr.get("headRefOid") or "")
        if state == "MERGED" or pr.get("mergedAt"):
            self.complete_merged_pull_request(pr)
            return
        if state == "CLOSED":
            if self.store.event(
                f"pr:{number}:closed:{sha}",
                "pull_request.closed",
                {"pull_request": int(number), "head_sha": sha},
            ):
                self.notify_once(
                    f"pr:{number}:closed-notice:{sha}",
                    "pull_request.closed_notice",
                    (
                        f"🛑 PR #{number} closed without merge. Work is paused.\n"
                        f"Stage: review\nFailure: closed-without-merge\n"
                        f"Issue: /issue pr:{number}:closed-notice:{sha}"
                    ),
                    {
                        "pull_request": int(number),
                        "head_sha": sha,
                        "stage": "review",
                        "code": "closed-without-merge",
                        "retryable": False,
                    },
                    severity="failure",
                )
                self.store.set("paused", "true")
            return
        review = str(pr.get("reviewDecision") or "")
        if review == "CHANGES_REQUESTED":
            self.notify_once(
                f"pr:{number}:changes:{sha}",
                "pull_request.changes_requested",
                (
                    f"📝 Changes requested on PR #{number}.\n"
                    f"Stage: review\nFailure: changes-requested\n"
                    f"Pause: /pause\nIssue: /issue pr:{number}:changes:{sha}"
                ),
                {
                    "pull_request": int(number),
                    "head_sha": sha,
                    "stage": "review",
                    "code": "changes-requested",
                    "retryable": "review" in self.config.notifications.retry_stages,
                },
                severity="failure",
            )
            return
        check_state = checks_state(pr)
        if check_state == "failed":
            self.notify_once(
                f"pr:{number}:checks-failed:{sha}",
                "pull_request.checks_failed",
                (
                    f"❌ Checks failed on PR #{number}.\n"
                    f"Stage: checks\nFailure: checks-failed\n"
                    + (
                        "Retry: /retry checks\n"
                        if "checks" in self.config.notifications.retry_stages
                        else ""
                    )
                    + f"Pause: /pause\nIssue: /issue pr:{number}:checks-failed:{sha}"
                ),
                {
                    "pull_request": int(number),
                    "head_sha": sha,
                    "stage": "checks",
                    "code": "checks-failed",
                    "retryable": "checks" in self.config.notifications.retry_stages,
                },
                severity="failure",
            )
            return
        if check_state != "passed" or pr.get("mergeable") != "MERGEABLE":
            return
        payload = {
            "repository": self.config.repository,
            "pull_request": int(number),
            "head_sha": sha,
        }
        self.store.supersede_merge_approvals(int(number), sha)
        approval = self.store.pending_approval("merge_pr", payload)
        if approval is None:
            approval = self.store.create_approval(
                "merge_pr", payload, self.config.approval_ttl_seconds
            )
            actions = tuple(
                InlineAction(
                    label,
                    self.store.create_callback_token(
                        action,
                        self.config.approval_ttl_seconds,
                        str(approval["id"]),
                    ),
                )
                for label, action in (
                    ("Approve", "approve"),
                    ("Reject", "reject"),
                    ("Details", "details"),
                    ("Pause", "pause"),
                )
            )
            self.update_status_card(actions)

    def update_status_card(
        self, actions: tuple[InlineAction, ...] = ()
    ) -> None:
        message = self.status_text()
        message_id = self.store.get("status_message_id")
        if message_id:
            try:
                self.telegram.edit(MessageReference(message_id), message, actions)
                return
            except SupervisorError:
                self.store.event(
                    f"status-card-edit:{int(self.store.now())}",
                    "communications.message_edit_failed",
                    {"provider": "telegram", "outcome": "failed"},
                )
        reference = self.telegram.send(message, actions)
        self.store.set("status_message_id", reference.message_id)

    def notify_once(
        self,
        fingerprint: str,
        kind: str,
        message: str,
        payload: dict[str, Any],
        severity: str = "info",
    ) -> None:
        sanitized = sanitize_diagnostics(payload)
        if not isinstance(sanitized, dict):
            sanitized = {}
        preferences = self.config.notifications
        deferred = preferences.quiet(self.store.now()) or (
            preferences.mode == "failures" and severity != "failure"
        )
        bucket = preferences.digest_bucket(self.store.now()) if deferred else None
        row, created = self.store.upsert_notification(
            fingerprint,
            kind,
            severity,
            str(sanitize_diagnostics(message, 500)),
            sanitized,
            "digest" if deferred else "pending",
            bucket,
        )
        self.store.event(fingerprint, kind, sanitized)
        if deferred:
            return
        rendered = str(row["message"])
        if int(row["occurrences"]) > 1:
            rendered += f"\nOccurrences: {row['occurrences']}"
        try:
            if row["message_id"]:
                self.telegram.edit(MessageReference(str(row["message_id"])), rendered)
            elif created or row["state"] == "pending":
                reference = self.telegram.send(rendered)
                self.store.mark_notification(
                    fingerprint, "delivered", reference.message_id
                )
        except SupervisorError:
            self.store.mark_notification(fingerprint, "pending")
            self.store.event(
                f"delivery:{fingerprint}:{int(self.store.now())}",
                "communications.delivery_failed",
                {"fingerprint": fingerprint, "provider": "telegram"},
            )

    def deliver_digest(self) -> None:
        """Deliver completed digest buckets; a failed send remains pending."""

        current = self.config.notifications.digest_bucket(self.store.now())
        rows = self.store.connection.execute(
            """
            SELECT * FROM notifications
            WHERE state = 'digest' AND digest_bucket < ?
            ORDER BY updated_at, fingerprint LIMIT 25
            """,
            (current,),
        ).fetchall()
        if not rows:
            return
        lines = [f"Fortify SDLC digest ({rows[0]['digest_bucket']})"]
        for row in rows:
            lines.append(
                f"- [{row['severity']}] {row['message']} "
                f"(x{row['occurrences']}, ref {row['fingerprint']})"
            )
        try:
            reference = self.telegram.send("\n".join(lines)[:3500])
        except SupervisorError:
            self.store.event(
                f"digest-delivery:{rows[0]['digest_bucket']}:{int(self.store.now())}",
                "communications.delivery_failed",
                {"provider": "telegram", "type": "digest"},
            )
            return
        for row in rows:
            self.store.mark_notification(
                str(row["fingerprint"]), "delivered", reference.message_id
            )

    def queue_next_issue(
        self, completed_issue: int | None = None
    ) -> dict[str, Any] | None:
        excluded = {completed_issue} if completed_issue is not None else None
        issue = self.github.next_issue(self.config.milestone, excluded)
        if not issue:
            self.notify_once(
                f"milestone:{self.config.milestone}:complete",
                "milestone.complete",
                f"🎉 No eligible issues remain in {self.config.milestone}.",
                {"milestone": self.config.milestone},
            )
            return None
        number = str(issue["number"])
        self.store.set("current_issue", number)
        self.notify_once(
            f"issue:{number}:queued",
            "issue.queued",
            f"▶️ Queued issue #{number}: {issue['title']}\n{issue.get('url', '')}",
            {"issue": int(number), "title": issue["title"]},
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
            self.store.set("runner_state", f"started for issue #{number}")
        return issue


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
    commands.add_parser("register-commands")
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
            supervisor.telegram.register_commands()
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
        elif arguments.command == "register-commands":
            supervisor.telegram.register_commands()
            print("Registered private Telegram command menu.")
        return 0
    except (SupervisorError, OSError, sqlite3.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
