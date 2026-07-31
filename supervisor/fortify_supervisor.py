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

from autonomy_policy import (
    AutonomyPolicyError,
    EffectivePolicy,
    load_policy,
    replace_policy,
)
from workflow_status import (
    heartbeat_interval,
    read_heartbeat,
    render_card,
    render_stall,
)

class SupervisorError(RuntimeError):
    """Expected, user-actionable supervisor failure."""


@dataclasses.dataclass(frozen=True)
class InlineAction:
    """Provider-neutral contextual action rendered by a communications adapter."""

    label: str
    token: str
    row: int = 0


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
    milestones: tuple[str, ...] = ()
    poll_seconds: int = 120
    approval_ttl_seconds: int = 3600
    runner_command: tuple[str, ...] = ()
    runner_stop_command: tuple[str, ...] = ()
    heartbeat_root: Path | None = None
    autonomy_policy_file: Path | None = None
    required_merge_checks: tuple[str, ...] = ("repository", "secrets")
    secret_scan_check: str = "secrets"
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
        configured_milestones = values.get("milestones", [])
        if not isinstance(configured_milestones, list) or any(
            not isinstance(item, str) or not item.strip()
            for item in configured_milestones
        ):
            raise SupervisorError(
                "Authorized milestones must be a list of non-empty titles"
            )
        milestones = tuple(configured_milestones)
        if milestones and (
            len(set(milestones)) != len(milestones)
            or str(values["milestone"]) not in milestones
        ):
            raise SupervisorError(
                "Authorized milestones must be unique and include milestone"
            )
        config = cls(
            repository=str(values["repository"]),
            milestone=str(values["milestone"]),
            milestones=milestones,
            state_file=Path(values["state_file"]).expanduser(),
            telegram_token_file=Path(values["telegram_token_file"]).expanduser(),
            telegram_user_file=Path(values["telegram_user_file"]).expanduser(),
            telegram_chat_file=Path(values["telegram_chat_file"]).expanduser(),
            poll_seconds=max(15, int(values.get("poll_seconds", 120))),
            approval_ttl_seconds=max(
                60, int(values.get("approval_ttl_seconds", 3600))
            ),
            runner_command=tuple(str(item) for item in values.get("runner_command", [])),
            runner_stop_command=tuple(
                str(item) for item in values.get("runner_stop_command", [])
            ),
            heartbeat_root=Path(
                values.get(
                    "heartbeat_root",
                    Path(values["state_file"]).expanduser().parent
                    / "runner-heartbeats",
                )
            ).expanduser(),
            autonomy_policy_file=(
                Path(str(values["autonomy_policy_file"])).expanduser()
                if values.get("autonomy_policy_file")
                else None
            ),
            required_merge_checks=tuple(
                str(item) for item in values.get(
                    "required_merge_checks", ["repository", "secrets"]
                )
            ),
            secret_scan_check=str(values.get("secret_scan_check", "secrets")),
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
        if config.runner_stop_command:
            validate_runner(config.runner_stop_command[0])
        if (
            not config.required_merge_checks
            or len(set(config.required_merge_checks)) != len(config.required_merge_checks)
            or any(not value.strip() for value in config.required_merge_checks)
            or config.secret_scan_check not in config.required_merge_checks
        ):
            raise SupervisorError(
                "required_merge_checks must be unique and include secret_scan_check"
            )
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
                actor TEXT,
                payload TEXT NOT NULL DEFAULT '{}',
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
        columns = {
            str(row["name"])
            for row in self.connection.execute("PRAGMA table_info(callback_tokens)")
        }
        if "actor" not in columns:
            self.connection.execute("ALTER TABLE callback_tokens ADD COLUMN actor TEXT")
        if "payload" not in columns:
            self.connection.execute(
                "ALTER TABLE callback_tokens ADD COLUMN payload TEXT NOT NULL DEFAULT '{}'"
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

    def unset(self, key: str) -> None:
        self.connection.execute("DELETE FROM settings WHERE key = ?", (key,))
        self.connection.commit()

    def claim_issue(self, issue: int, title: str, milestone: str) -> bool:
        """Atomically claim one idle queue slot across monitor processes."""

        try:
            self.connection.execute("BEGIN IMMEDIATE")
            current = self.connection.execute(
                "SELECT value FROM settings WHERE key = 'current_issue'"
            ).fetchone()
            if current and str(current["value"]):
                self.connection.rollback()
                return False
            for key, value in (
                ("current_issue", str(issue)),
                ("current_issue_title", title[:200]),
            ):
                self.connection.execute(
                    """
                    INSERT INTO settings(key, value) VALUES(?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (key, value),
                )
            self.connection.execute(
                """
                INSERT INTO events(fingerprint, kind, payload, created_at)
                VALUES(?, 'issue.selected', ?, ?)
                """,
                (
                    f"issue:{issue}:selected:{milestone}",
                    json.dumps(
                        {"issue": issue, "milestone": milestone},
                        sort_keys=True,
                    ),
                    int(self.now()),
                ),
            )
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            self.connection.rollback()
            return False

    def advance_milestone(
        self,
        expected: str,
        following: str,
        initial: str,
        payload: dict[str, Any],
    ) -> bool:
        """Compare-and-set the active milestone and its audit event."""

        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                "SELECT value FROM settings WHERE key = 'active_milestone'"
            ).fetchone()
            active = str(row["value"]) if row else initial
            paused = self.connection.execute(
                "SELECT value FROM settings WHERE key = 'paused'"
            ).fetchone()
            if active != expected or (paused and paused["value"] == "true"):
                self.connection.rollback()
                return False
            self.connection.execute(
                """
                INSERT INTO settings(key, value) VALUES('active_milestone', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (following,),
            )
            self.connection.execute(
                """
                INSERT INTO events(fingerprint, kind, payload, created_at)
                VALUES(?, 'milestone.rollover', ?, ?)
                """,
                (
                    f"milestone:{expected}:advanced:{following}",
                    json.dumps(payload, sort_keys=True),
                    int(self.now()),
                ),
            )
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            self.connection.rollback()
            return False

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

    def notification(self, fingerprint: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM notifications WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()

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

    def supersede_approvals_for_pull_request(
        self, pull_request: int, reason: str
    ) -> int:
        decided_at = int(self.now())
        superseded = 0
        for row in self.pending_approvals("merge_pr"):
            payload = json.loads(row["payload"])
            if int(payload.get("pull_request", -1)) == pull_request:
                self.connection.execute(
                    """
                    UPDATE approvals
                    SET state = 'superseded', decided_at = ?, reason = ?
                    WHERE id = ?
                    """,
                    (decided_at, reason, row["id"]),
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
        self,
        action: str,
        ttl: int,
        approval_id: str | None = None,
        *,
        actor: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> str:
        token = secrets.token_urlsafe(24)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        created = int(self.now())
        self.connection.execute(
            """
            INSERT INTO callback_tokens(
                token_hash, approval_id, action, actor, payload, created_at, expires_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token_hash,
                approval_id,
                action,
                actor,
                json.dumps(payload or {}, sort_keys=True),
                created,
                created + ttl,
            ),
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
            if row["actor"] is not None and str(row["actor"]) != actor:
                raise SupervisorError("This action belongs to another identity")
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
    def milestone(self, title: str) -> dict[str, Any]: ...
    def issue_details(self, number: int) -> dict[str, Any]: ...


class GitHub:
    PR_FIELDS = (
        "number,state,isDraft,headRefOid,headRefName,mergeable,mergeStateStatus,"
        "reviewDecision,statusCheckRollup,url,mergedAt,files,labels"
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
        return (
            min(
                eligible,
                key=lambda item: (
                    "queue:next"
                    not in {label["name"] for label in item.get("labels", [])},
                    int(item["number"]),
                ),
            )
            if eligible
            else None
        )

    def milestone(self, title: str) -> dict[str, Any]:
        owner, repository = self.repository.split("/", 1)
        milestones = self._json(
            [
                "api",
                "--method",
                "GET",
                f"repos/{owner}/{repository}/milestones",
                "-f",
                "state=all",
                "-f",
                "per_page=100",
            ]
        )
        matches = [item for item in milestones if item.get("title") == title]
        if len(matches) != 1:
            raise SupervisorError(f"Milestone is unavailable or ambiguous: {title}")
        return matches[0]

    def issue_details(self, number: int) -> dict[str, Any]:
        return self._json(
            [
                "issue", "view", str(number), "--repo", self.repository,
                "--json", "number,state,milestone,labels",
            ]
        )


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
        rows: dict[int, list[dict[str, str]]] = {}
        for action in actions:
            rows.setdefault(action.row, []).append(
                {
                    "text": action.label,
                    "callback_data": action.token,
                }
            )
        return json.dumps(
            {
                "inline_keyboard": list(rows.values())
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
            {"command": "autonomy", "description": "Show or request autonomy"},
            {"command": "hold", "description": "Confirm a workflow hold"},
            {"command": "resume", "description": "Confirm workflow resume"},
            {"command": "pr", "description": "Show the tracked pull request"},
            {"command": "approve", "description": "Approve the pending PR merge"},
            {"command": "reject", "description": "Reject the pending PR merge"},
            {"command": "retry", "description": "Retry an allowlisted failed stage"},
            {"command": "issue", "description": "Request an issue for a failure"},
            {"command": "pause", "description": "Pause new automated work"},
            {"command": "continue", "description": "Resume automated work"},
            {"command": "watch", "description": "Enable routine status updates"},
            {"command": "unwatch", "description": "Mute routine status updates"},
            {"command": "advance", "description": "Approve milestone rollover"},
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


SENSITIVE_AUTOMERGE_LABELS = {
    "approval-required",
    "destructive-operation",
    "scope-change",
    "secret-change",
    "sensitive-operation",
}
SENSITIVE_AUTOMERGE_PATHS = ("secrets/input/",)


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
        try:
            self.policy = load_policy(
                config.autonomy_policy_file,
                now=datetime.datetime.fromtimestamp(
                    self.store.now(), datetime.timezone.utc
                ),
                allow_expired=True,
            )
        except AutonomyPolicyError as error:
            raise SupervisorError(str(error)) from error
        self.allowed_user = read_protected(
            config.telegram_user_file, "Telegram user ID"
        )
        self.allowed_chat = read_protected(
            config.telegram_chat_file, "Telegram chat ID"
        )
        self.audit_policy()
        self.revert_expired_lease()

    def revert_expired_lease(self) -> bool:
        """Atomically restore Assisted at the original absolute lease boundary."""

        if not self.policy.expires_at:
            return False
        expiry = datetime.datetime.fromisoformat(
            self.policy.expires_at.replace("Z", "+00:00")
        )
        now = datetime.datetime.fromtimestamp(self.store.now(), datetime.timezone.utc)
        if expiry > now:
            return False
        expired_profile = self.policy.profile
        expired_generation = self.policy.generation
        expired_at = self.policy.expires_at
        if self.config.autonomy_policy_file is None:
            self.store.set("autonomy_configuration_state", "expired-lease")
            raise SupervisorError("autonomous lease expired; Assisted reversion unavailable")
        try:
            self.policy = replace_policy(
                self.config.autonomy_policy_file,
                profile="assisted",
                generation=expired_generation + 1,
                now=now,
            )
        except AutonomyPolicyError as error:
            self.store.set("autonomy_configuration_state", "expired-lease")
            raise SupervisorError("autonomous lease expired; Assisted reversion failed") from error
        self.audit_policy()
        self.store.set("autonomy_configuration_state", "active")
        payload = {
            "expired_profile": expired_profile,
            "expired_generation": expired_generation,
            "expired_at": expired_at,
            "profile": "assisted",
            "generation": self.policy.generation,
        }
        self.notify_once(
            f"autonomy:expiry:{expired_generation}:{expired_at}",
            "autonomy.lease_expired",
            f"⏱ Autonomous lease expired at {expired_at}.",
            payload,
            meaningful=True,
        )
        self.notify_once(
            f"autonomy:reverted:{self.policy.generation}",
            "autonomy.reverted",
            "↩ Autonomy reverted to Assisted; automatic PR merging is disabled.",
            payload,
            meaningful=True,
        )
        return True

    def reload_policy(self, role: str) -> None:
        """Atomically adopt one complete policy generation and attest it."""

        try:
            policy = load_policy(
                self.config.autonomy_policy_file,
                now=datetime.datetime.fromtimestamp(
                    self.store.now(), datetime.timezone.utc
                ),
                allow_expired=True,
            )
        except AutonomyPolicyError as error:
            self.store.set("autonomy_configuration_state", "restart-required")
            raise SupervisorError("configuration restart required") from error
        if (
            policy.generation < self.policy.generation
            or (
                policy.generation == self.policy.generation
                and policy.digest != self.policy.digest
            )
        ):
            self.store.set("autonomy_configuration_state", "mismatch")
            raise SupervisorError("configuration mismatch; actions are blocked")
        self.policy = policy
        self.audit_policy()
        if self.revert_expired_lease():
            policy = self.policy
        self.store.set(
            f"process_policy:{role}",
            json.dumps(
                {
                    "generation": policy.generation,
                    "digest": policy.digest,
                    "updated_at": int(self.store.now()),
                },
                sort_keys=True,
            ),
        )
        self.store.set("autonomy_configuration_state", "active")

    def configuration_state(self) -> str:
        persisted = self.store.get("autonomy_configuration_state", "active")
        if persisted in {"expired-lease", "restart-required"}:
            return persisted
        now = int(self.store.now())
        identities = {(self.policy.generation, self.policy.digest)}
        for role in ("monitor", "listener", "runner", "status"):
            raw = self.store.get(f"process_policy:{role}")
            if not raw:
                continue
            try:
                value = json.loads(raw)
                if now - int(value["updated_at"]) <= max(
                    90, self.config.poll_seconds * 3
                ):
                    identities.add(
                        (int(value["generation"]), str(value["digest"]))
                    )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                return "mismatch"
        return "active" if len(identities) == 1 else "mismatch"

    def require_consistent_policy(
        self, role: str, *, allow_expired_recovery: bool = False
    ) -> None:
        try:
            self.reload_policy(role)
        except SupervisorError:
            if (
                allow_expired_recovery
                and self.configuration_state() == "expired-lease"
            ):
                return
            raise
        if self.configuration_state() != "active":
            self.store.set("autonomy_configuration_state", "mismatch")
            raise SupervisorError("configuration mismatch; actions are blocked")

    def audit_policy(self) -> None:
        """Record each effective policy generation/digest transition once."""

        previous_digest = self.store.get("autonomy_policy_digest")
        previous_generation = self.store.get("autonomy_policy_generation")
        if (
            previous_digest == self.policy.digest
            and previous_generation == str(self.policy.generation)
        ):
            return
        self.store.event(
            f"autonomy-policy:{self.policy.generation}:{self.policy.digest}",
            "autonomy.policy_changed",
            {
                "profile": self.policy.profile,
                "generation": self.policy.generation,
                "digest": self.policy.digest,
                "previous_digest": previous_digest or None,
                "previous_generation": (
                    int(previous_generation)
                    if previous_generation.isdigit()
                    else None
                ),
            },
        )
        self.store.set("autonomy_policy_digest", self.policy.digest)
        self.store.set("autonomy_policy_generation", str(self.policy.generation))

    def policy_decision(self, action: str) -> str:
        try:
            return self.policy.decision(action)
        except AutonomyPolicyError as error:
            raise SupervisorError(str(error)) from error

    def authorized_milestones(self) -> tuple[str, ...]:
        return self.config.milestones or (self.config.milestone,)

    def active_milestone(self) -> str:
        active = self.store.get("active_milestone", self.config.milestone)
        if active not in self.authorized_milestones():
            raise SupervisorError(
                "Active milestone is outside the configured authorization sequence"
            )
        return active

    def next_milestone(self) -> str | None:
        authorized = self.authorized_milestones()
        position = authorized.index(self.active_milestone())
        return authorized[position + 1] if position + 1 < len(authorized) else None

    def status_text(self) -> str:
        paused = self.store.get("paused", "false") == "true"
        pr = self.store.get("current_pr", "none")
        issue = self.store.get("current_issue")
        heartbeat = (
            read_heartbeat(self.config.heartbeat_root, int(issue))
            if self.config.heartbeat_root and issue.isdigit()
            else None
        )
        status = self.policy.status()
        status["configuration_state"] = self.configuration_state()
        return render_card(
            milestone=self.active_milestone(),
            issue=issue,
            title=self.store.get("current_issue_title"),
            paused=paused,
            heartbeat=heartbeat,
            pr_state=f"#{pr}" if pr and pr != "none" else "none",
            ci_state=self.store.get("ci_state", "not started"),
            approval_ready=bool(self.store.pending_approvals("merge_pr")),
            autonomy_policy=status,
            queue_state=self.queue_state(),
            now=self.store.now(),
        )

    def queue_state(self) -> str:
        if self.store.get("current_issue"):
            return "active"
        if self.store.get("paused", "false") == "true":
            return "held"
        if self.store.get("last_error"):
            return "blocked"
        current = self.active_milestone()
        if self.store.has_event(f"milestone:{current}:complete"):
            return "rollover-pending" if self.next_milestone() else "complete"
        return "idle"

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
        if text.split(maxsplit=1)[0].split("@", 1)[0].lower() == "/confirm":
            # Prove that the private control channel is writable before consuming
            # the single-use capability or applying its requested mutation.
            self.telegram.send("Confirmation received; applying the requested change.")
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
            if outcome.startswith("CONFIRM_STOP:"):
                confirm_token = outcome.split(":", 1)[1]
                self.telegram.send(
                    "⚠ Confirm stopping the active bounded runner. "
                    "This does not delete its worktree or data.",
                    (InlineAction("Confirm Stop", confirm_token),),
                )
                self.telegram.answer_callback(callback_id, "Confirmation sent")
            elif outcome.startswith("PR #") or outcome.startswith("Workflow details"):
                self.telegram.send(outcome)
                self.telegram.answer_callback(callback_id, "Details sent")
            else:
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
        candidate = self.store.connection.execute(
            "SELECT * FROM callback_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if not candidate:
            raise SupervisorError("This action is invalid or no longer available")
        candidate_action = str(candidate["action"])
        candidate_payload = json.loads(str(candidate["payload"] or "{}"))
        expired_policy_recovery = (
            candidate_action == "autonomy-change"
            and candidate_payload.get("operation") == "profile"
        )
        if candidate_action not in {
            "status",
            "refresh",
            "workflow-details",
            "details",
        }:
            self.require_consistent_policy(
                "listener",
                allow_expired_recovery=expired_policy_recovery,
            )
        if candidate["approval_id"]:
            approval = self.store.approval(str(candidate["approval_id"]))
            approval_payload = json.loads(approval["payload"])
            if approval["action"] == "merge_pr":
                approval_pr = self.github.pull_request(
                    int(approval_payload["pull_request"])
                )
                self.verify_merge_plan(
                    approval_pr, approval_payload, allow_draft=True
                )
            elif approval["action"] == "milestone_rollover":
                self.verify_milestone_rollover(approval_payload)
            else:
                raise SupervisorError("Unsupported approval action")
        row = self.store.consume_callback_token(token, actor)
        action = str(row["action"])
        callback_payload = json.loads(str(row["payload"] or "{}"))
        if action == "autonomy-change":
            self.require_consistent_policy(
                "listener",
                allow_expired_recovery=callback_payload.get("operation") == "profile",
            )
            return self.apply_autonomy_change(callback_payload, actor)
        if action in {"status", "refresh"}:
            return self.status_text()
        if action == "workflow-details":
            details = "Workflow details\n" + self.status_text()
            number = self.store.get("current_pr")
            if number.isdigit():
                pr = self.github.pull_request(int(number))
                details += (
                    f"\nChecks: {checks_state(pr)}"
                    f"\nMerge: {pr.get('mergeStateStatus', 'unknown')}"
                    f"\n{pr.get('url', '')}"
                )
            return details
        if action == "watch":
            watched = self.store.get("watched", "true") == "true"
            self.store.set("watched", "false" if watched else "true")
            self.store.event(
                f"watch:{int(self.store.now())}:{actor}",
                "runner.watch_changed",
                {"actor": actor, "watched": not watched},
            )
            return "Workflow watched" if not watched else "Routine updates muted"
        if action == "pause-general":
            self.store.set("paused", "true")
            self.store.event(
                f"pause:{int(self.store.now())}:{actor}",
                "supervisor.paused",
                {"actor": actor},
            )
            return "Supervisor paused"
        if action == "continue-general":
            self.store.set("paused", "false")
            self.store.event(
                f"continue:{int(self.store.now())}:{actor}",
                "supervisor.continued",
                {"actor": actor},
            )
            return "Supervisor resumed"
        if action == "stop":
            if not self.config.runner_stop_command:
                raise SupervisorError("Stop is disabled by local policy")
            confirm = self.store.create_callback_token(
                "stop-confirm",
                min(300, self.config.approval_ttl_seconds),
                actor=actor,
                payload=callback_payload,
            )
            return f"CONFIRM_STOP:{confirm}"
        if action == "stop-confirm":
            issue = int(callback_payload.get("issue", 0))
            if not self.config.runner_stop_command or issue < 1:
                raise SupervisorError("Stop is disabled by local policy")
            self.run(
                [*self.config.runner_stop_command, str(issue)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            self.store.event(
                f"runner:{issue}:stop:{int(self.store.now())}",
                "runner.stop_requested",
                {"actor": actor, "issue": issue},
            )
            return f"Stop requested for issue #{issue}"
        approval_id = str(row["approval_id"] or "")
        approval = self.store.approval(approval_id)
        payload = json.loads(approval["payload"])
        pr = approval_pr if approval["action"] == "merge_pr" else None
        if action == "advance-milestone":
            return self.approve_milestone_rollover(approval_id, actor)
        if action == "stay-milestone":
            self.store.decide(
                approval_id, "rejected", actor, "operator-deferred"
            )
            self.store.set("paused", "true")
            self.store.event(
                f"approval:{approval_id}:rollover-deferred",
                "milestone.rollover_deferred",
                {
                    "actor": actor,
                    "from": payload["from"],
                    "to": payload["to"],
                },
            )
            return "Milestone rollover deferred; supervisor paused"
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
            assert pr is not None
            return (
                f"PR #{payload['pull_request']}\n"
                f"Checks: {checks_state(pr)}\n"
                f"Merge: {pr.get('mergeStateStatus', 'unknown')}\n"
                f"Draft: {'yes' if pr.get('isDraft') else 'no'}\n"
                f"Head: {str(pr.get('headRefOid') or '')[:12]}\n"
                f"{pr.get('url', '')}"
            )
        raise SupervisorError("Unsupported callback action")

    def request_confirmation(
        self, action: str, payload: dict[str, Any], actor: str
    ) -> str:
        token = self.store.create_callback_token(
            action,
            min(300, self.config.approval_ttl_seconds),
            actor=actor,
            payload=payload,
        )
        return (
            "Pending confirmation. This request expires in 5 minutes and is "
            f"single-use. Confirm with /confirm {token}"
        )

    def apply_autonomy_change(self, payload: dict[str, Any], actor: str) -> str:
        operation = str(payload.get("operation"))
        if operation == "hold":
            self.store.set("paused", "true")
            result = "Held"
        elif operation == "resume":
            self.store.set("paused", "false")
            result = "Resumed"
        elif operation == "approve-once":
            self.store.set("autonomy_approve_once", "true")
            result = "One merge approval armed"
        else:
            profile = str(payload.get("profile"))
            if profile not in {"manual", "assisted", "autonomous"}:
                raise SupervisorError("Unsupported autonomy change")
            if self.config.autonomy_policy_file is None:
                raise SupervisorError("configuration restart required")
            expiry = payload.get("expires_at")
            try:
                self.policy = replace_policy(
                    self.config.autonomy_policy_file,
                    profile=profile,
                    generation=self.policy.generation + 1,
                    expires_at=str(expiry) if expiry else None,
                    now=datetime.datetime.fromtimestamp(
                        self.store.now(), datetime.timezone.utc
                    ),
                )
            except AutonomyPolicyError as error:
                raise SupervisorError(str(error)) from error
            self.audit_policy()
            result = f"Autonomy changed to {profile}"
        self.store.event(
            f"autonomy-control:{int(self.store.now())}:{secrets.token_hex(4)}",
            "autonomy.control_changed",
            {
                "actor": actor,
                "operation": operation,
                "profile": self.policy.profile,
                "generation": self.policy.generation,
                "digest": self.policy.digest,
            },
        )
        self.reload_policy("listener")
        if operation == "profile":
            self.notify_once(
                f"autonomy:activated:{self.policy.generation}:{self.policy.digest}",
                "autonomy.activated",
                (
                    f"🤖 Autonomous mode activated until {self.policy.expires_at}."
                    if self.policy.profile == "autonomous"
                    else f"Autonomy changed to {self.policy.profile}."
                ),
                {
                    "actor": actor,
                    "profile": self.policy.profile,
                    "generation": self.policy.generation,
                    "expires_at": self.policy.expires_at,
                },
                meaningful=True,
            )
        return f"{result}. {self.autonomy_text()}"

    def autonomy_text(self) -> str:
        held = self.store.get("paused", "false") == "true"
        expiry = self.policy.expires_at or "none"
        decisions = ", ".join(
            f"{name}={value}" for name, value in self.policy.decisions.items()
        )
        state = self.configuration_state()
        return (
            f"Autonomy: {self.policy.profile}\n"
            f"State: {'held' if held else 'active'}\n"
            f"Generation: {self.policy.generation}\n"
            f"Digest: {self.policy.digest[:12]}\n"
            f"Lease expiry: {expiry}\n"
            f"Configuration: {state}\nPolicy: {decisions}"
        )

    def workflow_actions(self) -> tuple[InlineAction, ...]:
        issue = self.store.get("current_issue")
        paused = self.store.get("paused", "false") == "true"
        actions = [("Details", "workflow-details")]
        if paused:
            actions.insert(0, ("Continue", "continue-general"))
        elif issue.isdigit() and self.config.runner_stop_command:
            actions.append(("Stop", "stop"))
        else:
            actions.append(("Refresh", "refresh"))
        return tuple(
            InlineAction(
                label,
                self.store.create_callback_token(
                    action,
                    self.config.approval_ttl_seconds,
                    actor=self.allowed_user,
                    payload={"issue": int(issue)} if issue.isdigit() else {},
                ),
            )
            for label, action in actions
        )

    def handle_command(self, text: str, actor: str) -> str:
        parts = shlex.split(text)
        command = parts[0].split("@", 1)[0].lower()
        if command == "/hold":
            if len(parts) != 1:
                raise SupervisorError("Usage: /hold")
            self.store.set("paused", "true")
            self.store.event(
                f"emergency-hold:{int(self.store.now())}",
                "supervisor.emergency_hold",
                {"actor": actor},
            )
            self.notify_once(
                f"emergency-hold-notice:{int(self.store.now())}",
                "supervisor.emergency_hold_notice",
                "🛑 Emergency hold active. Monitoring continues; no automatic action may start.",
                {"actor": actor},
                severity="failure",
                meaningful=True,
            )
            return "Emergency hold active"
        try:
            self.reload_policy("listener")
        except SupervisorError:
            if self.configuration_state() == "expired-lease":
                if command == "/autonomy" and len(parts) == 1:
                    return self.autonomy_text()
                if command in {"/autonomy", "/confirm"}:
                    pass
                else:
                    raise
            else:
                raise
        if command == "/autonomy":
            if len(parts) == 1:
                return self.autonomy_text()
            if parts[1] not in {"manual", "assisted", "autonomous"}:
                raise SupervisorError(
                    "Usage: /autonomy [manual|assisted|autonomous <duration>]"
                )
            profile = parts[1]
            payload: dict[str, Any] = {
                "operation": "profile",
                "profile": profile,
            }
            if profile == "autonomous":
                if len(parts) != 3:
                    raise SupervisorError(
                        "Usage: /autonomy autonomous <duration>"
                    )
                match = re.fullmatch(r"([1-9][0-9]*)(m|h|d)", parts[2])
                if not match:
                    raise SupervisorError("Duration must use a positive m, h, or d value")
                seconds = int(match.group(1)) * {"m": 60, "h": 3600, "d": 86400}[
                    match.group(2)
                ]
                if seconds > 7 * 86400:
                    raise SupervisorError("Autonomous duration cannot exceed 7 days")
                payload["expires_at"] = datetime.datetime.fromtimestamp(
                    self.store.now() + seconds, datetime.timezone.utc
                ).isoformat().replace("+00:00", "Z")
            elif len(parts) != 2:
                raise SupervisorError(f"Usage: /autonomy {profile}")
            return self.request_confirmation("autonomy-change", payload, actor)
        if command in {"/resume", "/approve-once"}:
            if len(parts) != 1:
                raise SupervisorError(f"Usage: {command}")
            return self.request_confirmation(
                "autonomy-change",
                {"operation": command.removeprefix("/")},
                actor,
            )
        if command == "/confirm":
            if len(parts) != 2:
                raise SupervisorError("Usage: /confirm <token>")
            return self.execute_callback(parts[1], actor)
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
        self.require_consistent_policy("listener")
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
        if command in {"/watch", "/unwatch"}:
            watched = command == "/watch"
            self.store.set("watched", "true" if watched else "false")
            self.store.event(
                f"watch-command:{int(self.store.now())}:{actor}",
                "runner.watch_changed",
                {"actor": actor, "watched": watched},
            )
            return (
                "▶️ Routine status updates enabled."
                if watched
                else "🔕 Routine status updates muted."
            )
        if command == "/start-next":
            if len(parts) != 1:
                raise SupervisorError("Usage: /start-next")
            if self.policy_decision("start_next_issue") != "approval":
                raise SupervisorError(
                    "Starting the next issue is not approval-bound by policy"
                )
            issue = self.queue_next_issue(operator_approved=True)
            return (
                f"Issue #{issue['number']} was started."
                if issue
                else "No eligible issue is available."
            )
        if command == "/close-completed":
            if len(parts) != 1:
                raise SupervisorError("Usage: /close-completed")
            if self.policy_decision("close_completed_issue") != "approval":
                raise SupervisorError(
                    "Completed issue closure is not approval-bound by policy"
                )
            issue = self.store.get("pending_close_issue")
            if not issue.isdigit():
                raise SupervisorError("No completed issue is awaiting closure")
            self.github.close_issue(int(issue))
            self.store.set("pending_close_issue", "")
            self.store.event(
                f"issue:{issue}:close-approved",
                "issue.close_approved",
                {"actor": actor, "issue": int(issue)},
            )
            return f"Issue #{issue} was closed."
        if command == "/advance":
            if len(parts) != 1:
                raise SupervisorError("Usage: /advance")
            if self.policy_decision("advance_milestone") == "disabled":
                raise SupervisorError("Milestone advance is disabled by autonomy policy")
            approval_id = self.current_approval_id("milestone_rollover")
            return self.approve_milestone_rollover(approval_id, actor)
        if command == "/approve":
            if len(parts) > 2:
                raise SupervisorError("Usage: /approve [approval-id]")
            if self.policy_decision("merge_pull_request") == "disabled":
                raise SupervisorError("Pull request merge is disabled by autonomy policy")
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
            if self.policy_decision("retry_idempotent_failure") == "disabled":
                raise SupervisorError("Retry is disabled by autonomy policy")
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
                "/start-next\n/close-completed\n/pause\n/continue\n"
                "/watch\n/unwatch\n/advance\n/help"
            )
        raise SupervisorError("Unknown command. Use /help.")

    def current_approval_id(self, action: str) -> str:
        approvals = self.store.pending_approvals(action)
        current_pr = self.store.get("current_pr")
        if action == "merge_pr" and current_pr:
            current = [
                row
                for row in approvals
                if str(json.loads(row["payload"]).get("pull_request")) == current_pr
            ]
            if len(current) == 1:
                return str(current[0]["id"])
            if len(current) > 1:
                approvals = current
        if not approvals:
            raise SupervisorError(f"No pending {action.replace('_', ' ')} approval")
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
        if actor == "autonomy-policy":
            self.verify_autonomous_merge(pr, payload)
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
        if actor == "autonomy-policy":
            self.notify_once(
                f"pr:{payload['pull_request']}:automatic-merge:{payload['head_sha']}",
                "pull_request.automatic_merge",
                f"🤖 PR #{payload['pull_request']} automatically merged at "
                f"{str(payload['head_sha'])[:12]}.",
                {
                    "pull_request": int(payload["pull_request"]),
                    "head_sha": str(payload["head_sha"]),
                },
                meaningful=True,
            )
        self.store.event(
            f"approval:{approval_id}:merge",
            "pull_request.merge_approved",
            {"pull_request": payload["pull_request"], "actor": actor},
        )
        next_issue = self.complete_merged_pull_request(pr)
        if next_issue is None:
            if self.store.get("paused", "false") == "true":
                return (
                    f"✅ PR #{payload['pull_request']} merge approved and completed. "
                    "The supervisor is paused; no new issue was started."
                )
            if not re.fullmatch(r"agent/issue-\d+", str(pr.get("headRefName") or "")):
                return (
                    f"✅ PR #{payload['pull_request']} merge approved and completed. "
                    "The maintenance PR did not advance the issue queue."
                )
            return (
                f"✅ PR #{payload['pull_request']} merge approved and completed. "
                f"Milestone {self.active_milestone()} is complete."
            )
        return (
            f"✅ PR #{payload['pull_request']} merge approved and completed; "
            f"issue #{next_issue['number']} was started."
        )

    def verify_milestone_rollover(self, payload: dict[str, Any]) -> None:
        if payload.get("repository") != self.config.repository:
            raise SupervisorError("Milestone rollover repository changed")
        if payload.get("from") != self.active_milestone():
            raise SupervisorError("Active milestone changed; request a new approval")
        if payload.get("to") != self.next_milestone():
            raise SupervisorError("Next authorized milestone changed")
        milestone = self.github.milestone(self.active_milestone())
        if milestone.get("state") != "closed":
            raise SupervisorError("Current milestone must be closed before rollover")
        if int(milestone.get("open_issues", 0)) != 0:
            raise SupervisorError("Current milestone still has open issues")
        if self.github.next_issue(self.active_milestone()) is not None:
            raise SupervisorError("Current milestone has newly eligible work")
        following = self.github.milestone(str(payload["to"]))
        if following.get("state") != "open":
            raise SupervisorError("Next authorized milestone must be open")

    def transition_milestone(
        self, payload: dict[str, Any], actor: str
    ) -> dict[str, Any] | None:
        self.verify_milestone_rollover(payload)
        decision = self.policy_decision("advance_milestone")
        audit = {
            "actor": actor,
            "decision": decision,
            "from": payload["from"],
            "to": payload["to"],
            "preconditions": {
                "current_closed": True,
                "current_open_issues": 0,
                "current_eligible_work": False,
                "next_open": True,
                "sequence_match": True,
                "paused": False,
                "conflicting_approval": False,
            },
        }
        if not self.store.advance_milestone(
            str(payload["from"]),
            str(payload["to"]),
            self.config.milestone,
            audit,
        ):
            return None
        self.store.set("last_error", "")
        return self.queue_next_issue()

    def approve_milestone_rollover(self, approval_id: str, actor: str) -> str:
        row = self.store.approval(approval_id)
        if row["action"] != "milestone_rollover":
            raise SupervisorError("Unsupported approval action")
        payload = json.loads(row["payload"])
        self.verify_milestone_rollover(payload)
        self.store.decide(approval_id, "approved", actor)
        issue = self.transition_milestone(payload, actor)
        self.store.event(
            f"approval:{approval_id}:rollover",
            "milestone.rollover_approved",
            {"actor": actor, "from": payload["from"], "to": payload["to"]},
        )
        if issue is None:
            return f"Advanced to {payload['to']}; no eligible issue is available"
        return f"Advanced to {payload['to']}; issue #{issue['number']} was started"

    def offer_milestone_rollover(self) -> None:
        current = self.active_milestone()
        following = self.next_milestone()
        if following is None:
            return
        try:
            milestone = self.github.milestone(current)
        except SupervisorError as error:
            self.store.set("last_error", "milestone rollover blocked")
            self.notify_once(
                f"milestone:{current}:rollover-state-error",
                "milestone.rollover_blocked",
                f"Milestone rollover blocked: {error}",
                {"from": current, "reason": "github-state"},
                severity="failure",
                meaningful=True,
            )
            return
        if (
            milestone.get("state") != "closed"
            or int(milestone.get("open_issues", 0)) != 0
        ):
            self.notify_once(
                f"milestone:{current}:awaiting-close",
                "milestone.awaiting_close",
                f"Milestone {current} has no eligible issues. Close it after "
                "confirming completion to enable rollover.",
                {"milestone": current},
            )
            return
        payload = {
            "repository": self.config.repository,
            "from": current,
            "to": following,
        }
        try:
            self.verify_milestone_rollover(payload)
        except SupervisorError as error:
            self.store.set("last_error", "milestone rollover blocked")
            self.notify_once(
                f"milestone:{current}:rollover-invalid:{following}",
                "milestone.rollover_blocked",
                f"Milestone rollover blocked: {error}",
                {"from": current, "to": following, "reason": "precondition"},
                severity="failure",
                meaningful=True,
            )
            return
        decision = self.policy_decision("advance_milestone")
        if decision == "disabled":
            self.notify_once(
                f"milestone:{current}:rollover-disabled:{following}",
                "milestone.rollover_disabled",
                f"Milestone advance from {current} is disabled by autonomy policy.",
                {"from": current, "to": following},
                meaningful=True,
            )
            return
        approval = self.store.pending_approval("milestone_rollover", payload)
        if approval is None:
            approval = self.store.create_approval(
                "milestone_rollover",
                payload,
                self.config.approval_ttl_seconds,
            )
        if decision == "auto":
            if self.store.pending_approvals("merge_pr"):
                self.notify_once(
                    f"milestone:{current}:rollover-conflicting-approval",
                    "milestone.rollover_blocked",
                    "Milestone rollover is blocked by a pending merge approval.",
                    {"from": current, "to": following},
                    severity="failure",
                    meaningful=True,
                )
                return
            self.store.decide(
                str(approval["id"]), "approved", "autonomy-policy"
            )
            self.transition_milestone(payload, "autonomy-policy")
            return
        actions = tuple(
            InlineAction(
                label,
                self.store.create_callback_token(
                    action,
                    self.config.approval_ttl_seconds,
                    str(approval["id"]),
                    actor=self.allowed_user,
                ),
            )
            for label, action in (
                ("Advance", "advance-milestone"),
                ("Stay", "stay-milestone"),
            )
        ) + (
            InlineAction(
                "Details",
                self.store.create_callback_token(
                    "workflow-details",
                    self.config.approval_ttl_seconds,
                    actor=self.allowed_user,
                ),
                row=1,
            ),
        )
        self.notify_once(
            f"milestone:{current}:rollover:{following}:{approval['id']}",
            "milestone.rollover_ready",
            f"🎯 {current} is complete. Advance to {following}?",
            {"from": current, "to": following},
            meaningful=True,
            actions=actions,
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

        self.store.supersede_approvals_for_pull_request(
            number, "pull request merged"
        )
        if self.store.has_event(fingerprint):
            return None

        close_decision = self.policy_decision("close_completed_issue")
        if issue_number is not None and close_decision == "auto":
            self.github.close_issue(issue_number)
        elif issue_number is not None:
            if close_decision == "approval":
                self.store.set("pending_close_issue", str(issue_number))
            self.notify_once(
                f"issue:{issue_number}:close:{close_decision}",
                "issue.close_policy",
                f"Issue #{issue_number} requires operator closure."
                if close_decision == "approval"
                else f"Issue #{issue_number} closure is disabled by autonomy policy.",
                {"issue": issue_number, "decision": close_decision},
                meaningful=True,
            )

        advances_queue = issue_number is not None
        self.notify_once(
            f"pr:{number}:merged-notice:{sha}",
            "pull_request.merged_notice",
            (
                f"✅ PR #{number} merged. Selecting next issue."
                if advances_queue
                else f"✅ Maintenance PR #{number} merged. Issue queue unchanged."
            ),
            {"pull_request": number, "head_sha": sha},
        )
        if issue_number is not None and self.store.get("current_issue") == str(
            issue_number
        ):
            self.store.set("current_issue", "")
        next_issue = (
            self.queue_next_issue(issue_number) if advances_queue else None
        )
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

    def verify_autonomous_merge(self, pr: dict[str, Any], payload: dict[str, Any]) -> None:
        """Apply every fail-closed gate unique to unattended merging."""

        self.verify_merge_plan(pr, payload)
        if self.policy.profile != "autonomous" or self.policy.expires_at is None:
            raise SupervisorError("Autonomous lease is not active")
        if self.store.get("paused", "false") == "true":
            raise SupervisorError("Emergency hold or pause is active")
        if self.configuration_state() != "active":
            raise SupervisorError("Autonomy configuration is not consistent")
        if self.store.get("last_error"):
            raise SupervisorError("An unresolved workflow failure exists")
        if str(pr.get("reviewDecision") or "") == "CHANGES_REQUESTED":
            raise SupervisorError("Changes are requested")

        checks: dict[str, list[dict[str, Any]]] = {}
        for check in pr.get("statusCheckRollup") or []:
            name = str(check.get("name") or check.get("context") or "")
            if name:
                checks.setdefault(name, []).append(check)
        for name in self.config.required_merge_checks:
            matches = checks.get(name, [])
            if len(matches) != 1:
                raise SupervisorError(f"Required check is missing or ambiguous: {name}")
            check = matches[0]
            if (
                str(check.get("status") or "").upper() != "COMPLETED"
                or str(check.get("conclusion") or "").upper() != "SUCCESS"
            ):
                raise SupervisorError(f"Required check did not pass: {name}")

        branch = str(pr.get("headRefName") or "")
        match = re.fullmatch(r"agent/issue-(\d+)", branch)
        if match is None:
            raise SupervisorError("PR branch is not bound to an issue")
        issue_number = int(match.group(1))
        if self.store.get("current_issue") != str(issue_number):
            raise SupervisorError("PR branch does not match the active issue")
        issue = self.github.issue_details(issue_number)
        milestone = issue.get("milestone") or {}
        if (
            int(issue.get("number", 0)) != issue_number
            or issue.get("state") != "OPEN"
            or str(milestone.get("title") or "") != self.active_milestone()
        ):
            raise SupervisorError("Issue is not open in the active authorized milestone")

        labels = {
            str(item.get("name") or "")
            for item in [*(pr.get("labels") or []), *(issue.get("labels") or [])]
        }
        if labels & SENSITIVE_AUTOMERGE_LABELS:
            raise SupervisorError("Sensitive-operation policy requires approval")
        paths = [str(item.get("path") or "") for item in pr.get("files") or []]
        if any(path.startswith(SENSITIVE_AUTOMERGE_PATHS) for path in paths):
            raise SupervisorError("Sensitive file scope requires approval")

    def monitor_once(self) -> None:
        self.require_consistent_policy("monitor")
        self.deliver_digest()
        self.monitor_runner()
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
                self.notify_once(
                    f"pr:{number}:created",
                    "pull_request.created",
                    f"🔀 PR #{number} created for the active workflow.",
                    {"pull_request": int(number)},
                    meaningful=True,
                )
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
                if not self.store.get("current_issue"):
                    self.queue_next_issue()
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
        previous_ci = self.store.get(f"pr:{number}:ci")
        self.store.set("ci_state", check_state)
        self.store.set(f"pr:{number}:ci", check_state)
        if previous_ci == "pending" and check_state in {"passed", "failed"}:
            self.notify_once(
                f"pr:{number}:ci:{sha}:{check_state}",
                "pull_request.ci_completed",
                f"{'✅' if check_state == 'passed' else '❌'} "
                f"CI {check_state} for PR #{number}.",
                {"pull_request": int(number), "ci_state": check_state},
                severity="failure" if check_state == "failed" else "info",
                meaningful=True,
            )
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
            if (
                "checks" in self.config.notifications.retry_stages
                and self.policy_decision("retry_idempotent_failure") == "auto"
            ):
                self.store.event(
                    f"retry:pr:{number}:checks:{sha}",
                    "recovery.retry_requested",
                    {
                        "actor": "autonomy-policy",
                        "pull_request": int(number),
                        "stage": "checks",
                        "verified_idempotent": True,
                    },
                )
            return
        if check_state != "passed" or pr.get("mergeable") != "MERGEABLE":
            return
        merge_decision = self.policy_decision("merge_pull_request")
        if merge_decision == "disabled":
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
        if merge_decision == "auto":
            try:
                self.verify_autonomous_merge(pr, payload)
                self.approve(str(approval["id"]), "autonomy-policy")
            except SupervisorError as error:
                merged = self.store.notification(
                    f"pr:{number}:automatic-merge:{sha}"
                ) is not None
                self.notify_once(
                    f"pr:{number}:autonomous-exception:{sha}:{hashlib.sha256(str(error).encode()).hexdigest()[:12]}",
                    "pull_request.autonomous_exception",
                    (
                        f"⚠ Automatic post-merge progression failed for PR #{number}: {error}"
                        if merged
                        else f"⚠ Automatic merge blocked for PR #{number}: {error}"
                    ),
                    {
                        "pull_request": int(number),
                        "head_sha": sha,
                        "reason": str(error),
                        "merged": merged,
                    },
                    severity="failure",
                    meaningful=True,
                )
            return
        if self.store.get("autonomy_approve_once") == "true":
            self.store.set("autonomy_approve_once", "false")
            self.approve(str(approval["id"]), "autonomy-approve-once")
            return
        fingerprint = f"pr:{number}:approval-ready:{sha}"
        notification = self.store.notification(fingerprint)
        if notification is None or notification["state"] == "pending":
            actions = tuple(
                InlineAction(
                    label,
                    self.store.create_callback_token(
                        action,
                        self.config.approval_ttl_seconds,
                        str(approval["id"]),
                        actor=self.allowed_user,
                    ),
                )
                for label, action in (
                    ("Approve", "approve"),
                    ("Reject", "reject"),
                    ("Details", "details"),
                )
            )
            actions = tuple(
                dataclasses.replace(action, row=1)
                if action.label == "Details"
                else action
                for action in actions
            )
            self.notify_once(
                fingerprint,
                "pull_request.approval_ready",
                f"✅ PR #{number} is ready for operator approval.",
                {"pull_request": int(number), "head_sha": sha},
                meaningful=True,
                actions=actions,
            )
            self.update_status_card(actions)

    def monitor_runner(self) -> None:
        """Observe durable runner evidence; never advance runner authority."""

        issue = self.store.get("current_issue")
        if not issue.isdigit() or not self.config.heartbeat_root:
            return
        heartbeat = read_heartbeat(self.config.heartbeat_root, int(issue))
        if not heartbeat:
            return
        now = self.store.now()
        generation = int(heartbeat["generation"])
        phase = str(heartbeat["phase"])
        health = str(heartbeat["runner_health"])
        if health in {"completed", "failed"}:
            self.store.unset("process_policy:runner")
        else:
            self.store.set(
                "process_policy:runner",
                json.dumps(
                    {
                        "generation": heartbeat["policy_generation"],
                        "digest": heartbeat["policy_digest"],
                        "updated_at": int(now),
                    },
                    sort_keys=True,
                ),
            )
            if (
                int(heartbeat["policy_generation"]) != self.policy.generation
                or str(heartbeat["policy_digest"]) != self.policy.digest
            ):
                self.store.set("autonomy_configuration_state", "mismatch")
                raise SupervisorError(
                    "configuration mismatch; runner actions are blocked"
                )
        prefix = f"runner:{issue}:{generation}"
        previous_phase = self.store.get(f"{prefix}:phase")
        previous_health = self.store.get(f"{prefix}:health")

        if not self.store.has_event(f"{prefix}:started"):
            self.notify_once(
                f"{prefix}:started",
                "runner.started",
                f"▶️ Work started on issue #{issue}: "
                f"{self.store.get('current_issue_title', 'title unavailable')}",
                {"issue": int(issue), "phase": phase},
                meaningful=True,
            )

        attention_phases = {"waiting-for-approval", "failed"}
        if previous_phase and phase != previous_phase and phase in attention_phases:
            self.notify_once(
                f"{prefix}:phase:{phase}",
                "runner.phase_attention",
                f"🔔 Issue #{issue} entered {phase}.",
                {"issue": int(issue), "phase": phase},
                severity="failure" if phase == "failed" else "info",
                meaningful=True,
            )

        stalled = health in {"possibly-stalled", "stalled"}
        was_stalled = previous_health in {"possibly-stalled", "stalled"}
        if stalled and health != previous_health:
            self.notify_once(
                f"{prefix}:health:{health}",
                "runner.stalled",
                render_stall(heartbeat, now),
                {
                    "issue": int(issue),
                    "phase": phase,
                    "runner_health": health,
                },
                severity="failure",
                meaningful=True,
            )
        elif was_stalled and not stalled:
            self.notify_once(
                f"{prefix}:recovered:{heartbeat['revision']}",
                "runner.recovered",
                f"✅ Runner recovered on issue #{issue}; phase {phase}.",
                {"issue": int(issue), "phase": phase},
                meaningful=True,
            )

        elapsed = max(0, now - datetime.datetime.fromisoformat(
            str(heartbeat["started_at"]).replace("Z", "+00:00")
        ).timestamp())
        last_routine = float(self.store.get(f"{prefix}:last-routine", "0") or 0)
        due = elapsed >= 600 and (
            last_routine == 0 or now - last_routine >= heartbeat_interval(elapsed)
        )
        meaningful_at = float(self.store.get("last_meaningful_notification", "0") or 0)
        if (
            due
            and self.store.get("watched", "true") == "true"
            and not self.config.notifications.quiet(now)
            and now - meaningful_at >= min(600, heartbeat_interval(elapsed))
        ):
            slot = int(elapsed // heartbeat_interval(elapsed))
            self.notify_once(
                f"{prefix}:heartbeat:{slot}",
                "runner.heartbeat",
                self.status_text(),
                {"issue": int(issue), "phase": phase, "slot": slot},
            )
            self.store.set(f"{prefix}:last-routine", str(int(now)))

        self.store.set(f"{prefix}:phase", phase)
        self.store.set(f"{prefix}:health", health)
        if not self.store.pending_approvals("merge_pr"):
            self.update_status_card()

    def update_status_card(
        self, actions: tuple[InlineAction, ...] = ()
    ) -> None:
        if not actions:
            actions = self.workflow_actions()
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
        meaningful: bool = False,
        actions: tuple[InlineAction, ...] = (),
    ) -> None:
        sanitized = sanitize_diagnostics(payload)
        if not isinstance(sanitized, dict):
            sanitized = {}
        preferences = self.config.notifications
        deferred = (
            preferences.quiet(self.store.now()) and not meaningful
        ) or (
            preferences.mode == "failures"
            and severity != "failure"
            and not meaningful
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
                self.telegram.edit(
                    MessageReference(str(row["message_id"])), rendered, actions
                )
            elif created or row["state"] == "pending":
                reference = self.telegram.send(rendered, actions)
                self.store.mark_notification(
                    fingerprint, "delivered", reference.message_id
                )
                if meaningful:
                    self.store.set(
                        "last_meaningful_notification", str(int(self.store.now()))
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
        self,
        completed_issue: int | None = None,
        *,
        operator_approved: bool = False,
    ) -> dict[str, Any] | None:
        if self.store.get("paused", "false") == "true":
            return None
        decision = self.policy_decision("start_next_issue")
        if decision != "auto" and not (
            decision == "approval" and operator_approved
        ):
            self.notify_once(
                f"issue:start-policy:{self.active_milestone()}:{decision}",
                "issue.start_policy",
                "Starting the next issue requires operator approval."
                if decision == "approval"
                else "Starting the next issue is disabled by autonomy policy.",
                {"milestone": self.active_milestone(), "decision": decision},
                meaningful=True,
            )
            return None
        excluded = {completed_issue} if completed_issue is not None else None
        milestone = self.active_milestone()
        issue = self.github.next_issue(milestone, excluded)
        if not issue:
            completed = self.store.event(
                f"milestone:{milestone}:complete",
                "milestone.complete",
                {"milestone": milestone},
            )
            if completed:
                self.notify_once(
                    f"milestone:{milestone}:complete-notice",
                    "milestone.complete",
                    f"🎉 No eligible issues remain in {milestone}.",
                    {"milestone": milestone},
                )
            self.offer_milestone_rollover()
            return None
        number = str(issue["number"])
        if not self.store.claim_issue(
            int(number), str(issue["title"]), milestone
        ):
            return None
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
            supervisor.reload_policy("status")
            print(supervisor.status_text())
        elif arguments.command == "track-pr":
            store.set("current_pr", str(arguments.number))
            print(f"Tracking PR #{arguments.number}")
        elif arguments.command == "monitor-once":
            supervisor.monitor_once()
        elif arguments.command == "telegram-once":
            supervisor.reload_policy("listener")
            offset = int(store.get("telegram_offset", "0"))
            for update in supervisor.telegram.updates(offset, 1):
                offset = max(offset, int(update["update_id"]) + 1)
                supervisor.handle_update(update)
                store.set("telegram_offset", str(offset))
        elif arguments.command == "telegram-loop":
            supervisor.telegram.register_commands()
            while True:
                try:
                    supervisor.reload_policy("listener")
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
