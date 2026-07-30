"""Sanitized workflow-card rendering and adaptive heartbeat decisions."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any


def parse_time(value: str) -> float:
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{hours}h {minutes}m" if hours else f"{minutes}m"


def heartbeat_interval(elapsed_seconds: float) -> int:
    """First update at 10m, 15m cadence through 60m, then every 30m."""

    if elapsed_seconds < 600:
        return 600
    if elapsed_seconds < 3600:
        return 900
    return 1800


def read_heartbeat(root: Path, issue: int) -> dict[str, Any] | None:
    """Read one bounded heartbeat without following links or accepting extras."""

    path = root / f"issue-{issue}.json"
    try:
        if path.is_symlink() or not path.is_file():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    allowed = {
        "schema_version",
        "issue",
        "milestone",
        "generation",
        "revision",
        "phase",
        "phase_started_at",
        "started_at",
        "total_elapsed_seconds",
        "last_activity_at",
        "runner_health",
        "changed_file_count",
        "validation_state",
        "pr_reference",
        "next_expected_transition",
        "last_completed_safe_step",
    }
    value = {key: raw.get(key) for key in allowed}
    if (
        value["schema_version"] != 1
        or value["issue"] != issue
        or not isinstance(value["generation"], int)
        or not isinstance(value["revision"], int)
    ):
        return None
    try:
        for key in ("started_at", "phase_started_at", "last_activity_at"):
            parse_time(str(value[key]))
        if str(value["runner_health"]) not in {
            "active",
            "quiet",
            "possibly-stalled",
            "stalled",
            "completed",
            "failed",
        }:
            return None
        if not isinstance(value["changed_file_count"], int):
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return value


def render_card(
    *,
    milestone: str,
    issue: str,
    title: str,
    paused: bool,
    heartbeat: dict[str, Any] | None,
    pr_state: str,
    ci_state: str,
    approval_ready: bool,
    now: float,
) -> str:
    if not heartbeat:
        if not issue:
            workflow = "paused" if paused else "idle"
            next_step = (
                "operator resume or queue selection"
                if paused
                else "eligible issue selection"
            )
        else:
            workflow = "paused" if paused else "waiting"
            next_step = (
                "operator action"
                if paused
                else "runner startup or operator action"
            )
        return (
            f"Fortify SDLC Workflow — {milestone}\n"
            f"Milestone progress: issue #{issue or 'none'}\n"
            f"Current: {title or 'none'}\n"
            f"Workflow: {workflow}\n"
            "Runner: no heartbeat\n"
            f"PR / CI: {pr_state} / {ci_state}\n"
            f"Approval ready: {'yes' if approval_ready else 'no'}\n"
            f"Next: {next_step}"
        )
    started = parse_time(str(heartbeat["started_at"]))
    phase_started = parse_time(str(heartbeat["phase_started_at"]))
    activity = parse_time(str(heartbeat["last_activity_at"]))
    phase = str(heartbeat["phase"])
    return (
        f"Fortify SDLC Workflow — {milestone}\n"
        f"Milestone progress: issue #{issue} · {duration(now - started)} elapsed\n"
        f"Current: {title or 'title unavailable'}\n"
        f"Workflow: {'paused' if paused else 'running'}\n"
        f"Started: {str(heartbeat['started_at'])}\n"
        f"Last activity: {duration(now - activity)} ago\n"
        f"Phase: {phase} · {duration(now - phase_started)}\n"
        f"Runner: {heartbeat['runner_health']}\n"
        f"Changed files: {heartbeat['changed_file_count']}\n"
        f"Validation: {heartbeat['validation_state']}\n"
        f"PR / CI: {pr_state} / {ci_state}\n"
        f"Approval ready: {'yes' if approval_ready else 'no'}\n"
        f"Next: {heartbeat['next_expected_transition'] or 'operator review'}"
    )


def render_stall(heartbeat: dict[str, Any], now: float) -> str:
    activity_age = now - parse_time(str(heartbeat["last_activity_at"]))
    elapsed = now - parse_time(str(heartbeat["started_at"]))
    safe_step = heartbeat.get("last_completed_safe_step") or "not recorded"
    return (
        f"⚠ Runner {heartbeat['runner_health']} on issue #{heartbeat['issue']}.\n"
        f"Phase: {heartbeat['phase']}\n"
        f"Elapsed: {duration(elapsed)}\n"
        f"Activity age: {duration(activity_age)}\n"
        f"Last safe step: {safe_step}\n"
        "Actions: Status, Details, Refresh, Pause"
    )
