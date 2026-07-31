"""Sanitized, durable evidence for the bounded issue runner.

Heartbeat documents deliberately contain only enumerated workflow state and
small scalar references. They are not a log, a workflow engine, or authority
to advance an issue.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

PHASES = (
    "preparing",
    "inspecting",
    "planning",
    "implementing",
    "testing",
    "validating",
    "scanning",
    "committing",
    "pushing",
    "creating-pr",
    "waiting-for-ci",
    "waiting-for-approval",
)
TERMINAL_PHASES = ("completed", "failed")
VALIDATION_STATES = ("not-started", "running", "passed", "failed")
HEALTH_STATES = (
    "active",
    "quiet",
    "possibly-stalled",
    "stalled",
    "completed",
    "failed",
)
NEXT_TRANSITIONS = {
    phase: PHASES[index + 1] if index + 1 < len(PHASES) else "completed"
    for index, phase in enumerate(PHASES)
}
NEXT_TRANSITIONS.update({"completed": None, "failed": None})


class HeartbeatError(RuntimeError):
    """Raised when heartbeat input or concurrency state is unsafe."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class ActivityThresholds:
    quiet_seconds: int = 120
    possibly_stalled_seconds: int = 600
    stalled_seconds: int = 1800

    def classify(self, age_seconds: float) -> str:
        if age_seconds >= self.stalled_seconds:
            return "stalled"
        if age_seconds >= self.possibly_stalled_seconds:
            return "possibly-stalled"
        if age_seconds >= self.quiet_seconds:
            return "quiet"
        return "active"


class HeartbeatStore:
    """Atomic JSON heartbeat store with writer leases and bounded retention."""

    def __init__(
        self,
        root: Path,
        *,
        thresholds: ActivityThresholds | None = None,
        max_terminal_records: int = 100,
        max_records: int = 200,
        terminal_max_age_days: int = 30,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.root = root
        self.thresholds = thresholds or ActivityThresholds()
        self.max_terminal_records = max_terminal_records
        self.max_records = max_records
        self.terminal_max_age_days = terminal_max_age_days
        self.clock = clock

    def _path(self, issue: int) -> Path:
        return self.root / f"issue-{issue}.json"

    def _locked(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock = (self.root / ".lock").open("a+", encoding="utf-8")
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        return lock

    def _read_unlocked(self, issue: int) -> dict | None:
        try:
            with self._path(issue).open(encoding="utf-8") as stream:
                value = json.load(stream)
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as error:
            raise HeartbeatError("heartbeat is unreadable") from error
        return value

    def _write_unlocked(self, issue: int, document: dict) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".issue-{issue}.", dir=self.root
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(document, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self._path(issue))
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def start(
        self, issue: int, milestone: str, policy_generation: int, policy_digest: str
    ) -> dict:
        if issue < 1 or not milestone or len(milestone) > 200:
            raise HeartbeatError("invalid issue heartbeat identity")
        if policy_generation < 0 or not re.fullmatch(r"[0-9a-f]{64}", policy_digest):
            raise HeartbeatError("invalid heartbeat policy identity")
        now = self.clock()
        with self._locked():
            previous = self._read_unlocked(issue)
            generation = int(previous["generation"]) + 1 if previous else 1
            document = {
                "schema_version": 1,
                "issue": issue,
                "milestone": milestone,
                "writer_id": uuid.uuid4().hex,
                "generation": generation,
                "policy_generation": policy_generation,
                "policy_digest": policy_digest,
                "revision": 1,
                "phase": "preparing",
                "phase_started_at": _timestamp(now),
                "started_at": _timestamp(now),
                "total_elapsed_seconds": 0,
                "last_activity_at": _timestamp(now),
                "runner_health": "active",
                "changed_file_count": 0,
                "validation_state": "not-started",
                "pr_reference": None,
                "last_completed_safe_step": "runner initialized",
                "next_expected_transition": "inspecting",
            }
            self._write_unlocked(issue, document)
            self._cleanup_unlocked(now)
            return document

    def read(self, issue: int, *, now: datetime | None = None) -> dict | None:
        with self._locked():
            document = self._read_unlocked(issue)
        if document is None:
            return None
        document = dict(document)
        current = now or self.clock()
        document["total_elapsed_seconds"] = max(
            0, int((current - _parse(document["started_at"])).total_seconds())
        )
        if document["phase"] not in TERMINAL_PHASES:
            age = max(
                0, (current - _parse(document["last_activity_at"])).total_seconds()
            )
            document["runner_health"] = self.thresholds.classify(age)
        return document

    def update(
        self,
        issue: int,
        writer_id: str,
        generation: int,
        *,
        phase: str | None = None,
        changed_file_count: int | None = None,
        validation_state: str | None = None,
        pr_reference: str | None = None,
    ) -> dict:
        if phase is not None and phase not in (*PHASES, *TERMINAL_PHASES):
            raise HeartbeatError("invalid heartbeat phase")
        if validation_state is not None and validation_state not in VALIDATION_STATES:
            raise HeartbeatError("invalid validation state")
        if changed_file_count is not None and changed_file_count < 0:
            raise HeartbeatError("invalid changed-file count")
        if pr_reference is not None and not re.fullmatch(
            r"(?:#[1-9][0-9]*|https://github\.com/"
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[1-9][0-9]*)",
            pr_reference,
        ):
            raise HeartbeatError("invalid PR reference")
        now = self.clock()
        with self._locked():
            current = self._read_unlocked(issue)
            if current is None:
                raise HeartbeatError("heartbeat is missing")
            if (
                current["writer_id"] != writer_id
                or int(current["generation"]) != generation
            ):
                raise HeartbeatError("stale heartbeat writer")
            if current["phase"] in TERMINAL_PHASES:
                raise HeartbeatError("heartbeat is terminal")
            document = dict(current)
            if phase is not None and phase != current["phase"]:
                if (
                    phase not in TERMINAL_PHASES
                    and PHASES.index(phase) < PHASES.index(current["phase"])
                ):
                    raise HeartbeatError("stale heartbeat phase")
                document["last_completed_safe_step"] = str(current["phase"])[:40]
                document["phase"] = phase
                document["phase_started_at"] = _timestamp(now)
            if changed_file_count is not None:
                document["changed_file_count"] = changed_file_count
            if validation_state is not None:
                document["validation_state"] = validation_state
            if pr_reference is not None:
                document["pr_reference"] = pr_reference
            document["revision"] = int(current["revision"]) + 1
            document["last_activity_at"] = _timestamp(now)
            document["total_elapsed_seconds"] = max(
                0, int((now - _parse(document["started_at"])).total_seconds())
            )
            document["runner_health"] = (
                phase if phase in TERMINAL_PHASES else "active"
            )
            document["next_expected_transition"] = NEXT_TRANSITIONS[document["phase"]]
            self._write_unlocked(issue, document)
            self._cleanup_unlocked(now)
            return document

    def _cleanup_unlocked(self, now: datetime) -> None:
        terminal: list[tuple[datetime, Path]] = []
        all_records: list[tuple[datetime, Path]] = []
        for path in self.root.glob("issue-*.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                updated = _parse(value["last_activity_at"])
                all_records.append((updated, path))
                if value.get("phase") in TERMINAL_PHASES:
                    terminal.append((updated, path))
            except (OSError, ValueError, KeyError):
                continue
        terminal.sort(reverse=True)
        all_records.sort(reverse=True)
        cutoff = self.terminal_max_age_days * 86400
        for index, (updated, path) in enumerate(terminal):
            if index >= self.max_terminal_records or (now - updated).total_seconds() > cutoff:
                path.unlink(missing_ok=True)
        for _, path in all_records[self.max_records :]:
            path.unlink(missing_ok=True)


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Manage sanitized runner heartbeats")
    parser.add_argument("--root", type=Path, required=True)
    subparsers = parser.add_subparsers(dest="action", required=True)
    start = subparsers.add_parser("start")
    start.add_argument("--issue", type=int, required=True)
    start.add_argument("--milestone", required=True)
    start.add_argument("--policy-generation", type=int, required=True)
    start.add_argument("--policy-digest", required=True)
    update = subparsers.add_parser("update")
    update.add_argument("--issue", type=int, required=True)
    update.add_argument("--writer-id", required=True)
    update.add_argument("--generation", type=int, required=True)
    update.add_argument("--phase", choices=(*PHASES, *TERMINAL_PHASES))
    update.add_argument("--changed-file-count", type=int)
    update.add_argument("--validation-state", choices=VALIDATION_STATES)
    update.add_argument("--pr-reference")
    read = subparsers.add_parser("read")
    read.add_argument("--issue", type=int, required=True)
    arguments = parser.parse_args()
    store = HeartbeatStore(arguments.root)
    try:
        if arguments.action == "start":
            result = store.start(
                arguments.issue,
                arguments.milestone,
                arguments.policy_generation,
                arguments.policy_digest,
            )
        elif arguments.action == "read":
            result = store.read(arguments.issue)
            if result is None:
                return 3
        else:
            result = store.update(
                arguments.issue,
                arguments.writer_id,
                arguments.generation,
                phase=arguments.phase,
                changed_file_count=arguments.changed_file_count,
                validation_state=arguments.validation_state,
                pr_reference=arguments.pr_reference,
            )
    except HeartbeatError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
