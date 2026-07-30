"""Structured bounded-runner heartbeat contract tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema

from manager.runner_heartbeat import (
    PHASES,
    ActivityThresholds,
    HeartbeatError,
    HeartbeatStore,
)


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


class RunnerHeartbeatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.clock = Clock()
        self.store = HeartbeatStore(
            self.root,
            thresholds=ActivityThresholds(10, 20, 30),
            clock=self.clock,
        )
        self.document = self.store.start(52, "0.2 — Observable Manager MVP")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def update(self, **values: object) -> dict:
        return self.store.update(
            52,
            self.document["writer_id"],
            self.document["generation"],
            **values,
        )

    def test_every_explicit_phase_is_persistable(self) -> None:
        for phase in PHASES:
            self.clock.advance(1)
            persisted = self.update(phase=phase)
            self.assertEqual(persisted["phase"], phase)
            self.assertEqual(persisted["runner_health"], "active")
        self.assertEqual(persisted["next_expected_transition"], "completed")

    def test_atomic_document_has_only_sanitized_contract_fields(self) -> None:
        path = self.root / "issue-52.json"
        raw = path.read_text(encoding="utf-8")
        self.assertEqual(json.loads(raw), self.document)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.root.glob(".issue-52.*")), [])
        forbidden = ("prompt", "source", "log", "environment", "secret", "command", "path")
        self.assertFalse(any(word in raw.lower() for word in forbidden))
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "registry/schemas/runner-heartbeat.schema.json"
            ).read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator(schema).validate(self.document)

    def test_restart_recovers_latest_safe_state(self) -> None:
        self.clock.advance(7)
        expected = self.update(
            phase="validating", changed_file_count=4, validation_state="running"
        )
        restarted = HeartbeatStore(self.root, clock=self.clock)
        recovered = restarted.read(52)
        self.assertEqual(recovered["revision"], expected["revision"])
        self.assertEqual(recovered["phase"], "validating")
        self.assertEqual(recovered["changed_file_count"], 4)
        self.assertEqual(recovered["last_completed_safe_step"], "preparing")

    def test_runner_restart_takes_over_and_rejects_stale_writer(self) -> None:
        replacement = self.store.start(52, "0.2 — Observable Manager MVP")
        self.assertEqual(replacement["generation"], self.document["generation"] + 1)
        with self.assertRaisesRegex(HeartbeatError, "stale"):
            self.update(phase="implementing")
        current = self.store.read(52)
        self.assertEqual(current["writer_id"], replacement["writer_id"])
        self.assertEqual(current["phase"], "preparing")

    def test_delayed_phase_write_cannot_replace_newer_state(self) -> None:
        self.update(phase="validating")
        with self.assertRaisesRegex(HeartbeatError, "stale heartbeat phase"):
            self.update(phase="implementing")
        self.assertEqual(self.store.read(52)["phase"], "validating")

    def test_activity_age_classifications_do_not_depend_on_output(self) -> None:
        expected = (
            (9, "active"),
            (1, "quiet"),
            (10, "possibly-stalled"),
            (10, "stalled"),
        )
        for seconds, health in expected:
            self.clock.advance(seconds)
            self.assertEqual(self.store.read(52)["runner_health"], health)

    def test_periodic_tick_keeps_long_validation_and_no_output_work_active(self) -> None:
        self.update(phase="validating", validation_state="running")
        for _ in range(12):
            self.clock.advance(9)
            self.update()
            self.assertEqual(self.store.read(52)["runner_health"], "active")
        self.assertEqual(self.store.read(52)["total_elapsed_seconds"], 108)
        self.assertEqual(self.store.read(52)["validation_state"], "running")

    def test_hung_process_eventually_becomes_stalled_without_becoming_failed(self) -> None:
        self.update(phase="implementing")
        self.clock.advance(31)
        heartbeat = self.store.read(52)
        self.assertEqual(heartbeat["runner_health"], "stalled")
        self.assertEqual(heartbeat["phase"], "implementing")

    def test_completion_and_failure_are_terminal(self) -> None:
        completed = self.update(phase="completed", validation_state="passed")
        self.assertEqual(completed["runner_health"], "completed")
        self.assertIsNone(completed["next_expected_transition"])
        with self.assertRaisesRegex(HeartbeatError, "terminal"):
            self.update()

        failed = self.store.start(53, "milestone")
        value = self.store.update(
            53, failed["writer_id"], failed["generation"], phase="failed"
        )
        self.assertEqual(value["runner_health"], "failed")

    def test_missing_heartbeat_recovery_is_explicit(self) -> None:
        self.assertIsNone(self.store.read(999))
        with self.assertRaisesRegex(HeartbeatError, "missing"):
            self.store.update(999, "0" * 32, 1)

    def test_sensitive_or_unbounded_pr_references_are_rejected(self) -> None:
        for unsafe in (
            "https://user@example.invalid/pr/1",
            "https://github.com/owner/repo/pull/1?token=sensitive",
            "token value",
            "line\nvalue",
            "x" * 201,
        ):
            with self.subTest(unsafe=unsafe[:20]):
                with self.assertRaisesRegex(HeartbeatError, "PR reference"):
                    self.update(pr_reference=unsafe)
        raw = (self.root / "issue-52.json").read_text(encoding="utf-8")
        self.assertNotIn("example.invalid", raw)
        self.assertNotIn("token value", raw)

    def test_terminal_retention_is_bounded_by_count_and_age(self) -> None:
        store = HeartbeatStore(
            self.root, max_terminal_records=2, terminal_max_age_days=1, clock=self.clock
        )
        for issue in range(60, 63):
            value = store.start(issue, "milestone")
            store.update(issue, value["writer_id"], value["generation"], phase="completed")
            self.clock.advance(1)
        self.assertFalse((self.root / "issue-60.json").exists())
        self.clock.advance(86401)
        store.start(70, "milestone")
        self.assertFalse((self.root / "issue-61.json").exists())
        self.assertFalse((self.root / "issue-62.json").exists())

    def test_total_record_retention_is_bounded(self) -> None:
        store = HeartbeatStore(self.root, max_records=3, clock=self.clock)
        for issue in range(80, 84):
            store.start(issue, "milestone")
            self.clock.advance(1)
        self.assertEqual(len(list(self.root.glob("issue-*.json"))), 3)

    def test_runner_validation_has_a_hard_timeout(self) -> None:
        runner = (
            Path(__file__).resolve().parents[1] / "scripts/fortify-issue-runner.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'VALIDATION_TIMEOUT="${FORTIFY_RUNNER_VALIDATION_TIMEOUT:-30m}"',
            runner,
        )
        self.assertIn(
            'timeout --signal=TERM --kill-after=10s "$VALIDATION_TIMEOUT"',
            runner,
        )


if __name__ == "__main__":
    unittest.main()
