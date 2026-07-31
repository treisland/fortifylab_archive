"""Durability, safety, retention, migration, and concurrency tests."""

from __future__ import annotations

import copy
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from manager.record_store import (
    CONTRACT_ROOT,
    LoopRecordStore,
    RecordStoreError,
    RetentionPolicy,
)


def examples() -> dict:
    with (CONTRACT_ROOT / "examples.json").open(encoding="utf-8") as stream:
        return json.load(stream)


class RecordStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "history.sqlite3"
        self.examples = examples()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_all_versioned_record_kinds_survive_restart(self) -> None:
        with LoopRecordStore(self.path) as store:
            for document in self.examples.values():
                store.append(document)
            self.assertEqual(store.migration_version(), 2)
        with LoopRecordStore(self.path) as restarted:
            self.assertEqual(
                {record["kind"] for record in restarted.records()},
                {
                    "Operation",
                    "OperationProgress",
                    "HealthObservation",
                    "LoopEvent",
                    "Incident",
                    "PlanApproval",
                    "SanitizedTrace",
                },
            )

    def test_interrupted_transaction_is_rolled_back_on_restart(self) -> None:
        store = LoopRecordStore(self.path)
        store.connection.execute("BEGIN IMMEDIATE")
        store.connection.execute(
            "INSERT INTO records(kind, record_id, occurred_at, stored_at, payload) "
            "VALUES (?, ?, ?, ?, ?)",
            ("LoopEvent", "partial", "2026-01-01T00:00:00Z", "2026-01-01", "{}"),
        )
        store.close()
        with LoopRecordStore(self.path) as restarted:
            self.assertEqual(restarted.records(), [])

    def test_malformed_records_are_quarantined_without_blocking_reads(self) -> None:
        with LoopRecordStore(self.path) as store:
            store.append(self.examples["event"])
            store.connection.execute(
                "INSERT INTO records(kind, record_id, occurred_at, stored_at, payload) "
                "VALUES (?, ?, ?, ?, ?)",
                ("LoopEvent", "broken", "2026-01-01", "2026-01-01", "{"),
            )
            self.assertEqual(
                [record["id"] for record in store.records()], ["event-001"]
            )
            quarantined = store.connection.execute(
                "SELECT reason FROM quarantine WHERE record_id = 'broken'"
            ).fetchone()
            self.assertEqual(quarantined["reason"], "malformed-record")

    def test_redaction_happens_before_persistence(self) -> None:
        trace = copy.deepcopy(self.examples["trace"])
        trace["entries"][0]["message"] = (
            "Authorization: Bearer abc.def.ghi password=hunter2 at "
            "/var/snap/microk8s/credentials/client.config"
        )
        trace["entries"][0]["fields"]["access_token"] = "do-not-store"
        with LoopRecordStore(self.path) as store:
            store.append(trace)
            raw = store.connection.execute("SELECT payload FROM records").fetchone()[0]
            self.assertNotIn("abc.def.ghi", raw)
            self.assertNotIn("hunter2", raw)
            self.assertNotIn("client.config", raw)
            self.assertNotIn("do-not-store", raw)
            persisted = store.records()[0]
            self.assertEqual(persisted["entries"][0]["message"].count("[REDACTED]"), 3)
            self.assertNotIn("access_token", persisted["entries"][0]["fields"])

    def test_invalid_document_never_reaches_storage(self) -> None:
        event = copy.deepcopy(self.examples["event"])
        event["unexpected"] = "value"
        with LoopRecordStore(self.path) as store:
            with self.assertRaises(RecordStoreError):
                store.append(event)
            self.assertEqual(store.records(), [])

    def test_count_and_age_retention_are_per_kind(self) -> None:
        policy = RetentionPolicy(max_records=2, max_age_days=2)
        now = datetime(2026, 7, 30, tzinfo=timezone.utc)
        with LoopRecordStore(self.path, retention=policy) as store:
            old = copy.deepcopy(self.examples["event"])
            old["id"] = "old"
            store.append(old, now=now - timedelta(days=3))
            for index in range(3):
                current = copy.deepcopy(self.examples["event"])
                current["id"] = f"current-{index}"
                store.append(current, now=now + timedelta(seconds=index))
            health = copy.deepcopy(self.examples["health"])
            store.append(health, now=now)
            self.assertEqual(
                [item["id"] for item in store.records(kind="LoopEvent")],
                ["current-1", "current-2"],
            )
            self.assertEqual(len(store.records(kind="HealthObservation")), 1)

    def test_concurrent_writers_do_not_lose_records(self) -> None:
        # Initialize the schema before synchronizing writers. If one thread
        # fails during first-open migration, the remaining threads would
        # otherwise wait forever at the barrier and hide the real failure.
        with LoopRecordStore(self.path):
            pass
        barrier = threading.Barrier(6)
        failures: list[Exception] = []

        def writer(index: int) -> None:
            try:
                document = copy.deepcopy(self.examples["event"])
                document["id"] = f"event-{index}"
                with LoopRecordStore(self.path) as store:
                    barrier.wait(timeout=5)
                    store.append(document)
            except Exception as error:  # pragma: no cover - asserted below
                failures.append(error)
                barrier.abort()

        threads = [threading.Thread(target=writer, args=(index,)) for index in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(
            any(thread.is_alive() for thread in threads),
            "concurrent writers did not finish within the bounded wait",
        )
        self.assertEqual(failures, [])
        with LoopRecordStore(self.path) as store:
            self.assertEqual(len(store.records()), 6)

    def test_existing_migration_is_not_reapplied(self) -> None:
        with LoopRecordStore(self.path) as store:
            versions = store.connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
            self.assertEqual([row[0] for row in versions], [1, 2])
        with LoopRecordStore(self.path) as restarted:
            versions = restarted.connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
            self.assertEqual([row[0] for row in versions], [1, 2])


if __name__ == "__main__":
    unittest.main()
