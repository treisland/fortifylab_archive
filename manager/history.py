"""Secret-safe projection of durable records for the dashboard."""

from __future__ import annotations

from typing import Any

from manager.record_store import LoopRecordStore, sanitize_record


class StoreHistoryReader:
    def __init__(self, store: LoopRecordStore) -> None:
        self._store = store

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        records = self._store.records()
        return [_project(item) for item in reversed(records[-max(0, min(limit, 100)):])]


def _project(record: dict[str, Any]) -> dict[str, Any]:
    clean = sanitize_record(record)
    timestamp = next(
        (clean.get(key) for key in ("requestedAt", "updatedAt", "occurredAt", "openedAt", "createdAt", "observedAt") if clean.get(key)),
        clean.get("provenance", {}).get("observedAt"),
    )
    subject = clean.get("subject") or {}
    return {
        "id": clean.get("id", "unknown"),
        "kind": clean.get("kind", "Record"),
        "state": clean.get("state") or clean.get("status") or clean.get("outcome") or "recorded",
        "summary": clean.get("summary") or clean.get("message") or clean.get("type") or clean.get("kind", "Record"),
        "subject": subject.get("displayName") or subject.get("id"),
        "occurredAt": timestamp,
    }
