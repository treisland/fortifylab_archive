"""Secret-safe projection of durable records for the dashboard."""

from __future__ import annotations

from typing import Any

from manager.record_store import LoopRecordStore, sanitize_record
from manager.operation_engine import OperationStore


class StoreHistoryReader:
    def __init__(
        self, store: LoopRecordStore, operations: OperationStore | None = None
    ) -> None:
        self._store = store
        self._operations = operations

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        records = self._store.records()
        combined = list(records)
        if self._operations is not None:
            combined.extend(self._operations.recent(limit))
        projected = [_project(item) for item in combined]
        projected.sort(key=lambda item: str(item.get("occurredAt") or ""), reverse=True)
        return projected[:max(0, min(limit, 100))]


def _project(record: dict[str, Any]) -> dict[str, Any]:
    clean = sanitize_record(record)
    timestamp = next(
        (clean.get(key) for key in ("requestedAt", "updatedAt", "occurredAt", "openedAt", "createdAt", "observedAt") if clean.get(key)),
        clean.get("provenance", {}).get("observedAt"),
    )
    subject = clean.get("subject") or {}
    workflow = clean.get("workflow")
    progress = (
        f"{clean.get('completedSteps', 0)}/{clean.get('totalSteps', 0)} steps"
        if clean.get("kind") == "LifecycleOperation"
        else None
    )
    summary = clean.get("summary") or clean.get("message") or clean.get("type")
    if workflow == "clean-install":
        summary = f"Clean install {clean.get('state', 'recorded')} · {progress}"
    return {
        "id": clean.get("id", "unknown"),
        "kind": clean.get("kind", "Record"),
        "state": clean.get("state") or clean.get("status") or clean.get("outcome") or "recorded",
        "summary": summary or clean.get("kind", "Record"),
        "subject": subject.get("displayName") or subject.get("id"),
        "occurredAt": timestamp,
    }
