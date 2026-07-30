"""Durable, sanitized persistence for versioned control-loop records."""

from __future__ import annotations

import copy
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker, RefResolver

from manager.loop_contract_validation import SENSITIVE_KEY, validate_semantics


CONTRACT_ROOT = Path(__file__).resolve().parents[1] / "contracts" / "v1alpha1"
SCHEMA_ROOT = CONTRACT_ROOT / "schemas"
KIND_SCHEMAS = {
    "Operation": "operation",
    "OperationProgress": "progress",
    "HealthObservation": "health",
    "LoopEvent": "event",
    "Incident": "incident",
    "PlanApproval": "approval",
    "SanitizedTrace": "trace",
}
TIMESTAMP_FIELDS = {
    "Operation": "requestedAt",
    "OperationProgress": "updatedAt",
    "HealthObservation": "observedAt",
    "LoopEvent": "occurredAt",
    "Incident": "openedAt",
    "PlanApproval": "createdAt",
    "SanitizedTrace": None,
}
DEFAULT_MAX_RECORDS = 10_000
DEFAULT_MAX_AGE_DAYS = 30
REDACTED = "[REDACTED]"
SENSITIVE_TEXT = re.compile(
    r"(?i)(?:authorization\s*:\s*)?(bearer\s+)[a-z0-9._~+/=-]+|"
    r"((?:password|passwd|secret|token|credential|authorization)\s*[=:]\s*)\S+|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"(?<![A-Za-z0-9._-])/(?:etc|root|home|var/snap/microk8s/credentials)(?:/[^\s,;]*)?",
    re.DOTALL,
)


class RecordStoreError(RuntimeError):
    """A sanitized persistence or contract failure."""


@dataclass(frozen=True)
class RetentionPolicy:
    """Per-kind limits applied transactionally after every append."""

    max_records: int = DEFAULT_MAX_RECORDS
    max_age_days: int = DEFAULT_MAX_AGE_DAYS

    def __post_init__(self) -> None:
        if self.max_records < 1 or self.max_age_days < 1:
            raise ValueError("retention limits must be positive")


def _redact_text(value: str) -> str:
    return SENSITIVE_TEXT.sub(
        lambda match: (match.group(1) or "") + REDACTED,
        value,
    )


def sanitize_record(document: dict[str, Any]) -> dict[str, Any]:
    """Return a deep sanitized copy; never mutate caller-owned input."""

    redactions: set[str] = set(document.get("redactions", []))

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            clean: dict[str, Any] = {}
            for key, child in value.items():
                if SENSITIVE_KEY.search(key):
                    redactions.add("credential")
                    continue
                clean[key] = walk(child)
            return clean
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, str):
            clean = _redact_text(value)
            if clean != value:
                redactions.update(("credential", "path"))
            return clean
        return value

    clean = walk(copy.deepcopy(document))
    if clean.get("kind") == "SanitizedTrace":
        clean["sanitized"] = True
        clean["redactions"] = sorted(redactions)
    return clean


class LoopRecordStore:
    """SQLite-backed append-only history with transactional retention."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        retention: RetentionPolicy = RetentionPolicy(),
    ) -> None:
        self.path = Path(path)
        self.retention = retention
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        self.connection = sqlite3.connect(
            self.path, timeout=30, isolation_level=None, check_same_thread=False
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=30000")
        self._migrate()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "LoopRecordStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _migrate(self) -> None:
        migrations = (
            (
                1,
                """
                CREATE TABLE records (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX records_kind_sequence
                    ON records(kind, sequence DESC);
                """,
            ),
            (
                2,
                """
                CREATE TABLE quarantine (
                    sequence INTEGER PRIMARY KEY,
                    kind TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL,
                    reason TEXT NOT NULL
                );
                """,
            ),
        )
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            applied = {
                row[0]
                for row in self.connection.execute(
                    "SELECT version FROM schema_migrations"
                )
            }
            now = datetime.now(timezone.utc).isoformat()
            for version, script in migrations:
                if version not in applied:
                    for statement in script.split(";"):
                        if statement.strip():
                            self.connection.execute(statement)
                    self.connection.execute(
                        "INSERT INTO schema_migrations VALUES (?, ?)", (version, now)
                    )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    @staticmethod
    def _validator(kind: str) -> Draft202012Validator:
        name = KIND_SCHEMAS.get(kind)
        if name is None:
            raise RecordStoreError("unsupported record kind")
        with (SCHEMA_ROOT / f"{name}.schema.json").open(encoding="utf-8") as stream:
            schema = json.load(stream)
        with (SCHEMA_ROOT / "common.schema.json").open(encoding="utf-8") as stream:
            common = json.load(stream)
        return Draft202012Validator(
            schema,
            resolver=RefResolver.from_schema(
                schema, store={common["$id"]: common}
            ),
            format_checker=FormatChecker(),
        )

    @classmethod
    def _validate(cls, document: dict[str, Any]) -> None:
        kind = document.get("kind")
        errors = sorted(
            cls._validator(kind).iter_errors(document), key=lambda error: list(error.path)
        )
        semantic = validate_semantics(document)
        if errors or semantic:
            raise RecordStoreError("record failed sanitized contract validation")

    def append(
        self, document: dict[str, Any], *, now: datetime | None = None
    ) -> int:
        clean = sanitize_record(document)
        self._validate(clean)
        kind = clean["kind"]
        timestamp_field = TIMESTAMP_FIELDS[kind]
        occurred_at = (
            clean["provenance"]["observedAt"]
            if timestamp_field is None
            else clean[timestamp_field]
        )
        stored_at = (now or datetime.now(timezone.utc)).isoformat()
        payload = json.dumps(clean, sort_keys=True, separators=(",", ":"))
        cutoff = (
            (now or datetime.now(timezone.utc))
            - timedelta(days=self.retention.max_age_days)
        ).isoformat()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            cursor = self.connection.execute(
                "INSERT INTO records(kind, record_id, occurred_at, stored_at, payload) "
                "VALUES (?, ?, ?, ?, ?)",
                (kind, clean["id"], occurred_at, stored_at, payload),
            )
            self.connection.execute(
                "DELETE FROM records WHERE kind = ? AND stored_at < ?",
                (kind, cutoff),
            )
            self.connection.execute(
                "DELETE FROM records WHERE sequence IN "
                "(SELECT sequence FROM records WHERE kind = ? "
                "ORDER BY sequence DESC LIMIT -1 OFFSET ?)",
                (kind, self.retention.max_records),
            )
            self.connection.commit()
            return int(cursor.lastrowid)
        except Exception:
            self.connection.rollback()
            raise

    def records(self, *, kind: str | None = None) -> list[dict[str, Any]]:
        parameters: tuple[str, ...] = ()
        query = "SELECT sequence, kind, record_id, payload FROM records"
        if kind is not None:
            if kind not in KIND_SCHEMAS:
                raise RecordStoreError("unsupported record kind")
            query += " WHERE kind = ?"
            parameters = (kind,)
        query += " ORDER BY sequence"
        valid: list[dict[str, Any]] = []
        malformed: list[tuple[int, str, str]] = []
        for row in self.connection.execute(query, parameters):
            try:
                document = json.loads(row["payload"])
                self._validate(document)
                valid.append(document)
            except (json.JSONDecodeError, RecordStoreError, TypeError, KeyError):
                malformed.append((row["sequence"], row["kind"], row["record_id"]))
        if malformed:
            self._quarantine(malformed)
        return valid

    def _quarantine(self, rows: Iterable[tuple[int, str, str]]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            for sequence, kind, record_id in rows:
                self.connection.execute(
                    "INSERT OR IGNORE INTO quarantine VALUES (?, ?, ?, ?, ?)",
                    (sequence, kind, record_id, now, "malformed-record"),
                )
                self.connection.execute(
                    "DELETE FROM records WHERE sequence = ?", (sequence,)
                )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def migration_version(self) -> int:
        row = self.connection.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
        ).fetchone()
        return int(row[0])
