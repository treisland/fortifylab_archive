"""Versioned, technology-neutral autonomy policy contract."""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "fortify.autonomy/v1alpha1"
ACTIONS = (
    "start_next_issue",
    "close_completed_issue",
    "advance_milestone",
    "retry_idempotent_failure",
    "merge_pull_request",
    "destructive_operations",
    "secret_operations",
    "scope_changes",
)
DECISIONS = ("auto", "approval", "disabled")
PROTECTED_ACTIONS = (
    "destructive_operations",
    "secret_operations",
    "scope_changes",
)
PROFILE_DEFAULTS: dict[str, dict[str, str]] = {
    "manual": {action: "approval" for action in ACTIONS},
    "assisted": {
        "start_next_issue": "auto",
        "close_completed_issue": "auto",
        "advance_milestone": "auto",
        "retry_idempotent_failure": "auto",
        "merge_pull_request": "approval",
        "destructive_operations": "approval",
        "secret_operations": "approval",
        "scope_changes": "approval",
    },
    "autonomous": {
        "start_next_issue": "auto",
        "close_completed_issue": "auto",
        "advance_milestone": "auto",
        "retry_idempotent_failure": "auto",
        "merge_pull_request": "auto",
        "destructive_operations": "approval",
        "secret_operations": "approval",
        "scope_changes": "approval",
    },
}


class AutonomyPolicyError(RuntimeError):
    """Actionable policy error that never contains configuration values or paths."""


@dataclasses.dataclass(frozen=True)
class EffectivePolicy:
    """Sanitized effective policy shared by every supervisor process."""

    profile: str
    generation: int
    decisions: Mapping[str, str]
    digest: str
    expires_at: str | None = None
    configured: bool = True

    def decision(self, action: str) -> str:
        if action not in ACTIONS:
            raise AutonomyPolicyError(f"Unknown autonomy action: {action}")
        return self.decisions[action]

    def status(self) -> dict[str, Any]:
        result = {
            "schema_version": SCHEMA_VERSION,
            "profile": self.profile,
            "generation": self.generation,
            "digest": self.digest,
            "decisions": dict(self.decisions),
        }
        if self.expires_at is not None:
            result["expires_at"] = self.expires_at
        return result


def _digest(payload: Mapping[str, Any]) -> str:
    normalized = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _effective(
    *,
    profile: str,
    generation: int,
    overrides: Mapping[str, Any],
    expires_at: str | None,
    configured: bool,
    now: datetime.datetime,
    allow_expired: bool = False,
) -> EffectivePolicy:
    if profile not in PROFILE_DEFAULTS:
        raise AutonomyPolicyError(f"Unknown autonomy profile: {profile}")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise AutonomyPolicyError("Autonomy generation must be a non-negative integer")
    if not isinstance(overrides, Mapping):
        raise AutonomyPolicyError("Autonomy actions must be an object")
    unknown = sorted(set(overrides) - set(ACTIONS))
    if unknown:
        raise AutonomyPolicyError(f"Unknown autonomy action: {unknown[0]}")
    decisions = dict(PROFILE_DEFAULTS[profile])
    for action, decision in overrides.items():
        if decision not in DECISIONS:
            raise AutonomyPolicyError(
                f"Unknown autonomy policy for {action}; expected auto, approval, or disabled"
            )
        decisions[action] = str(decision)
    unsafe = [
        action
        for action in PROTECTED_ACTIONS
        if decisions[action] != "approval"
    ]
    if unsafe:
        raise AutonomyPolicyError(
            f"Unsafe autonomy combination: {unsafe[0]} must require approval"
        )
    normalized_expiry: str | None = None
    if profile == "autonomous":
        if not expires_at or not isinstance(expires_at, str):
            raise AutonomyPolicyError(
                "Autonomous profile requires a future expires_at timestamp"
            )
        try:
            expiry = datetime.datetime.fromisoformat(
                expires_at.replace("Z", "+00:00")
            )
        except ValueError as error:
            raise AutonomyPolicyError(
                "Autonomous expires_at must be an RFC 3339 timestamp"
            ) from error
        if expiry.tzinfo is None:
            raise AutonomyPolicyError("Autonomous expires_at must include a timezone")
        if expiry <= now and not allow_expired:
            raise AutonomyPolicyError("Autonomous policy has expired")
        normalized_expiry = expiry.astimezone(datetime.timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    elif expires_at is not None:
        raise AutonomyPolicyError(
            "expires_at is only valid for the autonomous profile"
        )
    canonical = {
        "schema_version": SCHEMA_VERSION,
        "profile": profile,
        "generation": generation,
        "expires_at": normalized_expiry,
        "decisions": decisions,
    }
    return EffectivePolicy(
        profile=profile,
        generation=generation,
        decisions=decisions,
        digest=_digest(canonical),
        expires_at=normalized_expiry,
        configured=configured,
    )


def migration_policy() -> EffectivePolicy:
    """Exact pre-policy behavior for installations without configuration."""

    return _effective(
        profile="assisted",
        generation=0,
        overrides={},
        expires_at=None,
        configured=False,
        now=datetime.datetime.now(datetime.timezone.utc),
    )


def load_policy(
    path: Path | None,
    *,
    now: datetime.datetime | None = None,
    allow_expired: bool = False,
) -> EffectivePolicy:
    """Load one protected external policy file, or the compatible migration default."""

    if path is None:
        return migration_policy()
    try:
        if path.is_symlink() or not path.is_file():
            raise AutonomyPolicyError(
                "Autonomy policy must be a regular non-symlink file"
            )
        details = path.stat()
        if details.st_uid != os.getuid():
            raise AutonomyPolicyError(
                "Autonomy policy must be owned by the service user"
            )
        mode = stat.S_IMODE(details.st_mode)
        if mode & 0o077:
            raise AutonomyPolicyError(
                f"Autonomy policy must not be group/world accessible ({mode:o})"
            )
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise AutonomyPolicyError("Autonomy policy is not valid JSON") from error
    except OSError as error:
        raise AutonomyPolicyError("Autonomy policy could not be read") from error
    if not isinstance(document, dict):
        raise AutonomyPolicyError("Autonomy policy must be an object")
    allowed = {"schema_version", "profile", "generation", "expires_at", "actions"}
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise AutonomyPolicyError(f"Unknown autonomy field: {unknown[0]}")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise AutonomyPolicyError(
            f"Unsupported autonomy schema_version; expected {SCHEMA_VERSION}"
        )
    return _effective(
        profile=document.get("profile"),
        generation=document.get("generation"),
        overrides=document.get("actions", {}),
        expires_at=document.get("expires_at"),
        configured=True,
        now=now or datetime.datetime.now(datetime.timezone.utc),
        allow_expired=allow_expired,
    )


def replace_policy(
    path: Path,
    *,
    profile: str,
    generation: int,
    expires_at: str | None = None,
    now: datetime.datetime | None = None,
) -> EffectivePolicy:
    """Atomically install a validated protected policy document."""

    current_time = now or datetime.datetime.now(datetime.timezone.utc)
    policy = _effective(
        profile=profile,
        generation=generation,
        overrides={},
        expires_at=expires_at,
        configured=True,
        now=current_time,
    )
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "profile": profile,
        "generation": generation,
    }
    if policy.expires_at is not None:
        document["expires_at"] = policy.expires_at
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".autonomy.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        raise AutonomyPolicyError("Autonomy policy could not be replaced") from error
    finally:
        temporary.unlink(missing_ok=True)
    return policy
