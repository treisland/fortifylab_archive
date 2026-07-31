"""Fail-closed access to versioned Fortify platform profiles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILES = ROOT / "profiles"


class PlatformProfileError(ValueError):
    """A profile is unavailable, malformed, or internally incompatible."""


class PlatformProfile:
    def __init__(self, document: dict[str, Any], path: Path) -> None:
        self.document = document
        self.path = path

    @property
    def id(self) -> str:
        return str(self.document["id"])

    @property
    def maturity(self) -> str:
        return str(self.document["maturity"])

    @classmethod
    def load(
        cls, profile_id: str, directory: Path = DEFAULT_PROFILES
    ) -> "PlatformProfile":
        if not profile_id or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for character in profile_id):
            raise PlatformProfileError("platform profile id is invalid")
        path = directory / f"{profile_id}.json"
        schema_path = directory / "schemas" / "platform-profile.schema.json"
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PlatformProfileError("platform profile is unavailable or malformed") from error
        errors = sorted(
            Draft202012Validator(schema).iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.path),
        )
        if errors:
            raise PlatformProfileError("platform profile does not satisfy its schema")
        profile = cls(document, path)
        profile._validate_semantics(directory)
        return profile

    def _validate_semantics(self, directory: Path) -> None:
        components = self.document["components"]
        required = {
            "mysql", "postgresql", "ssc", "scancentral-sast",
            "lim", "scancentral-dast-core", "scancentral-dast-scanner",
        }
        if set(components) != required:
            raise PlatformProfileError("platform profile component set is incomplete")
        if self.maturity in {"validated", "recommended"} and (
            self.document["evidence"]["level"] != "licensed-live"
            or self.document["cleanInstall"]["status"] != "passed"
        ):
            raise PlatformProfileError(
                "validated platform profiles require licensed clean-install evidence"
            )
        if self.maturity == "recommended" and not self.document["upgrade"]["allowedSources"]:
            raise PlatformProfileError(
                "recommended platform profiles require an allowed upgrade source"
            )
        if self.maturity in {"deprecated", "unsupported"} and not self.document.get("replacement"):
            raise PlatformProfileError(
                "deprecated platform profiles require a replacement"
            )
        evidence_path = directory / self.document["evidence"]["record"]
        schema_path = directory / "schemas" / "release-evidence.schema.json"
        try:
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            Draft202012Validator(schema).validate(evidence)
        except (OSError, json.JSONDecodeError, ValidationError) as error:
            raise PlatformProfileError("platform profile evidence is unavailable or invalid") from error
        if (
            evidence["profileId"] != self.id
            or evidence["evidenceLevel"] != self.document["evidence"]["level"]
            or evidence["conclusion"]
            != ("validated" if self.maturity in {"validated", "recommended"} else "experimental")
        ):
            raise PlatformProfileError("platform profile evidence does not match profile")

    def public_document(self) -> dict[str, Any]:
        """Return the safe API/CLI/UI contract without local paths or claims."""
        return json.loads(json.dumps(self.document))

    def component_version(self, component_id: str) -> dict[str, Any]:
        try:
            component = self.document["components"][component_id]
        except KeyError as error:
            raise PlatformProfileError(
                f"platform profile has no component: {component_id}"
            ) from error
        return {"chart": component["chart"], "images": component["images"]}
