#!/usr/bin/env python3
"""Validate every committed platform profile and its release evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from manager.component_registry import ComponentRegistry, RegistryError  # noqa: E402
from manager.platform_profiles import PlatformProfile, PlatformProfileError  # noqa: E402


def main() -> int:
    profile_paths = sorted(
        path for path in (ROOT / "profiles").glob("*.json") if path.is_file()
    )
    if not profile_paths:
        print("Platform profiles are invalid: no profiles found", file=sys.stderr)
        return 1
    try:
        profiles = [
            PlatformProfile.load(
                json.loads(path.read_text(encoding="utf-8"))["id"]
            )
            for path in profile_paths
        ]
        registry = ComponentRegistry.load()
    except (
        OSError, json.JSONDecodeError, PlatformProfileError, RegistryError
    ) as error:
        print(f"Platform profiles are invalid: {error}", file=sys.stderr)
        return 1
    if registry.profile.id not in {profile.id for profile in profiles}:
        print("Platform profiles are invalid: registry profile is absent", file=sys.stderr)
        return 1
    print(
        f"Platform profiles are valid ({len(profiles)} profiles; "
        f"selected {registry.profile.id})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
