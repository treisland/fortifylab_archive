#!/usr/bin/env python3
"""Validate authoritative component definitions without cluster access."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from manager.component_registry import ComponentRegistry, RegistryError  # noqa: E402


def main() -> int:
    try:
        registry = ComponentRegistry.load()
    except RegistryError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Component registry is valid ({len(registry.component_ids)} components).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
