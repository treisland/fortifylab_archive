#!/usr/bin/env python3
"""Validate authoritative component definitions without cluster access."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from manager.registry_validation import validate_registry  # noqa: E402


def main() -> int:
    registry_path = ROOT / "registry" / "components.json"
    with registry_path.open(encoding="utf-8") as stream:
        document = json.load(stream)
    errors = validate_registry(document, ROOT)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Component registry is valid ({len(document['components'])} components).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
