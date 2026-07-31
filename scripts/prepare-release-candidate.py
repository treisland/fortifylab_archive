#!/usr/bin/env python3
"""Build a bounded local release candidate without publishing it."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from manager.release_candidate import ReleaseCandidateError, build_candidate  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="0.4.0-rc.1")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "release-candidates")
    arguments = parser.parse_args()
    try:
        result = build_candidate(ROOT, arguments.output, version=arguments.version)
    except (OSError, ValueError, ReleaseCandidateError) as error:
        print(f"Release candidate failed: {error}", file=sys.stderr)
        return 1
    print(f"Candidate: {result.directory}")
    print(f"Verdict: {result.verdict.upper()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
