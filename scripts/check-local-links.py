#!/usr/bin/env python3
"""Fail when a tracked Markdown file references a missing local file."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")


def tracked_markdown() -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "*.md"], cwd=ROOT, text=True
    )
    return [ROOT / item for item in output.splitlines() if item]


def main() -> int:
    failures: list[str] = []
    for document in tracked_markdown():
        content = document.read_text(encoding="utf-8")
        for target in LINK.findall(content):
            target = target.strip().strip("<>")
            if (
                not target
                or target.startswith(("#", "http://", "https://", "mailto:"))
            ):
                continue
            path_text = unquote(target.split("#", 1)[0])
            if not path_text:
                continue
            candidate = (document.parent / path_text).resolve()
            if not candidate.exists():
                failures.append(
                    f"{document.relative_to(ROOT)}: missing local target {target}"
                )
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
