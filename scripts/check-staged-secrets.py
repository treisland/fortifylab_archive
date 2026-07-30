#!/usr/bin/env python3
"""Conservative secret-pattern gate for staged text changes."""

from __future__ import annotations

import re
import subprocess
import sys


PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Telegram bot token": re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"),
    "generic bearer token": re.compile(
        r"(?i)\b(?:authorization|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9._~-]{24,}"
    ),
}


def main() -> int:
    result = subprocess.run(
        ["git", "diff", "--cached", "--no-ext-diff", "--unified=0"],
        text=True,
        capture_output=True,
        check=True,
    )
    findings: list[str] = []
    file_name = "unknown"
    for line in result.stdout.splitlines():
        if line.startswith("+++ b/"):
            file_name = line[6:]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        content = line[1:]
        for label, pattern in PATTERNS.items():
            if pattern.search(content):
                findings.append(f"{file_name}: possible {label}")
    if findings:
        print("Potential secrets detected in staged changes:", file=sys.stderr)
        print("\n".join(sorted(set(findings))), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
