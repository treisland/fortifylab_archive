#!/usr/bin/env bash

set -euo pipefail

ISSUE_NUMBER="${1:-}"
[[ "$ISSUE_NUMBER" =~ ^[0-9]+$ ]] || {
  printf 'Usage: %s <issue-number>\n' "$0" >&2
  exit 2
}

systemctl --user start "fortify-issue-runner@${ISSUE_NUMBER}.service"
