#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_ROOT="${FORTIFY_MANAGER_CONFIG_DIR:-$HOME/.config/fortify-lab-manager}"
STATE_ROOT="${FORTIFY_MANAGER_STATE_DIR:-$HOME/.local/share/fortify-lab-manager}"
LIB_ROOT="$HOME/.local/lib/fortify-lab-manager"
BIN_ROOT="$HOME/.local/bin"
UNIT_ROOT="$HOME/.config/systemd/user"

install -d -m 700 "$CONFIG_ROOT" "$STATE_ROOT" "$LIB_ROOT"
install -d -m 755 "$BIN_ROOT" "$UNIT_ROOT"
install -m 700 "$REPOSITORY_ROOT/supervisor/fortify_supervisor.py" \
  "$LIB_ROOT/fortify_supervisor.py"
install -m 700 "$REPOSITORY_ROOT/scripts/fortify-issue-runner.sh" \
  "$BIN_ROOT/fortify-issue-runner"
install -m 700 "$REPOSITORY_ROOT/scripts/fortify-issue-dispatch.sh" \
  "$BIN_ROOT/fortify-issue-dispatch"

if [ ! -f "$CONFIG_ROOT/supervisor.toml" ]; then
  install -m 600 "$REPOSITORY_ROOT/config/supervisor.example.toml" \
    "$CONFIG_ROOT/supervisor.toml"
  printf 'Created %s; review it before enabling services.\n' \
    "$CONFIG_ROOT/supervisor.toml"
fi

install -m 644 "$REPOSITORY_ROOT"/packaging/systemd/*.service "$UNIT_ROOT/"
install -m 644 "$REPOSITORY_ROOT"/packaging/systemd/*.timer "$UNIT_ROOT/"

WRAPPER="$BIN_ROOT/fortify-supervisor"
{
  printf '%s\n' '#!/bin/sh'
  printf '%s\n' \
    'exec /usr/bin/python3 "$HOME/.local/lib/fortify-lab-manager/fortify_supervisor.py" "$@"'
} >"$WRAPPER"
chmod 700 "$WRAPPER"

systemctl --user daemon-reload
printf 'Installed supervisor. Validate with:\n'
printf '  %s init\n' "$WRAPPER"
printf 'Then enable with:\n'
printf '  systemctl --user enable --now fortify-supervisor-telegram.service\n'
printf '  systemctl --user enable --now fortify-github-monitor.timer\n'
printf 'After validating supervisor-only behavior, optionally configure:\n'
printf '  runner_command = ["%s"]\n' "$BIN_ROOT/fortify-issue-dispatch"
