#!/usr/bin/env bash

# Bounded background implementation runner. It operates only in a clean,
# dedicated Git worktree and never targets the live MicroK8s environment.

set -euo pipefail
umask 077

ISSUE_NUMBER="${1:-}"
[[ "$ISSUE_NUMBER" =~ ^[0-9]+$ ]] || {
  printf 'Usage: %s <issue-number>\n' "$0" >&2
  exit 2
}

REPOSITORY="${FORTIFY_GITHUB_REPOSITORY:-treisland/fortifylab}"
SOURCE_ROOT="${FORTIFY_REPOSITORY_ROOT:-/home/ubuntu/lab}"
STATE_ROOT="${FORTIFY_MANAGER_STATE_DIR:-$HOME/.local/share/fortify-lab-manager}"
SUPERVISOR_CONFIG="${FORTIFY_SUPERVISOR_CONFIG:-$HOME/.config/fortify-lab-manager/supervisor.toml}"
CODEX_BIN="${FORTIFY_CODEX_BIN:-$HOME/.local/bin/codex}"
export GIT_SSH_COMMAND="${FORTIFY_GIT_SSH_COMMAND:-ssh -F /dev/null}"
WORKSPACE_ROOT="$STATE_ROOT/workspaces"
WORKTREE="$WORKSPACE_ROOT/issue-$ISSUE_NUMBER"
LOG_FILE="$STATE_ROOT/runner-$ISSUE_NUMBER.log"
RESULT_FILE="$STATE_ROOT/runner-$ISSUE_NUMBER-result.txt"
LOCK_FILE="$STATE_ROOT/runner.lock"
HEARTBEAT_ROOT="$STATE_ROOT/runner-heartbeats"
HEARTBEAT_TOOL="${FORTIFY_HEARTBEAT_TOOL:-$HOME/.local/lib/fortify-lab-manager/runner_heartbeat.py}"
HEARTBEAT_INTERVAL="${FORTIFY_HEARTBEAT_INTERVAL_SECONDS:-30}"
VALIDATION_TIMEOUT="${FORTIFY_RUNNER_VALIDATION_TIMEOUT:-30m}"
HEARTBEAT_WRITER=""
HEARTBEAT_GENERATION=""
HEARTBEAT_TERMINAL=0
HEARTBEAT_TICKER_PID=""

install -d -m 700 "$STATE_ROOT" "$WORKSPACE_ROOT"
exec 9>"$LOCK_FILE"
flock -n 9 || {
  printf 'Another issue runner is already active.\n' >&2
  exit 1
}

exec >>"$LOG_FILE" 2>&1

notify() {
  if [ -x "$HOME/.local/bin/fortify-telegram-bootstrap" ]; then
    "$HOME/.local/bin/fortify-telegram-bootstrap" notify "$1" || true
  fi
}

fail() {
  if declare -F heartbeat_terminal >/dev/null; then
    heartbeat_terminal failed
  fi
  notify "❌ Automated issue #$ISSUE_NUMBER stopped: $1"
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

for command in git gh python3 timeout; do
  command -v "$command" >/dev/null 2>&1 || fail "missing command: $command"
done
[ -x "$CODEX_BIN" ] || fail "Codex CLI is not executable: $CODEX_BIN"
[ -r "$HEARTBEAT_TOOL" ] || fail "runner heartbeat helper is not readable"
[ -r "$SUPERVISOR_CONFIG" ] || fail "supervisor configuration is not readable"
APPROVED_MILESTONE="$(
  python3 - "$SUPERVISOR_CONFIG" "$HEARTBEAT_TOOL" <<'PY'
import sqlite3
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[2]).resolve().parent))
from autonomy_policy import AutonomyPolicyError, load_policy

with open(sys.argv[1], "rb") as stream:
    supervisor = tomllib.load(stream)["supervisor"]
policy_path = supervisor.get("autonomy_policy_file")
try:
    policy = load_policy(Path(policy_path) if policy_path else None)
except AutonomyPolicyError as error:
    raise SystemExit(str(error)) from error
if policy.decision("start_next_issue") == "disabled":
    raise SystemExit("issue runner start is disabled by autonomy policy")
authorized = tuple(supervisor.get("milestones") or (supervisor["milestone"],))
with sqlite3.connect(supervisor["state_file"]) as connection:
    row = connection.execute(
        "SELECT value FROM settings WHERE key = 'active_milestone'"
    ).fetchone()
active = str(row[0]) if row else str(supervisor["milestone"])
if active not in authorized:
    raise SystemExit("active milestone is outside the authorized sequence")
print(active)
PY
)"
[ -n "$APPROVED_MILESTONE" ] || fail "approved milestone is empty"

heartbeat_update() {
  [ -n "$HEARTBEAT_WRITER" ] || return 0
  python3 "$HEARTBEAT_TOOL" --root "$HEARTBEAT_ROOT" update \
    --issue "$ISSUE_NUMBER" \
    --writer-id "$HEARTBEAT_WRITER" \
    --generation "$HEARTBEAT_GENERATION" "$@" >/dev/null
}

heartbeat_phase() {
  heartbeat_update --phase "$1"
}

heartbeat_terminal() {
  [ "$HEARTBEAT_TERMINAL" -eq 0 ] || return 0
  [ -z "$HEARTBEAT_TICKER_PID" ] || {
    kill "$HEARTBEAT_TICKER_PID" 2>/dev/null || true
    wait "$HEARTBEAT_TICKER_PID" 2>/dev/null || true
    HEARTBEAT_TICKER_PID=""
  }
  heartbeat_update --phase "$1" || true
  HEARTBEAT_TERMINAL=1
}

heartbeat_ticker_start() {
  (
    while sleep "$HEARTBEAT_INTERVAL"; do
      heartbeat_update || exit 0
    done
  ) &
  HEARTBEAT_TICKER_PID="$!"
}

heartbeat_ticker_stop() {
  [ -z "$HEARTBEAT_TICKER_PID" ] || {
    kill "$HEARTBEAT_TICKER_PID" 2>/dev/null || true
    wait "$HEARTBEAT_TICKER_PID" 2>/dev/null || true
    HEARTBEAT_TICKER_PID=""
  }
}

HEARTBEAT_JSON="$(python3 "$HEARTBEAT_TOOL" --root "$HEARTBEAT_ROOT" start \
  --issue "$ISSUE_NUMBER" --milestone "$APPROVED_MILESTONE")"
HEARTBEAT_WRITER="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["writer_id"])' \
  <<<"$HEARTBEAT_JSON")"
HEARTBEAT_GENERATION="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["generation"])' \
  <<<"$HEARTBEAT_JSON")"
trap 'heartbeat_terminal failed' EXIT
heartbeat_ticker_start
heartbeat_phase inspecting

ISSUE_JSON="$(gh issue view "$ISSUE_NUMBER" --repo "$REPOSITORY" \
  --json number,title,body,state,milestone,url)"
ISSUE_STATE="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])' \
  <<<"$ISSUE_JSON")"
ISSUE_MILESTONE="$(python3 -c 'import json,sys; print((json.load(sys.stdin).get("milestone") or {}).get("title", ""))' \
  <<<"$ISSUE_JSON")"
ISSUE_TITLE="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["title"])' \
  <<<"$ISSUE_JSON")"

[ "$ISSUE_STATE" = "OPEN" ] || fail "issue is not open"
[ "$ISSUE_MILESTONE" = "$APPROVED_MILESTONE" ] \
  || fail "issue is outside the approved milestone"
[ ! -e "$WORKTREE" ] || fail "workspace already exists: $WORKTREE"

git -C "$SOURCE_ROOT" fetch origin main
BRANCH="agent/issue-$ISSUE_NUMBER"
git -C "$SOURCE_ROOT" worktree add -b "$BRANCH" "$WORKTREE" origin/main

notify "▶️ Starting automated work on issue #$ISSUE_NUMBER: $ISSUE_TITLE"
heartbeat_phase planning

{
  printf '%s\n' \
    "Use \$fortify-implement-issue and other applicable Fortify skills." \
    "Implement GitHub issue #$ISSUE_NUMBER in this dedicated worktree." \
    "Work locally only. Do not call GitHub, push, merge, publish, or mutate the live MicroK8s cluster." \
    "Do not read external secret/configuration directories or copy sensitive data." \
    "Preserve project scope: Fortify Lab Manager, MicroK8s first, ASPM excluded." \
    "Add tests and documentation, run ./scripts/validate-repository.sh, and leave changes uncommitted." \
    "" \
    "Issue JSON:"
  printf '%s\n' "$ISSUE_JSON"
} | "$CODEX_BIN" -a never exec \
      --sandbox danger-full-access \
      --ephemeral \
      --cd "$WORKTREE" \
      --output-last-message "$RESULT_FILE" \
      - &
CODEX_PID="$!"
heartbeat_phase implementing
wait "$CODEX_PID" || fail "implementation command failed"

heartbeat_phase testing
(
  cd "$WORKTREE"
  CHANGED_FILE_COUNT="$(git status --short --untracked-files=all | wc -l)"
  heartbeat_update --changed-file-count "$CHANGED_FILE_COUNT"
  heartbeat_update --phase validating --validation-state running
  if ! timeout --signal=TERM --kill-after=10s "$VALIDATION_TIMEOUT" \
      ./scripts/validate-repository.sh || ! git diff --check; then
    heartbeat_update --validation-state failed
    fail "repository validation failed"
  fi
  heartbeat_update --validation-state passed
  heartbeat_phase scanning
  git add -A
  python3 scripts/check-staged-secrets.py
  git diff --cached --quiet && fail "agent produced no repository changes"
  heartbeat_phase committing
  git commit -m "Implement issue #$ISSUE_NUMBER"
  heartbeat_phase pushing
  git push -u origin "$BRANCH"
)

heartbeat_phase creating-pr
PR_URL="$(gh pr create \
  --repo "$REPOSITORY" \
  --base main \
  --head "$BRANCH" \
  --draft \
  --title "$ISSUE_TITLE" \
  --body $'Closes #'"$ISSUE_NUMBER"$'.\n\nCreated by the bounded Fortify SDLC issue runner. The pull request remains draft until verification and human approval complete.')"
heartbeat_update --phase waiting-for-ci --pr-reference "$PR_URL"

git -C "$SOURCE_ROOT" worktree remove "$WORKTREE"
git -C "$SOURCE_ROOT" branch -D "$BRANCH"

notify "✅ Automated issue #$ISSUE_NUMBER opened draft PR: $PR_URL"
heartbeat_terminal completed
trap - EXIT
