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
CODEX_BIN="${FORTIFY_CODEX_BIN:-$HOME/.local/bin/codex}"
export GIT_SSH_COMMAND="${FORTIFY_GIT_SSH_COMMAND:-ssh -F /dev/null}"
WORKSPACE_ROOT="$STATE_ROOT/workspaces"
WORKTREE="$WORKSPACE_ROOT/issue-$ISSUE_NUMBER"
LOG_FILE="$STATE_ROOT/runner-$ISSUE_NUMBER.log"
RESULT_FILE="$STATE_ROOT/runner-$ISSUE_NUMBER-result.txt"
LOCK_FILE="$STATE_ROOT/runner.lock"

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
  notify "❌ Automated issue #$ISSUE_NUMBER stopped: $1"
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

for command in git gh python3; do
  command -v "$command" >/dev/null 2>&1 || fail "missing command: $command"
done
[ -x "$CODEX_BIN" ] || fail "Codex CLI is not executable: $CODEX_BIN"

ISSUE_JSON="$(gh issue view "$ISSUE_NUMBER" --repo "$REPOSITORY" \
  --json number,title,body,state,milestone,url)"
ISSUE_STATE="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])' \
  <<<"$ISSUE_JSON")"
ISSUE_MILESTONE="$(python3 -c 'import json,sys; print((json.load(sys.stdin).get("milestone") or {}).get("title", ""))' \
  <<<"$ISSUE_JSON")"
ISSUE_TITLE="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["title"])' \
  <<<"$ISSUE_JSON")"

[ "$ISSUE_STATE" = "OPEN" ] || fail "issue is not open"
[ "$ISSUE_MILESTONE" = "0.1 — Evaluation Foundation" ] \
  || fail "issue is outside the approved milestone"
[ ! -e "$WORKTREE" ] || fail "workspace already exists: $WORKTREE"

git -C "$SOURCE_ROOT" fetch origin main
BRANCH="agent/issue-$ISSUE_NUMBER"
git -C "$SOURCE_ROOT" worktree add -b "$BRANCH" "$WORKTREE" origin/main

notify "▶️ Starting automated work on issue #$ISSUE_NUMBER: $ISSUE_TITLE"

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
      -

(
  cd "$WORKTREE"
  ./scripts/validate-repository.sh
  git diff --check
  git add -A
  python3 scripts/check-staged-secrets.py
  git diff --cached --quiet && fail "agent produced no repository changes"
  git commit -m "Implement issue #$ISSUE_NUMBER"
  git push -u origin "$BRANCH"
)

PR_URL="$(gh pr create \
  --repo "$REPOSITORY" \
  --base main \
  --head "$BRANCH" \
  --draft \
  --title "$ISSUE_TITLE" \
  --body $'Closes #'"$ISSUE_NUMBER"$'.\n\nCreated by the bounded Fortify SDLC issue runner. The pull request remains draft until verification and human approval complete.')"

git -C "$SOURCE_ROOT" worktree remove "$WORKTREE"
git -C "$SOURCE_ROOT" branch -D "$BRANCH"

notify "✅ Automated issue #$ISSUE_NUMBER opened draft PR: $PR_URL"
