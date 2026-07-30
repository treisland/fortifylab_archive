# SDLC Supervisor

The SDLC supervisor monitors agent pull requests, sends status to the linked
private Telegram chat, and records bounded human approvals while development
continues away from the EC2 terminal.

It does not control live Fortify workloads, secrets, databases, PVCs, RBAC, or
releases.

## Install

Telegram must already be linked under:

```text
~/.config/fortify-lab-manager/telegram/
```

Install the supervisor:

```bash
./scripts/install-supervisor.sh
```

Review the protected external configuration:

```text
~/.config/fortify-lab-manager/supervisor.toml
```

Initialize and test:

```bash
~/.local/bin/fortify-supervisor init
~/.local/bin/fortify-supervisor status
~/.local/bin/fortify-supervisor monitor-once
~/.local/bin/fortify-supervisor telegram-once
```

Enable the private command listener and two-minute GitHub monitor:

```bash
systemctl --user enable --now fortify-supervisor-telegram.service
systemctl --user enable --now fortify-github-monitor.timer
```

Inspect status without exposing configuration:

```bash
systemctl --user status fortify-supervisor-telegram.service
systemctl --user status fortify-github-monitor.timer
journalctl --user -u fortify-supervisor-telegram.service
```

## Telegram commands

```text
/status
/pr
/approve
/reject [reason]
/pause
/continue
/help
```

Only the linked numeric user and private chat are accepted. Groups, channels,
other users, arbitrary shell commands, and arbitrary GitHub operations are
ignored or rejected.

## Merge approval

When a tracked pull request is unchanged, mergeable, and passing, the
supervisor creates one expiring approval. `/approve` targets that current
approval automatically, re-fetches the PR, and fails closed if the head SHA,
checks, state, or mergeability changed. `/reject [reason]` rejects it.
Explicit IDs remain available only as a safe fallback if multiple approvals
somehow coexist.

After an approved PR merges, the supervisor closes the issue identified by its
`agent/issue-N` branch and immediately starts the lowest-numbered eligible open
issue in the configured milestone. Merges performed outside Telegram are
reconciled on the next monitor run. Issues marked
`automated-observation` or `needs-triage` are not started automatically.
Issue closure is idempotent: GitHub's native `Closes #N` processing and the
supervisor may race without turning a successful merge into an operator error.

## Optional runner

`runner_command` is disabled by default. The installer provides an optional
bounded runner at:

```text
~/.local/bin/fortify-issue-dispatch
```

When configured, the supervisor appends the selected issue number and launches
it without a shell. The runner accepts only open issues in the approved
milestone, creates a clean worktree from `origin/main`, runs Codex with a
dedicated externally constrained systemd service, validates and scans staged
changes, pushes an `agent/issue-N` branch, and opens a draft PR. Codex's nested
Bubblewrap sandbox is disabled because Ubuntu hosts may restrict unprivileged
user namespaces; the service supplies the filesystem boundary with a
read-only home and system plus an explicit writable state directory and Git
metadata path.
After the branch is pushed and the draft PR is created, the runner removes its
clean local worktree and branch. The remote PR branch remains available for
review and recovery.

Enable it only after the supervisor-only path is verified:

```toml
runner_command = ["/home/ubuntu/.local/bin/fortify-issue-dispatch"]
```

The dispatcher starts a separate constrained systemd service so the runner
survives completion of the short GitHub-monitor job. The runner command is
configuration-controlled and cannot be supplied through Telegram. It cannot
merge its own PR. A dedicated worktree prevents ignored license, certificate,
and environment files from entering its workspace.

The systemd runner uses the explicit Codex CLI path
`~/.local/bin/codex`, so it does not depend on the user manager's restricted
`PATH`. Set `FORTIFY_CODEX_BIN` in a systemd override if Codex is installed
elsewhere, then run `systemctl --user daemon-reload`. The runner also isolates
Git SSH from host-wide client configuration by defaulting `GIT_SSH_COMMAND` to
`ssh -F /dev/null`; standard user keys and `known_hosts` remain in effect.
Override `FORTIFY_GIT_SSH_COMMAND` if the repository requires a custom SSH
configuration.

## Recovery

Telegram or GitHub failures leave durable state unchanged and are retried by
the service or next timer invocation. Use `/pause` before maintenance. The
SQLite state is stored outside the checkout at:

```text
~/.local/share/fortify-lab-manager/supervisor.db
```
