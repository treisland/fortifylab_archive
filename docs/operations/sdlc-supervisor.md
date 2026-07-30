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

After GitHub reports the PR merged, the supervisor queues the lowest-numbered
eligible open issue in the configured milestone. Issues marked
`automated-observation` or `needs-triage` are not started automatically.

## Optional runner

`runner_command` is disabled by default. The installer provides an optional
bounded runner at:

```text
~/.local/bin/fortify-issue-dispatch
```

When configured, the supervisor appends the selected issue number and launches
it without a shell. The runner accepts only open issues in the approved
milestone, creates a clean worktree from `origin/main`, runs Codex with a
workspace-write sandbox, validates and scans staged changes, pushes an
`agent/issue-N` branch, and opens a draft PR.

Enable it only after the supervisor-only path is verified:

```toml
runner_command = ["/home/ubuntu/.local/bin/fortify-issue-dispatch"]
```

The dispatcher starts a separate constrained systemd service so the runner
survives completion of the short GitHub-monitor job. The runner command is
configuration-controlled and cannot be supplied through Telegram. It cannot
merge its own PR. A dedicated worktree prevents ignored license, certificate,
and environment files from entering its workspace.

## Recovery

Telegram or GitHub failures leave durable state unchanged and are retried by
the service or next timer invocation. Use `/pause` before maintenance. The
SQLite state is stored outside the checkout at:

```text
~/.local/share/fortify-lab-manager/supervisor.db
```
