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
/reject <predefined-reason>
/retry <idempotent-stage>
/issue <failure-fingerprint>
/pause
/continue
/watch
/unwatch
/advance
/help
```

Only the linked numeric user and private chat are accepted. Groups, channels,
other users, arbitrary shell commands, and arbitrary GitHub operations are
ignored or rejected.

## Notification policy

Notification preferences live only in the protected external
`supervisor.toml`; they are not Telegram commands, database preferences, or
repository state. The installer creates that file mode `0600`, and startup
rejects a symlink, a file owned by another user, or group/world-readable
permissions.

`[notifications]` selects immediate `all` events or `failures` only, an IANA
timezone, quiet-hour start/end, daily digest time, idempotent retry stages, and
predefined rejection reasons. Quiet hours may cross midnight. Deferred
observations are grouped into the digest bucket ending at the configured
digest time. Duplicate fingerprints increment one durable record; an already
delivered notification is edited instead of sending another message.

Failure cards contain only a code, stage, affected PR, retry eligibility, and
typed recovery commands. Diagnostics are bounded, newlines are flattened,
secret-like fields and raw logs are dropped, and protected paths are replaced.
Telegram never receives raw command output or filesystem paths.

The default retry allowlist is empty. Add a stage only after its operation is
known to be idempotent:

```toml
[notifications]
retry_stages = ["checks"]
```

`/retry checks` records a typed recovery request for the latest matching
failure; it does not execute shell text. `/issue <failure-fingerprint>` creates
one fixed-format, sanitized GitHub issue and records its URL. The operator
cannot supply a title or body, and duplicate requests do not create another
issue. It does not copy logs or create arbitrary issue content. `/pause` stops
selection of new work while monitoring continues. Rejections accept only the
configured reason slugs, so audit records stay consistent.

## Merge approval

When a tracked pull request is unchanged, mergeable, and passing, the
supervisor creates one expiring approval and adds **Approve**, **Reject**,
**Details**, and **Pause** buttons to the workflow status card. Button payloads
are random, opaque, single-use values; they contain no approval identifier,
secret, or command text, and only their SHA-256 digests are stored. Every
button press revalidates the linked identity, private chat, token expiry,
exact PR head, checks, open state, and mergeability before acting. Expired,
replayed, changed-head, or duplicate callbacks fail closed.
**Details** sends a durable, sanitized PR summary to the private chat rather
than relying on Telegram's short-lived callback toast.
Approval readiness sends a new notification carrying the same actions as the
durable workflow card, because editing an existing Telegram message does not
notify the operator. Failed delivery remains pending; a later monitor pass
creates fresh opaque callback tokens and retries the notification without
duplicating a successfully delivered alert.

The original card is edited after a decision and the decision is recorded as
a sanitized event. If Telegram cannot edit the card, the authoritative
decision remains durable and a sanitized delivery-failure event is recorded.
Use `/approve` or `/reject [reason]` as a compatible fallback; these commands
apply the same merge-plan validation. Explicit approval IDs remain available
only if multiple approvals somehow coexist.

When stale approvals from older PRs coexist with the tracked PR, implicit
commands select the tracked PR. Merge reconciliation supersedes any remaining
approvals for the completed PR.

## Workflow status card

The supervisor maintains one durable card reference and edits that message as
the loop changes. The detailed card shows milestone and issue progress, the
sanitized issue title, workflow state, start and elapsed time, last activity,
phase and phase age, runner health, changed-file count, validation, PR/CI
state, approval readiness, and the next expected transition. A missing or
uneditable card is replaced, and its new message reference becomes the durable
reference. Telegram is never the authoritative workflow store.

For example:

```text
Fortify SDLC Workflow — 0.2 — Observable Manager MVP
Milestone progress: issue #53 · 40m elapsed
Current: Add detailed Telegram workflow cards and adaptive long-running updates
Workflow: running
Started: 2026-07-30T10:00:00Z
Last activity: 2m ago
Phase: validating · 6m
Runner: active
Changed files: 5
Validation: running
PR / CI: none / not started
Approval ready: no
Next: scanning
```

The card shows only controls relevant to its current state so Telegram labels
remain readable. Normal status offers **Details** and **Refresh**; an active
runner with a configured stop command offers **Details** and **Stop**; paused
state offers **Continue** and **Details**. PR approval uses **Approve** and
**Reject** on the first row with **Details** on a second row. Milestone
rollover similarly uses **Advance** and **Stay**, then **Details**. Status,
pause, and routine delivery preferences remain available through `/status`,
`/pause`, `/watch`, and `/unwatch`.

Details is a new durable sanitized message, not a callback toast. Watch
controls routine heartbeat delivery only; urgent notifications continue. Stop
creates a separate confirmation message, and only the second
identity-bound, expiring, single-use callback launches that fixed command with
the numeric issue as its sole appended argument. Confirmation records a
`runner.stop_requested` audit event. Stop is hidden by default and never
deletes a worktree or persistent data.

Work start sends a new Telegram message. The first routine heartbeat is due at
10 minutes, then every 15 minutes through the first hour, and every 30 minutes
afterward. Routine updates are suppressed during quiet hours, while unwatched,
or when a meaningful notification was delivered recently. Phase changes
requiring attention, suspected stalls, recovery, PR creation, CI completion,
failure, and approval readiness notify immediately. A stall warning contains
phase, elapsed time, activity age, the last recorded safe step, and bounded
controls; it never includes a raw log tail.

Delivery fingerprints, schedule checkpoints, watch state, and provider message
references are persisted in the supervisor database. Consequently monitor
overlap and service restart do not duplicate delivery. A provider outage leaves
delivery pending for retry and cannot pause, stop, approve, merge, or otherwise
change workflow authority.

After an approved PR merges, the supervisor closes the issue identified by its
`agent/issue-N` branch and immediately starts the lowest-numbered eligible open
issue in the configured milestone. Merges performed outside Telegram are
reconciled on the next monitor run. Issues marked
`automated-observation` or `needs-triage` are not started automatically.
Issue closure is idempotent: GitHub's native `Closes #N` processing and the
supervisor may race without turning a successful merge into an operator error.
Eligible issues labeled `queue:next` are selected before the normal
lowest-issue-number order. This is an explicit operator-controlled queue
override; ordering remains deterministic within the prioritized group.

## Milestone rollover

The required `milestone` value is the initial active milestone and preserves
compatibility with existing installations. To authorize controlled rollover,
add an ordered sequence to the protected external configuration:

```toml
[supervisor]
milestone = "0.2 — Observable Manager MVP"
milestones = [
  "0.2 — Observable Manager MVP",
  "0.3 — Controlled Operations",
]
```

The sequence is an allowlist, not a request to start every milestone silently.
When the active milestone has no eligible issues, the supervisor verifies that
its GitHub milestone is closed with zero open issues. It then sends the linked
private chat an **Advance** or **Stay** decision. **Advance** (or `/advance`)
revalidates the exact repository, current milestone, next configured
milestone, closed state, and issue count before persisting the transition and
immediately queuing the next issue. **Stay** rejects that approval and pauses
new work; `/continue` permits a fresh rollover proposal.

An open milestone produces guidance to close it but no approval. An unlisted,
reordered, removed, ambiguous, or externally changed milestone fails closed.
The supervisor never edits `supervisor.toml`; expanding the authorized
sequence remains a local operator action. The bounded issue runner reads the
persisted active milestone and rejects issues outside it.

## Autonomy policy

The monitor, Telegram listener, issue runner, and workflow status renderer use
one versioned policy loader. Policy is not accepted through Telegram and is
not stored in Git. With no policy setting, generation `0` of the `assisted`
profile preserves the historical behavior: eligible issue selection and
post-merge issue closure are automatic, while merges, milestone rollover, and
allowlisted retry requests remain operator-approved.

To opt in, create an owner-only, non-symlink JSON file outside the checkout:

```json
{
  "schema_version": "fortify.autonomy/v1alpha1",
  "profile": "assisted",
  "generation": 1,
  "actions": {
    "start_next_issue": "auto",
    "merge_pull_request": "approval"
  }
}
```

Then reference it from the protected supervisor configuration:

```toml
[supervisor]
autonomy_policy_file = "/home/ubuntu/.config/fortify-lab-manager/autonomy-policy.json"
```

Set its mode to `0600`, run `fortify-supervisor status`, and restart both
supervisor services only after the status output shows the intended profile,
generation, digest, and all eight effective action decisions. The digest is
calculated from the canonical effective policy, not its path or JSON key
order, so separate processes report the same value.

The supported profiles are:

- `manual`: every action requires approval;

- `assisted`: safe issue start and closure are automatic; merge, rollover,
  retry, destructive, secret, and scope actions require approval;

- `autonomous`: ordinary workflow actions default to automatic until a
  required future RFC 3339 `expires_at`; protected actions still require
  approval.

Every action can be `auto`, `approval`, or `disabled`, except
`destructive_operations`, `secret_operations`, and `scope_changes`, which must
remain `approval`. The other action names are `start_next_issue`,
`close_completed_issue`, `advance_milestone`,
`retry_idempotent_failure`, and `merge_pull_request`. Automatic decisions do
not bypass the repository, issue, or milestone allowlists, idempotent-stage
allowlist, CI and review gates, secret scan, dependency checks, branch binding,
mergeability, or milestone eligibility.

For a manual profile, `/start-next` performs one approved eligible-issue
selection and `/close-completed` closes the one completed issue recorded after
merge. The existing `/advance`, `/retry`, and `/approve` commands authorize
their respective approval-bound actions. Commands still revalidate the
underlying allowlists and operation gates; changing a decision to `disabled`
removes that authorization path.

An autonomous example must be explicitly time-bounded:

```json
{
  "schema_version": "fortify.autonomy/v1alpha1",
  "profile": "autonomous",
  "generation": 2,
  "expires_at": "2026-08-01T02:00:00Z",
  "actions": {
    "merge_pull_request": "approval"
  }
}
```

Unknown fields, profiles, actions, or decisions; an expired autonomous policy;
unsafe protected-action overrides; malformed JSON; and insecure file
ownership or permissions all fail closed with sanitized errors. Configuration
changes produce `autonomy.policy_changed` events containing the old and new
generation/digest but no policy path or raw values. Generation is an
operator-managed non-negative revision; increment it for each intended change.

To roll back, restore the last known valid external document and generation,
then restart both services and compare the status digest. To restore exact
pre-policy behavior, remove `autonomy_policy_file` from `supervisor.toml` and
restart the services; the effective policy returns to assisted generation `0`.
Do not delete the SQLite state database: its audit history is durable evidence.

## Optional runner

`runner_command` is disabled by default. The installer provides an optional
bounded runner at:

```text
~/.local/bin/fortify-issue-dispatch
```

When configured, the supervisor appends the selected issue number and launches
it without a shell. The runner accepts only open issues in the approved
milestone read from the protected external `supervisor.toml`, creates a clean
worktree from `origin/main`, runs Codex with a
dedicated externally constrained systemd service, validates and scans staged
changes, pushes an `agent/issue-N` branch, and opens a draft PR. Codex's nested
Bubblewrap sandbox is disabled because Ubuntu hosts may restrict unprivileged
user namespaces; the service supplies the filesystem boundary with a
read-only home and system plus an explicit writable state directory and Git
metadata path.
After the branch is pushed and the draft PR is created, the runner removes its
clean local worktree and branch. The remote PR branch remains available for
review and recovery.

The runner also persists atomic, sanitized heartbeat evidence throughout its
active lifetime. This is the supported way for an operator or future UI to
observe phase, elapsed time, last activity, changed-file count, validation
state, and the eventual PR reference without parsing Codex output or runner
logs. See the [runner heartbeat contract](../runner-heartbeats.md) for phases,
freshness classifications, restart behavior, bounded retention, and the
security boundary. Heartbeats never authorize or advance the workflow.
With no current issue, the card reports `idle` or `paused` and points to queue
selection or operator resume. A selected issue without heartbeat evidence is
`waiting`, never `running`; `running` is reserved for an issue with active
runner evidence.
On an enabled idle monitor cycle, the supervisor first reconciles any open
agent PR. If none exists, it selects the next eligible milestone issue exactly
once. A paused supervisor never performs this idle-to-queued transition.
Repository validation is bounded by `FORTIFY_RUNNER_VALIDATION_TIMEOUT`
(default `30m`). If validation or one of its child processes deadlocks, the
runner terminates it, records validation failure, preserves the issue
workspace, and stops instead of holding the queue indefinitely.

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
the service or next timer invocation. Notification delivery failure cannot
approve, reject, retry, merge, queue, or advance work. A failed immediate send
remains pending; a failed digest remains in its original bucket. Use `/pause`
before maintenance. The
SQLite state is stored outside the checkout at:

```text
~/.local/share/fortify-lab-manager/supervisor.db
```

Existing databases are upgraded in place by creating the callback-token table
and durable notification table on startup. No Telegram credential, protected
configuration value, diagnostic log, or identity value is migrated into it.

Recovery is deliberately limited: retry requests apply only to configured
idempotent stages, created issues still need operator processing, and
notification delivery cannot reconstruct lost provider messages or repair GitHub, CI, the
runner, or a live MicroK8s workload. Inspect the authoritative local state and
the original system before resuming. Raw logs must stay in their protected
source and must not be pasted into Telegram.

Runner heartbeat files recover independently from the SQLite supervisor state.
A restarted observer reads the last atomically completed document. A restarted
runner takes a new writer generation, which prevents the old process from
overwriting it. A missing heartbeat is unknown evidence, not proof that the
runner failed; use the systemd unit state and configured timeout to decide
whether operator action is needed.

The optional `heartbeat_root` defaults to the `runner-heartbeats` directory
beside `state_file`. It is read-only evidence. Heartbeat files with an
unexpected identity, schema version, symlink, or invalid JSON are ignored
rather than rendered. No external configuration, runner logs, or secret
directories are read to build a card.
