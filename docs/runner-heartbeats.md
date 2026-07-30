# Bounded runner heartbeat contract

The optional automated issue runner writes a sanitized JSON heartbeat to
`~/.local/share/fortify-lab-manager/runner-heartbeats/issue-N.json`. This is
durable operational evidence only. Reading or writing a heartbeat never
authorizes, retries, cancels, or advances GitHub, Git, CI, approval, or
deployment state.

## Document

The version 1 contract is defined by
[`registry/schemas/runner-heartbeat.schema.json`](../registry/schemas/runner-heartbeat.schema.json).
It contains only:

- issue number and milestone title;
- enumerated phase, phase start, run start, total elapsed time, last activity,
  health classification, and next expected transition;
- writer generation and revision used for concurrency protection;
- changed-file count, validation state, and the last completed enumerated safe
  phase (or runner initialization);
- an optional PR reference.

The phases are `preparing`, `inspecting`, `planning`, `implementing`, `testing`,
`validating`, `scanning`, `committing`, `pushing`, `creating-pr`,
`waiting-for-ci`, and `waiting-for-approval`, followed by `completed` or
`failed`. A particular run may finish or fail before reaching later phases.
The next transition is descriptive, not a percentage-complete estimate.

Prompts, source excerpts, raw output or logs, environment and secret values,
protected paths, and command lines are outside the contract and must never be
added. The PR reference accepts only a bounded, single-token public reference;
it must not contain credentials or user information.

## Atomicity, recovery, and concurrency

Each transition and periodic activity update is written to a mode `0600`
temporary file, flushed, atomically renamed, and followed by a directory
flush. A directory lock serializes writers. A new runner invocation creates a
new random writer ID and increments the issue generation. Updates from an
older invocation are then rejected, so a delayed or stale process cannot
replace newer state.

A supervisor or read-only observer can reopen the latest complete JSON
document after restart. A runner restart starts a new generation using the
previous generation as its recovery fence. Missing or unreadable heartbeat
state is reported as missing/unreadable; observers must not infer progress or
failure and must inspect the authoritative service state. Heartbeats do not
reconstruct commands or logs.

Terminal documents are retained for at most 30 days and the newest 100
terminal issue records. The heartbeat directory is additionally capped at the
newest 200 issue records. Cleanup is performed during writes and never changes
workflow state.

## Activity health

The installed runner writes at every phase transition and every 30 seconds
while active, independently of terminal output. Consequently a long validation
or other silent command is not failed merely because it emits no output.
The service's configured command timeout remains the authority for actually
terminating a hung run.

Readers classify the age since `last_activity_at` as:

| Age | Classification |
| --- | --- |
| less than 2 minutes | `active` |
| 2–10 minutes | `quiet` |
| 10–30 minutes | `possibly-stalled` |
| 30 minutes or more | `stalled` |
| terminal phase | `completed` or `failed` |

These classifications describe evidence freshness. In particular, `stalled`
does not kill, retry, or fail the runner.

For a local, sanitized inspection:

```bash
python3 ~/.local/lib/fortify-lab-manager/runner_heartbeat.py \
  --root ~/.local/share/fortify-lab-manager/runner-heartbeats \
  read --issue 52
```

Exit status 3 means no heartbeat exists for that issue. Do not substitute raw
runner logs in status messages or monitoring integrations.
