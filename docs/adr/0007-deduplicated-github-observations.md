# ADR 0007: File deduplicated GitHub observations automatically

- Status: Accepted
- Date: 2026-07-30

## Context

Health, lifecycle, validation, and improvement loops can find actionable
defects or gaps. Leaving findings only in transient logs loses work, while
creating an issue on every poll floods maintainers and fragments discussion.
Implementation tasks must remain in issues rather than being hidden in ADRs.

## Decision

GitHub issues are the durable work queue for actionable automated
observations. An observation producer emits a sanitized, provider-neutral
record with source, kind, affected scope, evidence summary, first and last
observation time, and a stable deduplication fingerprint derived from
non-secret normalized identity fields.

The GitHub adapter searches manager-owned observation metadata and creates an
issue only when no active matching observation exists. Repeated observations
update durable occurrence state and, according to a bounded policy, the
existing issue rather than creating duplicates. Resolution and recurrence
policies preserve history; they do not silently reopen or close
human-managed work without an explicit rule.

Automation applies recognizable labels such as `automated-observation` and
does not automatically schedule, implement, merge, or publish the resulting
work. Exact schemas, rate policies, and GitHub mutations remain
implementation tasks in GitHub issues.

## Considered alternatives

### Store observations only in local logs

This avoids GitHub writes but provides poor ownership, prioritization,
history, and collaboration.

### Create an issue for every occurrence

This preserves raw events but overwhelms the work queue and obscures whether
occurrences share one cause.

### Use issue title matching for deduplication

Titles are readable but unstable and prone to collisions. Explicit
machine-owned fingerprints provide a clearer contract.

### Automatically start every observed issue

This shortens response time but lets noisy or low-confidence observations
consume execution capacity without triage.

## Consequences

- Actionable findings become visible in the established work queue.
- Stable fingerprints reduce notification and issue churn.
- Normalization mistakes can merge distinct findings or split one finding,
  so fingerprints and evidence remain inspectable.
- GitHub outages defer filing; durable local delivery state must permit
  bounded retry.
- Maintainers retain triage and implementation control.

## Security and operational implications

Evidence is sanitized before persistence or transmission and excludes secret
values, private configuration, license content, raw support bundles, and
untrusted command text. GitHub credentials receive only the permissions
needed for the adapter. Idempotency keys, retry bounds, API-rate handling,
and an audit trail protect against duplicate external mutations.

## Compatibility and migration

Existing manually created issues are not retroactively tagged or merged.
The current SDLC supervisor already excludes automated observations from
automatic issue execution; this decision preserves that behavior. Future
fingerprint schema changes require versioning or a mapping strategy.

## Related decisions

- [ADR 0001](0001-sdlc-supervisor.md)
- [ADR 0002](0002-technology-neutral-control-loops.md)
- [ADR 0006](0006-provider-neutral-communications.md)
