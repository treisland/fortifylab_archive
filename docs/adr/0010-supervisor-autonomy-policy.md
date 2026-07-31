# ADR 0010: Externalize the supervisor autonomy policy

- Status: Accepted
- Date: 2026-07-31

## Context

The SDLC supervisor historically encoded its mix of automatic transitions and
human approvals directly in the monitor and Telegram behavior. Operators need
to select manual, assisted, or time-bounded autonomous operation without
letting a communications provider become an authority or weakening the issue,
milestone, CI, review, secret, scope, and destructive-operation boundaries.

The monitor, Telegram listener, bounded issue runner, and status renderer are
separate processes or adapters. Reimplementing profile logic in each one would
allow their decisions and audit evidence to drift.

## Decision

Define `fortify.autonomy/v1alpha1` as a technology-neutral external JSON
contract. A shared loader validates a named profile, monotonically
operator-managed configuration generation, optional per-action overrides, and
the future expiry required by the autonomous profile. It resolves every action
to exactly one of `auto`, `approval`, or `disabled` and creates a canonical
SHA-256 digest from the sanitized effective policy.

The actions are starting the next issue, closing a completed issue, advancing
a milestone, retrying an idempotent failure, merging a pull request,
destructive operations, secret operations, and scope changes. Destructive,
secret, and scope-changing operations can only resolve to `approval`.

The policy file and durable runtime state remain outside the repository.
Telegram renders and requests policy-governed actions but is never the policy
store. All supervisor processes use the same shared loader. Missing policy
configuration resolves to generation `0` of the assisted profile. Assisted is
the recommended steady-state after initial Manual verification: issue
start/closure, exact allowlisted milestone rollover, and verified-idempotent
retry requests are automatic. Merge, destructive, secret, and scope decisions
remain approval-bound.

## Considered alternatives

### Keep behavior embedded in each adapter

This minimizes configuration but makes cross-process drift likely and prevents
operators from reviewing one effective contract.

### Store policy in Telegram commands or supervisor state

This makes a delivery adapter or mutable runtime database authoritative and
complicates recovery. Both are rejected.

### Permit unrestricted autonomous operation

This conflicts with the lab's destructive, secret, and scope boundaries and
is rejected. Autonomous mode is time-bounded and does not bypass eligibility,
CI, review, secret scanning, dependency, or milestone checks.

## Consequences

- Every process derives identical effective decisions and digest from the same
  external document.
- Status and audit records can identify policy changes without exposing a path
  or source values.
- Operators must deliberately maintain generation and autonomous expiry.
- An expired autonomous lease is atomically replaced by a new Assisted
  generation before any action. Invalid, inconsistent, unknown, unreadable,
  or insecurely permissioned policy still prevents action.
- Schema evolution requires an explicit version and migration.

## Security and operational implications

The policy is owner-only and must be a regular non-symlink file. Protected
actions remain approval-bound in every profile. The existing issue and
milestone allowlists and all CI, review, branch, mergeability, idempotency, and
eligibility gates remain mandatory. Durable audit events contain only profile,
generation, and digests; they exclude policy paths and raw configuration.

## Compatibility and migration

Issue #94 intentionally changes the omitted-policy Assisted default from
approval-first rollover/retry to deterministic automatic rollover/retry.
Operators requiring the earlier posture must install a `manual` policy before
upgrading. Migration to Assisted and rollback to Manual each require a new
protected policy generation, status/digest verification, and restart of both
user services. Runtime state and Telegram messages are not authoritative and
need no data migration.

## Related decisions

- [ADR 0001](0001-sdlc-supervisor.md)
- [ADR 0002](0002-technology-neutral-control-loops.md)
- [ADR 0003](0003-microk8s-first-scope.md)
- [ADR 0006](0006-provider-neutral-communications.md)
