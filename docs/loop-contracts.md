# Technology-neutral loop contracts

Fortify Lab Manager exchanges durable control-loop records through the
versioned JSON Schemas in `contracts/v1alpha1/schemas`. They cover the four
loops accepted by ADR 0002:

- `lifecycle`: component operations and verification;
- `health`: observations, causal failures, and recovery;
- `development`: bounded repository change workflows;
- `improvement`: observations and planned product improvements.

These are data contracts, not a promise that every adapter or loop has been
implemented. They deliberately contain no Kubernetes, MicroK8s, Web UI,
communications-provider, or agent-framework types. MicroK8s remains the first
deployment target and ASPM is not a loop or supported subject.

## Contract catalog

| Kind | Schema | Purpose |
| --- | --- | --- |
| `Operation` | `operation.schema.json` | Immutable request metadata for a typed lifecycle or control-loop operation |
| `OperationProgress` | `progress.schema.json` | Current operation state, bounded execution policy, retry attempt, cancellation, and idempotency |
| `HealthObservation` | `health.schema.json` | Aggregate condition, individual evidence, and the selected causal check |
| `LoopEvent` | `event.schema.json` | Immutable, correlated state-change evidence |
| `Incident` | `incident.schema.json` | Deduplicated impact with an explicit root event |
| `PlanApproval` | `approval.schema.json` | Expiring, single-use authorization for an exact plan digest |
| `SanitizedTrace` | `trace.schema.json` | Provenance-bearing diagnostic entries after redaction |

Every record uses `apiVersion: fortifylab.io/v1alpha1`, rejects unknown
fields, identifies one of the four loops, and carries provenance. Additive
optional fields may be introduced within `v1alpha1`; incompatible changes
require a new contract directory and an explicit adapter migration.

## Execution semantics

An operation has a positive `timeoutSeconds` and a finite `maxAttempts`.
`attempt` starts at one and cannot exceed that maximum. Automatic retries are
allowed only for operations declared `idempotent` or `keyed`; a keyed
operation must reuse the same non-secret idempotency key. A
`non-idempotent` operation has exactly one automatic attempt.

Cancellation distinguishes a request from adapter support. A request records
`requestedAt`; adapters move through `cancelling` to `cancelled` only after
work has stopped. If interruption is unsafe or unsupported, the bounded
timeout still applies and the terminal result must say so without claiming
cancellation.

Failures use stable sanitized codes. Health and incident records identify
root cause by reference to evidence included in the same record: a health
check or event. Adapters should select the earliest failing required
dependency rather than repeating downstream symptoms. Recovery creates new
observations and events; it does not rewrite prior evidence.

## Approval semantics

An approval binds to `sha256:<64 lowercase hex characters>`, calculated from
the canonical bytes of the complete plan. Any plan or relevant input change
produces a different digest and requires a new approval. `expiresAt` must be
after `createdAt`; decisions and consumption must occur inside that window.
`singleUse` is always true. Execution atomically changes an approved record
to `consumed`; approved, rejected, expired, consumed, and superseded records
cannot authorize another execution.

The schemas define the portable record. The operation service that consumes an
approval must enforce the state transition and atomic single-use claim under
concurrency; durable history does not itself grant authorization.

Communications adapters may render contextual controls for an approval, but
their callback payloads are transport references rather than approval
contracts. They must be opaque, expiring, and single-use, and must resolve
back to the authoritative digest-bound approval before authorization is
evaluated. Provider message IDs and delivery outcomes do not change approval
semantics.

## Redaction and provenance

All stored and exported traces must set `sanitized: true`. Trace fields reject
names associated with credentials, tokens, licenses, private keys,
authorization data, and cookies. Semantic validation also rejects recognizable
Bearer credentials, password assignments, and private-key headers in messages
or values. This is a minimum fail-closed boundary; adapters must redact secret
values before constructing a trace and may apply stricter rules.

Do not put raw environment dumps, external secret/configuration paths, license
contents, certificates, or cluster credentials into these records. Use stable
opaque identifiers and sanitized summaries. Every record's `provenance`
identifies its source, collector, observation time, and correlation ID so
redaction and origin remain independently testable.

Representative valid records are in `contracts/v1alpha1/examples.json`.
`tests/test_loop_contracts.py` validates every example and negative cases for
retry, timeout, cancellation, idempotency, causal references, approvals,
redaction, and provenance without accessing a cluster.

The [versioned evaluation corpus](evaluation-corpus.md) builds on these
contracts with deterministic success and failure fixtures, expected
classifications, safe actions, and redaction assertions.

## Durable history

`manager.record_store.LoopRecordStore` persists every operation, progress
transition, health observation, event, incident, approval, and sanitized trace
in a local SQLite database. Each append is committed atomically with full
synchronous durability. SQLite's write-ahead log recovers committed records
after restart and discards interrupted transactions. Concurrent processes are
serialized with a bounded 30-second busy timeout.

The database and its parent directory are restricted to the manager account
(`0600` and `0700`). Deployments should place it in the manager's protected
state directory; it must not be placed in the repository, a shared directory,
or a Kubernetes ConfigMap. The store does not read external paths.

Retention defaults to 10,000 records of each kind and 30 days. Both positive
limits can be reduced with `RetentionPolicy`; pruning happens in the same
transaction as an append and is independent for every kind. Operators should
back up the SQLite database and its WAL consistently before upgrades when
history must be retained beyond this window. This history is diagnostic
evidence, not a backup of Fortify application data.

Sanitization runs on a deep copy before contract validation and before a
transaction begins. Sensitive keys are omitted; recognizable credentials,
private-key material, and protected absolute paths are replaced with
`[REDACTED]`. The strict schemas then reject unknown or malformed content.
Malformed rows encountered after startup are atomically removed from active
history and recorded in a metadata-only quarantine table; their unsafe payload
is not copied.

Storage schema changes are ordered in the `schema_migrations` table. Migration
1 creates append-only history; migration 2 adds metadata-only quarantine.
Migrations run once under an exclusive writer transaction. A downgrade is not
supported: restore the pre-upgrade database backup with the older manager
version. Contract-breaking changes still require a new contracts directory
and an explicit record adapter.
