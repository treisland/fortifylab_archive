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

The schemas define the portable record. A storage implementation must enforce
the state transition and atomic single-use claim under concurrency.

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
