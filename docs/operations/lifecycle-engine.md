# Typed lifecycle operation engine

The manager lifecycle engine is the shared execution foundation for future
authenticated Web UI, CLI, and private Telegram controls. It is MicroK8s-first,
operates only on components in
[`registry/components.json`](../../registry/components.json), and excludes
ASPM. This issue adds the engine contract, not an unauthenticated HTTP route or
a live-cluster adapter.

## Request contract

Callers submit only a typed operation, one or more registry component IDs, and
the authenticated actor identity. Supported request types are `install`,
`configure`, `start`, `stop`, `restart`, `upgrade`, `uninstall`, and
`delete-data`. Retry and cancel use separate typed methods with an operation ID
and actor.

Requests cannot contain a command, executable, adapter path, working directory,
environment, Kubernetes resource name, or secret. The engine resolves the
adapter, timeout, idempotency, and verification checks from the validated
registry. A component can use an operation only when it declares that
capability. Upgrade therefore fails closed until a tested platform profile
adds a bounded `upgrade` capability to every affected component.

`delete-data` remains distinct from `uninstall`. Persistent data is never
deleted as an implicit uninstall or retry side effect.

## Planning and ordering

Install, configure, start, and upgrade plans include the complete dependency
closure and execute dependencies before consumers. Stop, uninstall, and
delete-data plans execute selected consumers before dependencies. Such a plan
is rejected with `DEPENDENCY_BLOCKED` unless every affected dependent is
explicitly selected; the engine never silently expands a disruptive request.

Restart is composed from a reverse-ordered stop phase for the explicitly
selected components followed by a dependency-ordered start phase. Every
component/operation pair must exist in the registry before any step executes.
Plans whose affected component sets overlap are rejected with
`OPERATION_CONFLICT`.

## Progress, recovery, and verification

Each durable operation has an opaque ID, target set, actor, timestamps, state,
current step and attempt, completed and total step counts, retry parent, and a
sanitized error. The machine-readable response is
[`lifecycle-operation.schema.json`](../../registry/schemas/lifecycle-operation.schema.json).
Cancellation records `cancelling`; completion changes to `cancelled` only
after the adapter observes the request.

Adapter and verification work share the registry timeout, capped by the engine
maximum. Idempotent steps receive a finite retry bound; non-idempotent steps
receive one attempt. A manual retry creates a new operation linked by
`retryOf` and is accepted only for failed, timed-out, or restart-interrupted
operations.

After each mutation, every registry-declared `verify` check must succeed before
the step completes. Failed verification is a failed attempt, and no later plan
step runs after final failure. Events contain only component IDs, operation
IDs, attempt numbers, outcome flags, actors, and timestamps.

On manager startup, operations left queued, running, or cancelling are marked
`interrupted`; they are never assumed successful or resumed midway. An
authorized operator can inspect the last completed step and submit a bounded
retry.

## Runtime integration boundary

A production MicroK8s adapter must execute only the registry-resolved adapter
passed by the engine. It must not accept caller arguments, must poll
cancellation, and must stop at the monotonic deadline. A health adapter must
evaluate only the supplied component/check IDs without returning secret-bearing
evidence.

The repository does not yet wire this engine to a live adapter or expose
mutation routes. Before doing so, add authenticated authorization and
destructive-operation approval at the service boundary, narrowly scoped
MicroK8s permissions, and integration evidence against a disposable lab.

## Failure codes

| Code | Meaning |
| --- | --- |
| `INVALID_OPERATION` | Invalid request, unsupported capability, or invalid retry |
| `DEPENDENCY_BLOCKED` | A disruptive plan omitted an affected dependent |
| `OPERATION_CONFLICT` | Another active plan overlaps an affected component |
| `OPERATION_NOT_FOUND` | Retry, cancel, or lookup referenced an unknown ID |
| `OPERATION_TIMEOUT` | A step exceeded its bounded deadline |
| `OPERATION_CANCELLED` | The adapter observed cancellation |
| `OPERATION_FAILED` | Execution or post-operation health verification failed |
