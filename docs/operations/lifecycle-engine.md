# Typed lifecycle operation engine

The manager lifecycle engine is the shared execution foundation for
authenticated Web UI, HTTP API, CLI, and private Telegram controls. Web and
CLI callers use the same API methods and receive the same plan, approval,
progress, sanitized event, and completion-health documents. It is MicroK8s-first,
operates only on components in
[`registry/components.json`](../../registry/components.json), and excludes
ASPM. The shared [local authorization service](authorization.md) is enforced
before a configured engine calls its adapter. The authenticated Web transport
is documented in the [manager API reference](../api.md). The repository does
not expose an unauthenticated mutation route. Its local MicroK8s adapter is an
explicit composition dependency; deployments that omit it fail closed.

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

Whole-platform transitions use the stricter
[profile-aware upgrade workflow](profile-upgrades.md). Its digest additionally
binds exact profile versions, capacity, health, dependency state, backup
evidence, migrations, rollback limits, downtime, and timeout.

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

Plans classify every step and present the aggregate recovery boundary before
execution. See [Rollback and recovery boundaries](rollback-recovery.md) for
the four classes, automatic chart/config rollback rules, migration restore
gate, and disposable-lab drills.

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

## Local MicroK8s adapter

`MicroK8sLifecycleAdapter` accepts only the immutable step produced by the
engine. Before process creation it resolves the component and operation again
against the loaded registry, requires the exact repository-relative action
under `apps/`, and fixes the repository root and `fortify` namespace. It invokes
`/bin/bash` with no request arguments, discards child output, closes stdin, and
supplies only a fixed `PATH`, `FORTIFY_HOME_K8S`, `NAMESPACE`, protected
`KUBECONFIG`, and `HELM_DRIVER=configmap`. A caller cannot add commands, paths,
manifests, values, namespaces, or environment entries.

The adapter polls both cooperative cancellation and the monotonic deadline. It
terminates the action on cancellation or timeout and escalates to a kill only
after a bounded termination grace period. Exit details and child output never
enter operation events or API responses.

`RegistryHealthVerifier` independently resolves every verification ID from the
same registry and sends only the typed check identity, target, and a
deadline-capped timeout to the protected health probe. It accepts no response
bodies or credentials and returns only the pass/fail decision used by the
engine.

The lifecycle ServiceAccount manifest is separate from the observer identity
and bound only in `fortify`. It has no cluster role and no access to Secrets,
pod logs, exec, attach, port-forward, RBAC, namespaces, or persistent volumes.
Helm must use ConfigMaps for release records (`HELM_DRIVER=configmap`), while
component charts reference pre-created Secrets by name. Applying the manifest
and creating its protected kubeconfig are explicit operator steps; repository
validation never applies them.

`DashboardApp` continues to fail closed when no authorized operation service
is supplied. Production composition must provide authorization, authoritative
current state, durable stores, the lifecycle adapter, and the health verifier.

Static and fake-process tests cover dependency-ordered start, stop and restart,
dependency blocking, timeout, cancellation, adapter failure, bounded retry,
health failure, and manager restart recovery. They do not claim live-cluster
evidence; release qualification still requires a disposable lab using the
dedicated ServiceAccount.

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

The CLI maps these errors and terminal states to stable process statuses in
the [API and CLI reference](../api.md#local-cli-automation). Its JSON errors
use the same versioned, secret-safe API envelope as HTTP errors. A local CLI
wait is bounded independently and never implies that server-side work was
cancelled.
