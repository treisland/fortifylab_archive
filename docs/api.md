# Manager API reference

The local Fortify Lab Manager exposes a versioned component
inventory at `GET /api/v1alpha1/components` and the selected tested-platform
contract at `GET /api/v1alpha1/platform-profile`. The CLI consumes the same
profile endpoint with `fortify-manager-cli ... profile`. `HEAD` is also supported.
Mutation methods are rejected with `405 Method Not Allowed`. This contract is
MicroK8s-first, limited to the managed `fortify` namespace, and excludes ASPM.

The authenticated mutation transport used by both Web and CLI clients uses
the service documented in
[Typed lifecycle operation engine](operations/lifecycle-engine.md). No
live-cluster adapter is enabled by this repository. It accepts component and
operation identifiers only; commands, paths, environment values, and secrets
are outside the contract.

## Effective capability API

`GET /api/v1alpha1/capabilities` returns the authenticated
`ManagerCapabilities` contract used by the Web header and every mutation
control. It covers observation, functional health, lifecycle execution,
approvals, backup/restore, upgrades, write-only secret workflows, and
notifications. States are `available`, `disabled`, `not-configured`,
`unauthorized`, `degraded`, and `temporarily-unavailable`; entries separately
declare inspection and mutation support and contain only safe reason,
prerequisite, remediation, and documentation codes.

Contract `1.0` is refreshed every 30 seconds and expires after 45 seconds.
Clients must fail closed for missing, malformed, expired, unknown, or newer
contract versions. Read-only inventory, health, history, and retained operation
progress remain inspectable when mutation support is unavailable. See
[Effective Manager capabilities](manager-capabilities.md) and its
[`manager-capabilities.schema.json`](../registry/schemas/manager-capabilities.schema.json).

## Lifecycle operation API

All routes require a server-side authenticated session and return
`Cache-Control: no-store`. Browser sessions have the `web` identity source;
sessions established with `{"client":"local-cli"}` have the `local-cli`
source. The client value is accepted only as part of successful password
authentication and is persisted in the server-side session. It does not
bypass authorization or approvals.

| Method and path | Result |
| --- | --- |
| `POST /api/v1alpha1/operations/plans` | Resolve ordered steps, dependency impact, risk, approval requirement, destructive boundary, bounds, and verification checks |
| `POST /api/v1alpha1/approvals` | Create a pending single-use approval for the exact plan and current state |
| `POST /api/v1alpha1/approvals/{id}/approve` | Approve from the bound session; high risk requires the documented phrase |
| `POST /api/v1alpha1/operations` | Queue a typed action with `operation`, `components`, and optional `approvalId` |
| `GET /api/v1alpha1/operations/{id}` | Read durable progress, sanitized events, and completion health |
| `POST /api/v1alpha1/operations/{id}/cancel` | Request cooperative cancellation |
| `POST /api/v1alpha1/operations/{id}/retry` | Retry failed, timed-out, or interrupted work |
| `POST /api/v1alpha1/clean-install/plan` | Refresh preflight and detect allow-listed workloads/PVCs for the complete selected profile |
| `POST /api/v1alpha1/clean-install` | Recheck all gates, then queue the complete dependency-ordered profile install |

For example, `{"operation":"start","components":["scancentral-sast"]}`
resolves MySQL and SSC dependency steps without exposing adapter paths.
Every lifecycle plan step includes `recoveryClass`: `reversible`,
`compensating-action`, `restore-required`, or `irreversible`. The plan's
`recoveryBoundary` is the strongest class across its steps. Terminal operation
documents include `recovery.required`, `recovery.boundary`, and a sanitized
`recovery.nextAction`; completed events remain queryable after failure,
timeout, cancellation, or Manager restart.

Dependency-blocked stop plans fail before execution. Uninstall and
`delete-data` are separate actions. A capability is supported only when the
component registry declares it; `configure` therefore fails closed until an
approved bounded capability exists.

The clean-install routes take only `{}`. The plan is ready only when every
preflight requirement passes and every registered component workload and
retained PVC is absent. Submission repeats those observations to close the
plan/execution race. Existing resources or data return
`EXISTING_INSTALLATION`; unavailable or failing readiness evidence returns
`PREFLIGHT_BLOCKED`. A new install never adopts or overwrites existing state.
After interruption, retry the durable operation ID. Retry skips steps with a
recorded `step-succeeded`/`step-resumed` event and re-enters only the
idempotent incomplete step and its remaining dependents. Each executed step
still completes only after all registry-declared application and functional
checks pass.

The internal [write-only secret service](operations/write-only-secrets.md)
defines a separate high-risk replacement contract for approved external
paths, protected uploads, existing Kubernetes Secret references, and generated
values. It returns only `SecretUpdate` metadata and remains separate from the
lifecycle routes; this change adds no browser secret-value endpoint.

Successful lifecycle plan, approval, and operation documents carry
`"apiVersion":"fortifylab.io/v1alpha1"`. Error responses use the same version,
`"kind":"Error"`, a stable code, and a sanitized message; their schema is
[`api-error.schema.json`](../registry/schemas/api-error.schema.json).
Clients must branch on the code or operation state rather than message text.

## Local CLI automation

The installed `fortify-manager-cli` is a narrow HTTP client for exactly the
plan, approval, submit, status, wait, cancel, and retry routes above. It never
executes an input as a shell command and has no command, path, environment, or
secret-value option. It prints one compact JSON document to standard output.
Passwords are prompted without echo by default; automation may provide one
line on standard input with `--password-stdin`. Do not place passwords in
arguments, scripts, or environment variables.

Plan and run a routine operation:

```bash
fortify-manager-cli --url https://lab.fortifydemo.com --username operator \
  plan start scancentral-sast
fortify-manager-cli --url https://lab.fortifydemo.com --username operator \
  submit start scancentral-sast --wait 1200
```

Inspect and run a complete clean install:

```bash
fortify-manager-cli --url https://lab.fortifydemo.com --username operator \
  clean-install-plan
fortify-manager-cli --url https://lab.fortifydemo.com --username operator \
  clean-install --wait 7200
```

The returned operation ID remains queryable after CLI or browser disconnect.
The Web UI renders the same step counts and sanitized events. Recent history,
including clean-install state and step counts, is also the source used by the
private Telegram `/history` status command.

For a disruptive or high-risk action, `submit --request-approval` requests
and approves the exact plan in the same authenticated session before
submitting it. High-risk approval requires `--confirm-high-risk`; the server
still validates freshness, actor, session, current state, and single use.

```bash
fortify-manager-cli --url https://lab.fortifydemo.com --username operator \
  submit uninstall scancentral-dast-scanner --request-approval \
  --confirm-high-risk --wait 900
```

The lower-level `approval-request`, `approve`, and `--approval-id` commands
exist for clients that retain one authenticated `OperationClient` session.
Separate CLI processes intentionally cannot replay a session-bound approval.

CLI exit statuses are stable:

| Status | Meaning |
| --- | --- |
| `0` | Request accepted, nonterminal status returned, or operation succeeded |
| `20` | Request or approval rejected |
| `21` | Plan blocked by component dependencies |
| `22` | Operation failed or was interrupted |
| `23` | Operation was cancelled |
| `24` | Operation or client-side bounded wait timed out |
| `25` | Manager unavailable or response invalid |

A client-side wait timeout does not cancel server-side work. Recover by
querying the durable operation ID, then explicitly cancel or retry according
to its state:

```bash
fortify-manager-cli --url https://lab.fortifydemo.com --username operator \
  status OPERATION_ID --wait 300
fortify-manager-cli --url https://lab.fortifydemo.com --username operator \
  cancel OPERATION_ID
fortify-manager-cli --url https://lab.fortifydemo.com --username operator \
  retry OPERATION_ID --wait 1200
```

The endpoint is a safe projection of the authoritative
[`registry/components.json`](../registry/components.json). It never returns
secret values or names, credentials, licenses, registry adapter paths,
configuration paths, persistent-volume paths, logs, or Kubernetes client
details.

`observation` always includes `state` and `latencyMs`. With live evidence it
also contains the sanitized single-node name, fixed namespace, Kubernetes
version, `observedAt`, and `ageSeconds`. Observation failures do not hide
desired inventory or produce a 503: resources become `unknown` and the
observation state becomes `unavailable`. A malformed registry remains a
sanitized `503 REGISTRY_UNAVAILABLE`.

Dependency-aware runtime health is exposed at `GET /api/v1alpha1/health`
using the same read-only method policy. Its explicit states, layered dependency
order, freshness semantics, safe evidence, and remediation catalog are
documented in [Dependency-aware health checks](health-checks.md). The response
schema is
[`registry/schemas/health-report.schema.json`](../registry/schemas/health-report.schema.json).

Deployment readiness is exposed at `GET /api/v1alpha1/preflight`. It performs
fresh, read-only checks for host capacity, MicroK8s and required addons,
storage, ingress, DNS/TLS, external-license readability, registry
authentication, pinned-image reachability, configuration, and platform
compatibility. The response fails closed, classifies blockers, warnings, and
information, and gives safe remediation for every blocker. Execution and
interpretation are documented in
[Deployment preflight](deployment-preflight.md); its schema is
[`registry/schemas/preflight-report.schema.json`](../registry/schemas/preflight-report.schema.json).

Profile transition planning uses
`POST /api/v1alpha1/profile-upgrades/plans`; submission and status use
`POST /api/v1alpha1/profile-upgrades` and
`GET /api/v1alpha1/profile-upgrades/{operationId}`. The corresponding local
CLI commands are `upgrade-plan`, `upgrade-profile`, and `upgrade-status`.
These routes fail closed unless the manager composition supplies the dedicated
service. See [Profile-aware upgrades](operations/profile-upgrades.md) for the
evidence, confirmation, Telegram, verification, and recovery contract.
Upgrade plans also contain ordered `steps`, each step's `recoveryClass`, and
the aggregate `recoveryBoundary`. Upgrade status retains sanitized `evidence`
and a `recovery` object with the bound backup ID and verification state.

Recent sanitized manager records are exposed at
`GET /api/v1alpha1/history`. The response is an `OperationHistory` document
with at most 20 newest-first items. Each item is limited to `id`, `kind`,
`state`, `summary`, `subject`, and `occurredAt`; persistence sanitization is
applied again before projection. An empty history is a successful response
with an empty `items` array. The response schema is
[`registry/schemas/operation-history.schema.json`](../registry/schemas/operation-history.schema.json).

The integrated [Web dashboard](web-dashboard.md) requires a server-side
session for every API endpoint above. `POST /api/v1alpha1/session` establishes
that session and `DELETE` removes only the requesting session. The
unauthenticated `GET /ready` response contains only `{"state":"ready"}`.
The low-level `ManagerAPI` remains transport-composable; `DashboardApp`
enforces authentication and same-origin browser security at the runtime
boundary.

The machine-readable response contract is
[`registry/schemas/component-inventory.schema.json`](../registry/schemas/component-inventory.schema.json).

## Response

```json
{
  "apiVersion": "fortifylab.io/v1alpha1",
  "kind": "ComponentInventory",
  "observation": {"state": "available"},
  "items": [
    {
      "identity": {"id": "mysql", "displayName": "MySQL"},
      "version": {
        "chart": "9.19.0",
        "images": {"database": "8.0.36-debian-11-r2"}
      },
      "dependencies": [],
      "desiredState": {
        "state": "present",
        "resources": [
          {
            "id": "mysql/database",
            "kind": "StatefulSet",
            "name": "mysql",
            "namespace": "fortify"
          }
        ]
      },
      "observedResources": [
        {
          "id": "mysql/database",
          "kind": "StatefulSet",
          "name": "mysql",
          "namespace": "fortify",
          "state": "present"
        }
      ]
    }
  ]
}
```

`version` contains the desired evaluation-bundle chart and image pins, not a
claim that a running resource has that version. `dependencies` contains stable
component IDs and represents the complete MySQL → SSC → ScanCentral SAST and
PostgreSQL/LIM (plus SSC) → ScanCentral DAST paths.

Each observed resource state is one of:

- `present`: the allow-listed resource was observed;
- `absent`: the cluster was queried successfully and the resource was not
  found; or
- `unknown`: current presence could not be determined.

When the component-inventory cluster adapter is unavailable or times out, the request still
returns the desired inventory with `observation.state` set to `unavailable`
and every observed resource set to `unknown`. It does not report those
resources as absent. A malformed or unavailable registry returns `503` with
the sanitized code `REGISTRY_UNAVAILABLE`.

The manager runtime and authentication boundary is documented in the
[manager runtime boundary](manager-runtime-boundary.md). This module defines
the inventory WSGI contract; listener setup and authenticated session serving
remain separate manager integration work.

## Communications consumer

The private mobile adapter consumes manager read models through
`GET /api/v1alpha1/summary`, `/health`, `/preflight`, `/incidents`, and
`/history`. It uses bounded `page` and `pageSize` query values and never falls
back to direct Kubernetes access. The provider-neutral response mapping,
expected fields, failure behavior, and Telegram command surface are documented
in [Private Telegram manager observability](operations/telegram-observability.md).

These read models retain the manager API's authorization and disclosure
boundary. In particular, health supplies authoritative dependency/root-cause
relationships, freshness, sanitized evidence, and safe remediation; adapters
must not infer those values by querying workloads themselves.
# Recovery API

Authenticated local Web UI and CLI clients use:

- `POST /api/v1alpha1/recovery/backup/plan`
- `POST /api/v1alpha1/recovery/backups`
- `POST /api/v1alpha1/recovery/restore/plan` with `backupId`
- `POST /api/v1alpha1/recovery/restores` with `backupId` and the exact typed
  confirmation
- `GET /api/v1alpha1/recovery/operations/{id}`
- `POST /api/v1alpha1/recovery/operations/{id}/cancel`

Requests never accept commands, paths, environments, Secret values, or
destination credentials. See the
[operator recovery guide](operations/backup-restore.md).
