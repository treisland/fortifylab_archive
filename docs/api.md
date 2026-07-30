# Manager API reference

The local Fortify Lab Manager exposes a versioned, read-only component
inventory at `GET /api/v1alpha1/components`. `HEAD` is also supported.
Mutation methods are rejected with `405 Method Not Allowed`. This contract is
MicroK8s-first, limited to the managed `fortify` namespace, and excludes ASPM.

The endpoint is a safe projection of the authoritative
[`registry/components.json`](../registry/components.json). It never returns
secret values or names, credentials, licenses, registry adapter paths,
configuration paths, persistent-volume paths, logs, or Kubernetes client
details.

Dependency-aware runtime health is exposed at `GET /api/v1alpha1/health`
using the same read-only method policy. Its six states, layered dependency
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
