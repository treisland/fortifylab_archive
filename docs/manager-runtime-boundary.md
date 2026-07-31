# Manager runtime boundary

The 0.2 observable-manager slice is a local, read-only control surface for one
single-node MicroK8s lab. [ADR 0009](adr/0009-manager-runtime-boundary.md) is
the authoritative decision; this page is the concise implementation
reference.

## Responsibility map

| Boundary | Manager owns | Manager does not own |
| --- | --- | --- |
| API | Versioned inventory, health, preflight, catalog, sanitized manager history | Generic commands, Kubernetes proxying, secret reveal, lifecycle mutations |
| Persistence | Local SQLite schema, manager history, health, sanitized derived-cache metadata | Secret values, Kubernetes credentials, licenses, SSC applications or findings |
| Authentication | Local account bootstrap, server-side sessions, read-only authorization | Anonymous detail APIs, cross-origin access by default, production identity federation |
| Web UI | Same-origin static assets and read-only views | Direct cluster/SSC credentials or write controls |
| Kubernetes | Typed observation through a namespace Role | Secrets, logs, exec, cluster scope, RBAC, or mutation verbs |
| Application security | Freshness-labelled derived SSC status | Applications, versions, findings, audit state, or reports; SSC remains authoritative |

The domain API is read-only. The only non-read methods are session creation
and deletion; they cannot invoke manager or cluster operations.

## Version and disclosure rules

The initial HTTP prefix and representation version are `/api/v1alpha1` and
`fortifylab.io/v1alpha1`. Incompatible API or persistence changes require a
new version and explicit migration guidance. An adapter may return a typed,
sanitized error; it may never return credentials, tokens, authorization
headers, cookies, licenses, private key material, secret values, environment
dumps, or external configuration paths.

When an observation would require forbidden access, report it as unavailable
or `unknown` with a safe reason. Do not expand permissions or read protected
data to improve a dashboard.

## Deployment posture

The supported host listener is `0.0.0.0` on private backend port 8080 by
default so MicroK8s ingress can reach it. MicroK8s nginx ingress is the only
browser-facing route and exposes `https://lab.$DOMAIN` on 443 using the
existing mkcert wildcard TLS Secret. The backend port is not opened in the
AWS Security Group. Except for coarse readiness and minimal sign-in assets,
requests use an authenticated server-side session. This is a restricted lab
posture, not a public Internet or production-security claim.

Installation, lifecycle, diagnostics, backup, rollback, and the separate
state-deletion boundary are in the
[manager operator guide](operations/manager.md).

The manager uses a dedicated ServiceAccount and a Role in only the `fortify`
namespace. Static manifests and tests must match the exact resource and verb
allow-list in ADR 0009. Live MicroK8s validation is a later integration step,
not evidence supplied by this architecture change.

The host-backed Manager Service uses `discovery.k8s.io/v1` EndpointSlice on
the supported MicroK8s profile. Layered operator diagnostics keep private
backend discovery, ingress routing, TLS, operator DNS, and external
reachability distinct. In particular, private HTTPS success is not evidence
that operator DNS or AWS exposure is correct.

## Ordered implementation

Implementation issues must preserve this dependency order:

1. versioned domain/API contracts and persistence migrations;
2. read-only manager core plus SQLite, Kubernetes, and SSC adapters;
3. namespace-scoped least-privilege manifests and permission tests;
4. local authentication and same-origin API/Web UI serving; and
5. integrated observable-slice validation and operator guidance.

Write-capable browser operations, production and multi-cluster support, and
ASPM are outside this sequence.
