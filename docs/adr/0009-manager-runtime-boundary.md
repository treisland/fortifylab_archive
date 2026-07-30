# ADR 0009: Define the minimum manager runtime boundary

- Status: Accepted
- Date: 2026-07-30

## Context

The 0.2 observable-manager vertical slice needs one runtime boundary before
API, persistence, Kubernetes, and Web UI work can be implemented safely.
Putting every concern in a browser, granting the manager broad cluster
credentials, or copying SSC-owned state into a new database would make a
read-only lab interface a privileged second control plane.

The first target is one host-local, single-node MicroK8s lab. The slice must expose
useful status and history without claiming production, remote, multi-cluster,
or ASPM support and without enabling browser-initiated lifecycle mutations.

## Decision

Run one manager service as the trust boundary between untrusted HTTP clients
and trusted local adapters. For 0.2 it serves the read-only Web UI and a
read-only HTTP API from the same origin, coordinates observations, and owns
local manager state. The browser never receives Kubernetes credentials,
database access, filesystem paths, adapter handles, or a generic command
facility.

The manager core depends on technology-neutral, versioned contracts for
component inventory, health observations, operation history, and sanitized
errors. HTTP, SQLite, SSC, and Kubernetes are adapters around those contracts,
not domain types. Contract versions appear in both the URL
(`/api/v1alpha1`) and representation (`apiVersion`). Incompatible changes use
a new version and a documented migration or compatibility interval; fields
are not silently repurposed.

### API boundary

The 0.2 domain API permits only `GET` and `HEAD` for:

- service readiness and version metadata;
- the manager-supported component catalog;
- current and recent component health;
- manager-owned operation history and sanitized event details; and
- bounded, freshness-labelled, derived SSC status needed for display or
  health verification.

The sole non-read authentication exception is `POST /api/v1alpha1/session`,
which accepts credentials to establish a session, never returns them, and is
rate limited and excluded from request-body logging. Session deletion may use
`DELETE` only on that authenticated client's session. All other methods fail
closed. There is no raw Kubernetes proxy, arbitrary query, shell command,
filesystem path, secret-reveal endpoint, or browser-triggered install,
configure, start, stop, scale, upgrade, uninstall, or data-deletion operation.
Responses use explicit schemas, bounded pagination, stable identifiers,
timestamps, provenance, and sanitized error codes. Unknown response fields
may be added within an alpha version, but clients must not depend on
undocumented fields.

Secret values, credentials, authorization headers, cookies, licenses,
private keys, certificate key material, environment dumps, and external
configuration paths cannot appear in any success or error representation.
Secret status is limited to non-sensitive metadata allowed by ADR 0005.

### Persistence boundary

Use one manager-owned SQLite database on the local host with restrictive file
permissions, single-writer migrations, transactional writes, and a recorded
schema version. It stores component/profile references, health observations,
operation and approval history, sanitized events, and minimal derived-cache
metadata with source, freshness, and retention information.

It does not store secret values, Kubernetes credentials, SSC credentials,
licenses, raw support bundles, or SSC-owned applications, versions, findings,
audit decisions, or reports. Database backup protects manager history only;
it is not an SSC or workload-data backup. Schema changes are forward
migrations with a tested backup/restore or explicit rollback boundary before
upgrade support is claimed.

### Authentication and Web UI boundary

The manager serves static UI assets and the API from one origin. The
supported remote-lab listener binds all host interfaces on a configurable
private backend port, default 8080, so the host's MicroK8s nginx ingress can
reach it. That backend is not a browser route and must not be allowed by the
AWS Security Group. MicroK8s ingress is the only supported browser entry
point, terminates TLS on port 443 for `lab.$DOMAIN`, and reuses the existing
mkcert wildcard certificate Secret. Operators restrict 443 to a controlled
IP or VPN CIDR. This remains privately trusted lab TLS and makes no public
Internet or production-security claim.

Every non-readiness API request requires an authenticated, server-side
session. An operator bootstraps the first local account outside the browser;
password verifiers, not plaintext passwords, are stored in manager state.
Session cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` whenever TLS is
used, have bounded idle and absolute lifetimes, and are rotated at login.
Authentication failures are generic, rate limited, and audited without
credentials. Read-only authorization is enforced by the API even if the UI
hides controls. Cross-origin API access is disabled by default, and the UI
uses a restrictive content security policy.

The readiness endpoint returns only a coarse service state and no component,
configuration, identity, or error detail. A later write-capable interface
requires a separate accepted security decision and is not implied by this
session model.

### Kubernetes permission boundary

Use a dedicated ServiceAccount bound only in the managed `fortify` namespace.
The Kubernetes adapter receives a typed, allow-listed read interface. Its
minimum Role allows `get`, `list`, and `watch` only for the workload and
configuration metadata needed for observation:

- core `pods`, `persistentvolumeclaims`, `services`, `endpoints`, `events`,
  and `configmaps`;
- `apps` `deployments`, `statefulsets`, and `replicasets`;
- `batch` `jobs`; and
- `networking.k8s.io` `ingresses`.

The Role grants no access to `secrets`, pod logs, pod exec/attach/port-forward,
service-account token resources, RBAC objects, nodes, namespaces,
PersistentVolumes, admission resources, or mutation verbs. It is neither a
ClusterRole nor bound outside the managed namespace. MicroK8s discovery and
addon preflight that require host or cluster-scoped access remain separate
operator-side adapters; they do not broaden the manager ServiceAccount.
Future operations must add narrowly scoped permissions with their
implementation and tests rather than pre-granting write access.

### Ownership and implementation order

SSC remains the application-security system of record under ADR 0008. The
manager may retain only bounded derived SSC metadata and never becomes an
alternate findings or audit database.

Follow-up implementation stays in ordered GitHub issues: first freeze
contracts and persistence migrations; then build the read-only core and
adapters; then add least-privilege manifests and static permission tests; then
add authentication and same-origin API/UI serving; finally integrate and
validate the observable vertical slice. Later issues may depend on earlier
contracts, but cannot weaken this boundary implicitly.

## Considered alternatives

### Run the manager inside MicroK8s

This simplifies in-cluster identity, but couples recovery and observation to
the cluster being healthy and encourages cluster-scoped discovery
permissions. A local host service is the smaller first failure domain.

### Use an in-browser Kubernetes or SSC client

Direct clients remove a server hop but expose powerful credentials and vendor
contracts to an untrusted execution environment. They also make redaction,
authorization, and audit behavior difficult to enforce consistently.

### Use a client/server database immediately

PostgreSQL could support concurrency and remote deployment, but 0.2 has one
local manager writer. It adds credentials, lifecycle, backup, and network
boundaries without a demonstrated need.

### Reuse SSC as the manager database

This avoids another file but mixes manager operational state with
application-security state, complicates SSC upgrades and recovery, and
violates system-of-record ownership.

### Grant broad Kubernetes read access

Cluster-wide `view` is easy to configure but exposes unrelated namespaces and
may include data the manager does not need. A resource and namespace
allow-list makes accidental scope growth visible in review.

### Defer authentication because the API is read-only

Health, versions, topology, and operation history are still sensitive lab
metadata. Loopback binding reduces exposure but does not replace identity for
local users or explicitly proxied access.

## Consequences

- One process and one local database are sufficient for the 0.2 slice.
- Core contracts can be tested without HTTP, SQLite, SSC, or Kubernetes.
- The Web UI cannot perform lifecycle operations in 0.2.
- Observation may be incomplete when data would require secrets, logs, or
  cluster-scoped permissions; the API reports `unknown` rather than silently
  escalating.
- SQLite limits concurrent writers and does not establish a multi-host
  availability model.
- Same-origin serving and server-side sessions reduce the initial browser
  attack surface but require secure bootstrap, expiry, and proxy guidance.
- Adding an observed resource or write operation requires explicit contract,
  RBAC, test, and documentation changes.

## Security and operational implications

The manager is sensitive local infrastructure even though it is read-only.
Adapters validate and sanitize at ingress and egress, use bounded timeouts,
and return typed failures. Logs and persisted records use the same
non-disclosure rules as API responses. Database and session files are
manager-user readable only; backups inherit those protections.

Compromise of the manager ServiceAccount is bounded to enumerating the listed
metadata in one namespace. It cannot retrieve Kubernetes Secrets or mutate
workloads. Operators compare deployed RBAC with the allow-list during
validation. No live-cluster access is required to validate the contract
statically.

## Compatibility and migration

The host installation keeps protected configuration and manager-owned state
outside the installed release. Reinstallation and program upgrades preserve
account verifiers and history. Manager schema changes are forward migrations;
program rollback does not imply database rollback and requires a matching
pre-upgrade backup after a schema change. Uninstall and state deletion remain
separate operations. The installation imports no secret material and never
rotates the existing mkcert trust root.

API and database schema versions start at `v1alpha1`. Alpha compatibility may
change only through explicit versioning and migration notes. Production,
multi-cluster, public Internet, write-capable browser, and ASPM support
require new decisions and validation rather than configuration switches.

## Related decisions

- [ADR 0002](0002-technology-neutral-control-loops.md)
- [ADR 0003](0003-microk8s-first-scope.md)
- [ADR 0004](0004-component-registry.md)
- [ADR 0005](0005-write-only-secrets.md)
- [ADR 0008](0008-ssc-system-of-record.md)
