# Dependency-aware health checks

The installed Manager composes Kubernetes metadata checks with a protected
local functional-probe service. Node, StorageClass, PVC, and
registry-declared workload readiness use live metadata. DNS, ingress, TLS,
native database readiness, authenticated constant queries, application
initialization/connectivity, safe license-pool presence, and worker/scanner
registration use the functional service. That service owns any required
credentials; the Manager sends only an allow-listed check identity and never
receives credentials, license data, response bodies, logs, or Kubernetes
output.

Set `cluster.health_probe_socket` to its Unix socket. The socket must not be
accessible to other users. A missing, inaccessible, malformed, oversized, or
slow service response becomes sanitized `unknown`; it never falls back to pod
state. A later request performs every unblocked check again and can report
recovery without restarting the Manager.

`GET /api/v1alpha1/health` reports actionable runtime health for the
single-node MicroK8s lab. This read-only contract never repairs resources,
reads external configuration directories, or returns credentials, licenses,
private certificate material, logs, raw responses, or Kubernetes output.

## Interpretation

Checks run from roots to consumers:

1. MicroK8s node;
2. storage and cluster DNS;
3. ingress and TLS;
4. MySQL and PostgreSQL;
5. SSC and LIM;
6. ScanCentral SAST controller/workers and ScanCentral DAST API/scanners.

Registry dependencies are preserved. When a dependency is not healthy, its
consumers are `blocked` without running their probes. The root item therefore
appears before downstream symptoms.

| State | Meaning |
| --- | --- |
| `healthy` | All required authoritative checks passed with fresh evidence. |
| `starting` | Initialization is making bounded progress but is not ready. |
| `degraded` | A check warned or optional evidence failed. |
| `misconfigured` | Required observable configuration is absent or invalid. |
| `stopped` | The desired workload is deliberately scaled to zero. |
| `unreachable` | The authoritative endpoint could not be reached. |
| `unhealthy` | A required check produced authoritative failure evidence. |
| `unknown` | A check timed out, failed safely, or could not be observed. |
| `blocked` | A dependency is not healthy; the downstream probe was skipped. |
| `stale` | Evidence is older than the five-minute freshness threshold. |

Each item includes timestamps, bounded latency, sanitized summaries,
root-cause fields, and a safe documentation link.
`evidence.source=live-cluster` means a runtime adapter supplied observations;
`unavailable` means no adapter was configured. Repository tests and rendered
configuration are static validation and are never live-cluster evidence.

## Functional probe contract

One newline-delimited JSON request is sent per check. `type`, `target`, and
timeout are copied from the validated component registry; API callers cannot
provide them.

```json
{"apiVersion":"fortifylab.io/v1alpha1","kind":"FunctionalHealthProbeRequest","check":{"id":"database-query","subjectId":"mysql","type":"database-query","target":"mysql","timeoutMs":30000}}
```

The service returns one bounded result and closes the connection:

```json
{"apiVersion":"fortifylab.io/v1alpha1","kind":"FunctionalHealthProbeResult","state":"healthy","summary":"Authenticated constant query succeeded","observedAt":"2026-07-31T12:00:00Z"}
```

The result state is one of the non-derived states in the table above
(`blocked` and `stale` are computed by the Manager).
The summary is a short classification, not captured command output. Each
service operation must honor `timeoutMs` and use a constant native command,
query, endpoint, and expected-registration definition selected by the check
identity. It must not accept shell text, paths, URLs, SQL, credentials, or
license content from the request.

## Safe diagnostics

### microk8s-node

Confirm the single node is schedulable and its control plane is available.

### storage

Inspect storage class, PVC phase, capacity, and safe volume events. Never
delete or recreate database claims as health remediation.

### dns

Use a bounded lookup for the allow-listed cluster service name. Listing a
Service is not DNS evidence.

### ingress

Confirm the MicroK8s ingress controller is ready and a managed host is
reachable through its allow-listed route. Resolve DNS first.

### tls

Check hostname, chain, reachability, and expiry. Never return private keys or
full certificate material.

### mysql

Check workload, the `data-mysql-0` PVC, native readiness, and a bounded
authenticated constant query.
Credential values and database response bodies are not health evidence.

### postgresql

Check workload, the `data-postgresql-0` PVC, native readiness, and a bounded
authenticated constant query.
Keep persistent-data recovery separate from health.

### ssc

Resolve MySQL and network roots first. Check SSC workload, HTTPS/application
readiness, and initialization without returning page bodies.

### lim

Resolve network roots first. Check the endpoint and required license/pool
configuration where observable safely.

### scancentral-sast

Resolve SSC first. Check the controller, SSC connectivity, and expected worker
registration; pod phase alone is insufficient.

### scancentral-dast-core

Resolve PostgreSQL, LIM, SSC, and network roots first. Check the API, database
schema availability, and service connectivity.

### scancentral-dast-scanner

Resolve DAST Core first. Check scanner health and API registration. Scaling is
an explicit lifecycle operation, not automatic repair.
