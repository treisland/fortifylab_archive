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
slow service response becomes sanitized application-health `unknown`; it never
turns ready workload metadata into application health. Independent Kubernetes
workload checks still run. A later request performs protected checks again and
can report recovery without restarting the Manager.

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
consumers report `dimensions.dependency.state=blocked`, but their independent
workload metadata checks still run. Protected application, functional, and
dependency-connectivity probes become `unknown` until the dependency recovers.
This preserves the upstream cause without hiding an absent workload or a
desired-versus-ready replica mismatch. Eligible checks for one subject use a
fixed worker pool; the whole report shares a 30-second aggregate deadline.
When that deadline expires, unfinished checks become sanitized `unknown`
evidence and queued work is cancelled. Runtime adapters must also honor each
allow-listed check timeout because worker threads cannot forcibly interrupt an
adapter that ignores cancellation.

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
| `blocked` | A dependency is not healthy; independent workload evidence remains visible. |
| `stale` | Evidence is older than the five-minute freshness threshold. |

Each item includes timestamps, bounded latency, sanitized summaries,
root-cause fields, three independent `dimensions`, and a safe documentation
link. The dimensions use these card/inspector terms:

- `blocked by dependency`: at least one upstream dependency is not healthy;
- `workload absent`: a desired registry workload returned Kubernetes 404;
- `workload not ready`: the workload exists, desired replicas are greater than
  zero, and ready replicas are fewer than desired replicas;
- `application health unknown`: a protected probe is unavailable, blocked, or
  stale; workload readiness is never substituted.

`rootCause` is the first ranked cause for compatibility. `rootCauses` contains
the upstream cause first, followed by independent component-local actionable
failures in registry check order, without duplicates.

The top-level `summary` counts only the seven registered components, never the
five infrastructure subjects. `components` is the registered component count;
`blocked`, `workloadAbsent`, `workloadNotReady`, and `applicationUnknown` each
count components whose matching dimension has that exact state. Counts overlap
by design, so one component can increment several fields. They are computed
from the same report and are deterministic for that evidence snapshot.
`evidence.source=live-cluster` means a runtime adapter supplied observations;
`unavailable` means no adapter was configured. Repository tests and rendered
configuration are static validation and are never live-cluster evidence.

## Service availability is separate

The dashboard's curated quick links use
`GET /api/v1alpha1/availability`, not this application-health aggregate. That
bounded Manager-host probe reports DNS resolution, observed-ingress address
mismatch, TLS validation, HTTP reachability, latency, evidence time, and a
small recovery history. A successful login page, `401`, or `403` is
`reachable`; it does not show that initialization, databases, dependencies,
licenses, worker registration, or authenticated functions are healthy.

`tls-warning` means certificate validation failed without returning
certificate contents. `dns-mismatch` means resolved addresses do not intersect
the IP addresses reported by ingress metadata when those addresses are
available. `unreachable` covers DNS or connection failure, while
`not-configured` means no approved TLS ingress was observed. The Manager does
not follow redirects and reports redirects or HTTP 5xx responses as
`degraded`. See [the API reference](api.md#curated-service-availability) for
the polling and SSRF boundary.

## Functional probe contract

The supported MicroK8s installation packages
`fortify-health-probe.service`. It runs as the separate
`fortify-health-probe` identity, shares only the `fortify-manager` socket
group, and creates `/run/fortify-lab-manager/health-probe.sock` as `0660`
inside a `0750` systemd runtime directory. The Manager validates the file
type, group ownership, and exact socket mode before every connection. Functional
health becomes `available` only after a version `1.0` handshake succeeds; a
configured path alone is never capability evidence.

The probe process is the credential boundary. Optional external inputs belong
in `/etc/fortify-lab-manager/health-probe.env`, owned by
`root:fortify-health-probe` with mode `0640`. The Manager and Web UI never
read, return, or log that file. Do not place it in the repository or Manager
configuration. A missing input produces `PROBE_EXTERNAL_INPUT_NOT_CONFIGURED`;
it never falls back to pod readiness or unauthenticated reachability.

The supported input names are `FORTIFY_PROBE_DOMAIN`,
`FORTIFY_PROBE_MANAGED_HOST`, and optionally
`FORTIFY_PROBE_DNS_SERVER` (the MicroK8s service address defaults to
`10.152.183.10`); `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PWD`; and `PGHOST`,
`PGDATABASE`, `PGUSER`, `PGPASSWORD`. Host/domain values are validated as DNS
names. The service runs fixed `SELECT 1`, native readiness, HTTPS `HEAD`, TLS,
TCP, DNS, configuration, dependency, and registration operations selected by
the registry identity. It discards native-client output and never reads HTTP
response bodies. `FORTIFY_PROBE_TOKEN`, when required by an application
endpoint, is sent only as an authorization header and is never returned.

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

Handshake messages use the same framing:

```json
{"apiVersion":"fortifylab.io/v1alpha1","kind":"FunctionalHealthProbeHandshake","protocolVersion":"1.0"}
```

The only successful response has kind
`FunctionalHealthProbeHandshakeResult`, protocol version `1.0`, and status
`ready`. Missing sockets, wrong ownership/mode, stale peers, malformed or
oversized JSON, unsupported protocol versions, and timeouts fail closed.

## Probe operations

Installation enables and starts the probe before the Manager. These workflows
do not read Kubernetes Secrets, broaden observer RBAC, execute in pods, or
change Fortify data:

```bash
sudo ./scripts/fortify-manager probe-status
sudo ./scripts/fortify-manager probe-diagnose
sudo ./scripts/fortify-manager probe-restart
sudo ./scripts/fortify-manager probe-disable
```

`probe-restart` restarts the Manager afterward so a recovered handshake is
visible immediately. `probe-disable` stops and disables only functional
health; metadata observation, configuration, credentials, workloads, and
persistent data are preserved. Re-run `install` to safely re-enable the
packaged service.

Diagnostics report only service state, socket policy, and sanitized codes.
Never attach the environment file, process environment, response bodies, or
unredacted journal output to a support case. `PROBE_REQUEST_MALFORMED` means
the peer did not send an exact registry identity;
`PROBE_TIMEOUT` means the bounded operation expired;
`PROBE_TARGET_UNREACHABLE` means the fixed target could not be reached; and
`FUNCTIONAL_PROBE_HANDSHAKE_FAILED` means capability negotiation did not
succeed. Correct the external input or service state, run `probe-restart`,
then confirm recovery with `probe-diagnose`.

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
