# Dependency-aware health checks

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
| `degraded` | A check warned or optional evidence failed. |
| `unhealthy` | A required check produced authoritative failure evidence. |
| `unknown` | A check timed out, failed safely, or could not be observed. |
| `blocked` | A dependency is not healthy; the downstream probe was skipped. |
| `stale` | Evidence is older than the five-minute freshness threshold. |

Each item includes timestamps, bounded latency, sanitized summaries,
root-cause fields, and a safe documentation link.
`evidence.source=live-cluster` means a runtime adapter supplied observations;
`unavailable` means no adapter was configured. Repository tests and rendered
configuration are static validation and are never live-cluster evidence.

## Safe diagnostics

### microk8s-node

Confirm the single node is schedulable and its control plane is available.

### storage

Inspect storage class, PVC phase, capacity, and safe volume events. Never
delete or recreate database claims as health remediation.

### dns

Use a bounded lookup for the allow-listed cluster service name.

### ingress

Confirm the MicroK8s ingress controller is ready and a managed host is
reachable. Resolve DNS first.

### tls

Check hostname, chain, reachability, and expiry. Never return private keys or
full certificate material.

### mysql

Check workload, PVC, native readiness, and a bounded authenticated query.
Credential values and database response bodies are not health evidence.

### postgresql

Check workload, PVC, native readiness, and a bounded authenticated query.
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
