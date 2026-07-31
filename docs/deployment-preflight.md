# Deployment preflight

The authenticated Manager runs the Kubernetes-observable subset through its
protected read-only observer. MicroK8s version, StorageClasses, Services, and
Ingresses use live evidence. Checks requiring host capacity, addon discovery,
license or registry credentials, image pulls, TLS contents, or external
configuration remain warnings because the observer is intentionally unable to
read Secrets, arbitrary files, or execute commands. Loss of Kubernetes access
is a sanitized blocker for observable checks and is retried on the next
request.

`GET /api/v1alpha1/preflight` tells an authenticated user whether the
single-node MicroK8s lab is ready for deployment. Run it immediately before a
deployment operation. It is a read-only, repeatable observation: it does not
install MicroK8s, enable addons, create namespaces or Secrets, pull images,
write files, rotate certificates, or otherwise repair a failure.

```text
GET /api/v1alpha1/preflight
```

`HEAD` is supported. Other methods return `405 Method Not Allowed`. Responses
use `Cache-Control: no-store`, and every request makes fresh adapter calls.
Repeating the request after remediation therefore reports recovery without
retaining a previous failure.

## Clean-install gate

The authenticated clean-install plan (`POST
/api/v1alpha1/clean-install/plan` with `{}`) embeds a fresh copy of this
report and adds a metadata-only scan for every registry-declared workload and
retained PVC. `ready` is false if either evidence source is incomplete, any
preflight item is a blocker, or an existing footprint is found. Submission
repeats both checks immediately before durable work is queued.

Do not delete a reported footprint merely to satisfy this gate. Determine
whether it is an active installation or retained lab data and use the
documented uninstall and separately approved data-deletion workflows. Only a
retry of the original interrupted clean-install operation may resume partial
work; it uses durable successful-step evidence and never treats arbitrary
existing resources as resumable ownership.

Completion evidence is stronger than pod readiness. Each dependency-ordered
component install must pass every verification check declared in the
component registry, including application endpoints, authenticated database
queries, connectivity, and registration checks where applicable. A fresh
single-node run is live evidence only when its sanitized operation document
is successful and the documented HTTPS endpoints are independently
accessible. Repository validation does not make that claim.

The manager core passes only typed, allow-listed check IDs and safe logical
targets to its runtime adapter. The adapter returns only a typed state; all
display text is fixed by the manager. License contents, license paths, passwords,
tokens, registry authorization, private keys, configuration values, raw
command output, and response bodies are never report evidence. An adapter that
is unavailable, times out, or cannot produce safe evidence creates an
actionable blocker; it is never treated as a pass.

## Interpretation

The top-level `ready` value is `true` only when there are no blockers.
`summary` counts all classifications:

| Classification | Meaning |
| --- | --- |
| `blocker` | Deployment must not begin. The item includes safe remediation. |
| `warning` | Deployment may begin, but the reported risk should be reviewed. |
| `information` | The required condition passed. |

`status` records the adapter result as `fail`, `warning`, or `pass`.
`evidence.source=runtime-adapter` means a configured adapter made the
observations. `unavailable` means the manager had no adapter and the report
fails closed. Repository tests and rendered configuration are not live
preflight evidence.

The report deliberately does not include a mutation link or retry action.
Correct the condition through the documented operator workflow and issue a
new `GET`.

## Checks and remediation

### host-capacity

Confirm the host has free CPU, memory, and disk for the documented evaluation
bundle, including image storage and persistent database data. Stop unrelated
workloads or increase host capacity, then rerun preflight. Capacity inspection
must not evict workloads or resize storage.

### microk8s

Confirm the supported MicroK8s installation is present, running, and usable by
the manager's configured adapter. Install or start it through the documented
host workflow. Preflight does not start services or change cluster state.

### microk8s-addons

Confirm the required DNS, storage, ingress, Helm, and registry addons are
enabled and ready. Enable missing addons explicitly before deployment, then
rerun preflight.

### storage

Confirm a writable default storage class exists and has sufficient capacity
for MySQL, PostgreSQL, SSC, LIM, and DAST data. Correct provisioning or
capacity problems without deleting existing persistent claims.

### ingress

Confirm the MicroK8s ingress controller can bind its required ports and is
ready. Resolve host port conflicts or enable the ingress addon before
deployment.

### dns

Every managed hostname must resolve to the lab node from the clients and
in-cluster consumers that use it. Correct the configured DNS or hosts entries
and rerun preflight. The report exposes neither internal resolver output nor
configuration paths.

### tls

Confirm the managed-host certificate covers the configured names, is within
its validity period, chains to the intended trust root, and is readable by its
authorized consumer. Generate or configure the certificate through the
documented TLS workflow. Never submit private key material as diagnostic
evidence.

### external-license

Configure the Fortify license through `FORTIFY_LICENSE_FILE` or the documented
repository-local default. The adapter may verify existence, regular-file
type, readability, and protected permissions; it must not read content into
the report or disclose the path. Fix ownership or permissions using the
operator's protected secret workflow, then rerun preflight.

### registry-authentication

Configure credentials for every registry required by the pinned bundle using
the protected registry-authentication workflow. The adapter may perform a
bounded authentication check but must never return credentials,
authorization headers, tokens, or response bodies.

### image-reachability

Confirm every pinned image in the component registry is reachable and has a
compatible manifest for the lab host. Restore network/registry access or
correct the pinned bundle. A read-only manifest check is sufficient;
preflight must not pull images as proof.

### configuration

Validate required fields, hostnames, ports, storage settings, and component
dependencies against the repository's configuration contract. Correct only
the reported field class; report evidence must not contain values or external
paths.

### compatibility

Compare the registry's pins, Kubernetes/MicroK8s version, addons, architecture,
and capacity with the exact profile ID in the report. An unknown profile, pin
mismatch, version outside the range, or unsupported maturity is a blocker. The
baseline is experimental, not vendor-supported; see
[Platform profiles](platform-compatibility.md).

## Example

```json
{
  "apiVersion": "fortifylab.io/v1alpha1",
  "kind": "DeploymentPreflight",
  "generatedAt": "2026-07-30T12:00:00Z",
  "ready": false,
  "profile": {"id": "fortify-24.4-eval.1", "maturity": "experimental", "vendorSupported": false},
  "summary": {"blocker": 1, "warning": 0, "information": 11},
  "evidence": {"source": "runtime-adapter", "mode": "read-only"},
  "items": [
    {
      "id": "external-license",
      "category": "license",
      "classification": "blocker",
      "status": "fail",
      "summary": "External license is not ready",
      "latencyMs": 2,
      "remediation": {
        "summary": "Configure a readable Fortify license file with protected permissions",
        "href": "/docs/deployment-preflight.md#external-license",
        "safe": true
      }
    }
  ]
}
```

The shortened example omits the other eleven items. Actual reports always
include every check so one blocker cannot hide an unrelated condition.
