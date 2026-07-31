# Install and operate the 0.2 manager

This is the supported remote-lab installation for one EC2 host running
single-node MicroK8s. It exposes the authenticated manager at
`https://lab.$DOMAIN`; the default evaluation URL is
`https://lab.fortifydemo.com`. ASPM, public production hosting, multi-node
deployment are excluded. Browser-triggered component changes are available
only after the protected lifecycle activation described below.

## Network and trust boundary

MicroK8s nginx ingress is the only browser-facing entry point. In the AWS
Security Group, allow TCP 443 only from an operator-controlled IP address or
VPN CIDR. Do **not** allow TCP 8080, and do **not** use unrestricted
`0.0.0.0/0` Internet exposure. Port 8080 is a private host backend reached
only by ingress.

The route reuses the existing `tls` Kubernetes Secret containing the
mkcert wildcard certificate for `*.$DOMAIN`. Installation neither invokes
`create-certs.sh` nor generates, replaces, or rotates a CA. mkcert provides
encrypted transport with private lab trust; it is not a publicly trusted
certificate or an Internet-hardening control.

The supported EC2 model has two addresses which must not be conflated:

- the **private backend address** is the EC2 private IPv4 address used by the
  host-backed EndpointSlice (`172.31.30.41` in the current lab);
- the **public operator address** is the Elastic IP used by browser-facing DNS
  (`184.33.159.224` in the current lab).

Public DNS (or an operator workstation's temporary `/etc/hosts` entries) must
map every browser hostname to the Elastic IP:

```text
184.33.159.224  lab.fortifydemo.com ssc.fortifydemo.com
184.33.159.224  lim.fortifydemo.com sast.fortifydemo.com dast.fortifydemo.com
```

The browser must already trust this lab's existing mkcert root CA.

## Install

Run from a trusted repository checkout on the MicroK8s host:

```bash
sudo ./scripts/fortify-manager install
sudo ./scripts/fortify-manager rbac-preflight
sudo ./scripts/fortify-manager install-cluster-access
sudo ./scripts/fortify-manager bootstrap-account operator
sudo ./scripts/fortify-manager configure \
  fortifydemo.com 172.31.30.41 8080 184.33.159.224
sudo ./scripts/fortify-manager start
sudo ./scripts/fortify-manager diagnose
sudo ./scripts/fortify-manager activate-lifecycle
```

Use the lab domain and an address reachable from ingress pods, normally the
EC2 instance's private IPv4 address. The fourth argument is the public IPv4
DNS expectation; IPv6, documentation, loopback, link-local, and private
addresses are rejected in this explicit public mode. Omitting it retains the
legacy behavior of using the backend address as the DNS expectation, so existing private-only labs remain
compatible. The renderer rejects public backend addresses. `configure`
applies only the manager Service, EndpointSlice, and Ingress in namespace
`fortify` and atomically aligns `server.port` plus the `[network]` address
model in the external manager configuration; it does not alter the TLS
Secret. Restart the service after changing an existing route. It validates and server-side
dry-runs the candidate route before replacing the protected configuration; a
rejected or failed apply leaves the prior configuration and recorded manifest
intact. Render without contacting MicroK8s using:

```bash
./scripts/fortify-manager render-ingress \
  fortifydemo.com 10.0.0.10 8080 /tmp/manager-ingress.yaml
```

Kubernetes versions supporting `discovery.k8s.io/v1` use EndpointSlice and do
not query deprecated core Endpoints. If API discovery proves EndpointSlice is
unavailable, `configure` emits a warning and renders the legacy Endpoints
compatibility manifest. For offline rendering only, an operator targeting
such an older cluster may set `FORTIFY_MANAGER_ENDPOINT_API=legacy`. Do not
use that override on the supported MicroK8s profile.

The manager listens on `0.0.0.0:8080` so ingress can reach it. This does not
authorize direct browser access to 8080.

## Configuration, state, and authentication

| Path | Purpose | Reinstall behavior |
| --- | --- | --- |
| `/etc/fortify-lab-manager/manager.toml` | Versioned protected listener, state, observer, and lifecycle references | Created once; operator values are preserved while missing safe defaults are migrated |
| `/var/lib/fortify-lab-manager/accounts.json` | PBKDF2 password verifiers only | Preserved |
| `/var/lib/fortify-lab-manager/history.sqlite3` | Schema-versioned manager history | Migrated in place and preserved |
| `/var/lib/fortify-lab-manager/cluster-access/lifecycle.kubeconfig` | Dedicated namespace lifecycle credential; mode `0600` | Created only by verified activation; never committed or returned to the browser |
| `/etc/fortify-lab-manager/health-probe.env` | Optional probe-only external credential inputs; `root:fortify-health-probe`, mode `0640` | Operator managed; never read by the Manager or Web UI |
| `/run/fortify-lab-manager/health-probe.sock` | Versioned functional-health socket; `fortify-health-probe:fortify-manager`, mode `0660` | Recreated by systemd/service startup |
| `/opt/fortify-lab-manager/releases` | Immutable content-addressed builds | Identical build reused; changed content added under a new identity |
| `/opt/fortify-lab-manager/current` | Active release symlink | Updated atomically |

`bootstrap-account` requires a TTY, never accepts a password on the command
line, and atomically stores only the verifier with mode `0600`. The service
runs as unprivileged user `fortify-manager`. Other than coarse `/ready` and
minimal sign-in assets, content fails closed without a valid server-side
session. Cookies are always `HttpOnly`, `SameSite=Strict`, and `Secure`.

Accounts and history survive service and host restarts. In-memory sessions
are deliberately invalidated by a manager restart, so users sign in again.
Re-running `install` does not overwrite external configuration, accounts, or
history. It does validate and, when necessary, migrate the configuration as
described below.

### Protected configuration migration

`manager.toml` uses the top-level `schema_version` field. The current version
is `1`; an existing unversioned file is the supported version `0`. Installation
and upgrade reject malformed, ambiguous, invalid, or newer unknown schemas
before replacing the configuration.

A migration preserves all existing listener, storage, authentication,
observer, lifecycle, recovery, custom values, and comments. It only adds
missing safe defaults. `lifecycle.enabled` is added as `false`. The `[cluster]`
observer defaults are added only when both
`cluster-access/token` and `cluster-access/ca.crt` are nonempty regular files,
the directory and files are owned by `fortify-manager:fortify-manager`, the
directory is mode `0700`, and both files are mode `0600`. Existing cluster
values are never replaced.

Before a changed candidate becomes active, the command parses and validates
it and writes a mode-`0600` backup below
`/var/lib/fortify-lab-manager/config-backups`. The candidate is then written
with owner `root:fortify-manager`, mode `0640`, and atomically renamed over the
active file. A failed validation or replacement leaves the original active.
Re-running migration after success makes no further change or backup.

Use the local, sanitized configuration operations:

```bash
sudo ./scripts/fortify-manager config-inspect
sudo ./scripts/fortify-manager config-migrate
sudo ./scripts/fortify-manager config-diagnose
sudo ./scripts/fortify-manager config-rollback \
  /var/lib/fortify-lab-manager/config-backups/manager.toml.schema-0.TIMESTAMP.bak
```

Inspection and diagnostics report only schema and capability status. They do
not print configuration values, tokens, CA content, passwords, verifiers, or
database content. Rollback accepts only a regular mode-`0600` backup owned by
`root:fortify-manager` within the protected configuration-backup directory;
it validates that document before atomic replacement. Restart and diagnose
the Manager after an explicit rollback.

### Verified runtime packaging

Installation is assembled beneath `releases/.candidate-*` from the explicit
[`manager-runtime.json`](../../packaging/manager-runtime.json) manifest. The
manifest closes over Manager imports, contracts, lifecycle adapters, registry
schemas, platform profiles and evidence, Web UI assets, MicroK8s templates,
the systemd unit, and the default external configuration template. The staged
candidate records its exact file inventory and is rejected if any file is
missing, is a symlink or special file, escapes the candidate root, or has a
mode outside the packaging policy.

Directories, lifecycle shell adapters, and generated Manager launchers use
mode `0755`; ordinary code, schemas, profiles, assets, and templates use mode
`0644`. The authoritative component registry is loaded from the staged root
before its release symlink can become active, so every declared adapter must
resolve to a regular file inside that root.

Every validated candidate receives the release identity
`build-<sha256>`. The digest covers every path, file byte, file type, and
policy mode; it is independent of the marketing version in `VERSION`. An
existing directory at that exact identity is reused only when validation and
the full digest are identical. Missing, modified, or mode-changed content is
an immutable-release collision and is never repaired or overwritten in
place. Thus rerunning the same checkout is idempotent while a changed checkout
always publishes a distinct release.

The `current` link is changed by creating a sibling link and renaming it over
the active link in one filesystem operation. A regular file or directory at
`current` is not overwritten. External configuration, accounts, history,
observer and lifecycle material, and backup trees remain outside releases and
are not part of activation.

`rbac-preflight` is read-only. It compares the desired authorization mode in
the MicroK8s API-server arguments with the running control-plane process. It
reports `restart-required` when the arguments were changed after that process
started. An unreadable arguments file, missing process evidence, or any other
ambiguous state is rejected.

`install-cluster-access` first disconnects any active Manager observer
credential. It then applies the dedicated observer ServiceAccount and
least-privilege RBAC, proves the complete allow-list, and proves denial of
Secrets, pod logs, and Services outside `fortify`. Only after every check
passes does it atomically activate that identity's token and cluster CA
into `/var/lib/fortify-lab-manager/cluster-access` with mode `0600`. The
runtime reads Kubernetes metadata over HTTPS and never invokes `kubectl`.
Its namespace Role can get/list only Services, PVCs, Deployments,
StatefulSets, and Ingresses in `fortify`. A separate discovery ClusterRole can get/list Nodes
and StorageClasses and read `/version`; it cannot enumerate namespaces.
Neither role grants Secrets, pod logs, exec, mutation, or workload access in
another namespace. Re-running the command refreshes only the observer
credential and CA; it does not read application Secrets.
After protecting the credential and CA, the command invokes the same
configuration migration. If candidate validation or replacement fails, it
disconnects the new token and leaves the prior configuration active.

### Protected lifecycle activation

`activate-lifecycle` is the only supported transition from
`lifecycle.enabled = false` to `true`. It is idempotent on the supported
single-node MicroK8s profile and starts every attempt disabled. Before
activation it verifies the installed runtime inventory, protected observer,
and readable/writable functional-health Unix socket. It then reapplies only
the `fortify-manager-lifecycle` ServiceAccount, token Secret, namespace Role,
and RoleBinding.

The command atomically renders
`/var/lib/fortify-lab-manager/cluster-access/lifecycle.kubeconfig`, owned by
`fortify-manager:fortify-manager` with mode `0600`. It uses that
credential—not administrator impersonation—to prove every declared namespace
permission. Mandatory negative checks prove denial of Secrets, logs, exec,
attach, port-forward, RBAC, namespaces, persistent volumes, and resources in
`default`. Helm execution remains fixed to `HELM_DRIVER=configmap`.

The Manager is never added to the privileged `microk8s` group. Activation
installs a root-owned, fixed-command shim beneath
`/var/lib/fortify-lab-manager/lifecycle-bin` that dispatches only `kubectl` and
`helm3` to MicroK8s's unprivileged client binaries. Lifecycle adapters receive
that directory first in their fixed `PATH` and always use the dedicated
kubeconfig. The general `/snap/bin/microk8s` administrative wrapper is excluded
from their environment.

Only after all checks pass does the command enable configuration and restart
the Manager. Success reports `lifecycle-execution: available`. Any failed
prerequisite leaves the flag false; post-configuration failures also remove
the kubeconfig and restart in disabled mode. The kubeconfig is never printed,
logged, placed in Git, sent through an API response, or stored in browser
state.

To remove mutation capability without uninstalling components or deleting
data:

```bash
sudo ./scripts/fortify-manager deactivate-lifecycle
```

Deactivation first disables configuration and removes the local kubeconfig,
then deletes only the lifecycle RoleBinding and token Secret. The
ServiceAccount and Role may remain harmlessly installed for an idempotent
retry. Fortify workloads, PVCs, application Secrets, Manager configuration,
accounts, history databases, and operation history are preserved.

Enabling RBAC and restarting MicroK8s are separate disruptive decisions.
Neither occurs implicitly. If preflight reports `enable-rbac`, review the
impact and run:

```bash
sudo ./scripts/fortify-manager install-cluster-access --approve-enable-rbac
```

The addon can update the API-server arguments and still return a failure (for
example, when an unrelated callback-token file is absent). The workflow
rechecks state after the addon command. If it reports that RBAC is configured
but not effective, inspect the arguments and explicitly approve the required
control-plane restart:

```bash
sudo ./scripts/fortify-manager install-cluster-access --approve-restart
```

When both actions are known to be required they may be approved together.
A failed enable, restart, or permission check leaves the Manager disconnected;
it does not modify Fortify workloads or persistent data. Do not start the
Manager until activation succeeds.

### RBAC recovery and rollback

Before enabling RBAC, save the existing
`/var/snap/microk8s/current/args/kube-apiserver` file with root-only
permissions. If the control plane cannot recover, restore that exact file,
then explicitly stop and start MicroK8s. Confirm that `microk8s status` and
`microk8s kubectl get nodes` succeed. The Manager must remain disconnected
while authorization is permissive or uncertain.

To retry the secure path, run `rbac-preflight`, repeat
`install-cluster-access` with only the approval it requests, and then run
`diagnose`. Do not restore `token.disconnected` manually: it represents an
identity whose effective authorization has not been proven. The workflow
reapplies only the dedicated ServiceAccount, namespace Role/binding, and
discovery ClusterRole/binding; it never rolls back or edits component
workloads, application Secrets, PVCs, or databases.

For lifecycle failures, keep `lifecycle.enabled = false` and run `diagnose`
first. Restore the installed runtime, observer access, or protected
functional-health probe named by the sanitized error, then rerun
`activate-lifecycle`; do not copy an administrator kubeconfig or manually
restore a failed candidate. If activation failed after a restart attempt, run
`deactivate-lifecycle`, confirm the Manager is active in inspection-only mode,
and retry. Support material may include the failing prerequisite category and
`systemctl is-active` result, but never the kubeconfig, token, CA contents,
application Secrets, environment dump, or unredacted journal.

MicroK8s clusters upgraded from older releases can retain a trusted cluster CA
without the RFC 5280 `keyUsage` extension. The Manager accepts that documented
legacy CA shape by disabling only OpenSSL strict-extension enforcement for its
Kubernetes client. CA-chain validation, hostname verification, HTTPS-only
origins, bounded timeouts, and the observer authorization checks remain
mandatory. An untrusted CA or hostname mismatch still fails closed.

## Health and sanitized diagnostics

Application-level health requires the protected functional probe configured
by `cluster.health_probe_socket`. Keep its Unix socket owner/group restricted
to the Manager and probe service. The probe service owns database and
application authentication; do not grant the Manager Kubernetes Secret, log,
or pod-exec access. If the service is absent or times out, affected root checks
report `unknown` and downstream components report `blocked`.

The versioned request/result format, component checks, safe evidence rules,
and recovery behavior are defined in the
[health check reference](../health-checks.md).

The clean installer creates the separate probe account, installs and enables
its hardened systemd unit, and starts it before the Manager. Use the
`probe-status`, `probe-diagnose`, `probe-restart`, and `probe-disable`
subcommands documented in the health reference. A path in `manager.toml`
does not enable the capability: the Manager performs a fresh bounded protocol
handshake for each capability document.

`sudo ./scripts/fortify-manager diagnose` checks the authoritative registry,
protected observer files, Kubernetes API reachability, actual observer
permissions and workload allow-list, configuration/account permissions,
systemd state, bounded backend readiness, server-side manifest
acceptance and live route drift. It then reports five bounded route layers:
private backend EndpointSlice address/port, ingress hostname/class/backend,
TLS Secret reference and private handshake, public operator DNS, and external HTTPS
reachability. A legacy Endpoints manifest is queried only on the documented
compatibility path. Override the TLS Secret name with
`FORTIFY_MANAGER_TLS_SECRET` when a lab
uses a different existing wildcard Secret. Diagnostics report categories
without reading or printing
passwords, cookies, keys, certificate contents, environment dumps, external
configuration directories, or response bodies. Route drift is remediated by
re-running `configure`; a missing TLS Secret must be recovered through the
existing lab certificate workflow, never regenerated by this command.

The component response continues to expose every desired registry workload
when Kubernetes is disconnected or returns 401/403, times out, or sends a
malformed response. Observation then becomes `unavailable` and workload
states become `unknown`; error bodies and credentials are discarded. After
recovery, the next request collects fresh evidence. Available evidence reports
the first sorted single-node name, fixed `fortify` namespace, Kubernetes
version, observation time/age, and bounded request latency.

For failures, check in this order:

1. `systemctl status fortify-manager` for configuration, permissions, or bind
   failure.
2. `curl --max-time 5 http://127.0.0.1:8080/ready` for host readiness.
3. `microk8s kubectl -n fortify get endpointslices \
   -l kubernetes.io/service-name=fortify-manager-host` for the expected private
   address and port. Use core Endpoints only when diagnosing a documented
   legacy manifest.
4. `microk8s kubectl -n fortify describe ingress fortify-manager` for host,
   backend, ingress class, and the configured TLS Secret.
5. Check operator DNS separately. All browser hostnames must resolve
   exclusively to the configured public operator address. A successful
   private HTTPS probe does not make a different public DNS target healthy.
6. Check Security Group reachability separately. Keep TCP 443 restricted to
   an operator-controlled IP address or VPN CIDR, never `0.0.0.0/0`, and never
   expose backend port 8080. Diagnostics do not recommend broadening sources.
7. Check the browser certificate hostname and existing lab CA.

Verify the layers without changing AWS or DNS:

```bash
# Public/operator view: all five results must be 184.33.159.224.
for host in lab ssc lim sast dast; do
  getent ahostsv4 "$host.fortifydemo.com" | awk '{print $1}' | sort -u
done

# Private backend and ingress metadata remain 172.31.30.41.
microk8s kubectl -n fortify get endpointslices,ingresses -o wide

# TLS/SNI and browser path (install the existing mkcert CA on the client).
curl --max-time 5 --resolve \
  lab.fortifydemo.com:443:172.31.30.41 https://lab.fortifydemo.com/ready
```

For in-cluster DNS, use a pre-approved diagnostics pod or the existing
operator troubleshooting environment to resolve each hostname. Do not grant
the Manager pod execution permission merely to perform this check. The AWS
Security Group must permit TCP 443 from the operator-controlled source to the
Elastic IP; it must not expose TCP 8080. These commands observe configuration
only and never modify Route 53, EC2, Security Groups, TLS Secrets, or the CA.

Do not include account files, cookies, private keys, or unredacted journal
output in support material.

## Upgrade, backup, and rollback

For complete pre-upgrade recovery covering manager state, MySQL/SSC,
PostgreSQL/DAST, configuration metadata, and preserved SSC `secret.key`, use
the [component-aware backup and restore workflow](backup-restore.md). Its
profile gate and application verification are distinct from the
manager-only safety copy described below.

The supported upgrade first stages, publishes, and validates the complete
runtime while the current Manager remains active. It verifies all three
launchers are executable and runs the candidate server's pre-start check.
Only a valid candidate permits the writer to stop. If that candidate is
already active, the command returns without stopping either service.
Otherwise, the upgrade creates a timestamped, mode-0600 SQLite online backup
plus copies of the verifier/configuration files below
`/var/lib/fortify-lab-manager/backups`. The protected `manager.toml` migration
runs before the runtime is replaced and also creates its own configuration
backup when a schema or safe-default change is required. The upgrade then
installs the immutable release, runs forward migrations at startup, and
restarts:

```bash
sudo ./scripts/fortify-manager upgrade
sudo ./scripts/fortify-manager diagnose
```

Copy that backup to separate protected storage before a high-risk upgrade.
If activation or either service restart fails, the command atomically restores
the prior `current` target and restarts the services that were previously
active. The protected backup is retained with a mode-`0600`, sanitized
`activation-failure.txt` containing only the build identity, failed stage,
rollback attempt, and an explicit statement that no secret material was
collected. Diagnose the restored service before retrying; the command never
deletes a failed-upgrade backup or failure evidence.
An incomplete candidate fails before the stop or backup boundary and leaves
the active service and release symlink unchanged.
Automatic program rollback covers failed activation only; database rollback
is **not** implied. For a later operator-directed rollback, atomically repoint
`/opt/fortify-lab-manager/current` to the prior release and restart the probe
and Manager together. If an
upgrade advanced the schema, stop the service and restore the matching
pre-upgrade database, verifier/configuration files, and program together.
Manager history backup does not back up SSC or component data.

### Live EC2 upgrade acceptance gate

`scripts/live-manager-upgrade-acceptance.sh` is an opt-in, mutating lab gate
for an authorized disposable EC2 host running the supported single-node
MicroK8s target. It is not run by repository validation and is **not
production certification**. ASPM, multi-node clusters, production exposure,
and vendor workload performance remain outside its scope.

Prerequisites are an already-installed older Manager, a different candidate
checkout on the same host, healthy MicroK8s, existing private HTTPS ingress,
and two root-readable curl cookie paths. Create the first by signing in before
the run. When the gate reports that restart is complete, sign in again from a
second protected terminal and create the second within the recovery deadline. Cookie files are
inputs only; the gate consumes no password or application/Kubernetes Secret
and never copies cookies into evidence. Run from the candidate checkout:

```bash
sudo env \
  FORTIFY_ACCEPTANCE_DOMAIN=fortifydemo.com \
  FORTIFY_ACCEPTANCE_PRIVATE_ADDRESS=10.0.0.10 \
  FORTIFY_ACCEPTANCE_PRE_SESSION_COOKIE=/root/protected/pre-upgrade.cookies \
  FORTIFY_ACCEPTANCE_POST_SESSION_COOKIE=/root/protected/post-upgrade.cookies \
  FORTIFY_ACCEPTANCE_EVIDENCE=/root/protected/manager-upgrade-evidence.json \
  ./scripts/live-manager-upgrade-acceptance.sh
```

Default command and recovery deadlines are 45 and 90 seconds. Bound them to
5–300 and 15–600 seconds with `FORTIFY_ACCEPTANCE_TIMEOUT_SECONDS` and
`FORTIFY_ACCEPTANCE_RECOVERY_SECONDS`. The gate checks the old package,
account/history preservation, a distinct immutable activation and protected
backup, configuration migration, old-session invalidation, service health,
legacy-CA cluster access, positive and mandatory-negative RBAC, inventory,
node/version, health, preflight, private HTTPS, and a private backend address.
The authorization denial followed by a fresh post-upgrade session supplies a
bounded partial-failure/recovery observation. Separately confirm that the EC2
Security Group exposes 443 only to the operator/VPN CIDR and never port 8080.

After activation begins, failure cleanup attempts to restore the prior release
and restart both services within the recovery deadline. Program rollback does
not reverse database migrations; use the protected pre-upgrade backup for
coordinated recovery. Errors identify the earliest package, configuration,
service, cluster-TLS, authorization, observation, ingress, DNS, or
remote-access layer.

The mode-0600 JSON contains categorical results, release digests, timestamps,
limitations, and the earliest layer only—never raw output, logs, cookies,
credentials, licensed artifacts, application Secrets, certificate contents,
or private paths. After review, copy only it to
`evaluations/manager-upgrade-ec2-v0.4/evidence.json`; the local 0.4
release-candidate assessment consumes it and it expires after seven days.
Keep protected troubleshooting data outside Git and remove temporary cookies.

## Uninstall and state deletion

`sudo ./scripts/fortify-manager uninstall` disables the service and removes
only manager ingress objects. It preserves `/etc/fortify-lab-manager` and
`/var/lib/fortify-lab-manager`.

State deletion is a separate destructive command requiring the service to be
stopped and the exact typed phrase:

```bash
sudo ./scripts/fortify-manager delete-state
```

Back up first. Deleted accounts and history are unrecoverable without it.

## Verification evidence

`./scripts/validate-repository.sh` and
`tests/test_manager_installation.py` provide rendered/static evidence only:
runtime closure and mode policy, staged registry validation, listener policy,
systemd hardening, private backend addressing, and ingress
host/TLS/service-port symmetry.

Completion on EC2 additionally requires separately recorded live evidence
from a browser outside the host:

1. Validate the `lab.$DOMAIN` certificate hostname and existing CA chain.
2. Confirm unauthenticated `/api/v1alpha1/history` is rejected.
3. Sign in, load the dashboard, and read the same-origin API.
4. Restart `fortify-manager`, sign in again, and confirm history persisted.
5. Confirm remote reachability on 443 and absence of 8080 from the Security
   Group.
6. Restart `fortify-manager`, then confirm `/components` reports the expected
   node, `fortify` namespace, Kubernetes version, evidence age/latency, and
   desired workloads with observed `present`/`absent` state.

Record date, manager version, domain, and sanitized pass/fail results. Never
record a password, cookie, private key, or full account file.
