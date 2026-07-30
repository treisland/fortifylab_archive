# Fortify Lab on Kubernetes

See [Architecture decisions](docs/architecture.md) for the accepted Fortify
Lab Manager boundaries and design contracts.

A scripted Fortify deployment for evaluation, training, and demos:
**SSC**, **ScanCentral SAST**, **ScanCentral DAST**, **LIM**, plus the
Kubernetes Dashboard, all running on [microk8s](https://microk8s.io/) with
mkcert-issued TLS. Every step driven by an interactive wizard or a single
"deploy from scratch" command.

> Not a production deployment guide — opinionated defaults, single-node
> cluster, NFS PVCs. Intended for lab and evaluation use.

## Support boundary

Fortify Lab Manager targets a local, single-node MicroK8s lab. Other
Kubernetes distributions and ASPM are outside the current project scope.
The pinned component versions in `.env.example` are intentional evaluation
defaults, not a verified or vendor-supported platform profile. See
[Platform compatibility](docs/platform-compatibility.md) for the precise
evidence boundary.

## What you get

| Component | Default URL | Notes |
|---|---|---|
| Software Security Center (SSC) | `https://ssc.fortifydemo.com` | Central app, MySQL 8 backed |
| ScanCentral SAST | `https://sast.fortifydemo.com` | Controller + Linux workers |
| ScanCentral DAST | `https://dast.fortifydemo.com` | API + scanner, PostgreSQL 17 backed |
| LIM | `https://lim.fortifydemo.com` | DAST license/pool server |
| Kubernetes Dashboard | `https://dashboard.fortifydemo.com` | Optional |

## Prerequisites

- Linux host (Ubuntu 22.04+ tested)
- ~16 GB RAM, ~50 GB disk free
- Browser reachability to the host (LAN IP, public IP, or VPN)
- A Fortify license (`fortify.license`), stored outside the repository when
  desired — see [`secrets/input/README.md`](secrets/input/README.md)
- A Docker Hub login that can pull from `fortifydocker/*` and `bitnamilegacy/*`

## Quick start

```bash
git clone https://github.com/treisland/fortifylab.git
cd fortifylab
cp .env.example .env
# Edit .env: at minimum set DOMAIN, DEFAULT_PASS, FORTIFY_LICENSE_FILE,
# and check image versions. The repository-local license default still works.
./start_wizard.sh
```

Inside the wizard:

1. **Option 3 — Install prerequisites**: JDK, Docker, mkcert, microk8s
   (with `dns`, `ingress`, `nfs`, `dashboard`, `community` add-ons).
2. **Option 4 — License files**: drop in your `fortify.license`.
3. **Option 1 — Deploy from scratch**: certs → secrets → MySQL + Postgres →
   SSC + LIM → SAST → DAST. Takes ~15-20 min on the recommended hardware.
4. **Option 6 — Configure**:
   - DNS (auto-patches CoreDNS so pods can resolve `*.$DOMAIN` themselves).
   - SSC ControllerToken (paste the value generated in the SSC UI).
   - LIM DAST license + pool (manual web UI step, instructions printed).

When the deploy finishes, **option 9** prints all URLs and the LIM admin
password decoded from its Secret.

## DNS setup

The lab issues TLS certs for the wildcard `*.$DOMAIN` (default
`fortifydemo.com`). Browsers and pods both need to resolve those hosts to
the cluster's node IP.

**Client-side** (your laptop) — add to `/etc/hosts` (or Pi-hole):

```
<host-ip>  ssc.fortifydemo.com sast.fortifydemo.com dast.fortifydemo.com lim.fortifydemo.com dashboard.fortifydemo.com
```

**In-cluster** — pods can't reach `*.$DOMAIN` through nginx because
nginx routes by Host header but the in-cluster DNS doesn't know the
domain. The wizard's **Configure → DNS** option patches CoreDNS's hosts
plugin so SCDAST scanner ↔ DAST API and SAST ↔ SSC traffic resolves
correctly.

## TLS trust

`scripts/create-certs.sh` uses [mkcert](https://github.com/FiloSottile/mkcert)
to create a per-machine root CA and a wildcard leaf for `*.$DOMAIN`. To
make your browser trust the lab:

```bash
# From your laptop:
scp ubuntu@<host>:~/fortifylab/certs/rootCA.pem ~/Downloads/fortify-rootCA.pem

# macOS: open Keychain Access → System keychain → drag in rootCA.pem →
#        double-click → set "Always Trust"
# Linux: sudo cp ~/Downloads/fortify-rootCA.pem /usr/local/share/ca-certificates/fortify-rootCA.crt
#        sudo update-ca-certificates
# Firefox: about:preferences#privacy → Certificates → import as authority
```

Re-running `create-certs.sh` rotates the root CA — you'll need to
re-import. The wizard does not warn you about this; treat it as a
fresh-install operation.

## Manual configuration after deploy

Two steps still need a human after `Deploy from scratch`:

- **SSC ControllerToken**: Log into SSC → Administration → ScanCentral SAST
  → Tokens → create a token of type `ScanCentralCtrlToken`. Run wizard
  Configure → option 2 to paste it; the wizard does
  `helm upgrade --reuse-values --set controller.sscScanCentralCtrlToken=...`.
- **DAST license + pool in LIM**: Open `https://lim.$DOMAIN`, sign in with
  the `lim_admin` credentials (URLs & credentials → option 9), upload the
  DAST license file, create a pool named `Default` (matches `LIM_POOL_NAME`
  in `.env`), then redeploy ScanCentral DAST so the scanner can authenticate.

## Repo layout

```
.env.example              Template — copy to .env, edit DOMAIN/passwords/versions.
start_wizard.sh           Interactive launcher.
setup.sh                  One-shot bootstrap (delegates to the wizard).
scripts/
  create-certs.sh         mkcert root + leaf, JKS keystore, JVM truststore.
  create-secrets.sh       k8s Secrets: explicit per-key, no folder dump.
  install_microk8s.sh     microk8s + addons.
registry/
  components.json         Authoritative component and dependency definitions.
  schemas/                Versioned structural contracts for the registry.
contracts/
  v1alpha1/               Technology-neutral loop schemas and examples.
manager/
  component_registry.py   Shared lifecycle and monitoring registry API.
secrets/
  input/                  User-provided files (license). Gitignored.
  templates/              Committed templates rendered at deploy time.
  generated/              Build artifacts. Wiped + rebuilt every run.
  README.md               Full file → Secret → consumer map.
apps/
  mysql, postgresql       Bitnami legacy charts.
  ssc, lim                Fortify charts.
  scsast                  ScanCentral SAST controller + workers.
  scdast/core, scdast/scanner   ScanCentral DAST.
  kubernetes-dashboard    Optional.
  sonatype                Optional Nexus IQ.
```

See the [component registry reference](docs/component-registry.md) for the
dependency graph, lifecycle safety metadata, health evidence, diagnostics,
and schema evolution rules.

See the [loop contracts reference](docs/loop-contracts.md) for versioned
progress, health, event, incident, approval, and sanitized-trace records
shared by lifecycle, health, development, and improvement loops.

## Conventions and gotchas

- **Run as your normal user**, never `sudo ./start_wizard.sh`. mkcert is
  per-user; running as root would create a different CA at `/root/...` and
  silently rotate every cert. `create-certs.sh` and `create-secrets.sh`
  refuse to start under sudo.
- **Image tags are pinned in `.env.example`** to specific versions of
  `bitnamilegacy/postgresql`, `bitnamilegacy/mysql`, etc. Bitnami's
  `:latest` tag has shifted under us before — always pin.
- **SSC `secret.key` is preserved across `create-secrets.sh` runs** because
  SSC uses it to encrypt credentials in its database. A fresh clone starts
  with the committed lab sample. Do not replace that key after SSC stores
  data; recovery and deliberate migration guidance is in
  [`secrets/README.md`](secrets/README.md).
- **`FORTIFY_LICENSE_FILE`** may reference a protected license outside the
  repository. The default remains `secrets/input/fortify.license`.
  `secrets/generated/` is owned by the scripts. License paths and content must
  never be included in logs, artifacts, Telegram messages, or support bundles.
- **Re-running `create-certs.sh`** rotates the root CA. Browsers will
  flag the new cert as untrusted until you re-import `rootCA.pem`.
- **Postgres data directory is initialized by the running image**. If
  the chart's image ever ships a newer major (PostgreSQL 18 vs 17), the
  PVC must be wiped to re-init. We pin the image tag to avoid surprise
  upgrades.

## Cleanup

```bash
./start_wizard.sh
# Apps → each app → Destroy
# Then on the host:
microk8s helm -n fortify list                     # confirm none remain
microk8s kubectl delete namespace fortify         # nuke everything else
```

## Development supervisor

Maintainers can use the optional private Telegram and GitHub
[SDLC supervisor](docs/operations/sdlc-supervisor.md) to monitor pull requests,
approve qualifying merges, and queue the next milestone issue while away from
the deployment host. The supervisor does not have authority to mutate live
Fortify workloads or sensitive data.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development workflow,
verification expectations, and sensitive-data rules. Issues with deploy
errors should include:

- Output of `microk8s kubectl -n fortify get pods`
- The relevant pod's `kubectl logs --tail=200`
- Your `.env` (with passwords redacted)

## License

MIT. See [`LICENSE`](LICENSE).
