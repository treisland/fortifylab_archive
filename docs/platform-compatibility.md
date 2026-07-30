# Platform compatibility

## Current boundary

Fortify Lab Manager is for evaluation, training, and demonstration labs. Its
first deployment target is a local, single-node MicroK8s cluster with the
addons installed by `scripts/install_microk8s.sh`. It is not a production
deployment guide.

ASPM is excluded. Other Kubernetes distributions, multi-node clusters, and
custom ingress, DNS, storage, or certificate arrangements are not currently
supported targets. Portable Kubernetes contracts may make later validation
possible, but portability is not evidence of support.

## Fresh-clone evaluation bundle

The following `.env.example` values are deliberate, pinned defaults for a
fresh-clone evaluation:

| Component | Chart version | Image version |
|---|---:|---:|
| SSC | `24.4.2-1` | `24.4.2.0009` |
| ScanCentral SAST | `24.4.0-2` | controller `24.4.0.0060`; worker `24.4.1` |
| ScanCentral DAST | `24.4.0-2` | chart defaults |
| LIM | `24.4.0-3` | chart defaults |
| MySQL | `9.19.0` | `8.0.36-debian-11-r2` |
| PostgreSQL | `18.6.2` | `17.6.0-debian-12-r4` |

Pins make a clone deterministic and protect it from moving image tags. They
do not establish compatibility, security maintenance, upgrade safety, or
vendor support.

## Evidence status

No versioned platform profile has yet completed the project's required
clean-install, lifecycle, integration, backup/restore, and upgrade evidence.
Consequently, the bundle above is **unverified** and must not be described as
a supported platform profile.

Changing any pin creates another unverified combination. Before a future
profile is called supported, record its exact MicroK8s, addon, chart, image,
and Fortify component versions together with reproducible clean-install and
upgrade-path results.

The architectural source of truth for these boundaries is
[ADR 0003](adr/0003-microk8s-first-scope.md).
