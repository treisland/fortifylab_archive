# Platform profiles

## Support boundary

Fortify Lab Manager is for evaluation, training, and demonstration labs. Its
clean-install target is a local, single-node MicroK8s cluster. ASPM, multi-node
clusters, other Kubernetes distributions, and production deployments are
excluded. A profile records what this project tested; it never creates or
replaces a vendor support statement.

`profiles/<id>.json` is the authoritative contract for component, database,
chart, image, MicroK8s, capacity, maturity, clean-install, and upgrade claims.
The component registry selects exactly one profile with `profileRef`. Manager
startup, registry validation, preflight, Web UI, CLI, and release evidence fail
closed when that reference is absent, unknown, malformed, or its pins differ.

Executable transitions are never inferred from version ordering. A target
must name each allowed source and provide one corresponding transition with
bounded downtime, backup, migration, rollback, and recovery metadata. Any
declared transition also requires licensed-live evidence with a passed upgrade
check. See [Profile-aware upgrades](operations/profile-upgrades.md).

## Current baseline

`fortify-24.4-eval.1` contains:

| Area | Pinned contract |
|---|---|
| MicroK8s | `>=1.28 <1.29`, `amd64`, single node |
| Minimum capacity | 8 CPU cores, 32 GiB memory, 100 GiB storage |
| SSC | product/image `24.4.2.0009`, chart `24.4.2-1` |
| ScanCentral SAST | `24.4`, chart `24.4.0-2`, controller `24.4.0.0060`, sensor `24.4.1` |
| ScanCentral DAST | `24.4`, charts `24.4.0-2`, Fortify images `24.4.ubi.9` |
| LIM | `24.4`, chart `24.4.0-3` |
| MySQL | `8.0.36`, chart `9.19.0`, image `8.0.36-debian-11-r2` |
| PostgreSQL | `17.6.0`, chart `18.6.2`, image `17.6.0-debian-12-r4` |

Its maturity is **experimental**. Static schema and repository checks are not
licensed environment evidence. No clean install, backup/restore, or upgrade
has been run, so no upgrade source is allowed. The LIM image is chart-selected
and DAST values contain moving third-party tags. The machine-readable profile
and `profiles/evidence/fortify-24.4-eval.1.json` record these limitations.

The `.env.example` pins remain a shell-compatible mirror. Regression tests
require them and the component registry to match the selected profile.

## Maturity and evidence

- `experimental`: structured and statically validated.
- `validated`: representative licensed clean-install evidence exists.
- `recommended`: validated and preferred, with a tested upgrade source.
- `deprecated`: usable during a migration window and names its replacement.
- `unsupported`: blocked except as historical migration information.

Release evidence names an immutable profile ID and separately records schema,
repository, clean-install, upgrade, and backup/restore outcomes. Rendering or
static validation cannot promote a profile to `validated` or `recommended`.

## Deprecation and forward migration

Do not edit a profile in place to change pins. Add a new profile and evidence
record. To deprecate an old profile:

1. Set maturity to `deprecated` and name the new ID in `replacement`.
2. Add the old ID to the replacement's `upgrade.allowedSources` only after that
   exact upgrade passes representative licensed testing.
3. Document migrations, data and rollback boundaries, SSC `secret.key`
   preservation, and known limitations.
4. Select the replacement in `registry/components.json` only when every pin
   matches.
5. Move the old profile to `unsupported` when its migration window ends.

Unknown combinations remain blocked and must not be described as
vendor-supported. See [ADR 0003](adr/0003-microk8s-first-scope.md).
