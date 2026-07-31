# Release-candidate preparation

Release preparation is local and does not tag, push, publish, sign, contact
GitHub, or access a MicroK8s cluster. From a clean review worktree, run:

```bash
SOURCE_DATE_EPOCH=0 python3 scripts/prepare-release-candidate.py \
  --version 0.4.0-rc.1
./scripts/validate-repository.sh
```

The recommended Manager version for milestone 0.4 is `0.4.0`: the milestone
adds backward-compatible platform lifecycle capabilities. Fortify component
versions remain independently pinned by the selected platform profile.
Review `CHANGELOG.md` against the intended milestone before publication.

The generated directory under `dist/release-candidates/` contains a
deterministic non-ignored review-source archive, `SHA256SUMS`, an SPDX 2.3
SBOM, a profile matrix, immutable evidence references, vulnerability and
signing status, documentation verification, and an objective go/no-go report.

The builder rejects symlinks, untracked files, sensitive path classes, private
key material, credential-like content, files over 2 MiB, more than 1,000
files, or more than 20 MiB total. Licenses, tokens, credentials, private keys,
protected configuration, raw logs, external paths, `secrets/input`, and
generated secrets are never release inputs. The archive is review material,
not a backup.

## Objective gates

`go-no-go.json` reports `GO` only when every gate is `passed`. `failed` and
`not-run` both block release:

| Gate | Required evidence |
|---|---|
| Bounded artifact and secret scan | Candidate manifest |
| SBOM and checksums | SPDX document and `SHA256SUMS` |
| Vulnerability scan | Named scanner result for the exact candidate |
| Artifact signature | Approved signer result for the exact checksum |
| Licensed lifecycle | Exact-profile clean install, supported upgrade, and backup/restore all passed |
| Installation and upgrade docs | Candidate-linked documentation verification |

The repository has no configured offline vulnerability scanner or signing
workflow. The local builder records those gates as `not-run`; it does not
download tooling or fabricate a signature. An approved publication workflow
may replace those results while retaining the candidate checksum and
scanner/signer identity.

## Current 0.4 candidate

The selected `fortify-24.4-eval.1` profile has static evidence only. Its clean
install, upgrade, and backup/restore checks are `not-run`; its moving-image
limitations remain in the profile matrix. Consequently, the locally prepared
candidate is objectively **NO-GO** until separately authorized tests on a
disposable, licensed, single-node MicroK8s lab produce sanitized evidence for
that exact profile.

Clean-install evidence must include preflight, dependency-ordered completion,
functional health, and bounded sanitized operation references. Upgrade
evidence must name an allowed source profile, bound backup, migration result,
downtime, health result, and recovery boundary. Backup/restore evidence must
show complete checksums and post-restore application verification. Never
retain raw logs, Secret values, protected paths, license data, or credentials.

## Rollback guidance

Do not treat Helm rollback as database recovery. Before any candidate upgrade,
retain and verify the complete profile-bound backup described in
[Component-aware backup and restore](backup-restore.md). Reversible chart or
configuration changes still require post-rollback health verification.
Database or application migrations are `restore-required`: restore the
matching backup and source Manager together. See
[Rollback and recovery boundaries](rollback-recovery.md) and
[Profile-aware upgrades](profile-upgrades.md).
