# Write-only secret and secret-file management

Fortify Lab Manager defines a transport-neutral, authenticated replacement
service for credentials, tokens, certificates, Fortify license references,
and other secrets declared in the component registry. It is MicroK8s-first,
excludes ASPM, and implements [ADR 0005](../adr/0005-write-only-secrets.md).
The repository does not yet include a live Kubernetes adapter or expose a
browser mutation route.

## Input and disclosure boundary

Only these typed source classes are accepted:

- `external-path`: a regular file beneath a configured protected root;
- `upload`: bounded bytes delivered directly to the protected-store adapter;
- `kubernetes-secret`: an existing Secret name and key reference;
- `generated`: adapter-generated material for policy-approved credentials,
  tokens, and keys.

External paths are canonicalized. Traversal, paths outside allowed roots,
symlinks, non-files, and group/world-accessible files are rejected before
authorization or mutation. There is no server-side filesystem browser.
Uploads are held only for the call and are never written to manager state.
Existing Secret names and keys are validated identifiers and are not returned.
Generated values are created inside the protected-store boundary and cannot be
used for licenses, certificates, image-pull material, or SSC `secret.key`.

After submission, all values are write-only. Responses, durable operation
state, audit records, history, diagnostics, logs, errors, Web UI projections,
and Telegram messages may contain only:

- the registry target ID and classification;
- source class, configured/update state, and timestamps;
- affected consumers and completed restarts;
- expected interruption, health-check requirement, and rollback boundary;
- a bounded sanitized error and recovery instruction.

They never contain content, uploads, filesystem paths, Kubernetes Secret
names or keys, generated values, or adapter revision handles. The response
contract is
[`secret-update.schema.json`](../../registry/schemas/secret-update.schema.json).

## Authorization and impact plan

Replacement is a high-risk typed operation under the shared
[authorization policy](authorization.md). An approval is bound to the actor,
session, exact `component/secret` target, and current metadata state. Approval
requires fresh local CLI or Web authentication and the standard high-risk
confirmation. Telegram can notify and deep-link to the Web UI, but cannot
approve a replacement and must ignore non-command secret content.

Call `plan(component, secret, sourceType)` before applying. It returns the
declared consumers, whether restarts and health verification are required,
the expected interruption, persistent-data backup requirement, and rollback
boundary. Runtime transports must present that plan before requesting
approval.

## Apply, restart, and recovery

The protected-store adapter performs an atomic replacement or reference
change when its backing store supports one. The workflow then restarts only
registry consumers of the affected Kubernetes Secret and verifies each
consumer before reporting success. Work is deadline-bounded and cancellation
aware.

If apply succeeded but restart or health verification fails, the service asks
the adapter to restore its opaque prior revision. A successful restore reports
`rolled-back`, but consumers still require verification. If no safely retained
revision exists or restoration fails, the operation reports
`recovery-required`; restore the authoritative external source and submit a
new replacement. The manager never retains plaintext to manufacture rollback.

Manager restart fences `applying`, `restarting`, `verifying`, and
`rolling-back` operations as `interrupted`. It does not resume with missing
write-only input or assume success. Inspect consumer health, restore the
authoritative source if needed, and submit a newly authorized replacement.

## SSC `secret.key`

Warning: SSC `secret.key` protects access to data already stored by SSC.
Replacing it without a compatible backup can make persistent data unusable.

The SSC workflow therefore rejects generated values and requires both a
verified persistent-data backup and the exact typed confirmation:

```text
REPLACE SSC SECRET.KEY AFTER VERIFIED BACKUP
```

Routine secret generation and script reruns must continue preserving the
existing key. Do not treat Helm rollback as a database or encrypted-data
rollback. Recover the prior authoritative key and persistent data together.

## Runtime integration checklist

Before enabling a live MicroK8s adapter:

1. Give it namespace-scoped access only to declared Secret and workload
   resources.
2. Consume uploads through protected file descriptors or standard input, not
   command-line arguments or Helm values.
3. Ensure adapter exceptions and Kubernetes responses are sanitized.
4. Demonstrate atomic update, targeted restart, health verification,
   cancellation, and revision restore against a disposable lab.
5. Confirm API, Web, Telegram, history, logs, and diagnostics expose only the
   metadata schema above.
