# User-provided files

This gitignored directory is the backward-compatible default for local license
files. A license may instead remain elsewhere on the host.

## Required

- `fortify.license` — the default Fortify license file used by SSC and
  ScanCentral SAST.

To keep the file outside the repository, set an absolute host path in `.env`:

```bash
export FORTIFY_LICENSE_FILE="/srv/fortify-protected/fortify.license"
```

The path must resolve to a readable, non-empty regular file. It is validated
before any Kubernetes resource or generated artifact is changed. Errors do not
print the configured path or license content.

## Optional

- `sonatype-license.lic` — Sonatype Nexus IQ license. Only required if you
  intend to deploy the optional Nexus IQ chart under `apps/sonatype/`.

## Where to obtain a license

- **Fortify customers**: download from the OpenText / Fortify customer portal.
- **Trial**: request at <https://www.opentext.com/products/fortify>.

## Notes on the DAST license

The DAST license is **not** dropped here. It is uploaded into LIM through
its web UI (or REST API) after LIM is running. See the LIM section of the
top-level README for instructions.

## Handling

Never commit, log, attach, archive, send through Telegram, or add a license to
a support bundle. Restrict host permissions to the account running the lab.
The deployment reads the file only to populate the Kubernetes Secret contract
documented in [`../README.md`](../README.md).
