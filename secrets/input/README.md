# User-provided files

Drop your license files in this directory. Everything here is gitignored.

## Required

- `fortify.license` — Fortify license file. Required for SSC and ScanCentral SAST.
  Without it, the deployment will fail-fast with a clear error.

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
