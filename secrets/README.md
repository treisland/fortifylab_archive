# Secrets layout

This directory contains everything required to build the Kubernetes Secrets
that the Fortify charts consume.

```
secrets/
├── input/        # user-provided files (gitignored)        — you put files here
├── templates/    # committed templates with $VAR placeholders — rendered at deploy
└── generated/    # build artifacts (gitignored)             — wiped + rebuilt each run
```

## Workflow

1. Drop your license file at `input/fortify.license` (see `input/README.md`).
2. Configure `.env` (domain, passwords, image versions).
3. Run `scripts/create-certs.sh` to generate the mkcert root + leaf cert and
   build the JVM keystore + truststore into `generated/`.
4. Run `scripts/create-secrets.sh` to render templates, generate ephemeral
   secrets (SSC `secret.key`, scancentral tokens, JWT keys), and create the
   Kubernetes Secret objects.

## Map: file → k8s Secret → consumer

The k8s Secret name and key are what the helm chart reads.

| File path                                      | k8s Secret                       | Key                  | Consumer                            |
|------------------------------------------------|----------------------------------|----------------------|-------------------------------------|
| `input/fortify.license`                        | `fortify-secrets`                | `fortify.license`    | SSC, ScanCentral SAST controller    |
| `templates/ssc.autoconfig.template` (rendered) | `fortify-secrets`                | `ssc.autoconfig`     | SSC (DB connection)                 |
| `generated/ssc/secret.key`                     | `fortify-secrets`                | `secret.key`         | SSC (credential encryption)         |
| `generated/certs/keystore.jks`                 | `fortify-secrets`                | `keystore.jks`       | SSC (HTTPS keystore)                |
| `generated/certs/truststore`                   | `fortify-secrets`                | `truststore`         | SSC (JVM truststore for outbound)   |
| `generated/certs/tls.crt` + `tls.key`          | `tls`                            | (TLS type)           | nginx ingress (server cert)         |
| `generated/certs/rootCA.pfx`                   | `tls-pfx`                        | `tls.pfx`            | LIM (signing cert PFX)              |
| —                                              | `tls-pfx-password`               | `password`           | LIM (PFX password)                  |
| —                                              | `lim-server-certificate`         | (TLS type)           | LIM (server cert)                   |
| —                                              | `lim-admin-credentials`          | basic-auth           | LIM admin                           |
| —                                              | `lim-pool`                       | basic-auth           | LIM default pool                    |
| —                                              | `lim-jwt-security-key`           | `token`              | LIM JWT signing                     |
| —                                              | `scdast-db-owner`                | basic-auth           | SCDAST upgradejob (DBO)             |
| —                                              | `scdast-db-standard`             | basic-auth           | SCDAST API (runtime DB user)        |
| —                                              | `scdast-ssc-serviceaccount`      | basic-auth           | SCDAST → SSC                        |
| —                                              | `scdast-service-token`           | `service-token`      | SCDAST core ↔ scanner               |
| —                                              | `regcred`                        | dockerconfigjson     | image pull from Docker Hub          |

Files in `input/` and `generated/` that aren't in the table are **not**
loaded into any k8s Secret (no more "everything in the folder becomes a key"
behavior — keys are added explicitly).

## Public CAs

Public certificate authorities (Amazon Root CA 1, the `update.fortify.com`
chain, etc.) are **not** stored here as secrets. They are imported into the
JVM truststore by `scripts/create-certs.sh` and travel with the
`truststore` file above.
