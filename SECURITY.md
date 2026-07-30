# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or exposed secret.
Use GitHub's private vulnerability reporting for this repository. If that
facility is unavailable, contact the repository owner privately.

Include affected versions, reproduction steps, impact, and suggested
mitigations. Do not include live credentials, licenses, private keys, or
unredacted environment data.

## Scope and support

This repository currently targets evaluation, training, and demonstration
labs on local MicroK8s. It is not a production deployment guide.

## Security boundaries

- SSC remains the application-security system of record.
- The manager must not expose arbitrary shell, Kubernetes, or filesystem
  access through its Web UI or communication channels.
- Secret values are never returned after configuration.
- Telegram is restricted initially to one allowlisted private chat.
- Sensitive operations require explicit human approval; high-risk operations
  require Web UI reauthentication.
- Helm rollback must not be represented as reversing database migrations.

Generated support data and operation traces must be sanitized before storage
or transmission.
