# Contributing

Fortify Lab is evolving into Fortify Lab Manager through small, verified
changes. The initial supported target is a local, single-node MicroK8s lab.
Do not describe a workflow as production-ready without explicit validation
and documentation.

## Development workflow

1. Start from an issue with testable acceptance criteria.
2. Create a short-lived branch from `main`.
3. Keep the change scoped and preserve unrelated local files.
4. Update tests and documentation with behavior changes.
5. Run `./scripts/validate-repository.sh`.
6. Open a draft pull request and include validation evidence.

Every operation should define how its result is verified. Prefer
application-level evidence, such as an authenticated database query, over
Kubernetes pod phase alone.

## Pull requests

Pull requests should explain:

- the problem and resulting behavior;
- dependencies and affected Fortify components;
- tests and validation performed;
- secret, security, and RBAC impact;
- configuration, persistence, or migration impact;
- interruption and rollback limitations;
- documentation changes.

Do not weaken tests or evaluation rubrics solely to make a change pass.

## Repository protection

Protect `main` with pull requests, passing validation checks, resolved review
conversations, and protection against force pushes and deletion. Keep
administrative bypasses limited to documented recovery situations.

## Sensitive data

Never commit or include in logs, issues, screenshots, fixtures, or support
bundles:

- Fortify licenses;
- passwords, tokens, or Docker credentials;
- certificate private keys;
- Telegram user/chat IDs or bot tokens;
- `.env` files;
- Kubernetes Secret values.

Use protected external files or existing Kubernetes Secrets. Secret values
must be treated as write-only after submission.

## Destructive operations

Uninstalling a component and deleting its persistent data are separate
actions. Database migrations, PVC deletion, trust rotation, SSC `secret.key`
rotation, and unsupported upgrades require explicit human approval and
recovery guidance.
