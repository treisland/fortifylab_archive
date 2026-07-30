# Read-only Web dashboard

The Fortify Lab Manager dashboard presents the complete single-node MicroK8s
lab on one same-origin browser page. It shows the desired component graph and
versions, current dependency-aware health evidence, primary root cause and
safe remediation, latest deployment preflight, cluster-observation state, and
recent sanitized manager operations. ASPM and browser-triggered lifecycle
actions are outside this release.

![Dashboard showing a healthy lab summary, dependency cards, health evidence, preflight, and operation history](images/web-dashboard.svg)

## Access and authentication

The dashboard follows [ADR 0009](adr/0009-manager-runtime-boundary.md).
Supported remote lab access is only through MicroK8s nginx ingress at
`https://lab.$DOMAIN`; the host backend listener is not a browser-facing
route. See the [manager operator guide](operations/manager.md). This lab UI is
not designed for public Internet exposure.

An operator must bootstrap the local account outside the browser and pass
only its PBKDF2 password verifier to `DashboardApp`. The helper
`manager.dashboard.password_verifier()` creates that verifier; do not put the
plaintext password in source, command history, environment dumps, or a
committed configuration file. A production launcher must store account
verifiers in manager-owned state with mode `0600`.

The login creates a random server-side session. Cookies are `HttpOnly` and
`SameSite=Strict`, have bounded idle and absolute lifetimes, and must be
configured with `secure_cookies=True` behind TLS. Only the coarse `/ready`
response is unauthenticated. Static assets contain no lab data; all
`/api/v1alpha1/*` read models require the session. Cross-origin API access is
not enabled and browser responses carry a restrictive Content Security
Policy.

![Local sign-in page describing the read-only session boundary](images/web-login.svg)

## Dashboard states

The page does not convert missing evidence into success:

- `healthy`, `starting`, `degraded`, `blocked`, `misconfigured`, `stopped`,
  `unreachable`, and `unknown` are separately labelled and colored; the
  current health contract also preserves `unhealthy` and `stale`;
- a disconnected cluster keeps desired inventory and versions visible while
  observed resources become unknown;
- loading, an empty read model, and an API failure each have distinct text;
- downstream failures retain `blockedBy` and `rootCause`, so the page
  emphasizes the primary problem instead of repeating symptoms;
- remediation links point only to repository health and preflight guides.

Color is never the only health cue: every badge includes visible state text.
The page provides landmarks, a skip link, labelled controls, table headers,
alert/status live regions, keyboard focus styles, responsive layouts, and
reduced-motion handling.

## Disclosure boundary

The browser receives the safe projections already defined by the inventory,
health, preflight, and record contracts. It never receives Kubernetes
credentials, Secrets, logs, filesystem paths, adapter targets, licenses,
tokens, passwords, private keys, authorization headers, or cookies through
JSON. History is projected to stable identity, kind, state, summary, subject,
and time after persistence-layer sanitization.

The UI uses DOM `textContent`, not HTML interpolation, for API data. A
read-path compromise therefore cannot use the supported API to retrieve
submitted secret values. Secret status remains metadata-only under
[ADR 0005](adr/0005-write-only-secrets.md).

## Failure recovery

Use **Refresh** after a transient manager or adapter failure. If the session
expires, the next API request returns `401` and the page returns to sign-in.
If only cluster observation is unavailable, investigate the manager's
allow-listed observer; do not broaden RBAC or grant access to Secrets. Health
and preflight remediation remain in
[health-checks.md](health-checks.md) and
[deployment-preflight.md](deployment-preflight.md).

Tests in `tests/test_dashboard.py` cover authentication, expiry, logout,
method rejection, headers, disclosure, API history, accessibility structure,
and the loading/empty/failure/disconnected presentations. They are static and
in-process tests: no live MicroK8s validation was performed.
