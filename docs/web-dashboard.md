# Authenticated Web dashboard

The Fortify Lab Manager dashboard presents the complete single-node MicroK8s
lab on one same-origin browser page. It shows the desired component graph and
versions, current dependency-aware health evidence, primary root cause and
safe remediation, latest deployment preflight, cluster-observation state, and
recent sanitized manager operations and controlled typed lifecycle actions.
ASPM remains outside project scope.

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
`/api/v1alpha1/*` reads and mutations require the session. Cross-origin API access is
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

## Controlled operations

Select an action and components, then choose **Review plan**. The manager
shows the registry-resolved ordered steps, dependency additions, bounded
timeouts, verification count, risk, and destructive/data-deletion
classification. Requests contain only operation and component identifiers,
never commands, paths, adapter names, environment values, or secrets.

Routine supported actions can start after review. Disruptive actions require
a single-use approval bound to the actor, browser session, exact plan, current
target state, and expiry. High-risk actions additionally require
`AUTHORIZE HIGH-RISK OPERATION` and a recently authenticated session.
Uninstall and persistent-data deletion remain separate plan types; uninstall
never implicitly deletes persistent data.

The progress panel renders durable state, completed and total steps, sanitized
events, cancellation, retry eligibility, and completion health. The active
opaque operation ID is retained in browser session storage. Refresh or a
same-session reconnect retrieves authoritative state from
`GET /api/v1alpha1/operations/{id}`; leaving the page does not cancel work.
Cancellation is cooperative and can remain `cancelling` until the adapter
reaches a cancellation boundary. Retry creates a new operation and does not
reuse an approval.

The repository deliberately ships no live MicroK8s mutation adapter.
`DashboardApp` returns `503 OPERATIONS_UNAVAILABLE` unless composition
supplies the shared engine, authorization service, current-state provider,
and an independently validated namespace-scoped adapter.

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

Use **Refresh** after a transient manager or adapter failure. Failed,
timed-out, and manager-interrupted operations offer **Retry** after the
operator reviews sanitized events and current health. If the session
expires, the next API request returns `401` and the page returns to sign-in.
If only cluster observation is unavailable, investigate the manager's
allow-listed observer; do not broaden RBAC or grant access to Secrets. Health
and preflight remediation remain in
[health-checks.md](health-checks.md) and
[deployment-preflight.md](deployment-preflight.md).

Tests in `tests/test_dashboard.py` and `tests/test_web_operations.py` cover authentication, expiry, logout,
method rejection, headers, disclosure, API history, accessibility structure,
loading/empty/failure/disconnected presentations, plans, dependency blocks,
approval, timeout, cancellation, retry, reconnect, completion health, and
sanitized failures. They are static and in-process tests: no live MicroK8s
validation was performed.
