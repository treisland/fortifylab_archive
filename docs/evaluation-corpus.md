# Loop evaluation corpus

The regression corpus in `evaluations/v1alpha1/cases.json` versions
representative inputs and expected outcomes for Fortify Lab Manager control
loops. It is a static, technology-neutral evaluation boundary: tests do not
access MicroK8s, external configuration, or secret material. ASPM is excluded.

Each case contains:

- stable signals that describe the observation without raw logs;
- one expected classification;
- a safe next action, including whether it is automatic or approval-gated;
- redaction categories and synthetic substrings that must not survive in
  evaluated output.

The initial `1.0.0` corpus covers a healthy baseline, database availability
and authentication failures, application readiness, slow initialization,
path and symlink rejection, TLS verification, LIM pool configuration, scanner
registration, retry exhaustion, duplicate observations, secret leakage, and
persistent-data deletion.

## Determinism and versioning

Cases have unique identifiers and contain no clock, network, cluster, or
random inputs. JSON object keys are canonicalized before hashing.
`tests/test_evaluation_corpus.py` pins the canonical SHA-256 digest, validates
the JSON Schema, checks coverage and safe-action constraints, and verifies
that every required redaction assertion is present.

Any change to a signal or expected result must deliberately update both
`corpusVersion` and the pinned digest. Use semantic versioning:

- patch for wording or additive assertions that do not change an expected
  classification or action;
- minor for backward-compatible new cases or fields;
- major for incompatible schema or expectation changes.

Run the local evaluation checks with:

```bash
python3 -m unittest tests.test_evaluation_corpus
```

The corpus describes expected behavior; it does not execute lifecycle
operations. In particular, the persistent-data case expects a blocked,
approval-gated action. Uninstall and persistent-data deletion remain separate.

## 0.2 observable-manager release gate

The general corpus is supplemented by the versioned
`evaluations/observable-manager-v0.2` suite. It proves the deterministic
portion of the complete 0.2 vertical slice: clean manager access, healthy and
dependency-blocked labs, infrastructure degradation, license preflight,
restart recovery, cluster disconnection, runner phases and long quiet work,
stall recovery, adaptive heartbeat cadence, Telegram delivery policy and
recovery, approval/stop security, and cross-surface redaction.

Every scenario explicitly states its expected health, heartbeat, event, API,
UI, Telegram, diagnostic, remediation, and workflow-authorization outcome.
The fixture clock is injected; the suite never sleeps to reach a cadence
boundary. `observations.json` contains only digests of normalized synthetic
outcomes, and `recorded-result.json` pins both input digests. Repository
validation recomputes that result and fails if a scenario is missing, changed,
failed, or accompanied by an unexpected observation.

Evaluation artifacts are intentionally unable to carry multiline or unbounded
text and reject fields for secrets, protected paths, raw prompts, source
excerpts, environment dumps, raw logs, and provider credentials. Diagnostics
are bounded categories with safe documentation links. In particular, a
Telegram delivery failure leaves workflow authorization unchanged.

Run this gate directly with:

```bash
python3 -m unittest tests.test_observable_manager_evaluation
```

This recorded result is deterministic fixture evidence, not live evidence. It
does **not** prove the EC2 Security Group, public DNS, browser trust, a live
MicroK8s installation, real Fortify licenses or images, component performance,
or Telegram provider delivery. The live browser/MicroK8s checklist remains in
the [manager operator guide](operations/manager.md#verification-evidence) and
must be recorded separately by an authorized operator. ASPM, production
hardening, multi-node Kubernetes, and component mutation remain outside 0.2.
