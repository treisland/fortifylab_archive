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
