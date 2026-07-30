# Component registry reference

`registry/components.json` is the authoritative, versioned description of
the components managed by Fortify Lab Manager. It describes capabilities and
relationships; it does not contain current health, desired replicas,
operation history, configuration values, or secret values.

The initial `fortifylab.io/v1alpha1` registry is deliberately limited to the
MicroK8s evaluation environment and excludes ASPM. It defines these dependency
paths:

```text
mysql -> ssc -> scancentral-sast
             -> scancentral-dast-core -> scancentral-dast-scanner
postgresql -> scancentral-dast-core
lim --------> scancentral-dast-core
```

DAST Core and Scanner are separate managed units because they have distinct
Helm releases, workloads, operations, and health evidence. Installing or
starting Scanner therefore includes the complete dependency closure through
Core.

## Contract

Each component declares:

- stable dependencies and Kubernetes workloads;
- bounded lifecycle operations, adapter paths, disruption and destruction;
- Kubernetes Secret references and classifications, never values;
- persistent claims and whether an ordinary uninstall retains them;
- required workload and application health evidence;
- sanitized diagnostic sources, with potentially sensitive logs marked.

Lifecycle consumers use `ComponentRegistry.lifecycle_operations()` and
dependency ordering. Monitoring consumers use
`ComponentRegistry.monitoring_checks()`. Both methods return data from the
same loaded component definition; runtime observations remain separate.

An operation's `verify` list identifies the post-operation checks a future
executor must evaluate. Checks with `required: false` describe stopped or
absent verification states and do not contribute to aggregate running health.
Timeouts bound the contract but do not add cancellation to the existing shell
adapters.

The existing MySQL, PostgreSQL, and LIM `destroy.sh` scripts remove their
persistent claims. They are consequently registered only as destructive
`delete-data` operations. They must not be presented as ordinary uninstall
actions. Other components expose `uninstall` only where the registered
adapter does not explicitly delete persistent data.

## Validation and evolution

The structural schemas are:

- `registry/schemas/component-registry.schema.json`
- `registry/schemas/component.schema.json`

`scripts/validate-component-registry.py` additionally rejects semantic
inconsistencies that JSON Schema alone cannot express: duplicate identifiers,
missing dependencies or adapters, dependency cycles, health references to
unknown workloads, operation references to unknown checks, scaling without a
scalable workload, and diagnostic references to unknown contracts.

Run both focused and repository validation after changing a definition:

```bash
python3 scripts/validate-component-registry.py
python3 -m unittest tests.test_component_registry
./scripts/validate-repository.sh
```

Change an existing contract and its consumers together. A breaking field or
meaning change requires a new `apiVersion`; do not silently reinterpret
`v1alpha1`. Registry membership represents manager support, not vendor
certification or evidence that a component is deployed and healthy.
