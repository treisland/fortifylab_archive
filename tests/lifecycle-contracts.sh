#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPOSITORY_ROOT"

assert_contains() {
    local file="$1"
    local expected="$2"
    grep -Fq -- "$expected" "$file" || {
        printf 'ERROR: %s does not contain lifecycle contract: %s\n' \
            "$file" "$expected" >&2
        return 1
    }
}

while IFS=$'\t' read -r adapter workload; do
    assert_contains "$adapter" "$workload"
done < <(python3 - <<'PY'
import json

with open("registry/components.json", encoding="utf-8") as stream:
    registry = json.load(stream)
for component in registry["components"]:
    workloads = component["workloads"]
    for operation in component["operations"]:
        if operation["id"] not in {"start", "stop"}:
            continue
        for workload in workloads:
            print(f"{operation['adapter']}\t{workload['name']}")
    for operation in component["operations"]:
        if operation["id"] == "scale":
            for workload in workloads:
                if workload["scalable"]:
                    print(f"{operation['adapter']}\t{workload['name']}")
PY
)

printf 'Lifecycle scripts match authoritative registry workloads.\n'
