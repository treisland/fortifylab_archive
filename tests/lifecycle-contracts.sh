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

SAST_CONTROLLER="scancentral-sast-controller"
SAST_SENSOR="scancentral-sast-sensor-linux"

for file in apps/scsast/start.sh apps/scsast/stop.sh; do
    assert_contains "$file" "$SAST_CONTROLLER"
    assert_contains "$file" "$SAST_SENSOR"
done
assert_contains apps/scsast/scale_scanners.sh "$SAST_SENSOR"

for workload in \
    sdast-core-scancentral-dast-core-api \
    sdast-core-scancentral-dast-core-globalservice \
    sdast-core-scancentral-dast-core-utilityservice
do
    assert_contains apps/scdast/core/start.sh "$workload"
    assert_contains apps/scdast/core/stop.sh "$workload"
done

printf 'Lifecycle contracts match start/stop/scale scripts.\n'
