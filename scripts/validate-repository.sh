#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPOSITORY_ROOT"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "Required validation tool is missing: $1"
}

mapfile -t SHELL_FILES < <(git ls-files '*.sh')
mapfile -t YAML_FILES < <(git ls-files '*.yaml' '*.yml')

printf 'Checking shell syntax (%d files)...\n' "${#SHELL_FILES[@]}"
((${#SHELL_FILES[@]} > 0)) && bash -n "${SHELL_FILES[@]}"

require_command shellcheck
printf 'Running ShellCheck at error severity...\n'
shellcheck --severity=error "${SHELL_FILES[@]}"

require_command yamllint
printf 'Checking YAML syntax (%d files)...\n' "${#YAML_FILES[@]}"
if ((${#YAML_FILES[@]} > 0)); then
    yamllint -c .yamllint.yml "${YAML_FILES[@]}"
fi

printf 'Checking lifecycle contracts...\n'
bash tests/lifecycle-contracts.sh

printf 'Checking local Markdown links...\n'
python3 scripts/check-local-links.py

printf 'Running Python unit tests...\n'
python3 -m unittest discover -s tests -p 'test_*.py'

printf 'Checking staged changes for secret patterns...\n'
python3 scripts/check-staged-secrets.py

printf 'Repository validation passed.\n'
