#!/bin/bash
# setup.sh — convenience entry point.
#
# This used to do its own JDK/Docker/microk8s install and shell-rc patching.
# That's now handled by the wizard's "Install prerequisites" menu (option 3),
# which is idempotent and doesn't modify your shell rc files. We just hand
# off to the wizard.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
exec ./start_wizard.sh "$@"
