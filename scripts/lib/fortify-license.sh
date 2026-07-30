#!/usr/bin/env bash

# Resolve and validate the Fortify license without printing its path or content.
# Call this after loading .env so existing installations retain the historical
# secrets/input/fortify.license default.
fortify_resolve_license_file() {
    local configured_path
    configured_path="${FORTIFY_LICENSE_FILE:-${FORTIFY_SECRETS_INPUT}/fortify.license}"

    if [ ! -f "$configured_path" ] || [ ! -r "$configured_path" ] || [ ! -s "$configured_path" ]; then
        printf '%s\n' \
            "❌ The configured Fortify license file is missing, unreadable, empty, or not a regular file." \
            "   Set FORTIFY_LICENSE_FILE to a readable fortify.license file and retry." >&2
        return 1
    fi

    if ! FORTIFY_LICENSE_FILE="$(realpath -- "$configured_path")"; then
        printf '%s\n' \
            "❌ The configured Fortify license file could not be resolved." \
            "   Set FORTIFY_LICENSE_FILE to a readable fortify.license file and retry." >&2
        return 1
    fi
    export FORTIFY_LICENSE_FILE
}
