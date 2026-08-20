#!/usr/bin/env bash
# Materialise the Prometheus scrape credential.
#
# Prometheus does not interpolate environment variables into its config file,
# so the bearer token for /metrics has to reach it as a file. This script reads
# the token from .env and writes it to a gitignored file that the prometheus
# service bind-mounts read-only.
#
# The precedence mirrors api/main.py exactly: METRICS_TOKEN if set, otherwise
# ADMIN_API_KEY. If neither is set the API fails closed and every scrape would
# return 401, so this script fails loudly rather than writing an empty file.
#
# Run from the repository root. Idempotent.

set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
OUT_FILE="${OUT_FILE:-infrastructure/prometheus/metrics_token}"

if [ ! -f "$ENV_FILE" ]; then
    echo "write_metrics_token: $ENV_FILE not found" >&2
    exit 1
fi

# A key that is absent makes grep exit 1, which under `pipefail` would abort the
# whole script before the ADMIN_API_KEY fallback could run. Absence is a normal
# case here, so swallow it and let the emptiness check below decide.
# The \r strip matters: a .env written on Windows has CRLF endings, and a token
# carrying a trailing carriage return fails the constant-time comparison in the
# API with an indistinguishable 401.
read_env() {
    grep "^${1}=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r' | tr -d '"' | tr -d "'" || true
}

TOKEN=$(read_env METRICS_TOKEN)
[ -z "$TOKEN" ] && TOKEN=$(read_env ADMIN_API_KEY)

if [ -z "$TOKEN" ]; then
    echo "write_metrics_token: neither METRICS_TOKEN nor ADMIN_API_KEY is set in $ENV_FILE." >&2
    echo "  /metrics fails closed without one, so Prometheus could not scrape." >&2
    echo "  Generate: python -c \"import secrets; print(secrets.token_hex(32))\"" >&2
    exit 1
fi

# A bind-mount source that does not exist is created by the daemon as a
# DIRECTORY, which Prometheus then fails to read as a credentials file. Always
# write the file before the stack starts.
mkdir -p "$(dirname "$OUT_FILE")"
printf '%s' "$TOKEN" > "$OUT_FILE"

# 0644, not 0600: the upstream image runs Prometheus as nobody (uid 65534), so a
# file owned by the invoking user and readable only by them is a permission
# denied at scrape time. The bind mount is read-only and the containing host
# directory is the operator's to protect. This is the reason .env.example asks
# for a dedicated METRICS_TOKEN -- with the ADMIN_API_KEY fallback, this file
# holds a full admin credential instead of a metrics-only one.
chmod 644 "$OUT_FILE"
