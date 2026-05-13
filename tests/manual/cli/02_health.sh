#!/usr/bin/env bash
# =============================================================================
# CLI Tests: wrapsec ping / wrapsec doctor
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

if [[ "${SKIP_CLI_TESTS}" == "true" ]]; then
    section "CLI Tests (SKIPPED)"
    skip "wrapsec ping / doctor" "SKIP_CLI_TESTS=true"
    section_summary
    exit 0
fi

if ! command -v wrapsec &>/dev/null; then
    section "CLI Tests (SKIPPED)"
    skip "wrapsec ping / doctor" "wrapsec not found in PATH"
    section_summary
    exit 0
fi

# Ensure API key is set
wrapsec config set api_key "${WRAPSEC_API_KEY}" >/dev/null 2>&1
wrapsec config set base_url "${WRAPSEC_URL}" >/dev/null 2>&1

# ----------------------------------------------------------------------------
section "CLI - wrapsec ping"

OUTPUT=$(wrapsec ping 2>&1)
EXIT_CODE=$?
assert_exit_code "wrapsec ping exits 0" "0" "$EXIT_CODE"
if echo "$OUTPUT" | grep -qiE "ok|alive|connected|pong|healthy"; then
    pass "wrapsec ping output indicates healthy"
else
    fail "wrapsec ping output indicates healthy" "output: $OUTPUT"
fi

# ----------------------------------------------------------------------------
section "CLI - wrapsec doctor"

OUTPUT=$(wrapsec doctor 2>&1)
EXIT_CODE=$?
# Doctor may exit 0 (all checks pass) or 1 (some warning) — both acceptable
if [[ "$EXIT_CODE" -eq 0 ]] || [[ "$EXIT_CODE" -eq 1 ]]; then
    pass "wrapsec doctor exits 0 or 1"
else
    fail "wrapsec doctor exits 0 or 1" "got exit code $EXIT_CODE"
fi

# Doctor output should contain connectivity and config checks
if echo "$OUTPUT" | grep -qiE "api.key|connect|health|check|config"; then
    pass "wrapsec doctor output shows checks"
else
    fail "wrapsec doctor output shows checks" "output: $OUTPUT"
fi

section_summary
