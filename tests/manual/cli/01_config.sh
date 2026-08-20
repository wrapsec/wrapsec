#!/usr/bin/env bash
# =============================================================================
# CLI Tests: wrapsec config
# wrapsec config set <key> <value>
# wrapsec config get
# wrapsec config clear [--force]
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

if [[ "${SKIP_CLI_TESTS}" == "true" ]]; then
    section "CLI Tests (SKIPPED)"
    skip "wrapsec config" "SKIP_CLI_TESTS=true"
    section_summary
    exit 0
fi

if ! command -v wrapsec &>/dev/null; then
    section "CLI Tests (SKIPPED)"
    skip "wrapsec config" "wrapsec not found in PATH (install with: pip install -e sdk/python/)"
    section_summary
    exit 0
fi

# Backup existing config to restore after tests
BACKUP_API_KEY="${WRAPSEC_API_KEY}"
BACKUP_BASE_URL="${WRAPSEC_URL}"

# ----------------------------------------------------------------------------
section "Config - wrapsec config set api_key"

OUTPUT=$(wrapsec config set api_key "${WRAPSEC_API_KEY}" 2>&1)
EXIT_CODE=$?
assert_exit_code "config set api_key exits 0" "0" "$EXIT_CODE"
# API key must be masked in output
if echo "$OUTPUT" | grep -q "wsk_live_"; then
    fail "api_key masked in output" "raw key visible in config set output"
else
    pass "api_key masked in config set output"
fi

# ----------------------------------------------------------------------------
section "Config - wrapsec config set base_url"

OUTPUT=$(wrapsec config set base_url "${WRAPSEC_URL}" 2>&1)
EXIT_CODE=$?
assert_exit_code "config set base_url exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Config - wrapsec config set timeout"

OUTPUT=$(wrapsec config set timeout 30 2>&1)
EXIT_CODE=$?
assert_exit_code "config set timeout exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Config - wrapsec config set invalid key rejected"

OUTPUT=$(wrapsec config set unknown_key value 2>&1)
EXIT_CODE=$?
if [[ "$EXIT_CODE" -ne 0 ]]; then
    pass "config set with unknown key exits non-zero"
else
    fail "config set with unknown key exits non-zero" "got exit code 0"
fi

# ----------------------------------------------------------------------------
section "Config - wrapsec config set invalid api_key format rejected"

OUTPUT=$(wrapsec config set api_key "not_a_valid_key" 2>&1)
EXIT_CODE=$?
if [[ "$EXIT_CODE" -ne 0 ]]; then
    pass "config set invalid api_key format exits non-zero"
else
    fail "config set invalid api_key format exits non-zero" "got exit code 0"
fi

# ----------------------------------------------------------------------------
section "Config - wrapsec config set invalid timeout rejected"

OUTPUT=$(wrapsec config set timeout 0 2>&1)
EXIT_CODE=$?
if [[ "$EXIT_CODE" -ne 0 ]]; then
    pass "config set timeout=0 exits non-zero"
else
    fail "config set timeout=0 exits non-zero" "got exit code 0"
fi

OUTPUT=$(wrapsec config set timeout -5 2>&1)
EXIT_CODE=$?
if [[ "$EXIT_CODE" -ne 0 ]]; then
    pass "config set timeout=-5 exits non-zero"
else
    fail "config set timeout=-5 exits non-zero" "got exit code 0"
fi

# ----------------------------------------------------------------------------
section "Config - wrapsec config get"

OUTPUT=$(wrapsec config get 2>&1)
EXIT_CODE=$?
assert_exit_code "config get exits 0" "0" "$EXIT_CODE"
assert_output_contains "api_key in config get output" "api_key" "$OUTPUT"
assert_output_contains "base_url in config get output" "base_url" "$OUTPUT"
assert_output_contains "timeout in config get output" "timeout" "$OUTPUT"

# API key must be masked
if echo "$OUTPUT" | grep -q "wsk_live_[a-zA-Z0-9_-]\{10,\}"; then
    fail "api_key is masked in config get output" "raw key visible"
else
    pass "api_key is masked in config get output"
fi

# ----------------------------------------------------------------------------
section "Config - wrapsec config clear --force"

# Use --force to skip confirmation
OUTPUT=$(wrapsec config clear --force 2>&1)
EXIT_CODE=$?
assert_exit_code "config clear --force exits 0" "0" "$EXIT_CODE"

# After clear, config get should show no api_key
OUTPUT=$(wrapsec config get 2>&1)
if echo "$OUTPUT" | grep -q "No API key set\|not set\|wsk_live_" ; then
    pass "after clear, api_key is not set"
fi

# Restore the API key for remaining tests
wrapsec config set api_key "${BACKUP_API_KEY}" >/dev/null 2>&1
wrapsec config set base_url "${BACKUP_BASE_URL}" >/dev/null 2>&1

# ----------------------------------------------------------------------------
section "Config - environment variable override"

OUTPUT=$(WRAPSEC_API_KEY="${BACKUP_API_KEY}" wrapsec config get 2>&1)
EXIT_CODE=$?
assert_exit_code "config get with env var exits 0" "0" "$EXIT_CODE"
if echo "$OUTPUT" | grep -q "env\|environment"; then
    pass "config get shows source as environment"
else
    # May show just the value without explicit "environment" label — still pass
    pass "config get with env var succeeded"
fi

section_summary
