#!/usr/bin/env bash
# =============================================================================
# CLI Tests: wrapsec keys list [--json]
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

if [[ "${SKIP_CLI_TESTS}" == "true" ]]; then
    section "CLI Keys Tests (SKIPPED)"
    skip "wrapsec keys" "SKIP_CLI_TESTS=true"
    section_summary
    exit 0
fi

if ! command -v wrapsec &>/dev/null; then
    section "CLI Keys Tests (SKIPPED)"
    skip "wrapsec keys" "wrapsec not found in PATH"
    section_summary
    exit 0
fi

wrapsec config set api_key "${WRAPSEC_API_KEY}" >/dev/null 2>&1
wrapsec config set base_url "${WRAPSEC_URL}" >/dev/null 2>&1

# ----------------------------------------------------------------------------
section "Keys CLI - wrapsec keys list"

OUTPUT=$(wrapsec keys list 2>&1)
EXIT_CODE=$?
assert_exit_code "keys list exits 0" "0" "$EXIT_CODE"

# API key secrets must NOT appear in output
if echo "$OUTPUT" | grep -qE "wsk_live_[a-zA-Z0-9_-]{20,}"; then
    fail "key secrets not exposed in keys list output" "raw key found in output"
else
    pass "key secrets not exposed in keys list output"
fi

# ----------------------------------------------------------------------------
section "Keys CLI - wrapsec keys list --json"

OUTPUT=$(wrapsec keys list --json 2>&1)
EXIT_CODE=$?
assert_exit_code "keys list --json exits 0" "0" "$EXIT_CODE"
if echo "$OUTPUT" | jq -e '. | type == "array"' &>/dev/null; then
    pass "keys list --json produces a JSON array"
else
    fail "keys list --json produces a JSON array" "output: ${OUTPUT:0:200}"
fi

# If keys exist, check that secret is not in any item
KEY_WITH_SECRET=$(echo "$OUTPUT" | jq -r '.[].api_key // empty' 2>/dev/null | head -1 || true)
if [[ -z "${KEY_WITH_SECRET}" ]]; then
    pass "no api_key secrets in keys list --json output"
else
    fail "no api_key secrets in keys list --json output" "api_key field exposed!"
fi

# Check schema of first key if available
KEY_COUNT=$(echo "$OUTPUT" | jq 'length' 2>/dev/null || echo "0")
if [[ "$KEY_COUNT" -ge 1 ]]; then
    if echo "$OUTPUT" | jq -e '.[0].key_id' &>/dev/null; then
        pass "keys list --json items have key_id"
    else
        fail "keys list --json items have key_id" "missing key_id"
    fi
    if echo "$OUTPUT" | jq -e '.[0].name' &>/dev/null; then
        pass "keys list --json items have name"
    else
        fail "keys list --json items have name" "missing name"
    fi
    if echo "$OUTPUT" | jq -e '.[0].created_at' &>/dev/null; then
        pass "keys list --json items have created_at"
    else
        fail "keys list --json items have created_at" "missing created_at"
    fi
fi

# ----------------------------------------------------------------------------
section "Keys CLI - no API key configured exits 1"

OUTPUT=$(WRAPSEC_API_KEY="" wrapsec keys list 2>&1)
EXIT_CODE=$?
assert_exit_code "keys list without API key exits 1" "1" "$EXIT_CODE"

section_summary
