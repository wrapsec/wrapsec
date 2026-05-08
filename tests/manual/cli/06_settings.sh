#!/usr/bin/env bash
# =============================================================================
# CLI Tests: wrapsec settings get [--json]
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

if [[ "${SKIP_CLI_TESTS}" == "true" ]]; then
    section "CLI Settings Tests (SKIPPED)"
    skip "wrapsec settings" "SKIP_CLI_TESTS=true"
    section_summary
    exit 0
fi

if ! command -v wrapsec &>/dev/null; then
    section "CLI Settings Tests (SKIPPED)"
    skip "wrapsec settings" "wrapsec not found in PATH"
    section_summary
    exit 0
fi

wrapsec config set api_key "${WRAPSEC_API_KEY}" >/dev/null 2>&1
wrapsec config set base_url "${WRAPSEC_URL}" >/dev/null 2>&1

# ----------------------------------------------------------------------------
section "Settings CLI - wrapsec settings get"

OUTPUT=$(wrapsec settings get 2>&1)
EXIT_CODE=$?
assert_exit_code "settings get exits 0" "0" "$EXIT_CODE"
if echo "$OUTPUT" | grep -qiE "block|threshold|detection|layer|rate"; then
    pass "settings get output contains configuration data"
else
    fail "settings get output contains configuration data" "output: $OUTPUT"
fi

# ----------------------------------------------------------------------------
section "Settings CLI - wrapsec settings get --json"

OUTPUT=$(wrapsec settings get --json 2>&1)
EXIT_CODE=$?
assert_exit_code "settings get --json exits 0" "0" "$EXIT_CODE"
if echo "$OUTPUT" | jq . &>/dev/null; then
    pass "settings get --json produces valid JSON"
else
    fail "settings get --json produces valid JSON" "output: $OUTPUT"
fi

# Check expected structure
if echo "$OUTPUT" | jq -e '.thresholds' &>/dev/null; then
    pass "settings --json contains thresholds"
else
    fail "settings --json contains thresholds" "missing thresholds"
fi
if echo "$OUTPUT" | jq -e '.layers' &>/dev/null; then
    pass "settings --json contains layers"
else
    fail "settings --json contains layers" "missing layers"
fi
if echo "$OUTPUT" | jq -e '.llm' &>/dev/null; then
    pass "settings --json contains llm"
else
    fail "settings --json contains llm" "missing llm"
fi
if echo "$OUTPUT" | jq -e '.rate_limit' &>/dev/null; then
    pass "settings --json contains rate_limit"
else
    fail "settings --json contains rate_limit" "missing rate_limit"
fi

# ----------------------------------------------------------------------------
section "Settings CLI - no API key configured exits 1"

OUTPUT=$(WRAPSEC_API_KEY="" wrapsec settings get 2>&1)
EXIT_CODE=$?
assert_exit_code "settings get without API key exits 1" "1" "$EXIT_CODE"

section_summary
