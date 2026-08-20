#!/usr/bin/env bash
# =============================================================================
# CLI Tests: wrapsec audit
# wrapsec audit list   [--decision] [--reason] [--mode] [--from] [--to]
#                      [--limit] [--offset] [--json]
# wrapsec audit get    TRACE_ID [--json]
# wrapsec audit stats  [--from] [--to] [--json]
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

if [[ "${SKIP_CLI_TESTS}" == "true" ]]; then
    section "CLI Audit Tests (SKIPPED)"
    skip "wrapsec audit" "SKIP_CLI_TESTS=true"
    section_summary
    exit 0
fi

if ! command -v wrapsec &>/dev/null; then
    section "CLI Audit Tests (SKIPPED)"
    skip "wrapsec audit" "wrapsec not found in PATH"
    section_summary
    exit 0
fi

wrapsec config set api_key "${WRAPSEC_API_KEY}" >/dev/null 2>&1
wrapsec config set base_url "${WRAPSEC_URL}" >/dev/null 2>&1

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit list (basic)"

OUTPUT=$(wrapsec audit list 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit list --decision BLOCK"

OUTPUT=$(wrapsec audit list --decision BLOCK --limit 10 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list --decision BLOCK exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit list --decision ALLOW"

OUTPUT=$(wrapsec audit list --decision ALLOW --limit 10 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list --decision ALLOW exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit list --decision SANITIZE"

OUTPUT=$(wrapsec audit list --decision SANITIZE --limit 10 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list --decision SANITIZE exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit list --mode scan_only"

OUTPUT=$(wrapsec audit list --mode scan_only --limit 10 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list --mode scan_only exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit list --mode proxy"

OUTPUT=$(wrapsec audit list --mode proxy --limit 10 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list --mode proxy exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit list --limit and --offset"

OUTPUT=$(wrapsec audit list --limit 5 --offset 0 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list --limit 5 exits 0" "0" "$EXIT_CODE"

OUTPUT=$(wrapsec audit list --limit 5 --offset 5 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list --limit 5 --offset 5 exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit list --from and --to"

OUTPUT=$(wrapsec audit list --from "2026-01-01" --to "2030-12-31" --limit 5 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list --from/--to exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit list --reason filter"

OUTPUT=$(wrapsec audit list --reason "NO_THREAT_DETECTED" --limit 10 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list --reason exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit list --json output"

OUTPUT=$(wrapsec audit list --json --limit 5 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list --json exits 0" "0" "$EXIT_CODE"

# Must be a valid JSON array
if echo "$OUTPUT" | jq -e '. | type == "array"' &>/dev/null; then
    pass "audit list --json produces a JSON array"
else
    fail "audit list --json produces a JSON array" "output: ${OUTPUT:0:200}"
fi

# If array has items, check fields
ITEM_COUNT=$(echo "$OUTPUT" | jq 'length' 2>/dev/null || echo "0")
if [[ "$ITEM_COUNT" -ge 1 ]]; then
    if echo "$OUTPUT" | jq -e '.[0].trace_id' &>/dev/null; then
        pass "audit list --json items have trace_id"
    else
        fail "audit list --json items have trace_id" "missing trace_id"
    fi
    if echo "$OUTPUT" | jq -e '.[0].decision' &>/dev/null; then
        pass "audit list --json items have decision"
    else
        fail "audit list --json items have decision" "missing decision"
    fi
fi

# Extract a trace_id for the get test
TRACE_ID=$(wrapsec audit list --json --limit 1 2>&1 | jq -r '.[0].trace_id // empty' 2>/dev/null || true)

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit get TRACE_ID"

if [[ -n "${TRACE_ID}" ]]; then
    OUTPUT=$(wrapsec audit get "$TRACE_ID" 2>&1)
    EXIT_CODE=$?
    assert_exit_code "audit get exits 0" "0" "$EXIT_CODE"
    if echo "$OUTPUT" | grep -q "Decision\|ALLOW\|BLOCK\|SANITIZE"; then
        pass "audit get output contains decision"
    else
        fail "audit get output contains decision" "output: $OUTPUT"
    fi
    if echo "$OUTPUT" | grep -q "Trace ID\|trace_id\|$TRACE_ID"; then
        pass "audit get output contains trace_id"
    else
        fail "audit get output contains trace_id" "output: $OUTPUT"
    fi
else
    skip "audit get by trace_id" "no trace_id from audit list (run scan tests first)"
fi

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit get TRACE_ID --json"

if [[ -n "${TRACE_ID}" ]]; then
    OUTPUT=$(wrapsec audit get "$TRACE_ID" --json 2>&1)
    EXIT_CODE=$?
    assert_exit_code "audit get --json exits 0" "0" "$EXIT_CODE"
    if echo "$OUTPUT" | jq -e '.decision' &>/dev/null; then
        pass "audit get --json produces valid JSON with .decision"
    else
        fail "audit get --json produces valid JSON with .decision" "output: $OUTPUT"
    fi
else
    skip "audit get by trace_id --json" "no trace_id available"
fi

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit get unknown trace_id exits 1"

OUTPUT=$(wrapsec audit get "req_doesnotexist0000" 2>&1)
EXIT_CODE=$?
if [[ "$EXIT_CODE" -ne 0 ]]; then
    pass "audit get unknown trace_id exits non-zero"
else
    fail "audit get unknown trace_id exits non-zero" "got exit code 0"
fi

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit stats"

OUTPUT=$(wrapsec audit stats 2>&1)
EXIT_CODE=$?
assert_exit_code "audit stats exits 0" "0" "$EXIT_CODE"
if echo "$OUTPUT" | grep -qE "Total|total|request|block|allow"; then
    pass "audit stats output contains summary data"
else
    fail "audit stats output contains summary data" "output: $OUTPUT"
fi

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit stats --from/--to"

OUTPUT=$(wrapsec audit stats --from "2026-01-01" --to "2030-12-31" 2>&1)
EXIT_CODE=$?
assert_exit_code "audit stats --from/--to exits 0" "0" "$EXIT_CODE"

# ----------------------------------------------------------------------------
section "Audit CLI - wrapsec audit stats --json"

OUTPUT=$(wrapsec audit stats --json 2>&1)
EXIT_CODE=$?
assert_exit_code "audit stats --json exits 0" "0" "$EXIT_CODE"
if echo "$OUTPUT" | jq -e '.total_requests' &>/dev/null; then
    pass "audit stats --json has total_requests"
else
    fail "audit stats --json has total_requests" "output: $OUTPUT"
fi
if echo "$OUTPUT" | jq -e '.block_rate' &>/dev/null; then
    pass "audit stats --json has block_rate"
else
    fail "audit stats --json has block_rate" "output: $OUTPUT"
fi

# ----------------------------------------------------------------------------
section "Audit CLI - no API key configured exits 1"

OUTPUT=$(WRAPSEC_API_KEY="" wrapsec audit list 2>&1)
EXIT_CODE=$?
assert_exit_code "audit list without API key exits 1" "1" "$EXIT_CODE"

section_summary
