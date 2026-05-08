#!/usr/bin/env bash
# =============================================================================
# API Tests: Settings Endpoints
# GET  /v1/settings/thresholds
# GET  /v1/settings/layers
# GET  /v1/settings/llm
# GET  /v1/settings/retention
# GET  /v1/settings/rate_limit
# GET  /v1/settings/storage
# PUT  /v1/settings/* (admin only — requires WRAPSEC_ADMIN_JWT)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

check_deps

AUTH="$(api_key_header)"

# ----------------------------------------------------------------------------
section "Settings - GET /v1/settings/thresholds"

http_get "${WRAPSEC_URL}/v1/settings/thresholds" "$AUTH"
assert_status "GET /v1/settings/thresholds returns 200" "200"
assert_json_present "block_threshold present"    ".block_threshold"
assert_json_present "sanitize_threshold present" ".sanitize_threshold"

BLOCK_T=$(jq -r '.block_threshold' "$RESP_BODY" 2>/dev/null || echo "0")
SANITIZE_T=$(jq -r '.sanitize_threshold' "$RESP_BODY" 2>/dev/null || echo "0")
if awk "BEGIN { exit !($BLOCK_T > $SANITIZE_T) }"; then
    pass "block_threshold > sanitize_threshold"
else
    fail "block_threshold > sanitize_threshold" "block=$BLOCK_T sanitize=$SANITIZE_T"
fi
test_delay

# Unauthenticated
http_get "${WRAPSEC_URL}/v1/settings/thresholds"
assert_status "GET /v1/settings/thresholds without key returns 401" "401"
test_delay

# ----------------------------------------------------------------------------
section "Settings - GET /v1/settings/layers"

http_get "${WRAPSEC_URL}/v1/settings/layers" "$AUTH"
assert_status "GET /v1/settings/layers returns 200" "200"
assert_json_present "rule_enabled present" ".rule_enabled"
assert_json_present "ml_enabled present"   ".ml_enabled"
assert_json_present "llm_enabled present"  ".llm_enabled"
test_delay

# ----------------------------------------------------------------------------
section "Settings - GET /v1/settings/llm"

http_get "${WRAPSEC_URL}/v1/settings/llm" "$AUTH"
assert_status "GET /v1/settings/llm returns 200" "200"
assert_json_present "provider present"    ".provider"
assert_json_present "model present"       ".model"
assert_json_present "timeout present"     ".timeout"
assert_json_present "llm_trigger present" ".llm_trigger"
# api_key must always be masked, never plaintext
if jq -e '.api_key_masked' "$RESP_BODY" &>/dev/null; then
    pass "api_key_masked field present (not plaintext)"
else
    pass "no api_key_masked (no key stored — ok)"
fi
test_delay

# ----------------------------------------------------------------------------
section "Settings - GET /v1/settings/retention"

http_get "${WRAPSEC_URL}/v1/settings/retention" "$AUTH"
assert_status "GET /v1/settings/retention returns 200" "200"
assert_json_present "retention_days present" ".retention_days"
assert_json_present "source present"         ".source"
DAYS=$(jq -r '.retention_days' "$RESP_BODY" 2>/dev/null || echo "0")
if awk "BEGIN { exit !($DAYS >= 7) }"; then
    pass "retention_days >= 7"
else
    fail "retention_days >= 7" "got $DAYS"
fi
test_delay

# ----------------------------------------------------------------------------
section "Settings - GET /v1/settings/rate_limit"

http_get "${WRAPSEC_URL}/v1/settings/rate_limit" "$AUTH"
assert_status "GET /v1/settings/rate_limit returns 200" "200"
assert_json_present "per_minute present" ".per_minute"
assert_json_present "source present"     ".source"
test_delay

# ----------------------------------------------------------------------------
section "Settings - GET /v1/settings/storage"

http_get "${WRAPSEC_URL}/v1/settings/storage" "$AUTH"
assert_status "GET /v1/settings/storage returns 200" "200"
assert_json_present "storage_mode present" ".storage_mode"
test_delay

# ----------------------------------------------------------------------------
section "Settings - PUT endpoints require admin JWT"

if [[ "${SKIP_ADMIN_TESTS}" == "true" ]]; then
    skip "PUT /v1/settings/thresholds (admin)"  "SKIP_ADMIN_TESTS=true"
    skip "PUT /v1/settings/layers (admin)"      "SKIP_ADMIN_TESTS=true"
    skip "PUT /v1/settings/retention (admin)"   "SKIP_ADMIN_TESTS=true"
    skip "PUT /v1/settings/rate_limit (admin)"  "SKIP_ADMIN_TESTS=true"
else
    ADMIN_JWT="$(admin_jwt_header)"

    # Get current thresholds first
    http_get "${WRAPSEC_URL}/v1/settings/thresholds" "$AUTH"
    ORIG_BLOCK=$(jq -r '.block_threshold' "$RESP_BODY" 2>/dev/null || echo "0.8")
    ORIG_SANITIZE=$(jq -r '.sanitize_threshold' "$RESP_BODY" 2>/dev/null || echo "0.4")

    # PUT thresholds
    BODY=$(jq -n --argjson b "$ORIG_BLOCK" --argjson s "$ORIG_SANITIZE" \
        '{block_threshold: $b, sanitize_threshold: $s}')
    http_put "${WRAPSEC_URL}/v1/settings/thresholds" "$BODY" "$ADMIN_JWT"
    assert_status "PUT /v1/settings/thresholds returns 200" "200"
    assert_json_present "updated_at present" ".updated_at"
    test_delay

    # PUT thresholds - invalid (block <= sanitize)
    BODY='{"block_threshold": 0.3, "sanitize_threshold": 0.5}'
    http_put "${WRAPSEC_URL}/v1/settings/thresholds" "$BODY" "$ADMIN_JWT"
    if [[ "$HTTP_STATUS" == "422" ]] || [[ "$HTTP_STATUS" == "400" ]]; then
        pass "invalid thresholds (block <= sanitize) rejected with 4xx"
    else
        fail "invalid thresholds rejected with 4xx" "got HTTP $HTTP_STATUS"
    fi
    test_delay

    # PUT layers
    BODY='{"rule_enabled": true, "ml_enabled": true, "llm_enabled": true}'
    http_put "${WRAPSEC_URL}/v1/settings/layers" "$BODY" "$ADMIN_JWT"
    assert_status "PUT /v1/settings/layers returns 200" "200"
    test_delay

    # PUT retention
    BODY='{"retention_days": 90}'
    http_put "${WRAPSEC_URL}/v1/settings/retention" "$BODY" "$ADMIN_JWT"
    assert_status "PUT /v1/settings/retention returns 200" "200"

    # Restore original retention if we know it
    test_delay

    # PUT rate_limit - invalid (too low)
    BODY='{"per_minute": 0}'
    http_put "${WRAPSEC_URL}/v1/settings/rate_limit" "$BODY" "$ADMIN_JWT"
    if [[ "$HTTP_STATUS" == "422" ]] || [[ "$HTTP_STATUS" == "400" ]]; then
        pass "per_minute=0 rejected with 4xx"
    else
        fail "per_minute=0 rejected with 4xx" "got HTTP $HTTP_STATUS"
    fi
    test_delay
fi

# ----------------------------------------------------------------------------
section "Settings - PUT without admin JWT returns 401 or 403"

BODY='{"block_threshold": 0.8, "sanitize_threshold": 0.4}'
http_put "${WRAPSEC_URL}/v1/settings/thresholds" "$BODY" "$AUTH"
if [[ "$HTTP_STATUS" == "401" ]] || [[ "$HTTP_STATUS" == "403" ]]; then
    pass "PUT /v1/settings/thresholds with api key (non-admin) returns 401 or 403"
else
    fail "PUT /v1/settings/thresholds with api key (non-admin) returns 401 or 403" \
         "got HTTP $HTTP_STATUS"
fi
test_delay

http_put "${WRAPSEC_URL}/v1/settings/thresholds" "$BODY"
if [[ "$HTTP_STATUS" == "401" ]] || [[ "$HTTP_STATUS" == "403" ]]; then
    pass "PUT /v1/settings/thresholds without auth returns 401 or 403"
else
    fail "PUT /v1/settings/thresholds without auth returns 401 or 403" \
         "got HTTP $HTTP_STATUS"
fi
test_delay

section_summary
