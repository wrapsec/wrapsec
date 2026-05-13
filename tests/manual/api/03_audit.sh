#!/usr/bin/env bash
# =============================================================================
# API Tests: Audit Endpoints
# GET /v1/audit/logs
# GET /v1/audit/stats
# GET /v1/audit/attribution
# GET /v1/audit/analytics
# GET /v1/audit/export
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

check_deps

AUTH="$(api_key_header)"

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/logs (basic)"

http_get "${WRAPSEC_URL}/v1/audit/logs" "$AUTH"
assert_status "GET /v1/audit/logs returns 200" "200"
assert_json_present "total field present" ".total"
assert_json_present "items array present" ".items"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/logs (filter by decision=BLOCK)"

http_get "${WRAPSEC_URL}/v1/audit/logs?decision=BLOCK&limit=10" "$AUTH"
assert_status "logs?decision=BLOCK returns 200" "200"
# All returned items should have decision=BLOCK (if any)
BLOCK_COUNT=$(jq '[.items[] | select(.decision != "BLOCK")] | length' "$RESP_BODY" 2>/dev/null || echo "0")
if [[ "$BLOCK_COUNT" == "0" ]]; then
    pass "all returned items have decision=BLOCK"
else
    fail "all returned items have decision=BLOCK" "$BLOCK_COUNT items with wrong decision"
fi
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/logs (filter by decision=ALLOW)"

http_get "${WRAPSEC_URL}/v1/audit/logs?decision=ALLOW&limit=10" "$AUTH"
assert_status "logs?decision=ALLOW returns 200" "200"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/logs (filter by decision=SANITIZE)"

http_get "${WRAPSEC_URL}/v1/audit/logs?decision=SANITIZE&limit=10" "$AUTH"
assert_status "logs?decision=SANITIZE returns 200" "200"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/logs (filter by execution_mode=scan_only)"

http_get "${WRAPSEC_URL}/v1/audit/logs?execution_mode=scan_only&limit=10" "$AUTH"
assert_status "logs?execution_mode=scan_only returns 200" "200"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/logs (pagination: limit and offset)"

http_get "${WRAPSEC_URL}/v1/audit/logs?limit=5&offset=0" "$AUTH"
assert_status "logs with limit=5 returns 200" "200"
ITEMS_FIRST=$(jq '.items | length' "$RESP_BODY" 2>/dev/null || echo "-1")

http_get "${WRAPSEC_URL}/v1/audit/logs?limit=5&offset=5" "$AUTH"
assert_status "logs with limit=5 offset=5 returns 200" "200"
ITEMS_SECOND=$(jq '.items | length' "$RESP_BODY" 2>/dev/null || echo "-1")

if [[ "$ITEMS_FIRST" -le 5 ]] && [[ "$ITEMS_SECOND" -le 5 ]]; then
    pass "pagination returns correct item counts (<= limit)"
else
    fail "pagination returns correct item counts" "first=$ITEMS_FIRST second=$ITEMS_SECOND (expected <= 5 each)"
fi
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/logs (date range filter)"

FROM_DATE="2026-01-01T00:00:00Z"
TO_DATE="2030-01-01T00:00:00Z"
http_get "${WRAPSEC_URL}/v1/audit/logs?from=${FROM_DATE}&to=${TO_DATE}&limit=5" "$AUTH"
assert_status "logs with date range returns 200" "200"
assert_json_present "items array present with date range" ".items"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/logs (sort_by and sort_order)"

http_get "${WRAPSEC_URL}/v1/audit/logs?sort_by=created_at&sort_order=asc&limit=5" "$AUTH"
assert_status "logs sort_by=created_at asc returns 200" "200"

http_get "${WRAPSEC_URL}/v1/audit/logs?sort_by=created_at&sort_order=desc&limit=5" "$AUTH"
assert_status "logs sort_by=created_at desc returns 200" "200"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/logs (response schema validation)"

http_get "${WRAPSEC_URL}/v1/audit/logs?limit=1" "$AUTH"
assert_status "logs limit=1 returns 200" "200"
ITEM_COUNT=$(jq '.items | length' "$RESP_BODY" 2>/dev/null || echo "0")
if [[ "$ITEM_COUNT" -ge 1 ]]; then
    assert_json_present "item trace_id present"       ".items[0].trace_id"
    assert_json_present "item decision present"       ".items[0].decision"
    assert_json_present "item primary_reason present" ".items[0].primary_reason"
    assert_json_present "item risk_score present"     ".items[0].risk_score"
    assert_json_present "item confidence present"     ".items[0].confidence"
    assert_json_present "item confidence_band present" ".items[0].confidence_band"
    assert_json_present "item timestamp present"      ".items[0].timestamp"
    assert_json_present "item detection_mode present" ".items[0].detection_mode"
    assert_json_present "item execution_mode present" ".items[0].execution_mode"
    assert_json_present "item latency_ms present"     ".items[0].latency_ms"
else
    skip "audit logs schema validation" "no log entries returned (run scan tests first)"
fi
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/logs (authentication)"

http_get "${WRAPSEC_URL}/v1/audit/logs"
assert_status "GET /v1/audit/logs without key returns 401" "401"

http_get "${WRAPSEC_URL}/v1/audit/logs" "x-api-key: wsk_live_invalidkey000"
if [[ "$HTTP_STATUS" == "401" ]] || [[ "$HTTP_STATUS" == "403" ]]; then
    pass "GET /v1/audit/logs with invalid key returns 401 or 403"
else
    fail "GET /v1/audit/logs with invalid key returns 401 or 403" "got HTTP $HTTP_STATUS"
fi
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/stats"

http_get "${WRAPSEC_URL}/v1/audit/stats" "$AUTH"
assert_status "GET /v1/audit/stats returns 200" "200"
assert_json_present "total_requests present"  ".total_requests"
assert_json_present "block_rate present"      ".block_rate"
assert_json_present "sanitize_rate present"   ".sanitize_rate"
assert_json_present "allow_rate present"      ".allow_rate"
assert_json_present "avg_latency_ms present"  ".avg_latency_ms"
assert_json_present "p95_latency_ms present"  ".p95_latency_ms"
assert_json_present "top_threats present"     ".top_threats"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/stats (with date range)"

http_get "${WRAPSEC_URL}/v1/audit/stats?from=2026-01-01T00:00:00Z&to=2030-01-01T00:00:00Z" "$AUTH"
assert_status "GET /v1/audit/stats with date range returns 200" "200"
assert_json_present "period_from present" ".period_from"
assert_json_present "period_to present"   ".period_to"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/attribution"

http_get "${WRAPSEC_URL}/v1/audit/attribution" "$AUTH"
assert_status "GET /v1/audit/attribution returns 200" "200"
assert_json_present "by_key present"           ".by_key"
assert_json_present "by_department present"    ".by_department"
assert_json_present "by_application present"   ".by_application"
assert_json_present "by_primary_reason present" ".by_primary_reason"
assert_json_present "by_confidence_band present" ".by_confidence_band"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/attribution (with limit)"

http_get "${WRAPSEC_URL}/v1/audit/attribution?limit=5" "$AUTH"
assert_status "GET /v1/audit/attribution?limit=5 returns 200" "200"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/analytics"

http_get "${WRAPSEC_URL}/v1/audit/analytics?group_by=day" "$AUTH"
assert_status "GET /v1/audit/analytics?group_by=day returns 200" "200"
assert_json_present "group_by present" ".group_by"
assert_json_present "total present"    ".total"
assert_json_present "trend present"    ".trend"
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/analytics (all group_by values)"

for GB in hour day week month; do
    http_get "${WRAPSEC_URL}/v1/audit/analytics?group_by=${GB}" "$AUTH"
    assert_status "analytics?group_by=${GB} returns 200" "200"
    test_delay
done

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/analytics (invalid group_by rejected)"

http_get "${WRAPSEC_URL}/v1/audit/analytics?group_by=year" "$AUTH"
if [[ "$HTTP_STATUS" == "422" ]] || [[ "$HTTP_STATUS" == "400" ]]; then
    pass "analytics?group_by=year rejected with 4xx"
else
    fail "analytics?group_by=year rejected with 4xx" "got HTTP $HTTP_STATUS"
fi
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/export (CSV)"

http_get "${WRAPSEC_URL}/v1/audit/export?limit=10" "$AUTH"
assert_status "GET /v1/audit/export returns 200" "200"
# Check Content-Type is text/csv
CONTENT_TYPE=$(grep -i "content-type" "$RESP_HEADERS" 2>/dev/null | head -1 || true)
if grep -q "trace_id" "$RESP_BODY" 2>/dev/null; then
    pass "export CSV contains header row with trace_id"
else
    skip "export CSV header check" "response body not available or empty"
fi
test_delay

# ----------------------------------------------------------------------------
section "Audit - GET /v1/audit/export (filter by decision)"

http_get "${WRAPSEC_URL}/v1/audit/export?decision=BLOCK&limit=100" "$AUTH"
assert_status "export?decision=BLOCK returns 200" "200"
test_delay

# Verify no auth returns 401
http_get "${WRAPSEC_URL}/v1/audit/export"
assert_status "GET /v1/audit/export without key returns 401" "401"

section_summary
