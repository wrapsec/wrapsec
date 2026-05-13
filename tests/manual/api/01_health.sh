#!/usr/bin/env bash
# =============================================================================
# API Tests: Health Endpoints
# GET /health
# GET /health/live
# GET /health/ready
# GET /health/config
# GET /metrics
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

check_deps

section "Health - GET /health"

http_get "${WRAPSEC_URL}/health"
assert_status "GET /health returns 200" "200"
assert_json_eq "status is ok" ".status" "ok"
assert_json_present "version field present" ".version"

test_delay

section "Health - GET /health/live"

http_get "${WRAPSEC_URL}/health/live"
assert_status "GET /health/live returns 200" "200"
assert_json_eq "status is alive" ".status" "alive"

test_delay

section "Health - GET /health/ready"

http_get "${WRAPSEC_URL}/health/ready"
assert_status "GET /health/ready returns 200" "200"
assert_json_oneof "status is ready or degraded" ".status" "ready" "degraded"
assert_json_present "database check present" ".checks.database"
assert_json_present "redis check present" ".checks.redis"
assert_json_present "ml_model check present" ".checks.ml_model"

test_delay

section "Health - GET /health/config (requires API key)"

http_get "${WRAPSEC_URL}/health/config" "$(api_key_header)"
assert_status "GET /health/config returns 200" "200"
assert_json_present "thresholds.block present" ".thresholds.block"
assert_json_present "thresholds.sanitize present" ".thresholds.sanitize"
assert_json_present "detection_layers.rule present" ".detection_layers.rule"
assert_json_present "detection_layers.ml present" ".detection_layers.ml"
assert_json_present "rate_limit.per_minute present" ".rate_limit.per_minute"

test_delay

section "Health - Unauthenticated access to /health/config is rejected"

http_get "${WRAPSEC_URL}/health/config"
assert_status "GET /health/config without key returns 401 or 403" "401"

test_delay

section "Health - GET /metrics"

http_get "${WRAPSEC_URL}/metrics" "Authorization: Bearer ${WRAPSEC_API_KEY}"
# Metrics returns Prometheus text format, not JSON
if [[ "$HTTP_STATUS" == "200" ]]; then
    pass "GET /metrics with valid token returns 200"
else
    fail "GET /metrics with valid token returns 200" "got HTTP $HTTP_STATUS"
fi

test_delay

http_get "${WRAPSEC_URL}/metrics"
assert_status "GET /metrics without token returns 401" "401"

section_summary
