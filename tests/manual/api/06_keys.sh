#!/usr/bin/env bash
# =============================================================================
# API Tests: API Key Endpoints
# GET    /v1/keys
# GET    /v1/keys/{key_id}
# POST   /v1/keys         (admin only)
# PUT    /v1/keys/{key_id} (admin only)
# DELETE /v1/keys/{key_id} (admin only)
# POST   /v1/keys/{key_id}/rotate (admin only)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

check_deps

AUTH="$(api_key_header)"

# ----------------------------------------------------------------------------
section "Keys - GET /v1/keys"

http_get "${WRAPSEC_URL}/v1/keys" "$AUTH"
assert_status "GET /v1/keys returns 200" "200"
assert_json_present "keys array present" ".keys"

FIRST_KEY_ID=$(jq -r '.keys[0].key_id // empty' "$RESP_BODY" 2>/dev/null || true)
test_delay

# Schema check if keys exist
KEY_COUNT=$(jq '.keys | length' "$RESP_BODY" 2>/dev/null || echo "0")
if [[ "$KEY_COUNT" -ge 1 ]]; then
    assert_json_present "first key key_id present"    ".keys[0].key_id"
    assert_json_present "first key name present"      ".keys[0].name"
    assert_json_present "first key key_type present"  ".keys[0].key_type"
    assert_json_present "first key created_at present" ".keys[0].created_at"
    # key secret must NEVER be present
    SECRET=$(jq -r '.keys[0].api_key // "absent"' "$RESP_BODY" 2>/dev/null)
    if [[ "$SECRET" == "absent" ]] || [[ "$SECRET" == "null" ]]; then
        pass "api_key (secret) not present in list response"
    else
        fail "api_key (secret) not present in list response" "key secret was exposed!"
    fi
else
    skip "keys list schema check" "no keys returned"
fi
test_delay

# ----------------------------------------------------------------------------
section "Keys - GET /v1/keys/{key_id}"

if [[ -n "${FIRST_KEY_ID}" ]]; then
    http_get "${WRAPSEC_URL}/v1/keys/${FIRST_KEY_ID}" "$AUTH"
    assert_status "GET /v1/keys/${FIRST_KEY_ID} returns 200" "200"
    assert_json_eq "key_id matches" ".key_id" "$FIRST_KEY_ID"
    assert_json_present "name present"      ".name"
    assert_json_present "key_type present"  ".key_type"
    assert_json_present "is_admin present"  ".is_admin"
    assert_json_present "revoked present"   ".revoked"
    assert_json_present "created_at present" ".created_at"
    # Secret must NOT be returned
    SECRET=$(jq -r '.api_key // "absent"' "$RESP_BODY" 2>/dev/null)
    if [[ "$SECRET" == "absent" ]] || [[ "$SECRET" == "null" ]]; then
        pass "api_key (secret) not present in single key response"
    else
        fail "api_key (secret) not present in single key response" "key secret was exposed!"
    fi
    test_delay
else
    skip "GET /v1/keys/{key_id}" "no key_id available from list"
fi

# Non-existent key
http_get "${WRAPSEC_URL}/v1/keys/key_doesnotexist00" "$AUTH"
if [[ "$HTTP_STATUS" == "404" ]] || [[ "$HTTP_STATUS" == "403" ]]; then
    pass "GET /v1/keys/{unknown} returns 404 or 403"
else
    fail "GET /v1/keys/{unknown} returns 404 or 403" "got HTTP $HTTP_STATUS"
fi
test_delay

# ----------------------------------------------------------------------------
section "Keys - Authentication checks"

http_get "${WRAPSEC_URL}/v1/keys"
assert_status "GET /v1/keys without key returns 401" "401"
test_delay

# ----------------------------------------------------------------------------
section "Keys - POST/PUT/DELETE require admin JWT"

if [[ "${SKIP_ADMIN_TESTS}" == "true" ]]; then
    skip "POST /v1/keys (create)"              "SKIP_ADMIN_TESTS=true"
    skip "PUT /v1/keys/{key_id} (rename)"      "SKIP_ADMIN_TESTS=true"
    skip "POST /v1/keys/{key_id}/rotate"       "SKIP_ADMIN_TESTS=true"
    skip "DELETE /v1/keys/{key_id} (revoke)"   "SKIP_ADMIN_TESTS=true"
else
    ADMIN_JWT="$(admin_jwt_header)"
    TEST_KEY_NAME="test-key-$(date +%s)"

    # POST - create key
    BODY=$(jq -n --arg name "$TEST_KEY_NAME" '{name: $name, key_type: "live"}')
    http_post "${WRAPSEC_URL}/v1/keys" "$BODY" "$ADMIN_JWT"
    assert_status "POST /v1/keys returns 201" "201"
    assert_json_present "key_id present"   ".key_id"
    assert_json_present "api_key present"  ".api_key"
    assert_json_eq "key_type is live"      ".key_type" "live"
    NEW_KEY_ID=$(jq -r '.key_id' "$RESP_BODY" 2>/dev/null || true)
    NEW_API_KEY=$(jq -r '.api_key' "$RESP_BODY" 2>/dev/null || true)
    echo "  Created key: $NEW_KEY_ID"
    test_delay

    # Verify the new key works
    if [[ -n "${NEW_API_KEY}" ]] && [[ "$NEW_API_KEY" != "null" ]]; then
        http_get "${WRAPSEC_URL}/health" "x-api-key: ${NEW_API_KEY}"
        assert_status "new key works for /health" "200"
        test_delay
    fi

    # POST - create trial key
    BODY=$(jq -n '{name: "test-trial-key", key_type: "trial"}')
    http_post "${WRAPSEC_URL}/v1/keys" "$BODY" "$ADMIN_JWT"
    assert_status "POST /v1/keys (trial) returns 201" "201"
    TRIAL_KEY_ID=$(jq -r '.key_id' "$RESP_BODY" 2>/dev/null || true)
    test_delay

    # POST - invalid key_type
    BODY='{"name": "bad-key", "key_type": "premium"}'
    http_post "${WRAPSEC_URL}/v1/keys" "$BODY" "$ADMIN_JWT"
    if [[ "$HTTP_STATUS" == "422" ]] || [[ "$HTTP_STATUS" == "400" ]]; then
        pass "invalid key_type rejected with 4xx"
    else
        fail "invalid key_type rejected with 4xx" "got HTTP $HTTP_STATUS"
    fi
    test_delay

    # PUT - rename key
    if [[ -n "${NEW_KEY_ID}" ]] && [[ "$NEW_KEY_ID" != "null" ]]; then
        BODY=$(jq -n '{name: "renamed-test-key"}')
        http_put "${WRAPSEC_URL}/v1/keys/${NEW_KEY_ID}" "$BODY" "$ADMIN_JWT"
        assert_status "PUT /v1/keys/${NEW_KEY_ID} returns 200" "200"
        assert_json_eq "name updated" ".name" "renamed-test-key"
        test_delay
    fi

    # POST /{key_id}/rotate
    if [[ -n "${NEW_KEY_ID}" ]] && [[ "$NEW_KEY_ID" != "null" ]]; then
        BODY='{"grace_period_minutes": 5}'
        http_post "${WRAPSEC_URL}/v1/keys/${NEW_KEY_ID}/rotate" "$BODY" "$ADMIN_JWT"
        assert_status "POST /v1/keys/${NEW_KEY_ID}/rotate returns 201" "201"
        assert_json_present "new_key_id present"      ".new_key_id"
        assert_json_present "new_api_key present"     ".new_api_key"
        assert_json_present "old_expires_at present"  ".old_expires_at"
        ROTATED_KEY_ID=$(jq -r '.new_key_id' "$RESP_BODY" 2>/dev/null || true)
        test_delay

        # Rotate again on same (already rotated) key should fail
        BODY='{"grace_period_minutes": 5}'
        http_post "${WRAPSEC_URL}/v1/keys/${NEW_KEY_ID}/rotate" "$BODY" "$ADMIN_JWT"
        if [[ "$HTTP_STATUS" == "400" ]]; then
            pass "rotating an already-rotated key returns 400"
        else
            fail "rotating an already-rotated key returns 400" "got HTTP $HTTP_STATUS"
        fi
        test_delay
    fi

    # DELETE - revoke trial key (cleanup)
    if [[ -n "${TRIAL_KEY_ID}" ]] && [[ "$TRIAL_KEY_ID" != "null" ]]; then
        http_delete "${WRAPSEC_URL}/v1/keys/${TRIAL_KEY_ID}" "$ADMIN_JWT"
        assert_status "DELETE /v1/keys/${TRIAL_KEY_ID} returns 200" "200"
        assert_json_eq "revoked is true" ".revoked" "true"
        assert_json_present "revoked_at present" ".revoked_at"
        test_delay
    fi

    # DELETE - cleanup rotated key
    if [[ -n "${ROTATED_KEY_ID}" ]] && [[ "$ROTATED_KEY_ID" != "null" ]]; then
        http_delete "${WRAPSEC_URL}/v1/keys/${ROTATED_KEY_ID}" "$ADMIN_JWT"
        assert_status "DELETE rotated key returns 200" "200"
        test_delay
    fi

    # DELETE - non-existent key
    http_delete "${WRAPSEC_URL}/v1/keys/key_doesnotexist00" "$ADMIN_JWT"
    if [[ "$HTTP_STATUS" == "404" ]] || [[ "$HTTP_STATUS" == "403" ]]; then
        pass "DELETE /v1/keys/{unknown} returns 404 or 403"
    else
        fail "DELETE /v1/keys/{unknown} returns 404 or 403" "got HTTP $HTTP_STATUS"
    fi
    test_delay
fi

# ----------------------------------------------------------------------------
section "Keys - POST/PUT/DELETE with api key (non-admin) returns 401 or 403"

BODY='{"name": "test"}'
http_post "${WRAPSEC_URL}/v1/keys" "$BODY" "$AUTH"
if [[ "$HTTP_STATUS" == "401" ]] || [[ "$HTTP_STATUS" == "403" ]]; then
    pass "POST /v1/keys with non-admin key returns 401 or 403"
else
    fail "POST /v1/keys with non-admin key returns 401 or 403" "got HTTP $HTTP_STATUS"
fi
test_delay

section_summary
