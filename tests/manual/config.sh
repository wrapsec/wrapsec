#!/usr/bin/env bash
# =============================================================================
# WrapSec Manual Test Suite - Configuration
# =============================================================================
# Edit the values below, then run: bash run_all.sh
#
# All values can also be set as environment variables before running:
#   export WRAPSEC_URL=http://my-instance:8000
#   export WRAPSEC_API_KEY=wsk_live_...
#   bash run_all.sh
# =============================================================================

# Base URL of your WrapSec instance
WRAPSEC_URL="${WRAPSEC_URL:-http://localhost:8000}"

# API key for scan, audit, settings (read), and keys (read)
# Must be a live key: wsk_live_...
WRAPSEC_API_KEY="${WRAPSEC_API_KEY:-wsk_live_changeme}"

# Default request timeout in seconds
WRAPSEC_TIMEOUT="${WRAPSEC_TIMEOUT:-30}"

# ----------------------------------------------------------------------------
# Admin JWT (optional)
# Required only for: PUT /v1/settings/*, POST /v1/keys, DELETE /v1/keys/*
# To obtain:
#   curl -s -X POST $WRAPSEC_URL/v1/auth/login \
#        -H "Content-Type: application/json" \
#        -d '{"email":"admin@example.com","password":"yourpassword"}' \
#        | jq -r '.access_token'
# ----------------------------------------------------------------------------
WRAPSEC_ADMIN_JWT="${WRAPSEC_ADMIN_JWT:-}"

# ----------------------------------------------------------------------------
# Test toggles
# Set to "true" to skip sections that need specific configuration
# ----------------------------------------------------------------------------

# Skip proxy endpoint tests (POST /v1/chat/completions)
# Set to true if no LLM provider (OpenAI, Ollama, etc.) is configured
SKIP_PROXY_TESTS="${SKIP_PROXY_TESTS:-true}"

# Skip admin-only write tests (requires WRAPSEC_ADMIN_JWT)
SKIP_ADMIN_TESTS="${SKIP_ADMIN_TESTS:-true}"

# Skip Python SDK tests (requires: pip install -e sdk/python/)
SKIP_SDK_TESTS="${SKIP_SDK_TESTS:-false}"

# Skip CLI tests (requires: wrapsec command in PATH)
SKIP_CLI_TESTS="${SKIP_CLI_TESTS:-false}"

# Print curl request/response bodies for failed tests
VERBOSE="${VERBOSE:-false}"

# Delay between tests in milliseconds (0 = no delay)
TEST_DELAY_MS="${TEST_DELAY_MS:-0}"
