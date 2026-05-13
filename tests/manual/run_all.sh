#!/usr/bin/env bash
# =============================================================================
# WrapSec Manual Test Suite - Run All Tests
#
# Usage:
#   bash tests/manual/run_all.sh
#
# With overrides:
#   WRAPSEC_URL=http://myhost:8000 WRAPSEC_API_KEY=wsk_live_... bash tests/manual/run_all.sh
#
# Skip options (environment variables):
#   SKIP_PROXY_TESTS=false    Run proxy tests (needs configured LLM provider)
#   SKIP_ADMIN_TESTS=false    Run admin write tests (needs WRAPSEC_ADMIN_JWT)
#   SKIP_SDK_TESTS=false      Run Python SDK tests
#   SKIP_CLI_TESTS=false      Run CLI tests (needs wrapsec in PATH)
#   VERBOSE=true              Show response bodies on failure
#   TEST_DELAY_MS=200         Add delay between requests (e.g. for rate limiting)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/lib/common.sh"

# Colors for run_all output (different from per-test colors)
BOLD='\033[1m'
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'

GRAND_PASS=0
GRAND_FAIL=0
GRAND_SKIP=0

START_TIME=$(date +%s)

# ----------------------------------------------------------------------------

print_header() {
    echo ""
    echo -e "${BOLD}${CYAN}============================================================${NC}"
    echo -e "${BOLD}${CYAN}  WrapSec Manual Test Suite${NC}"
    echo -e "${BOLD}${CYAN}  Target: ${WRAPSEC_URL}${NC}"
    echo -e "${BOLD}${CYAN}============================================================${NC}"
    echo ""
    echo "  Proxy tests:  $([ "${SKIP_PROXY_TESTS}" == "true" ] && echo "SKIP" || echo "RUN")"
    echo "  Admin tests:  $([ "${SKIP_ADMIN_TESTS}" == "true" ] && echo "SKIP" || echo "RUN")"
    echo "  SDK tests:    $([ "${SKIP_SDK_TESTS}" == "true" ] && echo "SKIP" || echo "RUN")"
    echo "  CLI tests:    $([ "${SKIP_CLI_TESTS}" == "true" ] && echo "SKIP" || echo "RUN")"
    echo ""
}

run_script() {
    local label="$1"
    local script="$2"

    if [[ ! -f "$script" ]]; then
        echo -e "  ${YELLOW}SKIP${NC}  $label  (script not found: $script)"
        GRAND_SKIP=$((GRAND_SKIP + 1))
        return
    fi

    echo -e "${BOLD}Running: $label${NC}"
    echo "  Script: $script"

    # Run script in subshell — captures PASS/FAIL/SKIP counts from output
    # We re-use the counter variables exported by common.sh section_summary
    PASS_COUNT=0 FAIL_COUNT=0 SKIP_COUNT=0
    export PASS_COUNT FAIL_COUNT SKIP_COUNT

    bash "$script"
    local exit_code=$?

    # Parse counts from exported variables (common.sh increments them in-process)
    # Since we run in a subshell, we parse from output instead
    # Re-run to get counts — just read from the last section_summary line
    # For simplicity, track via temp file approach

    echo ""
}

run_script_counted() {
    local label="$1"
    local script="$2"

    if [[ ! -f "$script" ]]; then
        echo -e "  ${YELLOW}MISS${NC}  $label  (script not found)"
        return
    fi

    echo -e "${BOLD}--------------------------------------------------------------${NC}"
    echo -e "${BOLD}$label${NC}"
    echo -e "${BOLD}--------------------------------------------------------------${NC}"

    # Run in a subshell and capture output + counts
    local tmpout
    tmpout=$(mktemp /tmp/wrapsec_test_XXXXXX.txt)

    bash "$script" 2>&1 | tee "$tmpout"
    local exit_code=${PIPESTATUS[0]}

    # Count PASS/FAIL/SKIP from output
    local p f s
    p=$(grep -c "  PASS  " "$tmpout" 2>/dev/null || echo 0)
    f=$(grep -c "  FAIL  " "$tmpout" 2>/dev/null || echo 0)
    s=$(grep -c "  SKIP  " "$tmpout" 2>/dev/null || echo 0)

    GRAND_PASS=$((GRAND_PASS + p))
    GRAND_FAIL=$((GRAND_FAIL + f))
    GRAND_SKIP=$((GRAND_SKIP + s))

    rm -f "$tmpout"
}

# ----------------------------------------------------------------------------

print_header

# API Tests
run_script_counted "API: Health Endpoints"     "$SCRIPT_DIR/api/01_health.sh"
run_script_counted "API: Scan Endpoint"        "$SCRIPT_DIR/api/02_scan.sh"
run_script_counted "API: Audit Endpoints"      "$SCRIPT_DIR/api/03_audit.sh"
run_script_counted "API: Proxy Endpoint"       "$SCRIPT_DIR/api/04_proxy.sh"
run_script_counted "API: Settings Endpoints"   "$SCRIPT_DIR/api/05_settings.sh"
run_script_counted "API: Key Endpoints"        "$SCRIPT_DIR/api/06_keys.sh"

# CLI Tests
if [[ "${SKIP_CLI_TESTS}" != "true" ]]; then
    run_script_counted "CLI: Config"           "$SCRIPT_DIR/cli/01_config.sh"
    run_script_counted "CLI: Health / Doctor"  "$SCRIPT_DIR/cli/02_health.sh"
    run_script_counted "CLI: Scan"             "$SCRIPT_DIR/cli/03_scan.sh"
    run_script_counted "CLI: Batch"            "$SCRIPT_DIR/cli/04_batch.sh"
    run_script_counted "CLI: Audit"            "$SCRIPT_DIR/cli/05_audit.sh"
    run_script_counted "CLI: Settings"         "$SCRIPT_DIR/cli/06_settings.sh"
    run_script_counted "CLI: Keys"             "$SCRIPT_DIR/cli/07_keys.sh"
else
    echo ""
    echo -e "  ${YELLOW}Skipping CLI tests (SKIP_CLI_TESTS=true)${NC}"
fi

# SDK Tests
if [[ "${SKIP_SDK_TESTS}" != "true" ]]; then
    echo ""
    echo -e "${BOLD}--------------------------------------------------------------${NC}"
    echo -e "${BOLD}SDK: Python SDK${NC}"
    echo -e "${BOLD}--------------------------------------------------------------${NC}"

    if command -v python3 &>/dev/null; then
        tmpout=$(mktemp /tmp/wrapsec_test_XXXXXX.txt)
        WRAPSEC_API_KEY="${WRAPSEC_API_KEY}" WRAPSEC_URL="${WRAPSEC_URL}" \
            python3 "$SCRIPT_DIR/sdk/test_python.py" 2>&1 | tee "$tmpout"

        p=$(grep -c "  PASS  " "$tmpout" 2>/dev/null || echo 0)
        f=$(grep -c "  FAIL  " "$tmpout" 2>/dev/null || echo 0)
        s=$(grep -c "  SKIP  " "$tmpout" 2>/dev/null || echo 0)

        GRAND_PASS=$((GRAND_PASS + p))
        GRAND_FAIL=$((GRAND_FAIL + f))
        GRAND_SKIP=$((GRAND_SKIP + s))
        rm -f "$tmpout"
    else
        echo -e "  ${YELLOW}SKIP${NC}  Python SDK tests (python3 not found)"
        GRAND_SKIP=$((GRAND_SKIP + 1))
    fi
else
    echo ""
    echo -e "  ${YELLOW}Skipping SDK tests (SKIP_SDK_TESTS=true)${NC}"
fi

# ----------------------------------------------------------------------------

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo -e "${BOLD}${CYAN}============================================================${NC}"
echo -e "${BOLD}  Grand Total${NC}"
echo -e "${BOLD}${CYAN}============================================================${NC}"
echo ""
echo -e "  Passed:  ${GREEN}${GRAND_PASS}${NC}"
echo -e "  Failed:  ${RED}${GRAND_FAIL}${NC}"
echo -e "  Skipped: ${YELLOW}${GRAND_SKIP}${NC}"
echo ""
echo "  Elapsed: ${ELAPSED}s"
echo ""

if [[ "$GRAND_FAIL" -gt 0 ]]; then
    echo -e "  ${RED}RESULT: FAILED${NC}  ($GRAND_FAIL test(s) failed)"
    exit 1
else
    echo -e "  ${GREEN}RESULT: PASSED${NC}"
    exit 0
fi
