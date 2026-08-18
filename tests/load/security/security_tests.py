# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec Security Tests
======================
Not load tests - correctness tests run as part of pre-production checklist.
Each test is self-contained with clear PASS/FAIL output.

Tests:
  A. Cross-department isolation   - dept A key cannot see dept B data
  B. RBAC enforcement             - role boundaries enforced
  C. Trace ID leakage             - cross-dept trace lookup returns 404
  D. Trial key restrictions       - input cap, rate limit, proxy disabled

Usage:
  python tests/load/security/security_tests.py

Run from repo root. API must be running at localhost:8000.
"""

from __future__ import annotations

import os as _os
import sys
import time

import requests

BASE_URL         = "http://127.0.0.1:8000"
ADMIN_KEY        = _os.environ.get("WRAPSEC_ADMIN_KEY",        "")
PURCHASE_KEY     = _os.environ.get("WRAPSEC_PURCHASE_KEY",     "")
FINANCE_KEY      = _os.environ.get("WRAPSEC_FINANCE_KEY",      "")
TRIAL_KEY        = _os.environ.get("WRAPSEC_TRIAL_KEY",        "")
PURCHASE_DEPT_ID = _os.environ.get("WRAPSEC_PURCHASE_DEPT_ID", "")
FINANCE_DEPT_ID  = _os.environ.get("WRAPSEC_FINANCE_DEPT_ID",  "")

passed = 0
failed = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        print(f"  \033[92m[PASS]\033[0m {label}")
        passed += 1
    else:
        print(f"  \033[91m[FAIL]\033[0m {label}" + (f" -- {detail}" if detail else ""))
        failed += 1


def section(title: str) -> None:
    print(f"\n\033[96m-- {title}\033[0m")


def scan(key: str, prompt: str = "hello world", mode: str = "fast") -> requests.Response:
    return requests.post(
        f"{BASE_URL}/v1/ai/request",
        headers = {"x-api-key": key, "Content-Type": "application/json"},
        json    = {
            "input":          prompt,
            "detection_mode": mode,
            "metadata":       {"source": "security-test", "user_id": "test"},
        },
        timeout = 10,
    )


def audit_list(key: str, **params) -> requests.Response:
    return requests.get(
        f"{BASE_URL}/v1/audit/logs",
        headers = {"x-api-key": key},
        params  = params,
        timeout = 10,
    )


def audit_get(key: str, trace_id: str) -> requests.Response:
    return requests.get(
        f"{BASE_URL}/v1/ai/requests/{trace_id}",
        headers = {"x-api-key": key},
        timeout = 10,
    )


# == Test A: Cross-department isolation ========================================

def test_isolation() -> None:
    section("A. Cross-department isolation")

    # Purchase key creates a scan
    resp = scan(PURCHASE_KEY, "Purchase department test prompt")
    check("Purchase scan succeeds", resp.status_code == 200,
          f"status={resp.status_code}")
    if resp.status_code != 200:
        return
    purchase_trace = resp.json().get("trace_id")
    check("Purchase scan has trace_id", purchase_trace is not None)

    # Finance key creates a scan
    resp = scan(FINANCE_KEY, "Finance department test prompt")
    check("Finance scan succeeds", resp.status_code == 200,
          f"status={resp.status_code}")
    if resp.status_code != 200:
        return
    finance_trace = resp.json().get("trace_id")
    check("Finance scan has trace_id", finance_trace is not None)

    time.sleep(0.5)

    # Purchase key lists logs -- should only see own dept
    resp = audit_list(PURCHASE_KEY, limit=100)
    check("Purchase audit list succeeds", resp.status_code == 200)
    if resp.status_code == 200:
        items            = resp.json().get("items", [])
        dept_ids         = {i.get("dept_id") for i in items if i.get("dept_id")}
        finance_visible  = any(i.get("trace_id") == finance_trace for i in items)
        check("Purchase cannot see Finance logs", not finance_visible,
              f"Finance trace {finance_trace} visible in Purchase audit list")
        check("Purchase audit list scoped to own dept only",
              all(d == PURCHASE_DEPT_ID for d in dept_ids if d),
              f"Unexpected dept IDs: {dept_ids - {PURCHASE_DEPT_ID}}")

    # Finance key lists logs -- should only see own dept
    resp = audit_list(FINANCE_KEY, limit=100)
    check("Finance audit list succeeds", resp.status_code == 200)
    if resp.status_code == 200:
        items            = resp.json().get("items", [])
        purchase_visible = any(i.get("trace_id") == purchase_trace for i in items)
        check("Finance cannot see Purchase logs", not purchase_visible,
              f"Purchase trace {purchase_trace} visible in Finance audit list")

    # Admin key can see both
    resp = audit_list(ADMIN_KEY, limit=200)
    check("Admin audit list succeeds", resp.status_code == 200)
    if resp.status_code == 200:
        items     = resp.json().get("items", [])
        trace_ids = [i.get("trace_id") for i in items]
        check("Admin can see Purchase logs", purchase_trace in trace_ids,
              "Purchase trace not in admin audit list")
        check("Admin can see Finance logs",  finance_trace  in trace_ids,
              "Finance trace not in admin audit list")


# == Test B: RBAC enforcement ==================================================

def test_rbac() -> None:
    section("B. RBAC enforcement")

    # API key rejected on JWT-only endpoints
    resp = requests.get(f"{BASE_URL}/v1/auth/me",
                        headers={"x-api-key": PURCHASE_KEY}, timeout=5)
    check("API key rejected on /auth/me (JWT only)", resp.status_code == 403,
          f"status={resp.status_code}")

    resp = requests.get(f"{BASE_URL}/v1/admin/users",
                        headers={"x-api-key": PURCHASE_KEY}, timeout=5)
    check("API key rejected on /admin/users (JWT only)", resp.status_code == 403,
          f"status={resp.status_code}")

    # Non-admin key cannot write settings
    resp = requests.put(
        f"{BASE_URL}/v1/settings/thresholds",
        headers = {"x-api-key": PURCHASE_KEY, "Content-Type": "application/json"},
        json    = {"block_threshold": 0.8},
        timeout = 5,
    )
    # API key cannot PUT settings -- requires JWT + ADMIN
    # Returns 401 (no JWT) or 403 (not admin role)
    check("Non-admin key cannot PUT settings", resp.status_code in (401, 403),
          f"status={resp.status_code}")

    # Non-admin key can read settings
    resp = requests.get(f"{BASE_URL}/v1/settings/thresholds",
                        headers={"x-api-key": PURCHASE_KEY}, timeout=5)
    check("Non-admin key can GET settings", resp.status_code == 200,
          f"status={resp.status_code}")

    # Invalid key rejected
    resp = requests.post(
        f"{BASE_URL}/v1/ai/request",
        headers = {"x-api-key": "wsk_live_thisisafakekeyvalue123456789",
                   "Content-Type": "application/json"},
        json    = {"input": "hello"},
        timeout = 5,
    )
    check("Invalid API key returns 401", resp.status_code == 401,
          f"status={resp.status_code}")

    # No auth returns 401
    resp = requests.post(
        f"{BASE_URL}/v1/ai/request",
        headers = {"Content-Type": "application/json"},
        json    = {"input": "hello"},
        timeout = 5,
    )
    check("No auth returns 401", resp.status_code == 401,
          f"status={resp.status_code}")

    # Admin key can access admin endpoints
    resp = requests.get(f"{BASE_URL}/v1/admin/departments",
                        headers={"x-api-key": ADMIN_KEY}, timeout=5)
    check("Admin key can access /admin/departments", resp.status_code == 200,
          f"status={resp.status_code}")

    # Unauthenticated GET settings now requires valid key
    resp = requests.get(f"{BASE_URL}/v1/settings/thresholds", timeout=5)
    check("Unauthenticated GET settings returns 401", resp.status_code == 401,
          f"status={resp.status_code}")

    # Both auth headers -- API key wins
    resp = requests.post(
        f"{BASE_URL}/v1/ai/request",
        headers = {
            "x-api-key":     PURCHASE_KEY,
            "Authorization": "Bearer fake_jwt_token",
            "Content-Type":  "application/json",
        },
        json    = {"input": "hello"},
        timeout = 5,
    )
    check("API key wins when both headers present", resp.status_code == 200,
          f"status={resp.status_code}")


# == Test C: Trace ID leakage ==================================================

def test_trace_leakage() -> None:
    section("C. Trace ID leakage")

    # Create a Purchase scan
    resp = scan(PURCHASE_KEY, "Trace leakage test prompt")
    check("Purchase scan for leakage test succeeds", resp.status_code == 200)
    if resp.status_code != 200:
        return

    purchase_trace = resp.json().get("trace_id")
    check("Got Purchase trace_id", purchase_trace is not None)

    time.sleep(0.5)

    # Finance key tries to fetch Purchase trace_id
    # Must return 404 -- not 403 (403 confirms record exists)
    resp = audit_get(FINANCE_KEY, purchase_trace)
    check("Finance key gets 404 for Purchase trace_id (not 403 or 200)",
          resp.status_code == 404,
          f"status={resp.status_code} -- "
          f"200=CRITICAL data leak, 403=existence confirmed, 404=correct")

    # Purchase key can fetch its own trace_id
    resp = audit_get(PURCHASE_KEY, purchase_trace)
    check("Purchase key can fetch own trace_id", resp.status_code == 200,
          f"status={resp.status_code}")

    # Admin key can fetch any trace_id
    resp = audit_get(ADMIN_KEY, purchase_trace)
    check("Admin key can fetch any trace_id", resp.status_code == 200,
          f"status={resp.status_code}")

    # Non-existent trace_id returns 404
    fake_trace = "req_00000000000000000000000000"
    resp       = audit_get(PURCHASE_KEY, fake_trace)
    check("Non-existent trace_id returns 404", resp.status_code == 404,
          f"status={resp.status_code}")


# == Test D: Trial key restrictions ============================================

def test_trial_restrictions() -> None:
    section("D. Trial key restrictions")

    # Trial key scan works within limits
    resp = scan(TRIAL_KEY, "Hello world")
    check("Trial key scan succeeds within limits", resp.status_code == 200,
          f"status={resp.status_code}")

    # Trial key input cap (500 chars)
    long_prompt = "A" * 501
    resp        = scan(TRIAL_KEY, long_prompt)
    check("Trial key rejects input > 500 chars", resp.status_code == 400,
          f"status={resp.status_code}")

    # Trial key proxy disabled
    resp = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers = {"x-api-key": TRIAL_KEY, "Content-Type": "application/json"},
        json    = {"model": "openai/gpt-4o",
                   "messages": [{"role": "user", "content": "hi"}]},
        timeout = 5,
    )
    check("Trial key proxy returns 403", resp.status_code == 403,
          f"status={resp.status_code}")

    # Trial key rate limit (10 req/min)
    # Send 12 requests rapidly -- at least 1 should be rate limited
    print("    (sending 12 rapid requests to trigger rate limit -- takes ~5s)")
    statuses = []
    for _ in range(12):
        r = scan(TRIAL_KEY, "rate limit test")
        statuses.append(r.status_code)
    rate_limited = statuses.count(429)
    check("Trial key rate limited after 10 req/min",
          rate_limited >= 1,
          f"Got {rate_limited} 429s out of 12 requests -- expected at least 1")


# == Main ======================================================================

if __name__ == "__main__":
    print("\nWrapSec Security Tests")
    print("=" * 50)
    print(f"Target: {BASE_URL}\n")

    try:
        r = requests.get(f"{BASE_URL}/health/live", timeout=5)
        if not r.ok:
            print("\033[91mAPI not reachable -- start the API first\033[0m")
            sys.exit(1)
    except Exception as e:
        print(f"\033[91mCannot reach API: {e}\033[0m")
        sys.exit(1)

    print("\033[92mAPI reachable -- running tests\033[0m")

    test_isolation()
    test_rbac()
    test_trace_leakage()
    test_trial_restrictions()

    print(f"\n{'=' * 50}")
    total = passed + failed
    if failed == 0:
        print(f"\033[92m  {passed}/{total} passed -- ALL GREEN\033[0m")
    else:
        print(f"\033[91m  {passed}/{total} passed  |  {failed} FAILED\033[0m")
    print(f"{'=' * 50}\n")

    sys.exit(0 if failed == 0 else 1)
