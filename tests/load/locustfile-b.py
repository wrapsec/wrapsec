# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec Load Tests - Main Entry Point
======================================

Usage:
  # Baseline smoke test (always run first)
  locust -f tests/load/locustfile.py BaselineUser --headless -u 1 -r 1 -t 30s --host http://localhost:8000

  # Sustained load - 33 RPS for 10 minutes (watch in browser at localhost:8089)
  locust -f tests/load/locustfile.py SustainedUser --host http://localhost:8000

  # Burst - 100 users instantly
  locust -f tests/load/locustfile.py BurstUser --headless -u 100 -r 100 -t 2m --host http://localhost:8000

  # Soak - 30 RPS for 1 hour
  locust -f tests/load/locustfile.py SoakUser --headless -u 30 -r 5 -t 60m --host http://localhost:8000

  # Stress - ramp to 200, find breaking point
  locust -f tests/load/locustfile.py StressUser --headless -u 200 -r 10 -t 5m --host http://localhost:8000

  # Save CSV report
  locust -f tests/load/locustfile.py SustainedUser --headless -u 33 -r 5 -t 10m \
    --host http://localhost:8000 --csv=tests/load/results/sustained

Run from repo root. Locust web UI: http://localhost:8089

Notes:
  - Always run BaselineUser first to confirm system is healthy
  - Wait 30s between tests to let rate limit windows reset
  - Soak and stress tests should run with API on a clean restart
"""

import random

from locust import HttpUser, between, constant_throughput, task

from config import (
    ALL_PROMPTS,
    PURCHASE_KEY,
)


def _headers(key: str) -> dict:
    return {
        "x-api-key":    key,
        "Content-Type": "application/json",
    }


def _body(prompt: str, mode: str = "fast") -> dict:
    return {
        "input":          prompt,
        "detection_mode": mode,
        "metadata": {
            "source":  "load-test",
            "user_id": "locust",
        },
    }


# ── Base user - shared scan behaviour ─────────────────────────────────────────

class WrapSecUser(HttpUser):
    """
    Base class. Subclasses override wait_time and which key is used.
    All users hit the scan endpoint with realistic prompt mix.
    """
    abstract  = True
    api_key   = PURCHASE_KEY

    def _scan(self, mode: str = "fast") -> None:
        prompt = random.choice(ALL_PROMPTS)
        with self.client.post(
            "/v1/ai/request",
            json    = _body(prompt, mode),
            headers = _headers(self.api_key),
            catch_response = True,
            name    = f"POST /v1/ai/request [{mode}]",
        ) as resp:
            if resp.status_code == 200:
                data = resp.json()
                # SYSTEM_ERROR is a failure even though HTTP 200
                if data.get("primary_reason") == "SYSTEM_ERROR":
                    resp.failure("SYSTEM_ERROR returned")
                else:
                    resp.success()
            elif resp.status_code == 429:
                # Rate limit - expected under burst, not a test failure
                resp.success()
            else:
                resp.failure(f"Unexpected status {resp.status_code}")

    def _audit_list(self) -> None:
        with self.client.get(
            "/v1/audit/logs?limit=20",
            headers        = _headers(self.api_key),
            catch_response = True,
            name           = "GET /v1/audit/logs",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            elif resp.status_code == 429:
                # Rate limited - count as success for load test purposes
                # (rate limiting is correct behaviour under high load)
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}: {resp.text[:100]}")


# ── Scenario 1: Baseline ──────────────────────────────────────────────────────

class BaselineUser(WrapSecUser):
    """
    Smoke test. 1 user, 30 seconds.
    Run this before every other test to confirm system is healthy.

    Command:
      locust -f tests/load/locustfile.py BaselineUser \
        --headless -u 1 -r 1 -t 30s --host http://localhost:8000
    """
    wait_time = between(1, 2)
    api_key   = PURCHASE_KEY

    @task(8)
    def scan_fast(self):
        self._scan("fast")

    @task(2)
    def audit_list(self):
        self._audit_list()

    @task(1)
    def health_check(self):
        with self.client.get(
            "/health/live",
            catch_response = True,
            name           = "GET /health/live",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Health check failed: {resp.status_code}")


# ── Scenario 2: Sustained load ────────────────────────────────────────────────

class SustainedUser(WrapSecUser):
    """
    33 RPS sustained for 10 minutes. Normal peak load for 500-person company.
    Mix: 70% fast scan, 20% audit reads, 10% full mode scan.

    Command (headless):
      locust -f tests/load/locustfile.py SustainedUser \
        --headless -u 33 -r 5 -t 10m --host http://localhost:8000 \
        --csv=tests/load/results/sustained

    Command (web UI - recommended):
      locust -f tests/load/locustfile.py SustainedUser --host http://localhost:8000
      Then open http://localhost:8089, set 33 users, spawn rate 5

    Pass criteria:
      p95 < 30ms (fast), error rate < 0.1%
    """
    wait_time = constant_throughput(1)  # 1 req/s per user -> 33 RPS at 33 users
    api_key   = PURCHASE_KEY

    @task(7)
    def scan_fast(self):
        self._scan("fast")

    @task(2)
    def audit_list(self):
        self._audit_list()

    @task(1)
    def scan_full(self):
        self._scan("full")


# ── Scenario 3: Burst ─────────────────────────────────────────────────────────

class BurstUser(WrapSecUser):
    """
    100 users spawned instantly - morning spike simulation.
    All hitting fast scan only (most common real-world burst pattern).

    Command:
      locust -f tests/load/locustfile.py BurstUser \
        --headless -u 100 -r 100 -t 2m --host http://localhost:8000 \
        --csv=tests/load/results/burst

    Pass criteria:
      error rate < 1% (429s are acceptable, counted as success)
      p95 < 100ms
    """
    wait_time = between(0.5, 1.5)
    api_key   = PURCHASE_KEY

    @task
    def scan_fast(self):
        self._scan("fast")


# ── Scenario 4: Soak ──────────────────────────────────────────────────────────

class SoakUser(WrapSecUser):
    """
    30 RPS for 60 minutes. Validates no memory leaks, connection pool
    exhaustion, or Redis key accumulation over time.

    Command:
      locust -f tests/load/locustfile.py SoakUser \
        --headless -u 30 -r 5 -t 60m --host http://localhost:8000 \
        --csv=tests/load/results/soak

    Watch during test:
      - API process memory (Task Manager or htop)
      - PostgreSQL connection count:
        docker compose exec -T postgres psql -U wrapsec -d wrapsec \
          -c "SELECT count(*) FROM pg_stat_activity;"
      - Redis memory: docker compose exec -T redis redis-cli INFO memory

    Pass criteria:
      No degradation in p95 over time (compare first 5min vs last 5min)
      Error rate < 0.1% throughout
      No OOM or connection exhaustion
    """
    wait_time = constant_throughput(1)
    api_key   = PURCHASE_KEY

    @task(7)
    def scan_fast(self):
        self._scan("fast")

    @task(2)
    def audit_list(self):
        self._audit_list()

    @task(1)
    def scan_full(self):
        self._scan("full")


# ── Scenario 5: Stress ────────────────────────────────────────────────────────

class StressUser(WrapSecUser):
    """
    Ramp from 0 to 200 users over ~20 seconds. Find the breaking point.
    Breaking point = where error rate exceeds 1% OR p95 exceeds 100ms.

    Command:
      locust -f tests/load/locustfile.py StressUser \
        --headless -u 200 -r 10 -t 5m --host http://localhost:8000 \
        --csv=tests/load/results/stress

    What to watch:
      - At what RPS does p95 start climbing?
      - At what RPS do errors appear?
      - Does the system recover if load drops?

    Pass criteria: none - this test is about finding limits, not passing.
    Record the breaking point RPS for capacity planning.
    """
    wait_time = between(0.5, 2)
    api_key   = PURCHASE_KEY

    @task(9)
    def scan_fast(self):
        self._scan("fast")

    @task(1)
    def audit_list(self):
        self._audit_list()
