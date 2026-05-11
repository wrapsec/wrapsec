# WrapSec Load & Security Tests

## Structure

```
tests/load/
  config.py                  Shared config - keys, thresholds, prompts
  locustfile.py              All load test scenarios (Locust)
  security/
    security_tests.py        Security correctness tests (plain Python)
  results/                   CSV output from Locust runs (gitignored)
  README.md                  This file
```

---

## Prerequisites

```powershell
# Locust (already installed)
locust --version

# API running
curl http://127.0.0.1:8000/health/live

# Both departments have valid keys (verified in session)
# Purchase: wsk_live_siudfvbDrPkGPry-XYn_kXo167GLXE6Bf3WsDWqV3AM
# Finance:  wsk_live_VKyMV0WBPUFGFkU21bin_b_9DGOd0in2Xah4WH5fCso
```

---

## Order of execution

Always run in this order:

```
1. Security tests     (correctness - fast, ~30 seconds)
2. Baseline           (smoke - 1 user, 30 seconds)
3. Sustained          (10 minutes)
4. Burst              (2 minutes)
5. Soak               (60 minutes - optional pre-production)
6. Stress             (5 minutes - find breaking point)
```

Never run Soak or Stress on a system that hasn't passed Security + Baseline.

---

## Security tests

Run before any load test. These are correctness checks, not load:

```powershell
cd D:\Projects\wrapsec
python tests/load/security/security_tests.py
```

Expected: 20/20 passed -- ALL GREEN

Tests cover:
- Cross-department data isolation (A)
- RBAC enforcement (B)
- Trace ID leakage prevention (C)
- Trial key restrictions (D)

---

## Load tests

### 1. Baseline - smoke test (run first)

```powershell
locust -f tests/load/locustfile.py BaselineUser `
  --headless -u 1 -r 1 -t 30s `
  --host http://127.0.0.1:8000
```

Pass: all requests 200, p95 < 50ms, 0 failures.

---

### 2. Sustained load - 33 RPS for 10 minutes

**With web UI (recommended - watch live):**
```powershell
locust -f tests/load/locustfile.py SustainedUser `
  --host http://127.0.0.1:8000
```
Open http://localhost:8089, set Users=33, Spawn rate=5, click Start.

**Headless with CSV output:**
```powershell
mkdir tests\load\results -ErrorAction SilentlyContinue
locust -f tests/load/locustfile.py SustainedUser `
  --headless -u 33 -r 5 -t 10m `
  --host http://127.0.0.1:8000 `
  --csv=tests/load/results/sustained
```

Pass criteria:
- p95 fast scan < 30ms
- Error rate < 0.1%
- No SYSTEM_ERROR responses

---

### 3. Burst - 100 users for 2 minutes

```powershell
locust -f tests/load/locustfile.py BurstUser `
  --headless -u 100 -r 100 -t 2m `
  --host http://127.0.0.1:8000 `
  --csv=tests/load/results/burst
```

Pass criteria:
- Error rate < 1% (429s counted as success)
- p95 < 100ms

---

### 4. Soak - 30 RPS for 60 minutes

```powershell
locust -f tests/load/locustfile.py SoakUser `
  --headless -u 30 -r 5 -t 60m `
  --host http://127.0.0.1:8000 `
  --csv=tests/load/results/soak
```

While running, monitor in separate terminals:
```powershell
# DB connections (run every 5 minutes)
docker exec wrapsec_postgres psql -U wrapsec -d wrapsec `
  -c "SELECT count(*) FROM pg_stat_activity WHERE datname='wrapsec';"

# API process memory (watch Task Manager or)
Get-Process -Name "python" | Select-Object WorkingSet64
```

Pass criteria:
- No degradation comparing first 5min vs last 5min
- DB connections stable (not growing)
- No OOM or connection errors

---

### 5. Stress - find breaking point

```powershell
locust -f tests/load/locustfile.py StressUser `
  --headless -u 200 -r 10 -t 5m `
  --host http://127.0.0.1:8000 `
  --csv=tests/load/results/stress
```

No pass/fail - record the RPS where errors start. This is your capacity ceiling.

---

## Performance thresholds summary

| Scenario | p50 target | p95 target | p99 limit | Error rate |
|---|---|---|---|---|
| Scan fast (sustained) | < 10ms | < 30ms | < 100ms | < 0.1% |
| Scan fast (burst)     | -      | < 100ms | -        | < 1% |
| Scan full mode        | -      | < 800ms | -        | < 0.1% |
| Proxy mode            | -      | < 1500ms | -       | < 0.1% |

---

## Reading CSV results

After any headless run with --csv:

```powershell
# Summary stats
Import-Csv tests\load\results\sustained_stats.csv | Format-Table

# Per-endpoint breakdown
Import-Csv tests\load\results\sustained_stats.csv |
  Select-Object Name, "50%", "95%", "99%", "Failure Count" |
  Format-Table
```

Key columns: `50%` = p50ms, `95%` = p95ms, `Failure Count` = non-200 responses.

---

## After tests

Wait 60 seconds between test runs to let rate limit windows reset.

```powershell
# Flush Redis rate limit keys between runs
docker exec wrapsec_redis redis-cli --scan --pattern "rate:*" | `
  ForEach-Object { docker exec wrapsec_redis redis-cli DEL $_ }
```
