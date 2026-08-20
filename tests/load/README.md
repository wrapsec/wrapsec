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

```bash
# Locust
locust --version

# API running
curl http://127.0.0.1:8000/health/live
```

The security tests read every credential from the environment (see
`tests/load/security/security_tests.py`). Never paste real keys into this file or
any other tracked file -- export them per shell:

```bash
export WRAPSEC_ADMIN_KEY=...
export WRAPSEC_PURCHASE_KEY=wsk_live_...
export WRAPSEC_FINANCE_KEY=wsk_live_...
export WRAPSEC_TRIAL_KEY=wsk_trial_...
export WRAPSEC_PURCHASE_DEPT_ID=...
export WRAPSEC_FINANCE_DEPT_ID=...
```

`tests/load/locustfile.py` still carries a literal `wrapsec_admin_key`; it must match
the running stack's `ADMIN_API_KEY` for the load profiles to authenticate.

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

```bash
cd /path/to/wrapsec
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

```bash
locust -f tests/load/locustfile.py BaselineUser \
  --headless -u 1 -r 1 -t 30s \
  --host http://127.0.0.1:8000
```

Pass: all requests 200, p95 < 50ms, 0 failures.

---

### 2. Sustained load - 33 RPS for 10 minutes

**With web UI (recommended - watch live):**
```bash
locust -f tests/load/locustfile.py SustainedUser \
  --host http://127.0.0.1:8000
```
Open http://localhost:8089, set Users=33, Spawn rate=5, click Start.

**Headless with CSV output:**
```bash
mkdir -p tests/load/results
locust -f tests/load/locustfile.py SustainedUser \
  --headless -u 33 -r 5 -t 10m \
  --host http://127.0.0.1:8000 \
  --csv=tests/load/results/sustained
```

Pass criteria:
- p95 fast scan < 30ms
- Error rate < 0.1%
- No SYSTEM_ERROR responses

---

### 3. Burst - 100 users for 2 minutes

```bash
locust -f tests/load/locustfile.py BurstUser \
  --headless -u 100 -r 100 -t 2m \
  --host http://127.0.0.1:8000 \
  --csv=tests/load/results/burst
```

Pass criteria:
- Error rate < 1% (429s counted as success)
- p95 < 100ms

---

### 4. Soak - 30 RPS for 60 minutes

```bash
locust -f tests/load/locustfile.py SoakUser \
  --headless -u 30 -r 5 -t 60m \
  --host http://127.0.0.1:8000 \
  --csv=tests/load/results/soak
```

While running, monitor in separate terminals:
```bash
# DB connections (run every 5 minutes)
docker exec wrapsec_postgres psql -U wrapsec -d wrapsec \
  -c "SELECT count(*) FROM pg_stat_activity WHERE datname='wrapsec';"

# API process resident memory
ps -o pid,rss,comm -C python3

# Or watch both continuously
watch -n 300 'docker exec wrapsec_postgres psql -U wrapsec -d wrapsec \
  -tAc "SELECT count(*) FROM pg_stat_activity WHERE datname='"'"'wrapsec'"'"';"'
```

Pass criteria:
- No degradation comparing first 5min vs last 5min
- DB connections stable (not growing)
- No OOM or connection errors

---

### 5. Stress - find breaking point

```bash
locust -f tests/load/locustfile.py StressUser \
  --headless -u 200 -r 10 -t 5m \
  --host http://127.0.0.1:8000 \
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

```bash
# Summary stats
column -s, -t < tests/load/results/sustained_stats.csv | less -S

# Per-endpoint breakdown (name, p50, p95, p99, failures)
awk -F, 'BEGIN{OFS="\t"} {print $2, $6, $17, $19, $4}' \
  tests/load/results/sustained_stats.csv | column -t
```

Column positions follow the Locust CSV schema; if a Locust upgrade changes it,
check the header row with `head -1 tests/load/results/sustained_stats.csv`.

Key columns: `50%` = p50ms, `95%` = p95ms, `Failure Count` = non-200 responses.

---

## After tests

Wait 60 seconds between test runs to let rate limit windows reset.

```bash
# Flush Redis rate limit keys between runs
docker exec wrapsec_redis sh -c \
  'redis-cli --scan --pattern "rate:*" | xargs -r redis-cli DEL'
```
