# WrapSec Load & Security Tests

## Structure

```
tests/load/
  config.py                  Shared config - keys, thresholds, prompts
  locustfile.py              Load test scenarios (Locust)
  locustfile-b.py            Second scenario set; same invocation pattern
  scan_all_load.py           Scan-All cost + audit-lock contention (standalone)
  monitor.py                 System metrics during a run (API, Postgres, Redis)
  timing.py                  Per-request timing breakdown (total vs detection)
  security/
    security_tests.py        Security correctness tests (plain Python)
  results/                   CSV output from Locust runs (gitignored)
  README.md                  This file
```

Two different kinds of tool live here. The Locust scenarios and the security
tests drive a **running API over HTTP**. `scan_all_load.py` is standalone: it
imports the gateway and runs the pipeline **in process**, so it needs a database
but no server.

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

`locustfile.py` reads the same variables. `WRAPSEC_ADMIN_KEY` is the one the load
profiles need: the admin key bypasses the per-key rate limit, so the generator
measures the gateway rather than the limiter. Set `WRAPSEC_PROXY_KEY` as well to
drive the proxy profiles with a dedicated live key. A profile started without
`WRAPSEC_ADMIN_KEY` fails at test start with a message naming the variable.

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

Every check must pass. The script prints a per-check pass/fail list and a total;
any failure is a correctness bug, not a tuning matter, and blocks the load runs
below.

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
docker compose -f infrastructure/docker/docker-compose.yml exec -T postgres \
  psql -U wrapsec -d wrapsec \
  -c "SELECT count(*) FROM pg_stat_activity WHERE datname='wrapsec';"

# API process resident memory
ps -o pid,rss,comm -C python3

# Or watch both continuously
watch -n 300 'docker compose -f infrastructure/docker/docker-compose.yml exec -T postgres \
  psql -U wrapsec -d wrapsec \
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

## Scan-All cost and audit-lock contention

`scan_all_load.py` answers a different question from the Locust profiles: what
one Scan-All request costs, and whether `MAX_SCAN_ALL_MESSAGES` is set sanely.
It runs the pipeline in process, so it needs a Postgres with the schema applied
and **no running API**.

```bash
# a throwaway Postgres, migrated
DATABASE_URL=postgresql+asyncpg://wrapsec:wrapsec@localhost:55433/wrapsec_load \
  alembic upgrade head

# the build almost everyone runs
DATABASE_URL=... python tests/load/scan_all_load.py \
  --messages 10 --concurrency 1,4,8 --requests 8 --no-transformer

# the optional build, if Tier 2 is installed
DATABASE_URL=... python tests/load/scan_all_load.py \
  --messages 10 --concurrency 1,4,8 --requests 8
```

Options: `--messages` (eligible messages per request), `--concurrency`
(simultaneous requests from ONE tenant), `--requests` (requests per concurrency
level), `--no-transformer`.

**Measure the build you actually run.** The Tier-2 transformer ships only in the
optional build and dominates this measurement: with it installed the detectors
contend for CPU and time out, and detection is fail-closed, so each timeout
becomes a BLOCK the caller cannot distinguish from a content block. Measuring a
development machine that happens to have it installed reports a cost most
deployments never pay. `--no-transformer` blocks the import before the gateway
loads, reproducing a default deployment.

**Read the two lock columns first.** The audit chain is per tenant and each row
hashes the previous one, so writes serialise behind a per-tenant advisory lock:

- `hold` -- how long one request keeps every other request in that tenant out.
  This is what grows with the message count.
- `wait` -- how long a request sat queued behind the ones ahead of it. This is
  what a caller experiences as a stall somebody else caused.

One request's hold is every other request's wait, and a mean latency hides both.

**The outcome columns matter more than the error column.** Every scanned message
is classified as served, blocked on content, or blocked by detector failure. A
run in which most messages were refused because a detector ran out of time has
zero transport errors, so counting errors alone reports it as a clean run. The
tool also counts timeouts by the detector that raised them.

It writes real audit rows under a synthetic tenant id and prints the `DELETE`
statement to remove them. Use a throwaway database and the point is moot.

---

## Monitoring a run

```bash
python tests/load/monitor.py     # API CPU/memory/fds, Postgres, Redis, system
python tests/load/timing.py      # total round trip vs detection time per request
```

`monitor.py` samples the API process and the Postgres and Redis containers
during a load run. `timing.py` splits a request into total round trip versus the
pipeline time the API reports, which is how you tell a slow detector from a slow
network or a queue.

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
docker compose -f infrastructure/docker/docker-compose.yml exec -T redis sh -c \
  'redis-cli --scan --pattern "rate:*" | xargs -r redis-cli DEL'
```
