# WrapSec — Architecture Specification

> This document builds on [Core Concepts](core_concepts.md) as the canonical behavior definition.

Version: 1.2 — Security & Isolation  
Status: Implemented  
Last updated: April 2026

---

## Overview

WrapSec is a production-grade AI security gateway. It operates as a security layer between calling applications and any LLM provider, scanning every prompt through a four-layer detection pipeline before it reaches the model.

WrapSec supports two execution modes:

- **Scan-only** — inspect and decide. The calling application forwards the prompt to the LLM itself.
- **Proxy** — inspect, decide, and forward. WrapSec forwards the prompt to the LLM provider on the application's behalf, enforcing security on both input and output.

---

## Design Principles

**Detection vs guardrails — two independent subsystems**

Detection (rule, ML, LLM) and guardrails (PII) are architecturally, mathematically, and operationally separate. They are stored in separate database columns, evaluated independently, and never mixed in scoring.

**Threshold decoupling**

Detection thresholds (`thresholds.block`, `thresholds.sanitize`) and guardrail thresholds (`guardrails.pii.block_threshold`, `guardrails.pii.sanitize_threshold`) occupy separate policy paths and are extracted and passed as separate parameters. Changing one never affects the other.

**Guardrail-first enforcement**

Guardrail decisions override detection decisions unconditionally.

**SYSTEM_ERROR semantics**

SYSTEM_ERROR occurs when the detection pipeline fails (e.g., detector failure, timeout, or internal exception).

**SYSTEM_ERROR is never NO_THREAT_DETECTED**

These are produced by mutually exclusive code paths. `NO_THREAT_DETECTED` is only reachable when `detection_failed=False` and all scores are 0.0. `SYSTEM_ERROR` is always returned when `detection_failed=True`. This consistency is guaranteed across the codebase, docs, and audit records.

**SYSTEM_ERROR client contract**

At the engine level, `SYSTEM_ERROR` returns `decision=ALLOW` because detection did not confirm a threat. However, all clients — applications, SDKs, examples — must treat `primary_reason=SYSTEM_ERROR` as a failure condition and must not forward input to an LLM. The distinction between engine-level decision and application-level handling is intentional: the engine reports what it knows; the client enforces safety.

**All failure paths → LOW confidence**

Detection failure, guardrail failure, and gateway exceptions all produce `confidence=0.0` and `confidence_band=LOW`. There is no failure path that produces a non-LOW confidence.

**Conservative input limits**

8,000 characters + heuristic token limit `ceil(len/2) > 4000` → 422. Safe for English and CJK. Full tiktoken in V1.2.

**Idempotency with conflict detection**

Same key + same body → cached response. Same key + different body → 409 CONFLICT. This matches Stripe/AWS idempotency standards.

**Zero breaking changes**

Each phase is additive. Existing integrations work without modification.

**Configurable data storage**

Proxy interaction text is stored according to `DATA_STORAGE_MODE`: `full` (store as-is), `masked` (PII redacted before storing), or `none` (text never persisted). Metadata is always retained regardless of mode.

---

## System Architecture

### Scan-Only Mode

```
Calling Application
        │  x-api-key: wsk_live_...
        │  POST /v1/ai/request
        ▼
WrapSec API (FastAPI, port 8000)
┌──────────────────────────────────────────────────┐
│  Trace → RateLimit → Auth → Idempotency → Log   │
│                                                  │
│  Policy resolver                                 │
│  system → tenant → department → application      │
│                                                  │
│  Gateway Service                                 │
│  ├── InputGuard    PII detection + redaction     │
│  ├── RuleDetector  try/catch → detection_failed  │
│  ├── MLDetector    try/catch → detection_failed  │
│  ├── LLMDetector   try/catch → detection_failed  │
│  ├── RiskScorer    rule+ml+llm (PII excluded)    │
│  └── PolicyEngine  BLOCK / SANITIZE / ALLOW      │
└──────────────────────────────────────────────────┘
        │
        ├── audit_logs (decision, scores, threats)
        │
        └── Response → Calling Application
               (application forwards to LLM itself)
```

### Proxy Mode — AI Interaction Firewall

```
Calling Application
        │  x-api-key: wsk_live_...
        │  POST /v1/chat/completions
        │  model: "openai/gpt-4o" | "ollama/gemma3:4b"
        ▼
WrapSec API (FastAPI, port 8000)
┌──────────────────────────────────────────────────┐
│  Trace → RateLimit → Auth → Log                  │
│                                                  │
│  Input Guard                                     │
│  ├── Detection pipeline (same as scan-only)      │
│  ├── BLOCK  → return 400, provider never called  │
│  └── SANITIZE → redact PII before forwarding     │
│                                                  │
│  Provider Layer                                  │
│  ├── OpenAI / OpenAI-compatible (Groq, Azure)    │
│  ├── Ollama (local)                              │
│  └── Custom (any OpenAI-compatible endpoint)     │
│                                                  │
│  Output Guard                                    │
│  ├── PII scan on provider response               │
│  ├── BLOCK  → return 400, response suppressed    │
│  └── SANITIZE → redact PII before returning      │
└──────────────────────────────────────────────────┘
        │
        ├── proxy_interactions (full lifecycle)
        │     input_raw*, output_raw*, decisions,
        │     threats, provider, model, latency
        │     (* subject to DATA_STORAGE_MODE)
        │
        ├── audit_logs (FK → proxy_interactions.id)
        │     execution_mode=proxy, unified view
        │
        └── OpenAI-compatible response → Application
               + X-WrapSec-* headers on every response
```

### Dual-Write Pattern

Every proxy request writes to two tables atomically:

```
proxy_interactions → id (UUID, primary key)
audit_logs         → proxy_interaction_id = proxy_interactions.id (FK)

GET /v1/ai/requests/:trace_id
  → reads audit_logs
  → LEFT JOIN proxy_interactions ON proxy_interaction_id
  → returns unified response with "proxy" key
```

**Latency storage rule:**

```
audit_logs.latency_ms for scan_only rows = detection pipeline time only
audit_logs.latency_ms for proxy rows     = total end-to-end time (same as proxy.total_latency_ms)

proxy_interactions.provider_latency_ms   = external provider round-trip only
proxy_interactions.total_latency_ms      = total end-to-end wall time (canonical for proxy)
```

---

## Proxy Request Lifecycle

```
1. Parse model string:  "openai/gpt-4o" → provider=openai, model=gpt-4o
2. Load provider config from DB (provider_api_key is AES-256-GCM encrypted)
3. Extract scan target: last user message (default) or all user messages
4. Run detection pipeline (same as scan_only mode)
5. Input decision:
   BLOCK    → log, return 400, provider never called
   SANITIZE → redact PII in messages, forward sanitized text
   ALLOW    → forward messages unchanged
6. Provider call (OpenAI / Ollama / custom endpoint)
7. Output guard: scan provider response for PII
   BLOCK    → log, return 400, response suppressed
   SANITIZE → redact PII, return sanitized response
   ALLOW    → return response unchanged
8. Log to proxy_interactions + audit_logs (dual write, atomic)
9. Return OpenAI-compatible response + X-WrapSec-* headers
```

---

## Execution Status Values

| Status | Meaning |
|---|---|
| `SUCCESS` | Input ALLOW/SANITIZE, provider responded, output ALLOW/SANITIZE |
| `BLOCKED` | Input decision was BLOCK, provider never called |
| `OUTPUT_BLOCKED` | Input clean, provider responded, output was BLOCK |
| `FAILED` | Provider call failed (network error, auth error) |
| `TIMEOUT` | Provider call timed out |

---

## Data Storage Modes

| Mode | input_raw / output_raw | Use case |
|---|---|---|
| `full` | Stored as-is | Development, debugging |
| `masked` | PII redacted before storing (default) | Production |
| `none` | NULL — text never persisted | Strict compliance |

Metadata (decisions, threats, scores, latency, execution_status) is **always retained** regardless of mode. Text is purged via the retention worker after `DATA_RETENTION_DAYS_PROXY` days (default: 7).

---

## Entity Hierarchy

```
tenant (root)
│
├── global_policy
│     thresholds:   block=0.7, sanitize=0.4      (detection)
│     guardrails:   pii.block=0.7, pii.san=0.4   (PII — independent)
│
├── departments
│     ├── Finance
│     │     policy_override:
│     │       thresholds.block           = 0.5   (detection only)
│     │       guardrails.pii.block       = 0.6   (PII — independent)
│     │     → Finance Bot:  wsk_live_fin_...
│     │     → ERP System:   wsk_live_erp_...
│     ├── HR
│     │     policy_override:
│     │       thresholds.block           = 0.5
│     │       detection.llm_enabled      = false
│     │     → HR System:    wsk_live_hr_...
│     └── Engineering
│           policy_override:
│             thresholds.block           = 0.75
│           → Code Assistant: wsk_live_eng_...
```

---

## Policy Model

### Policy Object

```json
{
  "detection":  {"rule_weight": 0.4, "ml_weight": 0.3, "llm_weight": 0.3,
                 "rule_enabled": true, "ml_enabled": true, "llm_enabled": true, "llm_trigger": 0.2},
  "thresholds": {"block": 0.7, "sanitize": 0.4},
  "guardrails": {"pii": {"enabled": true, "block_threshold": 0.7, "sanitize_threshold": 0.4}},
  "llm":        {"provider": "ollama", "model": "llama3.2:latest", "base_url": "http://localhost:11434", "timeout": 30},
  "rate_limit": {"per_minute": 60}
}
```

### Threshold Decoupling in Code

```python
# In ai.py and proxy.py — after policy resolution
block_threshold    = policy["thresholds"]["block"]
sanitize_threshold = policy["thresholds"]["sanitize"]

pii_policy             = policy.get("guardrails", {}).get("pii", {})
pii_block_threshold    = pii_policy.get("block_threshold",    None)
pii_sanitize_threshold = pii_policy.get("sanitize_threshold", None)

# Passed as separate parameters — never shared
gateway.process(
    block_threshold        = block_threshold,
    sanitize_threshold     = sanitize_threshold,
    pii_block_threshold    = pii_block_threshold,
    pii_sanitize_threshold = pii_sanitize_threshold,
)
```

### Policy Resolution Order

**Updated in V1.2** — `global_policy` on the tenant table is no longer applied in policy resolution. It is kept in the DB for future use but not read. DB settings table is now the authoritative source for all global settings.

**Guardrail pipeline (V1.2):**
```
Input → PII guardrail (regex, ~<1ms)
      → RuleDetector / MLDetector / LLMDetector
      → Toxicity guardrail (reads ML label 6, ~0ms additional)
      → RiskScorer (detection scores only — guardrails excluded)
      → PolicyEngine: PII score → Toxicity score → Detection risk_score
```
Each guardrail has independent thresholds configurable per dept/app via `policy_override`.

```
system_defaults() (.env)
  ↓
DB settings table (thresholds, layers, llm, rate_limit)  ← authoritative global values
  ↓
dept.policy_override  ← per-dept overrides (null = inherit)
  ↓
app.policy_override   ← per-app overrides (null = inherit)
  ↓
resolved_policy → split:
  detection thresholds → thresholds.block / thresholds.sanitize
  PII thresholds       → guardrails.pii.block_threshold / sanitize_threshold
  rate_limit           → rate_limit.per_minute
```

---

## Database Schema

### tenants
```sql
CREATE TABLE tenants (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug          VARCHAR(50)  UNIQUE NOT NULL,
    name          VARCHAR(100) NOT NULL,
    description   TEXT,
    global_policy JSONB        NOT NULL DEFAULT '{}',
    is_active     BOOLEAN      DEFAULT true,
    contact_email VARCHAR(100),
    created_at    TIMESTAMP    DEFAULT NOW()
);
```

### departments
```sql
CREATE TABLE departments (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    slug            VARCHAR(50)  NOT NULL,
    name            VARCHAR(100) NOT NULL,
    description     TEXT,
    policy_override JSONB DEFAULT NULL,
    is_active       BOOLEAN DEFAULT true,
    contact_email   VARCHAR(100),
    created_at      TIMESTAMP DEFAULT NOW(),
    UNIQUE (tenant_id, slug)
);
```

### applications
```sql
CREATE TABLE applications (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    dept_id             UUID NOT NULL REFERENCES departments(id),
    slug                VARCHAR(50)  NOT NULL,
    name                VARCHAR(100) NOT NULL,
    environment         VARCHAR(20)  DEFAULT 'production',
    policy_override     JSONB DEFAULT NULL,
    rate_limit_override INTEGER DEFAULT NULL,
    is_active           BOOLEAN DEFAULT true,
    created_at          TIMESTAMP DEFAULT NOW()
);
```

### api_keys
```sql
CREATE TABLE api_keys (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id       VARCHAR(50)  UNIQUE NOT NULL,
    tenant_id    UUID REFERENCES tenants(id),
    dept_id      UUID REFERENCES departments(id),
    app_id       UUID REFERENCES applications(id),
    name         VARCHAR(100) NOT NULL,
    key_hash     VARCHAR(100) UNIQUE NOT NULL,
    key_type     VARCHAR(20)  NOT NULL DEFAULT 'live',  -- live | trial | admin
    -- trial: 500 char input cap, 10 req/min, proxy disabled
    -- CHECK (key_type IN ('live', 'trial', 'admin'))
    is_admin     BOOLEAN DEFAULT false,
    revoked      BOOLEAN DEFAULT false,
    expires_at   TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at   TIMESTAMP DEFAULT NOW(),
    -- Non-admin keys must always have tenant and department
    CONSTRAINT ck_api_keys_non_admin_tenant
        CHECK (is_admin = true OR (tenant_id IS NOT NULL AND dept_id IS NOT NULL))
);
```

### audit_logs
```sql
CREATE TABLE audit_logs (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trace_id             VARCHAR(50)  UNIQUE NOT NULL,
    decision             VARCHAR(20)  NOT NULL,
    risk_score           FLOAT        NOT NULL,
    threats              JSONB        DEFAULT '[]',
    input_hash           VARCHAR(100) NOT NULL,
    detection_mode       VARCHAR(20)  NOT NULL,
    execution_mode       VARCHAR(20)  NOT NULL,  -- scan_only | proxy
    llm_invoked          BOOLEAN      DEFAULT false,
    latency_ms           FLOAT        NOT NULL,
    detection_scores     JSONB,
    guardrail_scores     JSONB,
    primary_reason       VARCHAR(50),
    confidence           FLOAT,
    confidence_band      VARCHAR(10),
    -- Attribution
    tenant_id            VARCHAR(50),
    dept_id              VARCHAR(50),
    app_id               VARCHAR(50),
    key_id               VARCHAR(50),
    source               VARCHAR(100),
    user_id              VARCHAR(100),
    ip_address           VARCHAR(50),
    user_agent           VARCHAR(255),
    attribution_verified BOOLEAN DEFAULT false,
    policy_source        VARCHAR(50),
    input_length         INTEGER DEFAULT 0,
    -- Severity (SIEM/security tool integration)
    severity             VARCHAR(10),  -- CRITICAL | HIGH | MEDIUM | LOW
    -- Computed at write time from decision + risk_score + primary_reason
    -- Logic: domain/value_objects/severity.py
    -- Never returned in scan responses — audit and SIEM use only
    -- Proxy link
    proxy_interaction_id UUID REFERENCES proxy_interactions(id),  -- NULL for scan_only
    created_at           TIMESTAMP DEFAULT NOW()
);
```

### proxy_provider_configs
```sql
CREATE TABLE proxy_provider_configs (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id                VARCHAR(50) UNIQUE NOT NULL,
    provider              VARCHAR(32) NOT NULL,  -- openai | ollama | custom
    base_url              TEXT        NOT NULL,
    provider_api_key_enc  TEXT,        -- AES-256-GCM encrypted, NULL for Ollama
    default_model         VARCHAR(128) NOT NULL,
    timeout_seconds       INTEGER     DEFAULT 60,
    created_at            TIMESTAMP   DEFAULT NOW(),
    updated_at            TIMESTAMP   DEFAULT NOW()
);
```

### proxy_interactions
```sql
CREATE TABLE proxy_interactions (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trace_id              VARCHAR(64)  UNIQUE NOT NULL,
    key_id                VARCHAR(50),
    user_id               VARCHAR(256),
    -- Input (subject to DATA_STORAGE_MODE)
    input_raw             TEXT,        -- NULL after retention period or mode=none
    input_sanitized       TEXT,        -- PII-redacted version if SANITIZE applied
    input_decision        VARCHAR(16)  NOT NULL,  -- ALLOW | BLOCK | SANITIZE
    -- internal field: identical to audit_logs.decision
    -- audit_logs.decision is the canonical API-exposed field
    input_primary_reason  VARCHAR(64)  NOT NULL,
    input_confidence      FLOAT        NOT NULL,
    input_threats         JSONB,
    input_attack_type     VARCHAR(64),
    -- Provider
    provider              VARCHAR(32),  -- NULL when BLOCKED
    model                 VARCHAR(128),
    provider_latency_ms   INTEGER,
    execution_status      VARCHAR(32)  NOT NULL,
    -- Output (subject to DATA_STORAGE_MODE)
    output_raw            TEXT,        -- NULL after retention period or mode=none
    output_sanitized      TEXT,        -- PII-redacted version if output SANITIZE
    output_decision       VARCHAR(16),
    output_primary_reason VARCHAR(64),
    output_confidence     FLOAT,
    output_threats        JSONB,
    -- V2 evaluation hooks
    behavior_flag         VARCHAR(32),  -- NORMAL | OVER_REFUSAL | UNDER_REFUSAL
    output_flags          JSONB,        -- ["LOW_CONFIDENCE", "SUSPICIOUS_OUTPUT"]
    -- Timing
    total_latency_ms      INTEGER      NOT NULL,
    created_at            TIMESTAMP    DEFAULT NOW()
);
```

### settings
```sql
CREATE TABLE settings (
    key        VARCHAR(100) PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW()
);
-- Keys: policy_thresholds, detection_layers, llm_settings, audit_retention
```

---

## Observability Stack

### Prometheus
- Scrapes `GET /metrics` every 15 seconds
- Local dev target: `host.docker.internal:8000`
- Production target: `api:8000` (Docker internal network)
- Config: `infrastructure/prometheus/prometheus.yml`

### Grafana
- Datasource: Prometheus (provisioned via `infrastructure/grafana/datasources/prometheus.yml`)
- Dashboards: Security Overview, Latency & Performance, Threat Intelligence
- Dashboard JSONs: `infrastructure/grafana/dashboards/`
- Note: Grafana 12 has file provisioning issues — pin to 10.4.0 for production

### Metrics (`observability/metrics.py`)
All metric labels are validated against allowlists (`_safe()`) before use — no unbounded cardinality, no user data in labels.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `wrapsec_requests_total` | Counter | decision, detection_mode, execution_mode, key_type | All requests |
| `wrapsec_request_latency_ms` | Histogram | decision, execution_mode | Detection latency |
| `wrapsec_system_errors_total` | Counter | execution_mode | SYSTEM_ERROR events |
| `wrapsec_blocked_total` | Counter | primary_reason, execution_mode | BLOCK decisions |
| `wrapsec_sanitized_total` | Counter | primary_reason, execution_mode | SANITIZE decisions |
| `wrapsec_threats_detected_total` | Counter | category | Threat categories |
| `wrapsec_proxy_execution_total` | Counter | execution_status | Proxy outcomes |
| `wrapsec_proxy_latency_ms` | Histogram | execution_status | Proxy E2E latency |
| `wrapsec_layer_score` | Histogram | layer | Rule/ML/LLM scores |
| `wrapsec_cache_hits_total` | Counter | — | Semantic cache hits |
| `wrapsec_cache_misses_total` | Counter | — | Semantic cache misses |
| `wrapsec_rate_limited_total` | Counter | — | Rate limit rejections |

### Background Retention Worker
- `workers/tasks.py` — cleanup logic
- `workers/queue.py` — APScheduler wiring
- Schedule: daily at 02:00 UTC (configurable via `RETENTION_WORKER_HOUR`, `RETENTION_WORKER_MINUTE`)
- Disable: `RETENTION_WORKER_ENABLED=false`
- Manual fallback: `python scripts/cleanup_audit_logs.py`

---

## Authentication & Request Flow

```
1. Idempotency check (if Idempotency-Key header present)
   hash_key     = SHA-256(idem_key) + ":hash"
   response_key = SHA-256(idem_key) + ":resp"

   stored_hash exists + body_hash MATCHES → return cached (X-Idempotency-Replayed: true)
   stored_hash exists + body_hash DIFFERS → 409 CONFLICT (IDEMPOTENCY_CONFLICT)
   stored_hash missing                    → process + store both keys (TTL: 60s)

2. Rate limit (per API key)
   key_id used as Redis rate limit identifier
   X-RateLimit-Limit/Remaining/Reset on every response

3. Auth middleware
   SHA-256(api_key) → look up api_keys by hash → validate not revoked
   Load key.app_id, key.dept_id, key.tenant_id, key.key_type
   Accepted prefixes: wsk_live_ (standard), wsk_trial_ (restricted), admin key
   Sets request.state.key_type — used by endpoints for trial restrictions

4. Entity validation
   assert key.dept_id   == app.dept_id
   assert key.tenant_id == dept.tenant_id
   Failure → 401 + security log

5. Bearer JWT auth
   Not yet implemented — returns 401 UNAUTHORIZED
   JWT support planned for Phase 2 (user table + login endpoint)

6. Policy resolution
   resolve_policy(tenant_id, dept_id, app_id)
   Returns (policy_dict, policy_source)

6. Threshold extraction (decoupled)
   detection_bt  = policy["thresholds"]["block"]
   detection_st  = policy["thresholds"]["sanitize"]
   pii_bt        = policy["guardrails"]["pii"]["block_threshold"]
   pii_st        = policy["guardrails"]["pii"]["sanitize_threshold"]

7. Gateway processing
   Per-detector try/catch → sets detection_failed=True on any failure
   PolicyEngine receives all 4 thresholds as separate parameters

8. Primary reason (strict order)
   if detection_failed → SYSTEM_ERROR
   elif guardrail      → PII_GUARDRAIL_BLOCK/SANITIZE
   elif max_score > 0  → RULE/ML/LLM_DETECTOR
   else                → NO_THREAT_DETECTED

9. Confidence
   SYSTEM_ERROR paths   → 0.0 (LOW) always
   Guardrail paths      → tiered 0.70–0.95
   Detection paths      → scaled inverse variance
```

---

## Input Limits

| Limit | Value | Enforcement | Notes |
|---|---|---|---|
| Max characters | 8,000 | Schema Field → 422 | |
| Estimated token limit | 4,000 | `ceil(len/2) > 4000` → 422 | CJK-safe |
| Max payload | 64KB | Nginx → 413 | |
| Max audit export rows | 10,000 | Param validation | |
| Retention min | 7 days | Settings validation | |
| Retention max | 3,650 days | Settings validation | 10 years |
| Proxy text retention | 7 days | `DATA_RETENTION_DAYS_PROXY` | Configurable |

---

## Idempotency

```
Header: Idempotency-Key: <uuid>
Scope:  POST /v1/ai/request only
TTL:    60 seconds

Two Redis keys:
  idempotency:{SHA256(key)}:hash → body_hash of original request
  idempotency:{SHA256(key)}:resp → cached response JSON

Same key + same body  → cached response (X-Idempotency-Replayed: true)
Same key + diff body  → 409 CONFLICT (IDEMPOTENCY_CONFLICT)
Redis unavailable     → fail open (processes normally)
Only caches non-5xx responses
```

---

## Failure Modes

| Failure | Decision | Confidence | Primary Reason | Notes |
|---|---|---|---|---|
| One detector fails | continues | from remaining | per remaining | detection_failed=True |
| **All detectors fail** | **ALLOW** | **LOW (0.0)** | **`SYSTEM_ERROR`** | **NOT `NO_THREAT_DETECTED`** |
| PII guardrail fails | BLOCK | LOW (0.0) | `SYSTEM_ERROR` | fail closed |
| Gateway exception | BLOCK | LOW (0.0) | `SYSTEM_ERROR` | fail closed |
| LLM timeout (detection) | continues | from rule+ML | RULE/ML | degraded |
| Provider timeout (proxy) | 504 | — | — | input decision preserved in headers |
| Provider unreachable (proxy) | 502 | — | — | input decision preserved in headers |
| Redis unavailable | allows | — | — | idempotency + rate limit disabled |

---

## API Endpoints

```
Gateway (2):         POST /v1/ai/request · GET /v1/ai/requests/{trace_id}
Proxy (1):           POST /v1/chat/completions
Audit (4):           GET  /v1/audit/logs · stats · attribution · export
Settings (9):        GET/PUT /v1/settings/thresholds · layers · llm · retention · storage
                     GET/PUT/DELETE /v1/settings/proxy · GET /v1/settings/proxy/health
API Keys (5):        POST/GET/PUT/DELETE /v1/keys · GET /v1/keys/{key_id}
Tenant (2):          GET/PUT /v1/admin/tenant
Departments (7):     CRUD + /policy + /stats
Applications (6):    CRUD + /policy
Health (4):          GET /health · /health/ready · /health/live · /health/config
Metrics (1):         GET /metrics
Proxy Internal (2):  GET /v1/proxy/interactions · /v1/proxy/interactions/{trace_id}
Total: 43 endpoints
```

---

## Implementation Status V1.1

```
✅ Rule, ML, LLM detectors with per-detector try/catch
✅ detection_failed flag — SYSTEM_ERROR always distinct from NO_THREAT_DETECTED
✅ All failure paths: confidence=0.0, band=LOW, primary_reason=SYSTEM_ERROR
✅ Input: 8000 char limit + ceil(len/2)>4000 token heuristic → 422
✅ PII guardrail (22+ types, input + output)
✅ Guardrail-first enforcement
✅ Guardrail thresholds DECOUPLED from detection thresholds
✅ risk_score = rule*0.40 + ml*0.30 + llm*0.30 (PII excluded)
✅ Primary reason — 7 values, strict priority order
✅ Confidence: scaled inverse variance + tiered guardrail + failure=0.0
✅ decision_version — "v1.0"
✅ sanitization_applied — explicit boolean
✅ Idempotency-Key (60s TTL, 409 on conflict)
✅ ULID trace IDs
✅ Rate limiting per API key, X-RateLimit-* headers
✅ Audit log retention configurable via Settings UI (DB)
✅ Policy resolution: system → tenant → department
✅ Proxy mode — POST /v1/chat/completions (OpenAI-compatible)
✅ Provider support — OpenAI, OpenAI-compatible, Ollama
✅ Provider API keys encrypted AES-256-GCM at rest
✅ Input + output PII enforcement in proxy mode
✅ Dual write — proxy_interactions + audit_logs (FK linked)
✅ Unified requests view — GET /v1/ai/requests/:trace_id joins both tables
✅ Configurable storage modes — full | masked | none
✅ Proxy text retention worker — scripts/cleanup_audit_logs.py
✅ 43 API endpoints
✅ Next.js 14 dashboard (12 pages)
✅ 148 unit + integration tests passing
```

### V1.2 — Completed

```
✅ Bearer JWT placeholder removed — returns 401
✅ trace_id lookup dept-scoped — cross-dept returns 404
✅ All audit endpoints dept-scoped
✅ Idempotency scoped per API key
✅ Severity classification — CRITICAL/HIGH/MEDIUM/LOW stored in DB
✅ audit_logs.threats → JSONB
✅ api_keys CHECK constraint — non-admin must have tenant+dept
✅ Composite indexes — tenant+dept+time, severity+time, key+time
```

### V1.2 — Pending

```
→ Per-model token counting with tiktoken (replaces heuristic)
→ Application-level policy overrides (placeholder active)
→ API key rotation with grace period
→ Toxicity guardrail (independent thresholds)
→ Cursor-based pagination
→ Background retention worker (replaces manual script)
→ Per-key storage mode override
→ Demo safety restrictions (rate limit, input size cap, proxy disable)
→ DigitalOcean deployment (domain ready, plan: Groq instead of Ollama)
```

### V2.0 — Future

```
→ WildGuard over-refusal / under-refusal detection (behavior_flag)
→ Output evaluation engine (output_flags)
→ Security Events feed and alerting
→ JWT + SSO (attribution_verified=true)
→ Role-based policy overrides
→ Human review queue for LOW confidence
→ SaaS multi-tenancy
→ SDK, webhooks, streaming
```

---

## Security & Isolation

### Authentication

| Auth method | Status | Notes |
|---|---|---|
| `x-api-key: wsk_live_...` | ✅ Active | Standard key — scoped to dept/app |
| `x-api-key: <admin_key>` | ✅ Active | Admin key — full access, no dept scope |
| `Authorization: Bearer` | ❌ Returns 401 | JWT not yet implemented (Phase 2) |

### Request State Identity

Auth middleware populates `request.state` after key validation:

```python
request.state.key_id    = key_record.key_id
request.state.key_name  = key_record.name
request.state.app_id    = str(key_record.app_id)    if key_record.app_id    else None
request.state.dept_id   = str(key_record.dept_id)   if key_record.dept_id   else None
request.state.tenant_id = str(key_record.tenant_id) if key_record.tenant_id else None
request.state.is_admin  = False  # True for admin key only
```

Admin keys have `dept_id = None` — they access all data unscoped.

### Dept Scoping Rules

| Endpoint | Non-admin key | Admin key |
|---|---|---|
| `GET /v1/ai/requests/{trace_id}` | Own dept only — cross-dept returns 404 | Unrestricted |
| `GET /v1/audit/logs` | Own dept only — caller `dept_id` param ignored | Any dept or all |
| `GET /v1/audit/stats` | Own tenant only | Any tenant or all |
| `GET /v1/audit/attribution` | Own dept only | Any dept or all |
| `GET /v1/audit/analytics` | Own dept only | Any dept or all |
| `GET /v1/audit/export` | Own dept only | Any dept or all |

### Idempotency Scoping

Idempotency keys are scoped per API key:

```
Redis key = SHA-256(key_id + ":" + Idempotency-Key)
```

Two different API keys using the same `Idempotency-Key` value never collide.

### Severity Classification

`audit_logs.severity` is computed at write time. Logic in `domain/value_objects/severity.py`.

```
CRITICAL — BLOCK + (risk_score >= 0.9 OR primary_reason ends with _GUARDRAIL_BLOCK)
HIGH     — BLOCK + risk_score < 0.9 OR primary_reason = SYSTEM_ERROR
MEDIUM   — SANITIZE (any reason)
LOW      — ALLOW
```

The `_GUARDRAIL_BLOCK` suffix pattern covers all current and future guardrail types automatically. Severity is never returned in scan responses — audit and SIEM use only.

---

## Known Issues & Decisions

| Issue | Decision | Status |
|---|---|---|
| SYSTEM_ERROR vs NO_THREAT_DETECTED | Mutually exclusive code paths, strict priority | ✅ All paths correct |
| Threshold coupling | Fully decoupled — separate policy paths + parameters | ✅ Implemented |
| Token limit | Heuristic ceil(len/2) for V1.1, tiktoken in V1.2 | ✅ Implemented |
| Idempotency conflict | 409 CONFLICT on same key + different body | ✅ Implemented |
| Idempotency scoping | Scoped per API key — no cross-key collisions | ✅ Implemented |
| Entity relationship validation | Assert key→app→dept→tenant | ✅ Auth middleware |
| tenant_id in metadata | Removed — always from API key | ✅ Security fix |
| Audit retention | DB-configurable, default 30 days | ✅ Implemented |
| Guardrail failure | Fail closed (BLOCK + SYSTEM_ERROR) | ✅ Implemented |
| LLM timeout | Graceful degradation per mode | ✅ Implemented |
| Proxy text storage | Configurable mode (full/masked/none) + retention TTL | ✅ Implemented |
| Provider API keys | AES-256-GCM encrypted at rest, never returned in API | ✅ Implemented |
| audit_logs vs proxy_interactions | Separate tables, FK linked, unified via GET /v1/ai/requests | ✅ Implemented |
| Bearer JWT placeholder | Removed — returns 401 until Phase 2 JWT implemented | ✅ Fixed |
| Cross-dept trace_id leak | Scoped by dept_id — cross-dept returns 404 | ✅ Fixed |
| Audit endpoints unscoped | All audit endpoints enforce dept_id from request.state | ✅ Fixed |
| Severity classification | CRITICAL/HIGH/MEDIUM/LOW — stored in DB, SIEM-ready | ✅ Implemented |
| audit_logs.threats type | Migrated JSON → JSONB for GIN indexing | ✅ Migrated |
| api_keys NULL dept/tenant | CHECK constraint — non-admin keys must have tenant+dept | ✅ Enforced |

---

*Version: 1.2 — Security & Isolation · April 2026*
