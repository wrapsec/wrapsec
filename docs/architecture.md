# WrapSec — Architecture Specification

Version: 1.0 — Final  
Status: Implemented  
Last updated: April 2026

---

## Overview

WrapSec is a production-grade AI security gateway. It operates as a security layer between calling applications and any LLM provider, scanning every prompt through a four-layer detection pipeline before it reaches the model.

---

## Design Principles

**Detection vs guardrails — two independent subsystems**

Detection (rule, ML, LLM) and guardrails (PII) are architecturally, mathematically, and operationally separate. They are stored in separate database columns, evaluated independently, and never mixed in scoring.

**Threshold decoupling**

Detection thresholds (`thresholds.block`, `thresholds.sanitize`) and guardrail thresholds (`guardrails.pii.block_threshold`, `guardrails.pii.sanitize_threshold`) occupy separate policy paths and are extracted and passed as separate parameters. Changing one never affects the other.

**Guardrail-first enforcement**

Guardrail decisions override detection decisions unconditionally.

**SYSTEM_ERROR is never NO_THREAT_DETECTED**

These are produced by mutually exclusive code paths. `NO_THREAT_DETECTED` is only reachable when `detection_failed=False` and all scores are 0.0. `SYSTEM_ERROR` is always returned when `detection_failed=True`. This consistency is guaranteed across the codebase, docs, and audit records.

**All failure paths → LOW confidence**

Detection failure, guardrail failure, and gateway exceptions all produce `confidence=0.0` and `confidence_band=LOW`. There is no failure path that produces a non-LOW confidence.

**Conservative input limits**

8,000 characters + heuristic token limit `ceil(len/2) > 4000` → 422. Safe for English and CJK. Full tiktoken in V1.1.

**Idempotency with conflict detection**

Same key + same body → cached response. Same key + different body → 409 CONFLICT. This matches Stripe/AWS idempotency standards.

**Zero breaking changes**

Each phase is additive. Existing integrations work without modification.

---

## System Architecture

```
Calling Applications
              │  x-api-key: wsk_live_...
              │  Idempotency-Key: <uuid> (optional)
              ▼
    Nginx (port 80) — 64KB payload limit
              ▼
    WrapSec API (FastAPI, port 8000)
    ┌──────────────────────────────────────────────────┐
    │  Trace → RateLimit(per-key) → Auth →             │
    │  Idempotency(Redis,60s,409 conflict) → Logging   │
    │                                                  │
    │  Policy resolver                                 │
    │  system → tenant → department (→ app V1.1)      │
    │  → detection thresholds  (thresholds.*)          │
    │  → PII thresholds        (guardrails.pii.*)      │
    │    (resolved independently, passed separately)   │
    │                                                  │
    │  Gateway Service                                 │
    │  ├── InputGuard    PII detection + redaction     │
    │  ├── RuleDetector  try/catch → detection_failed  │
    │  ├── MLDetector    try/catch → detection_failed  │
    │  ├── LLMDetector   try/catch → detection_failed  │
    │  ├── RiskScorer    rule+ml+llm (PII excluded)    │
    │  ├── PolicyEngine                                │
    │  │     ├── PII:   guardrails.pii.* thresholds   │
    │  │     └── Det:   thresholds.* thresholds        │
    │  ├── Primary reason (detection_failed → SYSTEM_ERROR first)
    │  ├── LLM Client    proxy mode only               │
    │  └── OutputGuard   PII on LLM output             │
    └──────────────────────────────────────────────────┘
              │
    ┌─────────┴──────────────────┐
    │                            │
PostgreSQL                   Redis
(audit, settings,            idempotency (60s TTL)
 keys, entities,             rate limiting (per key)
 retention policy)           semantic cache
```

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
# In ai.py — after policy resolution
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

```
system defaults (.env)
  ↓ deep merge
tenant global_policy
  ↓ deep merge
DB settings (thresholds, layers, llm, retention)
  ↓ deep merge
department policy_override  (null = inherit)
  ↓ deep merge
application policy_override (null in V1, active V1.1)
  ↓
resolved_policy → split:
  detection thresholds → thresholds.block / thresholds.sanitize
  PII thresholds       → guardrails.pii.block_threshold / sanitize_threshold
```

### Deep Merge Semantics

Recursive merge. Only non-null explicitly provided fields override parent.

```
Finance dept sets: thresholds.block = 0.5
Result:
  thresholds.block                = 0.5  ← overridden
  thresholds.sanitize             = 0.4  ← inherited
  guardrails.pii.block_threshold  = 0.7  ← unchanged (independent path)
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
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id            UUID NOT NULL REFERENCES tenants(id),
    dept_id              UUID NOT NULL REFERENCES departments(id),
    slug                 VARCHAR(50)  NOT NULL,
    name                 VARCHAR(100) NOT NULL,
    description          TEXT,
    owner_name           VARCHAR(100),
    owner_email          VARCHAR(100),
    environment          VARCHAR(20)  DEFAULT 'production',
    metadata             JSONB DEFAULT NULL,
    policy_override      JSONB DEFAULT NULL,   -- V1: null, active V1.1
    rate_limit_override  JSONB DEFAULT NULL,   -- {"per_minute": 120}
    is_active            BOOLEAN DEFAULT true,
    created_at           TIMESTAMP DEFAULT NOW(),
    UNIQUE (dept_id, slug)
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
    key_hash     VARCHAR(100) NOT NULL UNIQUE,  -- SHA-256
    is_admin     BOOLEAN DEFAULT false,
    revoked      BOOLEAN DEFAULT false,
    expires_at   TIMESTAMP DEFAULT NULL,
    last_used_at TIMESTAMP DEFAULT NULL,
    created_at   TIMESTAMP DEFAULT NOW()
);
```

### audit_logs
```sql
CREATE TABLE audit_logs (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trace_id       VARCHAR(100) UNIQUE NOT NULL,  -- "req_" + ULID
    decision       VARCHAR(20)  NOT NULL,
    risk_score     FLOAT        NOT NULL,
    threats        JSON         NOT NULL,
    input_hash     VARCHAR(100) NOT NULL,           -- SHA-256, raw input never stored
    detection_mode VARCHAR(20)  NOT NULL,
    execution_mode VARCHAR(20)  NOT NULL,
    llm_invoked    BOOLEAN      NOT NULL DEFAULT false,
    latency_ms     FLOAT        NOT NULL,
    created_at     TIMESTAMP    DEFAULT NOW(),

    -- Stored separately — architectural separation preserved in DB
    detection_scores JSONB,     -- {"rule": 0.85, "ml": 0.30, "llm": 0.00}
    guardrail_scores JSONB,     -- {"pii": 0.73}

    -- Decision metadata
    confidence       FLOAT,
    confidence_band  VARCHAR(10),
    primary_reason   VARCHAR(50),  -- 7 values including SYSTEM_ERROR
    policy_source    VARCHAR(50),

    -- Attribution
    tenant_id            VARCHAR(50),
    dept_id              VARCHAR(50),
    app_id               VARCHAR(50),
    key_id               VARCHAR(50),
    source               VARCHAR(100),
    user_id              VARCHAR(100),
    ip_address           VARCHAR(50),
    user_agent           VARCHAR(255),
    attribution_verified BOOLEAN DEFAULT false
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
   Load key.app_id, key.dept_id, key.tenant_id

4. Entity validation
   assert key.dept_id   == app.dept_id
   assert key.tenant_id == dept.tenant_id
   Failure → 401 + security log

5. Policy resolution
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
| LLM timeout (proxy) | per detection | per detection | per detection | "[LLM unavailable]" |
| Redis unavailable | allows | — | — | idempotency + rate limit disabled |

**Consistency guarantee:** All failure scenarios produce `SYSTEM_ERROR`. `NO_THREAT_DETECTED` is only produced when detection succeeded and all scores were 0.0. These two values are produced by mutually exclusive code paths — they cannot be confused in audit records.

**SYSTEM_ERROR monitoring:**

`SYSTEM_ERROR` is an operational health signal, not a security event. It should be monitored separately from security decisions.

| Signal | Threshold | Action |
|---|---|---|
| Single `SYSTEM_ERROR` | Any | Log and investigate |
| Rate > 0.1% | Over 5 min | Page on-call |
| Rate > 1% | Over 1 min | Immediate incident |

Query via: `GET /v1/audit/logs?primary_reason=SYSTEM_ERROR`

Alert via Prometheus: `/metrics` exposes request counters by decision and primary_reason.

A low but non-zero rate (< 0.1%) is expected — transient LLM timeouts and occasional ML edge cases. A sustained or rising rate requires infrastructure investigation.

---

## API Endpoints

```
Gateway (2):      POST /v1/ai/request · GET /v1/ai/requests/{trace_id}
Audit (4):        GET  /v1/audit/logs · stats · attribution · export
Settings (8):     GET/PUT /v1/settings/thresholds · layers · llm · retention
API Keys (5):     POST/GET/PUT/DELETE /v1/keys · GET /v1/keys/{key_id}
Tenant (2):       GET/PUT /v1/admin/tenant
Departments (7):  CRUD + /policy + /stats
Applications (6): CRUD + /policy
Health (4):       GET /health · /health/ready · /health/live · /health/config
Metrics (1):      GET /metrics
Total: 39 endpoints
```

---

## Implementation Status V1.0

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
✅ 39 API endpoints
✅ Next.js 14 dashboard (11 pages)
✅ 85 unit + integration tests passing
```

### V1.1 — Planned

```
→ Per-model token counting with tiktoken (replaces heuristic)
→ Application-level policy overrides (placeholder active)
→ API key rotation with grace period
→ Toxicity guardrail (independent thresholds)
→ ML model improvement (3000+ samples)
→ Cursor-based pagination
```

### V2.0 — Future

```
→ JWT + SSO (attribution_verified=true)
→ Role-based policy overrides
→ Human review queue for LOW confidence
→ SaaS multi-tenancy
→ SDK, webhooks, streaming
```

---

## Known Issues & Decisions

| Issue | Decision | Status |
|---|---|---|
| SYSTEM_ERROR vs NO_THREAT_DETECTED | Mutually exclusive code paths, strict priority | ✅ All paths correct |
| Threshold coupling | Fully decoupled — separate policy paths + parameters | ✅ Implemented |
| Token limit | Heuristic ceil(len/2) for V1, tiktoken in V1.1 | ✅ Implemented |
| Idempotency conflict | 409 CONFLICT on same key + different body | ✅ Implemented |
| Entity relationship validation | Assert key→app→dept→tenant | ✅ Auth middleware |
| tenant_id in metadata | Removed — always from API key | ✅ Security fix |
| rate_limit_override type | JSONB (was INTEGER) | ✅ Migrated |
| Audit retention | DB-configurable, default 30 days | ✅ Implemented |
| Guardrail failure | Fail closed (BLOCK + SYSTEM_ERROR) | ✅ Implemented |
| LLM timeout | Graceful degradation per mode | ✅ Implemented |

---

*Version: 1.0 — Final · Review cycles: 7 · April 2026*
