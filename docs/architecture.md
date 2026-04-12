# WrapSec — Architecture Specification

Version: 1.0 — Final  
Status: Implemented  
Last updated: April 2026

---

## Overview

WrapSec is a production-grade AI security gateway for enterprise applications. It operates as a security layer between calling applications and any LLM provider, scanning every prompt through a four-layer detection pipeline before it reaches the model.

This document defines the complete V1 architecture: entity hierarchy, policy model, attribution chain, database schema, API structure, failure modes, and implementation status.

---

## Design Principles

**Separation of concerns**
Detection and guardrails are architecturally, mathematically, and operationally separate. They are stored in separate database columns, evaluated independently, and never mixed in scoring.

**Guardrail-first enforcement**
Guardrail decisions override detection-based decisions unconditionally. PII scores never contribute to the detection risk score. This is implemented and active in V1.

**Hierarchy-first policy**
Most specific level wins in policy resolution. Null fields always inherit from the parent level. Deep merge is recursive — nested fields are merged, not replaced.

**Attribution completeness**
Every request is traceable to tenant → department → application → API key → user → IP. Each identity level has a different trust level — API key identity is cryptographically verified, user identity is self-reported in V1.

**Security by default**
`tenant_id` is never accepted from request metadata — always derived from the API key. This prevents cross-tenant spoofing. Guardrail failures block — fail closed.

**Zero breaking changes**
Each implementation phase is additive. Existing API keys and integrations work without modification.

**SaaS readiness**
The on-premise architecture is identical to a SaaS architecture with one tenant. Going multi-tenant SaaS requires adding a sign-up flow — not a data model change.

---

## System Architecture

```
Calling Applications
(Finance Bot / HR System / ERP / Mobile App)
              │
              │  x-api-key: wsk_live_...
              │  Idempotency-Key: <uuid> (optional)
              ▼
    Nginx (port 80)
    64KB payload limit · Reverse proxy
              │
              ▼
    WrapSec API (FastAPI, port 8000)
    ┌──────────────────────────────────────────────┐
    │  Middleware stack (order matters)             │
    │  Trace → RateLimit (per-key) → Auth →        │
    │  Idempotency (Redis, 60s TTL) → Logging      │
    │                                              │
    │  Policy resolver                             │
    │  system → tenant → department (→ app V1.1)  │
    │                                              │
    │  Gateway Service                             │
    │  ├── InputGuard    PII detection + redaction │
    │  ├── RuleDetector  regex, ~0ms               │
    │  ├── MLDetector    TF-IDF+LR, ~5ms           │
    │  ├── LLMDetector   semantic, conditional     │
    │  ├── RiskScorer    weighted, guardrail-free  │
    │  ├── PolicyEngine  guardrail-first           │
    │  ├── LLM Client    proxy mode only           │
    │  └── OutputGuard   PII on LLM output         │
    └──────────────────────────────────────────────┘
              │
    ┌─────────┴──────────────────┐
    │                            │
PostgreSQL                   Redis
tenants, departments,        semantic cache
applications, api_keys,      rate limiting (per key)
audit_logs, settings         idempotency (60s TTL)
```

---

## Entity Hierarchy

```
tenant (root — one per installation)
│
├── global_policy (default for all departments)
│
├── departments (organisational divisions)
│     ├── Finance    → policy_override: block=0.5, sanitize=0.3
│     ├── HR         → policy_override: block=0.5, local LLM
│     └── Engineering → policy_override: block=0.75, LLM disabled
│
└── applications (systems per department)
      ├── Finance Bot     → dept: Finance  → api_key: wsk_live_fin_...
      ├── ERP System      → dept: Finance  → api_key: wsk_live_erp_...
      ├── HR HRIS         → dept: HR       → api_key: wsk_live_hr_...
      └── Code Assistant  → dept: Eng      → api_key: wsk_live_eng_...
```

Each application has one or more API keys. Each key is scoped to exactly one application, one department, and one tenant. API keys carry the full entity chain — tenant, dept, and app IDs stored on the key record.

---

## Policy Model

### Policy Object Structure

Full policy object stored at tenant level. Department and application levels store partial override objects — only the fields they change. Null = inherit from parent.

```json
{
  "detection": {
    "rule_weight":   0.4,
    "ml_weight":     0.3,
    "llm_weight":    0.3,
    "rule_enabled":  true,
    "ml_enabled":    true,
    "llm_enabled":   true,
    "llm_trigger":   0.2
  },
  "thresholds": {
    "block":    0.7,
    "sanitize": 0.4
  },
  "guardrails": {
    "pii": {
      "enabled":            true,
      "block_threshold":    0.7,
      "sanitize_threshold": 0.4
    }
  },
  "llm": {
    "provider":  "ollama",
    "model":     "llama3.2:latest",
    "base_url":  "http://localhost:11434",
    "timeout":   30
  },
  "rate_limit": {
    "per_minute": 60
  }
}
```

### Null Placeholder Policy

Every entity always has a `policy_override` field present. When no override is set, the field is `null` — not missing. This makes the schema consistent and documents intent clearly.

```json
{ "app_id": "app_engineering", "policy_override": null }
```

### Policy Resolution Order

```
system defaults (.env)
  ↓ deep merge
tenant global_policy          (tenants.global_policy)
  ↓ deep merge
DB settings                   (policy_thresholds, detection_layers, llm_settings)
  ↓ deep merge
department policy_override    (null = inherit, partial = override specific fields)
  ↓ deep merge
application policy_override   (null in V1 — placeholder active, used in V1.1)
  ↓
resolved_policy → applied to this request
```

### Deep Merge Semantics

Recursive merge. Only non-null explicitly provided fields override the parent. Missing or null fields are always preserved from parent.

```
Parent (tenant global):
  guardrails.pii.enabled            = true
  guardrails.pii.block_threshold    = 0.7
  guardrails.pii.sanitize_threshold = 0.4

Child (Finance dept override):
  guardrails.pii.block_threshold = 0.5  ← only this field

Result (deep merge — correct):
  guardrails.pii.enabled            = true   ← preserved
  guardrails.pii.block_threshold    = 0.5    ← overridden
  guardrails.pii.sanitize_threshold = 0.4    ← preserved

Shallow replace (WRONG — never do this):
  guardrails.pii = { block_threshold: 0.5 }
  → enabled and sanitize_threshold are LOST — dangerous
```

### Policy Source

`policy_source` records which hierarchy level determined the final resolved policy.

| Value | Meaning |
|---|---|
| `system_default` | No DB overrides — `.env` defaults only |
| `tenant_global` | Tenant global policy applied, no dept/app overrides |
| `department_override` | Department changed at least one field |
| `application_override` | Application changed at least one field (V1.1) |

### Resolution Example

```
Request: Finance Bot, Finance Department

block_threshold:
  system default:   0.7
  tenant global:    0.7
  department:       0.5  ← overrides
  application:      null  ← inherits dept

policy_source: "department_override"

guardrails.pii.block_threshold:
  tenant global:    0.7
  department:       null  ← inherits (only thresholds were overridden)
  → effective: 0.7
```

---

## Database Schema

### tenants

```sql
CREATE TABLE tenants (
    id            UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug          VARCHAR(50)  UNIQUE NOT NULL,
    name          VARCHAR(100) NOT NULL,
    description   TEXT,
    global_policy JSONB        NOT NULL DEFAULT '{}',
    is_active     BOOLEAN      DEFAULT true,
    contact_email VARCHAR(100),
    created_by    VARCHAR(100),
    created_at    TIMESTAMP    DEFAULT NOW()
);
```

### departments

```sql
CREATE TABLE departments (
    id               UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id        UUID         NOT NULL REFERENCES tenants(id),
    slug             VARCHAR(50)  NOT NULL,
    name             VARCHAR(100) NOT NULL,
    description      TEXT,
    policy_override  JSONB        DEFAULT NULL,
    is_active        BOOLEAN      DEFAULT true,
    contact_email    VARCHAR(100),
    created_by       VARCHAR(100),
    created_at       TIMESTAMP    DEFAULT NOW(),
    UNIQUE (tenant_id, slug)
);
```

### applications

```sql
CREATE TABLE applications (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id            UUID         NOT NULL REFERENCES tenants(id),
    dept_id              UUID         NOT NULL REFERENCES departments(id),
    slug                 VARCHAR(50)  NOT NULL,
    name                 VARCHAR(100) NOT NULL,
    description          TEXT,
    owner_name           VARCHAR(100),
    owner_email          VARCHAR(100),
    environment          VARCHAR(20)  DEFAULT 'production',
    metadata             JSONB        DEFAULT NULL,
    policy_override      JSONB        DEFAULT NULL,  -- V1: null placeholder
    rate_limit_override  JSONB        DEFAULT NULL,  -- JSONB: {"per_minute": 120}
    is_active            BOOLEAN      DEFAULT true,
    created_at           TIMESTAMP    DEFAULT NOW(),
    UNIQUE (dept_id, slug)
);
```

### api_keys

```sql
CREATE TABLE api_keys (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id       VARCHAR(50)  UNIQUE NOT NULL,    -- "key_abc123"
    tenant_id    UUID         REFERENCES tenants(id),
    dept_id      UUID         REFERENCES departments(id),
    app_id       UUID         REFERENCES applications(id),
    name         VARCHAR(100) NOT NULL,
    key_hash     VARCHAR(100) NOT NULL UNIQUE,    -- SHA-256 of wsk_live_...
    is_admin     BOOLEAN      DEFAULT false,
    revoked      BOOLEAN      DEFAULT false,
    expires_at   TIMESTAMP    DEFAULT NULL,
    last_used_at TIMESTAMP    DEFAULT NULL,
    created_at   TIMESTAMP    DEFAULT NOW()
);
```

### audit_logs

```sql
CREATE TABLE audit_logs (
    id             UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    trace_id       VARCHAR(100) UNIQUE NOT NULL,  -- "req_" + ULID
    decision       VARCHAR(20)  NOT NULL,
    risk_score     FLOAT        NOT NULL,
    threats        JSON         NOT NULL,
    input_hash     VARCHAR(100) NOT NULL,          -- SHA-256, raw input never stored
    detection_mode VARCHAR(20)  NOT NULL,
    execution_mode VARCHAR(20)  NOT NULL,
    llm_invoked    BOOLEAN      NOT NULL DEFAULT false,
    latency_ms     FLOAT        NOT NULL,
    created_at     TIMESTAMP    DEFAULT NOW(),

    -- Layer scores (separate by architectural concern)
    detection_scores JSONB,     -- {"rule": 0.85, "ml": 0.30, "llm": 0.00}
    guardrail_scores JSONB,     -- {"pii": 0.73}

    -- Decision metadata
    confidence       FLOAT,
    confidence_band  VARCHAR(10),
    primary_reason   VARCHAR(50),
    policy_source    VARCHAR(50),

    -- Attribution chain
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

-- Indexes
CREATE INDEX ix_audit_trace        ON audit_logs (trace_id);
CREATE INDEX ix_audit_decision     ON audit_logs (decision, created_at);
CREATE INDEX ix_audit_tenant       ON audit_logs (tenant_id, created_at);
CREATE INDEX ix_audit_dept         ON audit_logs (dept_id,   created_at);
CREATE INDEX ix_audit_app          ON audit_logs (app_id,    created_at);
CREATE INDEX ix_audit_key          ON audit_logs (key_id,    created_at);
CREATE INDEX ix_audit_user         ON audit_logs (user_id,   created_at);
```

### settings

```sql
CREATE TABLE settings (
    key        VARCHAR(100) PRIMARY KEY,
    value      TEXT         NOT NULL,
    updated_at TIMESTAMP    DEFAULT NOW()
);

-- Active keys:
-- "policy_thresholds" → {"block_threshold": 0.7, "sanitize_threshold": 0.4}
-- "detection_layers"  → {"rule_enabled": true, "ml_enabled": true, "llm_enabled": true}
-- "llm_settings"      → {"provider": "ollama", "model": "...", "timeout": 30, ...}
-- "audit_retention"   → {"retention_days": 30}
```

---

## Authentication & Policy Resolution Flow

```
1. Request arrives
   POST /v1/ai/request
   x-api-key: wsk_live_fin_abc123
   Idempotency-Key: 550e8400-... (optional)
   body: { input, metadata: { user_id, source } }

   SECURITY: tenant_id is NOT accepted in metadata.
   Tenant identity is ALWAYS derived from the API key.
   This prevents cross-tenant spoofing.

2. Idempotency check (if header present)
   cache_key = SHA-256(idempotency_key + body_hash)
   Redis hit → return cached response immediately
   Redis miss → continue processing, cache after completion
   TTL: 60 seconds

3. Rate limit check (per API key)
   key_id from api_keys record used as rate limit identifier
   Falls back to IP if no key authenticated yet
   Returns X-RateLimit-Limit/Remaining/Reset headers on all responses

4. Auth middleware
   a. Hash key (SHA-256)
   b. Look up api_keys by hash
   c. Validate not revoked
   d. Entity chain:
        key.app_id    = "app_finance_bot"
        key.dept_id   = "dept_finance"
        key.tenant_id = "tenant_acme"

5. Entity relationship validation
   assert key.dept_id   == app.dept_id      ← key must belong to app's dept
   assert key.tenant_id == dept.tenant_id   ← dept must belong to key's tenant
   If fails → 401 + security log entry

6. Policy resolution
   policy_resolver.resolve_policy(tenant_id, dept_id, app_id)
   Deep merge: system → tenant → dept → app (null in V1)
   Returns (policy_dict, policy_source)

7. request.state populated
   tenant_id, dept_id, app_id, key_id,
   user_id (from metadata — self-reported),
   ip_address, user_agent,
   policy (resolved), policy_source

8. Gateway processing with resolved policy

9. Audit log created with full attribution
```

---

## Complete Audit Entry

```json
{
  "trace_id":  "req_01knzhh81wrwg2r8r7wnwq139y",
  "timestamp": "2026-04-12T03:14:22Z",

  "attribution": {
    "tenant_id":            "42a083bf-...",
    "dept_id":              "d79ad4d5-...",
    "dept_name":            "Finance Department",
    "app_id":               "972eae29-...",
    "app_name":             "Finance Bot",
    "key_id":               "key_fin_abc123",
    "source":               "Finance Bot",
    "user_id":              "emp_789",
    "ip_address":           "10.0.0.45",
    "user_agent":           "FinanceBot/2.1",
    "attribution_verified": false
  },

  "decision": {
    "decision":             "BLOCK",
    "decision_version":     "v1.0",
    "risk_score":           0.73,
    "confidence":           0.9015,
    "confidence_band":      "HIGH",
    "primary_reason":       "PII_GUARDRAIL_BLOCK",
    "threats":              ["PII"],
    "policy_source":        "department_override"
  },

  "signals": {
    "detection_scores": {"rule": 0.0, "ml": 0.0, "llm": 0.0},
    "guardrail_scores": {"pii": 0.73}
  }
}
```

**Compliance answers:**

```
Who?      Finance Bot application (FinanceBot/2.1)
          acting as emp_789 (self-reported)
Dept?     Finance Department, Acme Corporation
Key?      key_fin_abc123
Network?  10.0.0.45 (internal)
What?     BLOCKED — PII score 0.73 exceeded block threshold 0.5
Certain?  90.15% confidence (HIGH)
Cause?    PII_GUARDRAIL_BLOCK
Policy?   Finance Department override (block=0.5)
Algorithm? v1.0
Verified? attribution_verified=false (user_id is self-reported)
```

---

## Metadata Trust Model

```
API key (system identity):
  → Cryptographically verified by WrapSec
  → Identifies: tenant, department, application
  → Cannot be spoofed — SHA-256 hash checked against DB
  → attribution_verified=true (implicit)

Request metadata (user identity):
  → Self-reported by the calling application
  → Trusted but not verified by WrapSec in V1
  → user_id and source accepted as labels only
  → attribution_verified=false

tenant_id is NEVER accepted from request metadata:
  → Always derived from the API key record
  → Prevents cross-tenant spoofing
  → Any tenant_id in metadata is silently ignored

V2: Signed JWT provides cryptographically verified user identity
    attribution_verified=true when JWT validated
```

---

## Input Limits

| Limit | Value | Enforcement |
|---|---|---|
| Max input characters | 10,000 | Pydantic schema validation → 422 |
| Max payload size | 64KB | Nginx `client_max_body_size` |
| Max audit export | 10,000 records | Query parameter validation |
| Max retention days | 3,650 (10 years) | Settings validation |
| Min retention days | 7 | Settings validation |

---

## Rate Limiting

```
V1: Per API key (not per IP)
    60 requests/minute default (configurable in .env)
    Redis sliding window
    key_id used as rate limit identifier
    Falls back to hashed API key value if key_id not yet in request.state
    Falls back to IP if completely unauthenticated

Response headers on every request:
    X-RateLimit-Limit:     60
    X-RateLimit-Remaining: 47
    X-RateLimit-Reset:     1712718262 (Unix timestamp)

429 response:
    {"error": {"code": "RATE_LIMITED", "message": "...", "trace_id": "..."}}

V1.1: Per department aggregate limits
      rate_limit_override on applications table (JSONB, currently null placeholder)
```

---

## Idempotency

```
Header: Idempotency-Key: <uuid>
Scope:  POST /v1/ai/request only

Behaviour:
  First request with key → process normally → cache (key + body_hash) → response
  Repeat request         → cache hit → return cached response immediately
  Response header:         X-Idempotency-Replayed: true

Cache key: SHA-256(idempotency_key + body_hash)
  body_hash ties the idempotency key to a specific request body
  same idempotency_key + different body = new request (cache miss)

TTL: 60 seconds
Storage: Redis

Fail open: if Redis unavailable → processes normally
Only caches non-5xx responses

Purpose: Prevents duplicate BLOCK decisions on client retries
```

---

## Trace ID Format

```
Format: "req_" + ULID
Example: req_01knzhh81wrwg2r8r7wnwq139y

ULID properties:
  → 26 characters, base32 encoded
  → Lexicographically sortable by creation time
  → Monotonically increasing
  → No UUID collisions at scale
  → Better PostgreSQL index performance than random UUIDs

Old format (replaced): "req_" + random 8-char hex
  Example: req_a1b2c3d4
```

---

## Audit Log Retention

```
Configuration: Settings page → Audit Log Retention card
Storage:       settings table, key="audit_retention"
Default:       30 days (from .env AUDIT_RETENTION_DAYS)
Range:         7–3650 days (1 week to 10 years)
Priority:      DB setting overrides .env setting

Cleanup script: scripts/cleanup_audit_logs.py
  Reads retention_days from DB first, falls back to config
  Usage:
    python scripts/cleanup_audit_logs.py              # uses DB/config setting
    python scripts/cleanup_audit_logs.py --dry-run    # shows what would be deleted
    python scripts/cleanup_audit_logs.py --days 90    # override setting

Recommended: run daily via cron or Docker scheduled task
  0 2 * * * python /app/scripts/cleanup_audit_logs.py
```

---

## Failure Modes

| Failure | Decision | Risk Score | Confidence | Primary Reason |
|---|---|---|---|---|
| One detector fails | continues with others | from remaining | from remaining | per remaining |
| All detectors fail | ALLOW | 0.0 | LOW | NO_THREAT_DETECTED |
| Guardrail failure | BLOCK | 1.0 | LOW | SYSTEM_ERROR |
| Gateway exception | BLOCK | 1.0 | LOW | SYSTEM_ERROR |
| LLM timeout (detection) | continues | from rule+ML | from rule+ML | RULE/ML_DETECTOR |
| LLM timeout (proxy) | per detection | per detection | per detection | per detection |
| Redis unavailable | allows (fail open) | — | — | rate limit + idempotency disabled |

**Fail closed vs fail open:**
- Data protection (guardrail failure) → fail closed (BLOCK)
- Detection failure → fail open (ALLOW + LOW confidence)
- Redis unavailable → fail open (rate limiting and idempotency disabled gracefully)

---

## API Endpoints — Complete V1 List

```
Gateway (2):
  POST   /v1/ai/request
  GET    /v1/ai/requests/{trace_id}

Audit (4):
  GET    /v1/audit/logs           (12 filter params)
  GET    /v1/audit/stats
  GET    /v1/audit/attribution
  GET    /v1/audit/export         (CSV download)

Settings (8):
  GET    /v1/settings/thresholds
  PUT    /v1/settings/thresholds
  GET    /v1/settings/layers
  PUT    /v1/settings/layers
  GET    /v1/settings/llm
  PUT    /v1/settings/llm
  GET    /v1/settings/retention
  PUT    /v1/settings/retention

API Keys (5):
  POST   /v1/keys
  GET    /v1/keys
  GET    /v1/keys/{key_id}
  PUT    /v1/keys/{key_id}
  DELETE /v1/keys/{key_id}

Tenant (2):
  GET    /v1/admin/tenant
  PUT    /v1/admin/tenant

Departments (7):
  POST   /v1/admin/departments
  GET    /v1/admin/departments
  GET    /v1/admin/departments/{id}
  PUT    /v1/admin/departments/{id}
  DELETE /v1/admin/departments/{id}
  GET    /v1/admin/departments/{id}/policy
  GET    /v1/admin/departments/{id}/stats

Applications (6):
  POST   /v1/admin/applications
  GET    /v1/admin/applications
  GET    /v1/admin/applications/{id}
  PUT    /v1/admin/applications/{id}
  DELETE /v1/admin/applications/{id}
  GET    /v1/admin/applications/{id}/policy

Health (4):
  GET    /health
  GET    /health/ready
  GET    /health/live
  GET    /health/config

Metrics (1):
  GET    /metrics

Total: 39 endpoints
```

---

## Dashboard Pages

| Page | Route | APIs Used |
|---|---|---|
| Overview | `/` | audit/stats, audit/logs |
| Requests | `/requests` | audit/logs (12 filters), ai/requests/{id} |
| Analytics | `/analytics` | audit/stats |
| Scanner | `/scanner` | ai/request (debug mode) |
| Settings | `/settings` | settings/*, admin/tenant |
| API Keys | `/settings/keys` | keys/* |
| Departments | `/departments` | admin/departments/* |
| Department Detail | `/departments/[id]` | admin/departments/{id}/*, admin/applications |
| Applications | `/applications` | admin/applications/* |
| Application Detail | `/applications/[id]` | admin/applications/{id}/* |
| Login | `/login` | (HttpOnly cookie auth) |

---

## SaaS Migration Path

```
On-premise (now — V1):
  tenants:      1 record (the company)
  departments:  N records (divisions)
  applications: N records (systems per division)

SaaS (V3):
  tenants:      N records (one per paying company)
  departments:  N records (same structure)
  applications: N records (same structure)

Migration requires:
  1. Tenant sign-up and onboarding flow
  2. Billing hooks at tenant level
  3. Self-service portal
  4. Tenant isolation enforcement audit

Zero changes to:
  API endpoints, detection pipeline, policy resolution,
  audit schema, dashboard components, authentication model,
  middleware stack, entity hierarchy
```

---

## Implementation Status

### V1.0 — Complete

```
✅ Detection engine: rule, ML, LLM, PII guardrail
✅ Guardrail-first enforcement
✅ Policy resolution: system → tenant → department
✅ Deep merge with null inheritance
✅ Entity relationship validation in auth middleware
✅ tenant_id removed from request metadata (security fix)
✅ Idempotency-Key header (Redis, 60s TTL)
✅ ULID trace IDs (time-sortable)
✅ Rate limiting per API key with standard headers
✅ Audit log retention (configurable via Settings UI + DB)
✅ Failure mode contract (SYSTEM_ERROR + LOW confidence)
✅ decision_version in all responses
✅ sanitization_applied flag
✅ Confidence score + confidence_band
✅ primary_reason (7 values)
✅ Nginx 64KB payload limit
✅ LLM timeout graceful degradation
✅ 39 API endpoints
✅ Next.js 14 dashboard (11 pages)
✅ HttpOnly cookie auth in dashboard
✅ Prometheus metrics + structured JSON logging
✅ Docker Compose full stack
✅ 85 unit + integration tests passing
```

### V1.1 — Planned

```
→ Application-level policy overrides (null placeholder active in V1)
→ API key rotation with grace period
→ Cursor-based pagination for large audit datasets
→ ML model improvement (3000+ samples from public datasets)
→ Toxicity guardrail layer
→ Per-layer latency breakdown in debug mode
→ Per-department rate limit aggregates
```

### V2.0 — Future

```
→ JWT + SSO for verified user attribution (attribution_verified=true)
→ Role-based policy overrides
→ Human review queue for LOW confidence decisions
→ Multi-tenant SaaS onboarding
→ SDK — Python, Node.js
→ Webhook notifications
→ Streaming support
```

---

## Known Issues & Design Decisions

| Issue | Decision | Status |
|---|---|---|
| Deep merge semantics | Recursive, null fields inherit | Implemented + 6 unit tests |
| Entity relationship validation | Assert key→app→dept→tenant | Auth middleware |
| Metadata trust model | Self-reported, attribution_verified=false | V1 implemented |
| tenant_id in metadata | Removed — always from API key | Security fix applied |
| Policy source definition | Highest level that changed any field | Implemented |
| Rate limiting scope | Per API key in V1, per dept in V1.1 | V1 done |
| Application policy overrides | Null placeholder, active in V1.1 | DB column present |
| rate_limit_override type | JSONB (was INTEGER) | Migrated |
| Idempotency | Redis-based, 60s TTL, per path | Implemented |
| Trace ID format | ULID (was random hex) | Implemented |
| Audit retention | DB-configurable, default 30 days | Implemented |
| Failure mode confidence | LOW + SYSTEM_ERROR on exception | Implemented |
| Guardrail confidence | Tiered: 0.90–0.95 BLOCK, 0.70–0.84 SANITIZE | Implemented |
| LLM timeout | Graceful degradation, continues without LLM | Implemented |
| Nginx payload limit | 64KB | Implemented |

---

*Version: 1.0 — Final*  
*Review cycles: 5*  
*Implementation: V1 complete*  
*Last updated: April 2026*
