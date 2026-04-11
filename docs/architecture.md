# WrapSec — Architecture Specification (Final)

Version: 1.0  
Status: Approved for implementation  
Last updated: April 2026

---

## Overview

WrapSec is a production-grade AI security gateway for enterprise applications. This document defines the complete architecture including entity hierarchy, policy model, attribution chain, database schema, and implementation roadmap.

The architecture is designed for single on-premise enterprise installations with a clean, zero-breaking-change migration path to SaaS.

---

## Design Principles

**Separation of concerns**
- Detectors identify malicious intent (probabilistic)
- Guardrails enforce data protection policies (deterministic)
- Policy engine applies configurable thresholds
- Attribution layer provides audit trail

**Guardrail-first enforcement**
- Guardrail decisions override detection-based decisions
- PII and future guardrails never contribute to the detection risk score

**Hierarchy-first policy**
- Most specific level wins
- Null fields always inherit from the parent level
- Deep merge — nested fields are merged recursively, not replaced

**Attribution completeness**
- Every request is traceable to tenant, department, application, key, user, and network origin
- Attribution is self-reported in v1 (system-level verified, user-level trusted)

**Zero breaking changes**
- Each implementation phase is additive
- Existing API keys and integrations continue working without modification

---

## Entity Hierarchy

```
tenant (root — the company installation)
│
├── global_policy (default rules for all departments)
│
├── departments (organisational divisions)
│     ├── Finance Department   → policy_override: stricter PII
│     ├── HR Department        → policy_override: strict PII, local LLM
│     └── Engineering Dept     → policy_override: relaxed, LLM disabled
│
└── applications (systems calling the API, per department)
      ├── Finance Bot          → dept: Finance, attribution only in v1
      ├── ERP Integration      → dept: Finance, attribution only in v1
      ├── HR HRIS System       → dept: HR,      attribution only in v1
      └── Code Assistant       → dept: Engineering
```

Each application has one or more API keys. Each API key is scoped to exactly one application, one department, and one tenant.

---

## Policy Model

### Policy Object Structure

Every level stores a complete or partial policy object in JSONB. The full structure is defined at the tenant level. Department and application levels store only the fields they override — all other fields are null (inherit from parent).

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

### Policy Override — Always Present, Null When Not Overriding

Every entity always has a `policy_override` field. When no override is set the field is present but null. This is intentional — it makes the schema consistent, avoids null-check ambiguity, and documents intent clearly.

```json
// Department with no overrides
{
  "dept_id": "dept_engineering",
  "policy_override": null
}

// Department with overrides
{
  "dept_id": "dept_finance",
  "policy_override": {
    "thresholds": {
      "block":    0.5,
      "sanitize": 0.3
    },
    "guardrails": {
      "pii": {
        "block_threshold": 0.5
      }
    }
  }
}

// Application — always has placeholder, null in v1
{
  "app_id": "app_finance_bot",
  "policy_override": null,
  "rate_limit_override": null
}
```

### Policy Resolution Order

```
system defaults (.env)
  ↓ deep merge
tenant global_policy
  ↓ deep merge (null fields inherit from above)
department policy_override
  ↓ deep merge (null fields inherit from above)
application policy_override  ← null in v1, active in v1.1
  ↓ deep merge (null fields inherit from above)
role policy_override          ← deferred to v2
  ↓
resolved_policy → used for this request
```

### Deep Merge Semantics (Critical)

Merge is recursive. Only explicitly provided non-null fields override the parent. Missing or null fields are preserved from the parent.

```
Parent (tenant global):
  { "guardrails": { "pii": { "enabled": true, "block": 0.7, "sanitize": 0.4 } } }

Child (department override):
  { "guardrails": { "pii": { "block": 0.5 } } }

Result (deep merge — correct):
  { "guardrails": { "pii": { "enabled": true, "block": 0.5, "sanitize": 0.4 } } }

Shallow replace (incorrect — never do this):
  { "guardrails": { "pii": { "block": 0.5 } } }
  → "enabled" and "sanitize" are lost — dangerous
```

### Policy Source

`policy_source` records which level of the hierarchy determined the final policy for the request. It is set to the highest priority level that overrode any field from its parent.

```
"global"               → tenant policy applied, no department or app overrides
"department_override"  → department policy changed at least one field
"application_override" → application policy changed at least one field (v1.1)
```

### Resolution Example

```
Request: Finance Bot (application), Finance Department, employee emp_789

block_threshold:
  system default:          0.7
  tenant global:           0.7   → 0.7
  department (Finance):    0.5   → 0.5  ← department wins
  application (Fin Bot):   null  → 0.5  ← inherits

llm_provider:
  system default:          ollama
  tenant global:           ollama → ollama
  department (Finance):    null   → ollama ← inherits
  application (Fin Bot):   null   → ollama ← inherits

policy_source: "department_override"
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

-- Default tenant record (single on-premise installation)
INSERT INTO tenants (slug, name, global_policy)
VALUES ('default', 'Default Organisation', '{ ... }');
```

### departments

```sql
CREATE TABLE departments (
    id               UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id        UUID         NOT NULL REFERENCES tenants(id),
    slug             VARCHAR(50)  NOT NULL,
    name             VARCHAR(100) NOT NULL,
    description      TEXT,
    policy_override  JSONB        DEFAULT NULL,  -- null = no override, inherit global
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
    metadata             JSONB        DEFAULT NULL,  -- informational only in v1
    policy_override      JSONB        DEFAULT NULL,  -- placeholder, null in v1
    rate_limit_override  INTEGER      DEFAULT NULL,  -- placeholder, null in v1
    is_active            BOOLEAN      DEFAULT true,
    created_at           TIMESTAMP    DEFAULT NOW(),
    UNIQUE (dept_id, slug)
);
```

### api_keys (updated)

```sql
CREATE TABLE api_keys (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id       VARCHAR(50)  UNIQUE NOT NULL,
    tenant_id    UUID         REFERENCES tenants(id),
    dept_id      UUID         REFERENCES departments(id),
    app_id       UUID         REFERENCES applications(id),
    name         VARCHAR(100) NOT NULL,
    key_hash     VARCHAR(100) NOT NULL UNIQUE,
    is_admin     BOOLEAN      DEFAULT false,
    revoked      BOOLEAN      DEFAULT false,
    expires_at   TIMESTAMP    DEFAULT NULL,
    last_used_at TIMESTAMP    DEFAULT NULL,
    created_at   TIMESTAMP    DEFAULT NOW()
);
```

### audit_logs (updated — full attribution)

```sql
-- Existing columns (unchanged)
id, trace_id, decision, risk_score, threats,
input_hash, detection_mode, execution_mode,
llm_invoked, latency_ms, detection_scores,
guardrail_scores, created_at

-- Phase 1 additions (attribution)
ALTER TABLE audit_logs
    ADD COLUMN key_id               VARCHAR(50)  DEFAULT NULL,
    ADD COLUMN ip_address           VARCHAR(50)  DEFAULT NULL,
    ADD COLUMN user_agent           VARCHAR(255) DEFAULT NULL,
    ADD COLUMN attribution_verified BOOLEAN      DEFAULT false;

-- Phase 2 additions (application)
ALTER TABLE audit_logs
    ADD COLUMN app_id   VARCHAR(50) DEFAULT NULL;

-- Phase 3 additions (department + policy source)
ALTER TABLE audit_logs
    ADD COLUMN dept_id        VARCHAR(50) DEFAULT NULL,
    ADD COLUMN policy_source  VARCHAR(50) DEFAULT NULL;

-- Phase 4 additions (tenant)
ALTER TABLE audit_logs
    ADD COLUMN tenant_id VARCHAR(50) DEFAULT NULL;

-- Indexes
CREATE INDEX ix_audit_tenant_created ON audit_logs (tenant_id, created_at);
CREATE INDEX ix_audit_dept_created   ON audit_logs (dept_id,   created_at);
CREATE INDEX ix_audit_app_created    ON audit_logs (app_id,    created_at);
CREATE INDEX ix_audit_key_created    ON audit_logs (key_id,    created_at);
CREATE INDEX ix_audit_user_created   ON audit_logs (user_id,   created_at);
```

### roles (deferred to v2)

```sql
CREATE TABLE roles (
    id               UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id        UUID         NOT NULL REFERENCES tenants(id),
    name             VARCHAR(50)  NOT NULL,
    description      TEXT,
    policy_override  JSONB        DEFAULT NULL,
    created_at       TIMESTAMP    DEFAULT NOW(),
    UNIQUE (tenant_id, name)  -- tenant-scoped to prevent cross-tenant pollution
);
```

---

## Authentication & Policy Resolution Flow

```
1. Request arrives
   POST /v1/ai/request
   x-api-key: wsk_live_fin_abc123
   metadata: { user_id: "emp_789" }

2. Auth middleware
   a. Hash the API key
   b. Look up api_keys by hash
   c. Validate not revoked
   d. Get key record:
        key.app_id    = "app_finance_bot"
        key.dept_id   = "dept_finance"
        key.tenant_id = "tenant_acme"

3. Entity relationship validation (security)
   assert key.dept_id  == app.dept_id      ← prevent mismatch
   assert key.tenant_id == dept.tenant_id  ← prevent mismatch
   If validation fails → 401 + security log entry

4. Load entity chain
   tenant      = get_tenant(key.tenant_id)
   department  = get_department(key.dept_id)
   application = get_application(key.app_id)

5. Resolve policy
   policy = system_defaults()
   policy = deep_merge(policy, tenant.global_policy)
   policy = deep_merge(policy, department.policy_override)  ← null safe
   policy = deep_merge(policy, application.policy_override) ← null in v1

6. Determine policy_source
   if   application.policy_override is not null → "application_override"
   elif department.policy_override  is not null → "department_override"
   else                                         → "global"

7. Attach to request.state
   request.state.tenant_id             = key.tenant_id
   request.state.dept_id               = key.dept_id
   request.state.app_id                = key.app_id
   request.state.key_id                = key.key_id
   request.state.user_id               = metadata.user_id
   request.state.ip_address            = request.client.host
   request.state.user_agent            = request.headers["user-agent"]
   request.state.attribution_verified  = false  ← user_id is self-reported
   request.state.policy                = resolved_policy
   request.state.policy_source         = policy_source

8. Gateway processes request using request.state.policy

9. Audit log stores full attribution
```

---

## Metadata Trust Model

```
API key authentication (system level):
  → Verified by WrapSec cryptographically
  → Trusted completely
  → Identifies: which application, department, tenant

Request metadata (user level):
  → Self-reported by the calling application
  → Trusted but not verified by WrapSec
  → Identifies: which user, which role (future)
  → attribution_verified = false

This is the industry standard model:
  API key    = system identity  (WrapSec verifies)
  metadata   = user identity    (calling system verifies)

v1:  Trust metadata as-is, flag attribution_verified=false
v2:  Signed JWT for verified user identity
```

---

## Rate Limiting Scope

```
v1 (current):
  Per API key — 60 req/min default
  Redis sliding window per key_id

v1.1 (planned):
  Per department aggregate limit
  rate_limit_override on applications table (currently null placeholder)

v2 (future):
  Per tenant aggregate limit
  Per role limits
```

---

## Complete Audit Entry

```json
{
  "trace_id":  "req_abc123",
  "timestamp": "2026-04-09T03:14:22Z",

  "attribution": {
    "tenant_id":            "tenant_acme",
    "dept_id":              "dept_finance",
    "app_id":               "app_finance_bot",
    "key_id":               "key_fin_abc123",
    "user_id":              "emp_789",
    "ip_address":           "10.0.0.45",
    "user_agent":           "FinanceBot/2.1",
    "attribution_verified": false
  },

  "decision": {
    "decision":        "BLOCK",
    "risk_score":      0.73,
    "primary_reason":  "PII_GUARDRAIL_BLOCK",
    "threats":         ["PII"],
    "policy_source":   "department_override"
  },

  "policy_applied": {
    "block_threshold":    0.5,
    "sanitize_threshold": 0.3
  },

  "signals": {
    "detectors": {
      "rule": 0.00,
      "ml":   0.00,
      "llm":  0.00
    },
    "guardrails": {
      "pii": 0.73
    }
  },

  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only"
  }
}
```

---

## API Endpoints

### Super Admin (admin key)

```
Tenant:
  GET  /v1/admin/tenant              → get tenant + global policy
  PUT  /v1/admin/tenant              → update global policy

Departments:
  POST   /v1/admin/departments       → create department
  GET    /v1/admin/departments       → list departments
  GET    /v1/admin/departments/{id}  → get department + policy
  PUT    /v1/admin/departments/{id}  → update department / policy
  DELETE /v1/admin/departments/{id}  → deactivate

Applications:
  POST   /v1/admin/applications      → create application
  GET    /v1/admin/applications      → list applications
  GET    /v1/admin/applications/{id} → get application
  PUT    /v1/admin/applications/{id} → update application
  DELETE /v1/admin/applications/{id} → deactivate

Cross-department analytics:
  GET  /v1/admin/audit/logs          → all requests, all depts
  GET  /v1/admin/audit/stats         → cross-department stats
  GET  /v1/admin/departments/{id}/stats → per-department stats
```

### Department / Application (dept or app key — scoped automatically)

```
  POST   /v1/ai/request               → scan or proxy
  GET    /v1/ai/requests/{trace_id}   → own requests only
  GET    /v1/audit/logs               → own dept requests only
  GET    /v1/audit/stats              → own dept stats only
  GET    /v1/keys                     → own dept keys only
  POST   /v1/keys                     → create key for own dept
  DELETE /v1/keys/{key_id}            → revoke own key
  GET    /v1/settings/thresholds      → resolved policy (read-only)
  GET    /v1/settings/layers          → resolved layers (read-only)
```

---

## Dashboard Structure

### Super Admin View

```
Overview          → cross-department metrics + top threats
Departments       → manage departments + view policy overrides
Applications      → manage applications per department
Requests          → all requests, filterable by dept/app/key/user
Analytics         → cross-department charts
Settings
  Global Policy   → tenant-wide thresholds + detection layers
  LLM Config      → global LLM settings (provider, model, URL)
API Keys          → all keys across departments
```

### Department View (department key)

```
Overview          → this department's metrics only
Applications      → this department's applications
Requests          → this department's requests only
Analytics         → this department's analytics
Settings          → this department's policy overrides
API Keys          → this department's keys only
```

---

## SaaS Migration Path

The on-premise architecture is identical to a SaaS architecture with one tenant. No breaking changes are required.

```
On-premise (now):
  tenants table:   1 record  (the company)
  departments:     N records (divisions)
  applications:    N records (systems per division)

SaaS (future):
  tenants table:   N records (one per paying company)
  departments:     N records (same structure)
  applications:    N records (same structure)

Code changes for SaaS:
  1. Tenant sign-up and onboarding flow
  2. Billing hooks at tenant level
  3. Tenant isolation audit
  4. Self-service tenant portal

Zero changes to:
  API endpoints, detection pipeline, policy resolution,
  audit schema, dashboard components
```

---

## Implementation Phases

### Phase 1 — Attribution (2 hours, implement now)

```
Goal: Every request attributed to key, IP, user agent

Changes:
  → Add key_id, ip_address, user_agent,
    attribution_verified to audit_logs
  → Auth middleware stores these in request.state
  → Audit log creation reads from request.state
  → Default source = key name if metadata.source empty
  → PostgreSQL migration (ALTER TABLE)

Result:
  "Which key from which IP sent this request?"
  Answered immediately.
```

### Phase 2 — Applications (1 week)

```
Goal: Every request attributed to a named system

Changes:
  → Create applications table
  → Add app_id to api_keys
  → Add app_id to audit_logs
  → Entity relationship validation in auth middleware
  → Update API Keys page:
      Associate key with application on creation
      Show application name in key list
  → Application management API endpoints

Result:
  "Which system made 847 requests today?"
  "Finance Bot — Finance Department"
```

### Phase 3 — Departments (1 week)

```
Goal: Organisational isolation + per-department policy

Changes:
  → Create departments table
  → Link applications to departments
  → Add dept_id to audit_logs
  → Policy resolution: tenant → department
  → Deep merge implementation
  → policy_source tracking
  → Department management API endpoints
  → Department management dashboard page
  → Per-department settings with global fallback
  → Settings page shows inherited vs overridden values

Result:
  Finance Department has stricter PII rules.
  HR uses local LLM only.
  Each department sees only their own data.
```

### Phase 4 — Tenant Root (2 days)

```
Goal: Single tenant root, global policy management

Changes:
  → Create tenants table with default record
  → Link departments to tenant
  → Tenant global policy as the master default
  → Cross-department analytics for super admin
  → Tenant settings page (global policy)

Result:
  Clean root entity. SaaS-ready with zero changes.
```

### Phase 5 — Roles (v2)

```
Goal: User-level policy overrides

Changes:
  → Create roles table (tenant-scoped)
  → Role in request metadata
  → Role policy overrides in resolution chain
  → Role management API + UI
  → JWT for verified role assignment

Result:
  Admin users get stricter checks.
  Analyst users get standard checks.
```

### Phase 6 — SaaS (v3)

```
Goal: Multi-company installation

Changes:
  → Tenant sign-up and onboarding
  → Billing integration
  → Self-service portal
  → Usage tracking per tenant

Result:
  Multiple companies on one installation.
```

---

## Known Issues & Decisions

| Issue | Decision | Phase |
|---|---|---|
| Deep merge semantics | Recursive, null fields inherit | Before Phase 3 |
| Entity relationship validation | Assert key→app→dept→tenant chain | Phase 2 |
| Metadata trust model | Self-reported in v1, attribution_verified=false | Phase 1 |
| Policy source ambiguity | Highest priority level that changed any field | Phase 3 |
| Rate limiting scope | Per API key in v1, per dept in v1.1 | Phase 1 |
| Role isolation | get_role(name, tenant_id) — tenant-scoped | Phase 5 |
| Application policy overrides | Null placeholder in v1, active in v1.1 | Phase 2 |

---

*Architecture version: 1.0 — Final*  
*Review status: Approved (3 review cycles)*  
*Implementation status: Phase 1 ready*
