# WrapSec — Implementation Plan & Task List

Version: 1.0  
Last updated: April 2026  
Status: Active development

---

## Priority Legend

```
P0 — Critical, blocks compliance or core functionality
P1 — High, needed before first enterprise customer
P2 — Important, needed for commercial readiness
P3 — Planned, needed for scale
P4 — Future, v2+ scope
```

---

## Current System Status

```
✅ Detection engine    — rule, ML, LLM, PII guardrail
✅ API layer           — all endpoints, auth, rate limiting
✅ PostgreSQL          — audit logs, settings, API keys
✅ Redis               — semantic cache, rate limiting
✅ LLM clients         — Ollama, OpenAI, Groq
✅ Observability       — structured logging, Prometheus
✅ Infrastructure      — Nginx, Docker Compose
✅ Dashboard           — 6 pages, login, request detail
✅ Tests               — 50/50 passing
✅ Settings wired      — thresholds + layers live from DB
✅ API key validation  — DB-checked, revocation instant
✅ Documentation       — README, scoring model, architecture
```

---

## Task List — Ordered by Priority

---

### SPRINT 1 — Compliance & Attribution (P0)

These tasks fix critical gaps in audit trail and compliance.  
Estimated: 1 day

---

#### TASK-001 — Store key_id in audit logs
**Priority:** P0  
**Effort:** 1 hour  
**Why:** Every request must be traceable to the specific key that made it

```
Backend:
  → Auth middleware: attach key_id to request.state
  → api/v1/endpoints/ai.py: include key_id in audit create
  → db/models.py: add key_id column to audit_logs
  → DB migration: ALTER TABLE audit_logs ADD COLUMN key_id

Dashboard:
  → Show key_id in request detail modal
  → Add key name lookup (key_id → key name)
```

---

#### TASK-002 — Store ip_address and user_agent in audit logs
**Priority:** P0  
**Effort:** 1 hour  
**Why:** Network-level attribution required for security forensics

```
Backend:
  → Auth middleware: extract client IP and user-agent
  → api/v1/endpoints/ai.py: include in audit create
  → db/models.py: add ip_address, user_agent columns
  → DB migration: ALTER TABLE

Dashboard:
  → Show ip_address and user_agent in request detail modal
```

---

#### TASK-003 — Add attribution_verified flag to audit logs
**Priority:** P0  
**Effort:** 30 mins  
**Why:** Compliance transparency — distinguish verified vs self-reported identity

```
Backend:
  → db/models.py: add attribution_verified BOOLEAN DEFAULT false
  → Audit log creation: always set false in v1
  → DB migration

Dashboard:
  → Show attribution_verified badge in request detail
  → "Self-reported" label when false
```

---

#### TASK-004 — Default source to key name if metadata.source empty
**Priority:** P0  
**Effort:** 30 mins  
**Why:** Every request must have a source for attribution

```
Backend:
  → api/v1/endpoints/ai.py:
    if not body.metadata.source:
        source = key.name  (from request.state)
  → Store resolved source in audit log
```

---

### SPRINT 2 — LLM Settings (P1)

Surface LLM configuration in the dashboard.  
Estimated: 1 day

---

#### TASK-005 — Backend LLM settings endpoint
**Priority:** P1  
**Effort:** 2 hours  
**Why:** LLM provider changes require restart currently — not acceptable

```
Backend:
  → api/v1/endpoints/settings.py:
    GET  /v1/settings/llm  → return current LLM config
    PUT  /v1/settings/llm  → update LLM config
  → db/repositories/settings.py:
    Store under key "llm_settings"
  → clients/__init__.py:
    Read provider from DB settings on each call
    Fall back to .env if no DB settings
  → engine/detection/llm_detector.py:
    Read llm_trigger from DB settings

Schema for llm_settings key:
  {
    "provider":    "ollama",
    "model":       "llama3.2:latest",
    "base_url":    "http://localhost:11434",
    "timeout":     30,
    "llm_trigger": 0.2
  }
```

---

#### TASK-006 — Dashboard LLM settings page
**Priority:** P1  
**Effort:** 2 hours  
**Why:** Users need to configure LLM without touching .env

```
Dashboard:
  → components/settings/LLMSettings.tsx:
    Provider dropdown (Ollama / OpenAI / Groq)
    Model name input
    Base URL input (shown only when provider = Ollama)
    Timeout input (seconds, min 5, max 120)
    LLM trigger threshold input (0.0 - 1.0)
    Save button with success/error feedback

  → app/settings/page.tsx:
    Add LLM Configuration card (third card)
    Below Detection Layers card

  → lib/types.ts:
    Add LLMSettings interface

  → lib/api.ts:
    Add getLLMSettings(), updateLLMSettings()
```

---

### SPRINT 3 — Architecture Phase 1 (P1)

Applications layer for attribution.  
Estimated: 3 days

---

#### TASK-007 — Create tenants table + default record
**Priority:** P1  
**Effort:** 2 hours

```
Backend:
  → db/models.py: add TenantModel
  → db/repositories/: add TenantRepository
  → DB migration: CREATE TABLE tenants
  → On startup: create default tenant if not exists
  → Config: TENANT_NAME, TENANT_SLUG in .env
```

---

#### TASK-008 — Create departments table
**Priority:** P1  
**Effort:** 3 hours

```
Backend:
  → db/models.py: add DepartmentModel
  → db/repositories/: add DepartmentRepository
  → DB migration: CREATE TABLE departments
  → On startup: create "Default" department if not exists
  → api/v1/endpoints/: add departments endpoints
    POST   /v1/admin/departments
    GET    /v1/admin/departments
    GET    /v1/admin/departments/{id}
    PUT    /v1/admin/departments/{id}
    DELETE /v1/admin/departments/{id}
```

---

#### TASK-009 — Create applications table
**Priority:** P1  
**Effort:** 3 hours

```
Backend:
  → db/models.py: add ApplicationModel
    Columns: id, tenant_id, dept_id, slug, name,
             description, owner_name, owner_email,
             environment, metadata JSONB NULL,
             policy_override JSONB NULL,
             rate_limit_override INTEGER NULL,
             is_active, created_at
  → db/repositories/: add ApplicationRepository
  → DB migration: CREATE TABLE applications
  → api/v1/endpoints/: add applications endpoints
    POST   /v1/admin/applications
    GET    /v1/admin/applications
    GET    /v1/admin/applications/{id}
    PUT    /v1/admin/applications/{id}
    DELETE /v1/admin/applications/{id}
```

---

#### TASK-010 — Link API keys to applications
**Priority:** P1  
**Effort:** 2 hours

```
Backend:
  → db/models.py: add app_id, dept_id, tenant_id to APIKeyModel
  → DB migration: ALTER TABLE api_keys
  → api/v1/endpoints/keys.py:
    Update create key to accept app_id
    Link key to application on creation
  → Auth middleware:
    Load app, dept, tenant from key
    Entity relationship validation:
      assert key.dept_id == app.dept_id
      assert key.tenant_id == dept.tenant_id
    Attach to request.state

Dashboard:
  → Update API Keys page:
    Select application when creating key
    Show application name in key list
  → Update CreateKeyModal to include application selector
```

---

#### TASK-011 — Store app_id, dept_id, tenant_id in audit logs
**Priority:** P1  
**Effort:** 1 hour

```
Backend:
  → DB migration: ALTER TABLE audit_logs
    ADD COLUMN app_id    VARCHAR(50) DEFAULT NULL
    ADD COLUMN dept_id   VARCHAR(50) DEFAULT NULL
    ADD COLUMN tenant_id VARCHAR(50) DEFAULT NULL
  → api/v1/endpoints/ai.py:
    Include app_id, dept_id, tenant_id in audit create
  → Add indexes for compliance queries

Dashboard:
  → Show dept and application in request detail modal
  → Add department filter to Requests page
```

---

### SPRINT 4 — Policy Engine (P1)

Per-department policy overrides.  
Estimated: 3 days

---

#### TASK-012 — Policy resolution engine
**Priority:** P1  
**Effort:** 4 hours

```
Backend:
  → services/policy_resolver.py (new file):
    resolve_policy(tenant_id, dept_id, app_id) → dict
    Implements deep merge with null-safe inheritance
    Returns resolved policy + policy_source
  → Unit tests for merge semantics:
    Test null fields inherit from parent
    Test explicit fields override parent
    Test nested object merge (guardrails.pii)
    Test all-null override = inherits completely

  def deep_merge(parent: dict, child: dict | None) -> dict:
    if child is None:
        return parent
    result = parent.copy()
    for key, value in child.items():
        if isinstance(value, dict) and key in result:
            result[key] = deep_merge(result[key], value)
        elif value is not None:
            result[key] = value
    return result
```

---

#### TASK-013 — Wire policy resolver into gateway
**Priority:** P1  
**Effort:** 2 hours

```
Backend:
  → api/v1/endpoints/ai.py:
    Load resolved policy using policy_resolver
    Pass to gateway service
  → Store policy_source in audit log
  → Gateway uses resolved thresholds and LLM config

Dashboard:
  → Settings page shows inherited vs overridden values
    Display "(inherited from global)" for null overrides
    Display "(overridden)" for explicit values
```

---

#### TASK-014 — Department settings in dashboard
**Priority:** P1  
**Effort:** 3 hours

```
Dashboard:
  → app/settings/page.tsx:
    Super admin: global policy settings
    Dept admin: department override settings
    Show inheritance clearly

  → components/settings/DepartmentPolicyForm.tsx:
    Threshold overrides with "inherit" option
    Detection layer overrides with "inherit" option
    LLM overrides with "inherit" option
    Visual indicator: "(Global: 0.7)" next to each field

  → Department management page:
    /departments → list all departments
    /departments/[id] → department detail + policy
```

---

### SPRINT 5 — Confidence Score (P2)

Implement the scoring model confidence specification.  
Estimated: 2 days

---

#### TASK-015 — Implement primary_reason field
**Priority:** P2  
**Effort:** 2 hours  
**Why:** High compliance value, low implementation cost

```
Backend:
  → domain/entities/decision.py:
    Add primary_reason field to GatewayDecision
  → services/gateway/service.py:
    Compute primary_reason after policy decision:
      if guardrail triggered + BLOCK   → "PII_GUARDRAIL_BLOCK"
      if guardrail triggered + SANITIZE → "PII_GUARDRAIL_SANITIZE"
      elif rule_score > ml > llm       → "RULE_DETECTOR"
      elif ml_score > llm              → "ML_DETECTOR"
      elif llm_score > 0               → "LLM_DETECTOR"
      else                             → "NO_THREAT_DETECTED"
  → api/v1/endpoints/ai.py:
    Include primary_reason in response
  → DB migration: ADD COLUMN primary_reason to audit_logs

Dashboard:
  → Show primary_reason in request detail modal
  → Show primary_reason in scanner result
  → Add primary_reason to recent requests table
```

---

#### TASK-016 — Implement confidence score
**Priority:** P2  
**Effort:** 4 hours  
**Note:** Requires production data for calibration. Implement after Phase 3.

```
Backend:
  → engine/scoring/confidence.py (new file):

    def detector_confidence(invoked_scores: list[float]) -> float:
      if len(invoked_scores) <= 1:
          return 1.0
      variance = np.var(invoked_scores)
      confidence = 1 / (1 + variance * 5)
      # Confidence floor for strong signals
      max_score = max(invoked_scores)
      if max_score >= 0.8:
          confidence = max(confidence, 0.75)
      return round(confidence, 4)

    def guardrail_confidence(pii_score, block_threshold,
                             sanitize_threshold) -> float:
      if pii_score >= block_threshold:
          return round(0.90 + (min(pii_score, 1.0)
                       - block_threshold) * 0.05, 4)
      elif pii_score >= sanitize_threshold:
          return round(0.70 + (pii_score
                       - sanitize_threshold) * 0.20, 4)
      return 0.0

    def confidence_band(confidence: float) -> str:
      if confidence >= 0.7: return "HIGH"
      if confidence >= 0.4: return "MEDIUM"
      return "LOW"

  → domain/entities/decision.py:
    Add confidence, confidence_band fields
  → services/gateway/service.py:
    Compute confidence after scoring
  → api/v1/endpoints/ai.py:
    Include confidence + confidence_band in response
  → DB migration:
    ADD COLUMN confidence      FLOAT
    ADD COLUMN confidence_band VARCHAR(10)

Dashboard:
  → Show confidence + band in scanner result
  → Show confidence badge in request detail
  → Add confidence to requests table (optional column)
```

---

#### TASK-017 — Guardrail-first enforcement in risk scorer
**Priority:** P2  
**Effort:** 2 hours

```
Backend:
  → engine/scoring/risk_scorer.py:
    Remove pii_score from weighted aggregation
    PII weight changes from 0.10 to 0.00
    Update weights: rule=0.40, ml=0.30, llm=0.30

  → engine/policy/engine.py:
    Add guardrail evaluation before detection policy:
      if pii_score >= block_threshold    → BLOCK (guardrail override)
      elif pii_score >= sanitize_threshold → SANITIZE (guardrail override)
      else → apply detection risk score policy

  → Tests: update scoring tests for new weights
```

---

### SPRINT 6 — Dashboard Completions (P2)

Remaining dashboard features.  
Estimated: 2 days

---

#### TASK-018 — Department management pages
**Priority:** P2  
**Effort:** 3 hours

```
Dashboard:
  → app/departments/page.tsx → list departments
  → app/departments/[id]/page.tsx → department detail
  → components/departments/DepartmentTable.tsx
  → components/departments/DepartmentForm.tsx
  → Sidebar: add Departments link for super admin
```

---

#### TASK-019 — Application management pages
**Priority:** P2  
**Effort:** 3 hours

```
Dashboard:
  → app/applications/page.tsx → list applications
  → app/applications/[id]/page.tsx → app detail + keys
  → components/applications/ApplicationTable.tsx
  → components/applications/ApplicationForm.tsx
  → Sidebar: add Applications link for super admin
```

---

#### TASK-020 — Analytics page improvements
**Priority:** P2  
**Effort:** 2 hours

```
Dashboard:
  → Add department filter to analytics
  → Add time range selector (today/7d/30d/custom)
  → Add block rate trend line chart
  → Add guardrail vs detector breakdown chart
    "How many blocks came from PII vs threat detection?"
```

---

### SPRINT 7 — ML Model Improvement (P2)

Expand training dataset for better detection accuracy.  
Estimated: 1 day

---

#### TASK-021 — Download and integrate public datasets
**Priority:** P2  
**Effort:** 4 hours

```
Datasets to integrate:
  → deepset/prompt-injections (662 samples)
  → jackhhao/jailbreak-classification (1000+ samples)
  → lmsys/toxic-chat (real ChatGPT conversations)
  → ai4privacy/pii-masking-400k (sample 500)
  → Generate synthetic DATA_EXFILTRATION samples

Steps:
  → pip install datasets
  → scripts/download_datasets.py (new script)
  → scripts/train_ml_model.py: update to use new data
  → Target: 500+ samples per category (3500+ total)
  → Retrain and evaluate model
  → Compare F1 score before/after
```

---

### SPRINT 8 — Testing & Quality (P1)

Expand test coverage.  
Estimated: 1 day

---

#### TASK-022 — Add tests for new components
**Priority:** P1  
**Effort:** 3 hours

```
New tests needed:
  → tests/unit/engine/test_confidence.py
      detector_confidence formula
      guardrail_confidence formula
      confidence_band thresholds
      edge cases: single layer, zero scores

  → tests/unit/services/test_policy_resolver.py
      deep merge with null override
      deep merge with partial override
      deep merge with nested objects
      all-null override inherits completely
      entity validation

  → tests/integration/test_api_departments.py
      create department
      get department
      update department policy
      department isolation

  → tests/integration/test_api_applications.py
      create application
      link key to application
      attribution in audit log
```

---

#### TASK-023 — Update existing tests for new schema
**Priority:** P1  
**Effort:** 2 hours

```
→ Update conftest.py for new DB schema
→ Update test_api_ai.py for new audit log fields
→ Update test_api_audit.py for dept/app filters
→ Update test_api_keys.py for app_id field
→ Verify 50+ tests still passing
```

---

### SPRINT 9 — Documentation (P2)

Complete documentation suite.  
Estimated: 1 day

---

#### TASK-024 — Save architecture documents to repo
**Priority:** P2  
**Effort:** 30 mins

```
→ Save docs/architecture.md
→ Save docs/scoring_model.md
→ Update README with links to docs/
→ Create docs/index.md (docs overview)
```

---

#### TASK-025 — API documentation
**Priority:** P2  
**Effort:** 3 hours

```
→ docs/api.md — complete endpoint reference
→ Include request/response examples for every endpoint
→ Include error codes reference
→ Include authentication guide
→ Include integration quickstart (curl examples)
```

---

#### TASK-026 — GitHub profile README update
**Priority:** P2  
**Effort:** 1 hour

```
→ Add WrapSec to github.com/kbajish profile README
→ Add description, tech stack, links
→ Add screenshot of dashboard
```

---

### SPRINT 10 — Production Hardening (P1)

Security and production readiness.  
Estimated: 1 day

---

#### TASK-027 — Admin key strength validation
**Priority:** P1  
**Effort:** 30 mins

```
Backend:
  → On startup, warn if ADMIN_API_KEY is default value
  → Log warning: "SECURITY WARNING: Default admin key in use"
  → config/settings.py: add validation

Dashboard:
  → Show warning banner if admin key is default
  → Link to documentation on key rotation
```

---

#### TASK-028 — Add request ID / idempotency key to audit log
**Priority:** P1  
**Effort:** 1 hour

```
Backend:
  → Check Idempotency-Key header on requests
  → Store in audit_logs.request_id
  → Return same response for duplicate idempotency keys
    within the 60s window
```

---

#### TASK-029 — Docker Compose production configuration
**Priority:** P1  
**Effort:** 2 hours

```
Infrastructure:
  → infrastructure/docker/docker-compose.prod.yml
    No exposed postgres/redis ports
    API container only — no uvicorn dev mode
    Health check on API container
    Restart policies on all containers

  → infrastructure/docker/Dockerfile.dashboard
    Build Next.js dashboard for production
    nginx serves static files

  → infrastructure/nginx/nginx.conf update
    Add dashboard routing (/ → dashboard)
    Add /api proxy to backend
```

---

#### TASK-030 — Environment variable documentation
**Priority:** P1  
**Effort:** 1 hour

```
→ Update .env.example with all variables
→ Mark required vs optional
→ Add validation comments
→ Document security recommendations
```

---

### SPRINT 11 — Deferred to V2 (P4)

---

#### TASK-031 — Roles and RBAC
**Priority:** P4 (v2)

```
→ roles table (tenant-scoped)
→ Role in request metadata
→ Role policy overrides
→ JWT for verified role assignment
→ Role management UI
```

---

#### TASK-032 — JWT identity verification
**Priority:** P4 (v2)

```
→ JWT validation in auth middleware
→ Signed user claims
→ attribution_verified = true for JWT requests
→ SSO integration (SAML/OAuth)
```

---

#### TASK-033 — Per-application policy overrides
**Priority:** P3 (v1.1)

```
→ Activate policy_override column on applications
→ Update policy resolution:
    system → tenant → dept → application
→ Application policy UI
→ Tests for application-level overrides
```

---

#### TASK-034 — SaaS multi-tenant onboarding
**Priority:** P4 (v3)

```
→ Tenant sign-up flow
→ Billing integration (Stripe)
→ Usage tracking per tenant
→ Self-service portal
→ Tenant isolation audit
```

---

## Sprint Summary

| Sprint | Focus | Priority | Effort | Status |
|---|---|---|---|---|
| Sprint 1 | Compliance & Attribution | P0 | 1 day | Ready |
| Sprint 2 | LLM Settings | P1 | 1 day | Ready |
| Sprint 3 | Applications Layer | P1 | 3 days | Ready |
| Sprint 4 | Policy Engine | P1 | 3 days | After Sprint 3 |
| Sprint 5 | Confidence Score | P2 | 2 days | After Sprint 4 |
| Sprint 6 | Dashboard Completions | P2 | 2 days | After Sprint 3 |
| Sprint 7 | ML Model Improvement | P2 | 1 day | Independent |
| Sprint 8 | Testing & Quality | P1 | 1 day | After Sprint 4 |
| Sprint 9 | Documentation | P2 | 1 day | Independent |
| Sprint 10 | Production Hardening | P1 | 1 day | Independent |
| Sprint 11 | V2 Scope | P4 | TBD | Future |

---

## Immediate Next Session (Start Here)

```
1. TASK-001 — key_id in audit logs           (30 mins)
2. TASK-002 — ip_address + user_agent        (30 mins)
3. TASK-003 — attribution_verified flag      (30 mins)
4. TASK-004 — default source to key name     (30 mins)
5. TASK-005 — LLM settings backend endpoint  (2 hours)
6. TASK-006 — LLM settings dashboard page    (2 hours)

Total: ~1 day
```

---

*Plan version: 1.0*  
*Total tasks: 34*  
*P0 tasks: 4 (Sprint 1)*  
*P1 tasks: 14*  
*P2 tasks: 10*  
*P3 tasks: 1*  
*P4 tasks: 4*  
*Estimated remaining effort: ~15 development days*
