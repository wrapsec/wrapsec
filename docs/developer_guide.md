# WrapSec Developer Guide

*For engineers maintaining or extending the WrapSec codebase.*
*Last updated: April 2026*

---

## Repository Overview

```
api/                    FastAPI application
  v1/
    endpoints/          Route handlers
      admin/            User management (users.py)
      auth.py           JWT auth endpoints
      ai.py             Scan-only gateway
      proxy.py          Proxy mode
      audit.py          Audit log endpoints
      settings.py       Settings endpoints
      keys.py           API key management
    middleware/
      auth.py           Authentication middleware (API key + JWT)
      rate_limit.py     Sliding window rate limiter
      idempotency.py    Idempotency-Key support
    dependencies/
      auth.py           RBAC dependencies (require_jwt, require_admin, etc.)
      db.py             get_db dependency with rollback handling
    router.py           Route registration

domain/
  enums.py              All enums — DecisionType, UserRole, AdminEventAction, etc.
  entities/
    principal.py        Principal dataclass + builder functions
    audit_log.py        AuditLog entity
    decision.py         Decision entity
  value_objects/
    severity.py         Severity computation logic

engine/                 Detection pipeline
  detection/            rule_detector, ml_detector, llm_detector
  guardrails/           pii/, toxicity/, input_guard, output_guard
  scoring/              risk_scorer, primary_reason, confidence
  policy/               engine, rules
  proxy/                providers/, router

services/
  auth/
    service.py          AuthService — login, refresh, logout, change_password
    token.py            JWT encode/decode (PyJWT)
    password.py         bcrypt hashing, normalize_email, verify_dummy
    lockout.py          Redis-based account lockout
  gateway/
    service.py          GatewayService.process() — full detection pipeline
  policy_resolver.py    Policy resolution chain

db/
  models.py             All SQLAlchemy models
  session.py            Async engine + AsyncSessionFactory
  repositories/         One file per table
    user.py, refresh_token.py, audit.py, settings.py
    admin_event.py, auth_event.py

config/
  settings.py           All env vars via pydantic-settings

workers/
  tasks.py              Retention cleanup (audit logs + refresh tokens)
  queue.py              APScheduler — daily 02:00 UTC

dashboard/              Next.js 14 frontend
  app/                  Pages
  components/           UI components
  lib/
    api.ts              All API calls
    auth.ts             Login, logout, changePassword
    types.ts            TypeScript types
```

---

## Authentication System

### Dual identity model

Two authentication methods coexist. Both resolve to identical fields on `request.state`. All downstream code is auth-agnostic — it never checks which auth method was used.

```
x-api-key header     → API_KEY principal  (applications and services)
Authorization Bearer → USER principal     (dashboard users)
```

### Header precedence — absolute rule

```python
# First code in middleware dispatch() — before any other logic
api_key = request.headers.get("x-api-key", "").strip()
auth    = request.headers.get("authorization", "").strip()

if api_key:
    return await self._authenticate_api_key(api_key, request, call_next)
elif auth.lower().startswith("bearer "):
    return await self._authenticate_jwt(auth[7:], request, call_next)
else:
    return _unauthorized(request, "missing_credentials")
```

If `x-api-key` is present, JWT is ignored — unconditionally. No exceptions.

### JWT structure

Access token payload (HS256):
```json
{
    "sub":       "user-uuid",
    "type":      "access",
    "ver":       1,
    "role":      "DEVELOPER",
    "tenant_id": "tenant-uuid",
    "dept_id":   "dept-uuid or null",
    "aud":       "wrapsec-dashboard",
    "iat":       1714000000,
    "exp":       1714001800
}
```

- `type` — prevents refresh tokens being used as access tokens
- `ver` — matched against `users.token_version` on every request
- `aud` — prevents tokens being replayed against other services
- `dept_id` — null for ADMIN, required for DEVELOPER/VIEWER

**Library:** PyJWT (`import jwt`, `from jwt.exceptions import InvalidTokenError`).
Not python-jose. These are not interchangeable — exception types differ.

### Token versioning — session invalidation

`users.token_version` starts at 1 and is atomically incremented by `UserRepository.increment_token_version()`. The JWT middleware checks `payload["ver"] == user.token_version` on every authenticated request. Mismatch → `SESSION_INVALIDATED` 401.

`logout_all_sessions()` increments `token_version` + revokes all refresh tokens. Called on:
- Password change
- Role change
- Department change
- Account deactivation
- Admin password reset

NOT called on reactivation — there are no active sessions to invalidate.

### Refresh token rotation

Raw token: `secrets.token_urlsafe(32)`. Never stored server-side — only `SHA-256(raw)` is stored.

Every use: old token revoked, new token issued. `RefreshTokenRepository.get_by_hash()` uses `SELECT FOR UPDATE` to prevent race conditions on parallel refresh requests with the same token.

Cookie: `Path=/v1/auth` — browser only sends it to `/v1/auth/*` endpoints. If the API prefix changes, the cookie path must also change.

### Account lockout

Redis keys: `auth:failed:{normalized_email}`, `auth:locked:{normalized_email}`.

- 5 failed attempts → 15 minute lockout (configurable via env vars)
- Counter TTL set on first failure, not reset on subsequent failures
- Lock TTL reset on each retry — attacker extends their own lockout
- On success: both keys deleted immediately

### Timing equalisation — email enumeration prevention

When a user is not found:
1. `verify_dummy()` is called — runs a full bcrypt verify against a hardcoded hash
2. `record_failure()` increments the counter
3. 401 is raised with the same message as wrong password

`_DUMMY_HASH` in `password.py` is hardcoded (not computed at runtime) to prevent timing variation across process restarts.

### force_password_change enforcement

Enforced at middleware level — not just frontend. When `force_password_change = True`, all requests except these three are blocked with 403 `PASSWORD_CHANGE_REQUIRED`:
- `POST /v1/auth/change-password`
- `POST /v1/auth/logout`
- `GET /v1/auth/me`

### Tenant enforcement — four layers

`tenant_id` is the outermost security boundary. All four layers must hold:

```
Layer 1 — DB schema:        users.tenant_id NOT NULL, api_keys.tenant_id NOT NULL
Layer 2 — JWT decode:       sub, tenant_id, role, ver — all required, missing → 401
Layer 3 — Middleware:       JWT tenant_id cross-validated against DB value
Layer 4 — Principal build:  raises ValueError if tenant_id is None
```

`tenant_id` is always derived from the authenticated identity. Never from request body, query params, or path params.

### UUID/string type boundary

```
DB layer      → UUID objects   (SQLAlchemy columns, FK joins, repository args)
API/JWT/state → string objects (request.state, JWT claims, audit logs, responses)

Cast at DB→API:  str(user.tenant_id)     — in middleware and principal builders
Cast at API→DB:  UUID(tenant_id_string)  — in repository queries
```

Mixing types causes silent comparison failures. This boundary must be maintained at every layer.

### key_id prefix convention

`request.state.key_id` is prefixed to prevent namespace collision:
- JWT users: `user:{user_uuid}`
- API keys: `key:{key_id}`
- Admin key: `key:admin`

Rate limiter, metrics, and logs all use `key_id`. The prefix ensures no collision between user UUIDs and API key ID strings.

---

## RBAC Dependencies

```python
# api/v1/dependencies/auth.py

get_current_principal(request)  # API key OR JWT — scan/audit endpoints
require_jwt(principal)          # JWT only — rejects API key with 403
require_role(*roles)            # JWT + role — factory, implies require_jwt
require_admin()                 # shorthand for require_role("ADMIN")
```

Principal is built from `request.state` — no second DB call in dependencies.

`has_permission()` raises `NotImplementedError` in v1. All guards use `has_role()` exclusively. Permission strings in `ROLE_PERMISSIONS` are defined for v2+ reference only.

### Endpoint protection matrix

```
Public:           GET /health*, GET /metrics, POST /v1/auth/login, POST /v1/auth/refresh
JWT any role:     POST /v1/auth/logout, GET /v1/auth/me, POST /v1/auth/change-password
JWT + ADMIN:      ALL /v1/admin/users*, /v1/admin/tenant*, /v1/admin/departments*,
                  /v1/admin/applications*, PUT /v1/settings/*
JWT ADMIN/DEV:    GET /v1/settings/*, ALL /v1/keys/*
API key OR JWT:   POST /v1/ai/request, POST /v1/chat/completions,
                  GET /v1/ai/requests/*, GET /v1/audit/*
```

---

## Database

### Session management

Production: `AsyncSessionFactory()` from `db/session.py` — shared async connection pool.

Test mode: `_get_db_session()` in `auth.py` middleware returns a `NullPool` engine — no connection pooling, safe across pytest event loop boundaries.

Never call `AsyncSessionFactory()` directly in middleware. Always use `_get_db_session()`.

### get_db vs get_session

All endpoints use `get_db` from `api/v1/dependencies/db.py`. It wraps the session with rollback handling on exception.

`get_session` from `db/session.py` is for internal/background use only — not endpoint dependencies.

### Datetime handling

PostgreSQL `TIMESTAMP WITHOUT TIME ZONE` rejects timezone-aware datetimes via asyncpg.

```python
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)  # timezone-aware for internal calculations

def _to_db(dt: datetime) -> datetime:
    return dt.replace(tzinfo=None)  # strip tz before writing to DB

# Usage in service.py:
expires_at = _utcnow() + timedelta(days=30)
await repo.create(..., expires_at=_to_db(expires_at))
```

### Email uniqueness

Stored lowercase always. `normalize_email()` called before every read and write.

`get_by_email()` uses `func.lower()` to match the `ux_users_email_lower` index:
```python
select(UserModel).where(func.lower(UserModel.email) == email)
```

Never use `WHERE email = :email` — it does not use the index and breaks case-insensitive uniqueness.

### Transaction boundaries

Each auth flow operation commits once:
- `login()` — create refresh token + update last_login → one commit
- `refresh()` — revoke old + create new → one commit
- `logout_all_sessions()` — increment token_version + revoke all → one commit
- `change_password()` — update hash + flag → commit, then logout_all → commit

### Refresh token cleanup

Two clauses run daily via APScheduler (02:00 UTC):

```
Clause 1: DELETE WHERE expires_at < NOW() AND revoked_at IS NOT NULL
          (both expired AND revoked — audit value exhausted)

Clause 2: DELETE WHERE expires_at < NOW() - 90 days
          (prevents unbounded growth from abandoned sessions)
```

---

## Logging

### Audit events (AI security)

Written to `audit_logs` table. Every scan request. Includes decision, risk score, threats, severity, principal attribution.

### Admin events (user management)

Written to `admin_events` table. Every user management action.

- Logging order (must follow):
  1. Perform database update
  2. Commit transaction
  3. Insert admin_event (post-commit, same session)
  4. If logging fails — log internally, do not fail request
- Synchronous within the request lifecycle, but best-effort — main operation always succeeds regardless of logging outcome
- `action` is enum-controlled via `AdminEventAction` — no free-form strings
- `dept_id` = target user's dept_id after the update (post-update state)
- For `dept_changed`: `admin_events.dept_id` = new_dept_id; metadata contains both old and new

### Auth events (login tracking)

Written to `auth_events` table. Every login attempt.

- Non-blocking — uses a separate NullPool DB session, never the request session
- Best-effort — failures logged internally and suppressed
- `tenant_id` is nullable — null when user not found (cannot resolve tenant)
- Prefer null over incorrect attribution

Action values: `login_success`, `login_failed`
Failure reasons: `invalid_password`, `user_not_found`, `account_inactive`, `token_expired`

**Mapping: API error code → auth_events.failure_reason**

| API error code (returned to client) | auth_events.failure_reason (stored in DB) |
|---|---|
| `INVALID_CREDENTIALS` | `invalid_password` or `user_not_found` |
| `ACCOUNT_DISABLED` | `account_inactive` |
| `SESSION_INVALIDATED` | `token_expired` |
| `ACCOUNT_LOCKED` | not stored in auth_events — lockout is Redis-only |

Note: `ACCOUNT_INACTIVE` never appears in API responses. The client always receives `ACCOUNT_DISABLED` when `is_active = false`. `account_inactive` is the internal `auth_events` failure reason only.

Note: `INVALID_CREDENTIALS` is the only error code that maps to two different failure reasons — the client receives the same message for both wrong password and unknown email (no enumeration). The auth_event distinguishes them internally.

### Structured logger

`logging.getLogger("wrapsec.auth")` logs auth events to stdout/file for real-time monitoring. This coexists with `auth_events` DB table — do not remove the logger.

Format: `auth_event EVENT_NAME key=value ...`

---

## User Management

### Role + dept_id consistency

Both directions enforced at DB level (`ck_users_dept_required_v2`) and application level:
```
role = ADMIN     → dept_id MUST be NULL
role != ADMIN    → dept_id MUST NOT be NULL
```

DB constraint added in `add_user_management.sql`. Application validation in `UserRepository.create()` and `update()`, and in the PATCH endpoint via `_validate_role_dept_consistency()`.

### PATCH — partial update, not PUT

User updates use `PATCH /v1/admin/users/{id}` — not `PUT`. Only provided fields are updated. This is intentional:

- `PUT` implies full resource replacement — client must send the complete object
- `PATCH` implies partial update — missing fields retain their current values

WrapSec uses `PUT` for settings endpoints (full replacement) and `PATCH` for user updates (partial). Do not use `PUT` on the users endpoint — it will be rejected.

### PATCH final state validation

`PATCH /v1/admin/users/{id}` validates the combined final state, not individual fields:

```python
final_role    = data.get("role",    user.role)
final_dept_id = data.get("dept_id", str(user.dept_id) if user.dept_id else None)
error = _validate_role_dept_consistency(final_role, final_dept_id)
```

Example: `PATCH {"role": "ADMIN", "dept_id": "uuid"}` → invalid even though either field alone might be valid in context.

### dept_id tenant integrity

`UserRepository` verifies `dept_id` belongs to the same tenant on every create and update:
```python
SELECT id FROM departments WHERE id = dept_id AND tenant_id = tenant_id
```

Also enforced at DB level via composite FK (`fk_users_dept_tenant`).

### Guards

- **Self-deactivation**: checked before last-admin protection — admin cannot set `is_active=False` on their own account
- **Last-admin**: `count_active_admins()` checked before every demotion or deactivation of an ADMIN

---

## Detection Pipeline

```
Input → InputGuard (PII guardrail, regex, ~<1ms)
      → RuleDetector (regex/heuristics, ~<1ms)
      → MLDetector (TF-IDF + LogReg, 7 labels, ~5ms)
      → ToxicityGuard (reads ML label 6, ~0ms additional)
      → LLMDetector (semantic, full mode only, ~100-500ms)
      → RiskScorer (rule×0.40 + ml×0.30 + llm×0.30, guardrails excluded)
      → PolicyEngine → BLOCK / SANITIZE / ALLOW
```

Guardrail priority: PII (highest) → Toxicity → Detection pipeline.
Guardrails always override detection. Independent thresholds.

`SYSTEM_ERROR` at engine level → `decision=ALLOW`, `confidence=0.0`. Clients must NOT forward to LLM when `primary_reason=SYSTEM_ERROR`.

---

## Policy Resolution

```python
system_defaults (.env)
    ↓ deep merge
DB settings table (policy_thresholds, detection_layers, llm_settings, rate_limit)
    ↓ deep merge
dept.policy_override   ← null fields inherit from above
    ↓ deep merge
app.policy_override    ← null fields inherit from above
    ↓
resolved_policy
```

`global_policy` on the tenant table is kept in DB but not applied in resolution. DB settings table is authoritative.

---

## Testing

### Running tests

```powershell
$env:TESTING = "true"
$env:PYTHONPATH = "D:\Projects\wrapsec"
pytest tests/unit tests/integration -v
# Expected: 251 passed
```

### Test infrastructure

**Event loop:** `pytest.ini` sets `asyncio_default_fixture_loop_scope = session` + `asyncio_default_test_loop_scope = session`. All tests share one event loop.

**NullPool in tests:** JWT middleware uses `_get_db_session()` which returns a `NullPool` engine when `TESTING=true`. This prevents asyncpg connection pool poisoning across the shared test event loop.

**Redis flushing:** `conftest.py` flushes `rate_limit:*`, `auth:failed:*`, `auth:locked:*` keys before and after each auth test to prevent cross-test accumulation.

**Dependency overrides:** `client` fixture clears `app.dependency_overrides` before AND after each test.

**Integration tests use real PostgreSQL** — not SQLite. JWT middleware needs real DB. Run the DB container before running integration tests.

### End-to-end validation

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\scripts\validate_e2e.ps1
```

Covers: login, auth event logging, user management, admin event logging, guards, cleanup.

---

## Adding a New Endpoint

1. Create the endpoint in `api/v1/endpoints/`
2. Use `get_current_principal` or `require_role()` from `api/v1/dependencies/auth.py`
3. Always filter queries by `principal.tenant_id` — never trust client-provided tenant_id
4. For ADMIN-role endpoints: apply dept_id filter conditionally (`if principal.dept_id`)
5. Register in `api/v1/router.py`
6. Add to the endpoint protection matrix in this document and in `api.md`

---

## Adding a New Guardrail

1. Create detector in `engine/guardrails/`
2. Add `primary_reason` values to `domain/enums.py` — use `_GUARDRAIL_BLOCK` / `_GUARDRAIL_SANITIZE` suffix
3. Add to `InputGuard.inspect()` in `engine/guardrails/input_guard.py`
4. Add to `PolicyEngine.decide()` priority order
5. Add threshold to policy schema
6. Add severity computation if needed in `domain/value_objects/severity.py`

The `_GUARDRAIL_BLOCK` suffix is used by severity computation for auto-CRITICAL classification — new guardrails get this automatically if the naming convention is followed.

---

## Non-Negotiable Conventions

These rules must be followed in all new code. Violation creates real production issues.

1. `tenant_id` always from authenticated identity — never from request body or params
2. `dept_id` always from authenticated identity — never from client input
3. Admin dept query: conditional `WHERE dept_id` — never `WHERE dept_id = NULL`
4. Wrong email and wrong password return the same error message — no enumeration
5. `verify_dummy()` must be called when user not found before raising any error
6. `_DUMMY_HASH` is hardcoded — never compute it at runtime
7. `token_version` checked on every JWT request — not only at refresh time
8. JWT `tenant_id` must be cross-validated against DB value on every request
9. JWT `dept_id` mismatch: log warning, use DB value, do not reject
10. `principal_type` written to `audit_logs` on every request
11. `user_role` always set on `request.state` in JWT path
12. `force_password_change` enforced in middleware — not just frontend
13. `normalize_email()` before every email read or write
14. `get_by_email()` must use `func.lower()` — never `WHERE email = :email`
15. Refresh token raw value never stored server-side — only SHA-256 hash
16. API key always wins if `x-api-key` header present — JWT ignored
17. `require_role()` always implies `require_jwt()` — API keys get 403
18. `has_permission()` not called in v1 guards — use `has_role()` only
19. `dept_id = NULL` for ADMIN: intentional, enforced by DB CHECK + application validation
20. Refresh cleanup: both clauses — expired+revoked AND 90-day absolute
21. Principal builders raise `ValueError` — never `assert`
22. Last-admin protection: `count_active_admins()` before every demotion/deactivation
23. Single DB commit per auth flow operation
24. Refresh token cookie `Path=/v1/auth` — if API prefix changes, cookie path must change
25. `key_id` prefixed: `user:{id}` for JWT users, `key:{id}` for API keys, `key:admin` for admin
26. `get_by_hash()` uses `SELECT FOR UPDATE` — prevents refresh token race condition
27. `dept_id` must belong to same tenant — validated on every create/update
28. `_unauthorized()` always logs reason and path — no silent 401s
29. Admin key fetches real `tenant_id` from DB — never uses placeholder strings
30. All auth events must be logged (login success/fail/lock, logout, session invalidation, password change, JWT mismatches, all 401 rejections)
31. PostgreSQL `READ COMMITTED` isolation assumed — do not change without reviewing refresh token rotation
32. JWT `dept_id` mismatch warnings must be routed to monitoring pipeline
33. 401 response always generic — frontend must treat all 401s as re-auth required
34. UUID/string boundary maintained at every layer
35. `cleanup_expired()` implements both clauses — not separate calls
36. PyJWT exceptions: use `InvalidTokenError` from `jwt.exceptions` — not `JWTError`
37. Datetimes at DB boundary: strip timezone with `_to_db()` — internal calculations stay aware
38. JWT middleware uses `_get_db_session()` — never `AsyncSessionFactory()` directly
39. Endpoints use `get_db` from dependencies — not `get_session` from `db/session.py`

---

## Starting the Stack

```powershell
# Infrastructure
docker compose -f infrastructure/docker/docker-compose.yml up -d postgres redis

# API
$env:PYTHONPATH = "D:\Projects\wrapsec"
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Dashboard
cd dashboard
npm run dev

# Observability (optional)
# Prometheus: http://localhost:9090
# Grafana:    http://localhost:3001  (admin / wrapsec)
```

---

## Known Pending Work

```
Secrets/credentials guardrail    — fast regex for API keys, tokens in prompts
Cursor-based pagination          — replace offset pagination on audit endpoints
Per-key storage mode override    — allow individual keys to override DATA_STORAGE_MODE
tiktoken                         — per-model token counting (replaces ceil(len/2) heuristic)
Production deployment            — domain ready, Groq instead of Ollama
Node.js SDK                      — after Python SDK stabilises
OWNER role                       — single per tenant, cannot be deactivated
Email invitations                — for SaaS onboarding
Permission engine                — replace has_role() with has_permission() (v2+)
```

---

*WrapSec Developer Guide — v1.4 — April 2026*
