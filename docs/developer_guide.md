# WrapSec Developer Guide

*For engineers maintaining or extending the WrapSec codebase.*
*Last updated: May 2026*

---

## Repository Overview

```
api/                    FastAPI application
  v1/
    endpoints/          Route handlers
      admin/            User management (users.py)
      auth.py           JWT auth endpoints
      setup.py          First-run setup endpoints (public, self-disables)
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
  enums.py              All enums - DecisionType, UserRole, AdminEventAction, etc.
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
    service.py          AuthService - login, refresh, logout, change_password
    token.py            JWT encode/decode (PyJWT)
    password.py         Argon2id hashing (bcrypt legacy verify + auto-rehash), normalize_email, verify_dummy
    lockout.py          Redis-based account lockout
  gateway/
    service.py          GatewayService.process() - full detection pipeline
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
  queue.py              APScheduler - daily 02:00 UTC

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

Two authentication methods coexist. Both resolve to identical fields on `request.state`. All downstream code is auth-agnostic - it never checks which auth method was used.

```
x-api-key header     -> API_KEY principal  (applications and services)
Authorization Bearer -> USER principal     (dashboard users)
```

### Header precedence - absolute rule

```python
# First code in middleware dispatch() - before any other logic
api_key = request.headers.get("x-api-key", "").strip()
auth    = request.headers.get("authorization", "").strip()

if api_key:
    return await self._authenticate_api_key(api_key, request, call_next)
elif auth.lower().startswith("bearer "):
    return await self._authenticate_jwt(auth[7:], request, call_next)
else:
    return _unauthorized(request, "missing_credentials")
```

If `x-api-key` is present, JWT is ignored - unconditionally. No exceptions.

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

- `type` - prevents refresh tokens being used as access tokens
- `ver` - matched against `users.token_version` on every request
- `aud` - prevents tokens being replayed against other services
- `dept_id` - null for ADMIN, required for DEVELOPER/VIEWER

**Library:** PyJWT (`import jwt`, `from jwt.exceptions import InvalidTokenError`).
Not python-jose. These are not interchangeable - exception types differ.

### Token versioning - session invalidation

`users.token_version` starts at 1 and is atomically incremented by `UserRepository.increment_token_version()`. The JWT middleware checks `payload["ver"] == user.token_version` on every authenticated request. Mismatch -> `SESSION_INVALIDATED` 401.

`logout_all_sessions()` increments `token_version` + revokes all refresh tokens + deletes the Redis user cache entry. Called on:
- Password change
- Role change
- Department change
- Account deactivation
- Admin password reset

NOT called on reactivation - there are no active sessions to invalidate.

### JWT user cache

To avoid a DB lookup on every authenticated request, the JWT middleware caches the user record in Redis after the first DB hit.

- **Cache key:** `auth:user:{user_id}` (UUID string)
- **TTL:** 1800 seconds - matches the JWT access token expiry
- **Cached fields:** `id`, `is_active`, `tenant_id`, `dept_id`, `role`, `force_password_change`, `token_version`, `email`
- **Invalidation:** `logout_all_sessions()` deletes the key immediately after the DB commit that increments `token_version`
- **Failure mode:** any Redis error falls back to a direct DB lookup - never fails auth

**Important for developers:** if you add a new field to the `users` table that must affect auth decisions (e.g., a new flag that should gate access), you must:
1. Add it to the cached payload dict in `_get_user_cached()` in `api/v1/middleware/auth.py`
2. Add it to the downstream check in `_authenticate_jwt()`
3. Ensure `logout_all_sessions()` is called whenever that field changes, so the cache is invalidated

Skipping step 3 means the old cached value will be used for up to 1800 seconds after the DB change.

### Dashboard session hardening

**Inactivity timeout:**
- 15 min inactivity -> `logout("inactivity")` -> redirect `/login`
- Warning modal shown at 2 min remaining - blocks interaction, cannot dismiss by clicking outside
- Events tracked: `mousemove`, `mousedown`, `keydown`, `touchstart`, `scroll`, `visibilitychange`
- `visibilitychange` to hidden tab counts as inactivity - timer continues
- Implemented in `dashboard/hooks/useInactivityTimer.ts`, wired in `Shell.tsx`

**Silent refresh on 401:**
- Any 401 from API -> attempt `POST /api/auth/refresh` -> retry original request once -> redirect `/login`
- Three guards (all required, all must be present):
  1. URL check: if URL contains `/api/auth/refresh` -> do NOT retry (prevents self-loop)
  2. `_retried` flag: if request already retried -> do NOT retry (prevents loop via other paths)
  3. `isLoggingOut` flag: if logout in progress -> skip refresh, redirect immediately
- 500/502 errors are NOT treated as 401 - show error to user, never redirect to login for server errors

**isLoggingOut race condition fix:**
```typescript
// auth.ts
export let isLoggingOut = false
export async function logout(reason = "manual") {
    isLoggingOut = true   // BEFORE fetch - blocks any concurrent refresh attempt
    await fetch("/api/auth/logout", { body: JSON.stringify({ reason }) })
}

// api.ts request() - checked before every refresh attempt
if (isLoggingOut) { window.location.href = "/login"; throw new Error("Logging out") }
```

**Next.js middleware exclusion:**
`/api/*` paths excluded from middleware redirect - these routes return JSON 401, not HTML.
Without this: expired JWT -> middleware redirects `/api/proxy/*` to `/login` (HTML) ->
`JSON.parse("<!DOCTYPE")` crash in frontend modal.

### Refresh token rotation

Raw token: `secrets.token_urlsafe(32)`. Never stored server-side - only `SHA-256(raw)` is stored.

Every use: old token revoked, new token issued. `RefreshTokenRepository.get_by_hash()` uses `SELECT FOR UPDATE` to prevent race conditions on parallel refresh requests with the same token.

**Cookie path - BFF pattern:**
The backend sets the refresh token cookie with `Path=/v1/auth`. The dashboard BFF does NOT forward this cookie directly to the browser. Instead, `login/route.ts` and `refresh/route.ts` parse the token value and re-issue it as a new `httpOnly` cookie with `Path=/api/auth` - the browser then sends it only to BFF auth routes (`/api/auth/refresh`, `/api/auth/logout`), never to arbitrary paths.

`logout/route.ts` reads the cookie from the browser request and forwards it to the backend via a server-side `Cookie` header so the backend can revoke it. If the API prefix ever changes, update `Path=/api/auth` in all three routes and `Path=/v1/auth` in `api/v1/endpoints/auth.py` (`REFRESH_COOKIE_PATH`).

**Rule:** Never forward the raw backend `set-cookie` header to the browser - always re-issue with the BFF-appropriate path.

### Account lockout

Redis keys: `auth:failed:{normalized_email}`, `auth:locked:{normalized_email}`.

- 5 failed attempts -> 15 minute lockout (configurable via env vars)
- Counter TTL set on first failure, not reset on subsequent failures
- Lock TTL reset on each retry - attacker extends their own lockout
- On success: both keys deleted immediately

### Password hashing - Argon2id with legacy bcrypt compatibility

As of v1.1.0 new passwords are hashed with Argon2id (winner of the Password
Hashing Competition; resistant to GPU/ASIC attacks that bcrypt cannot mitigate).
Per-user salt is embedded in the hash string; the `passlib` CryptContext keeps
`bcrypt` in the scheme list so hashes minted before v1.1.0 still verify.

Transparent upgrade path: after a successful login, `needs_rehash()` inspects
the stored hash and, if it uses a deprecated scheme, the service rehashes the
plaintext with Argon2id and updates the user record. Legacy users migrate to
Argon2id on their next successful login without any admin action.

### Timing equalisation - email enumeration prevention

When a user is not found:
1. `verify_dummy()` is called - runs a full Argon2id verify against a hardcoded hash
2. `record_failure()` increments the counter
3. 401 is raised with the same message as wrong password

`_DUMMY_HASH` in `password.py` is hardcoded (not computed at runtime) to prevent timing variation across process restarts.

### force_password_change enforcement

Enforced at middleware level - not just frontend. When `force_password_change = True`, all requests except these three are blocked with 403 `PASSWORD_CHANGE_REQUIRED`:
- `POST /v1/auth/change-password`
- `POST /v1/auth/logout`
- `GET /v1/auth/me`

### Tenant enforcement - four layers

`tenant_id` is the outermost security boundary. All four layers must hold:

```
Layer 1 - DB schema:        users.tenant_id NOT NULL, api_keys.tenant_id NOT NULL
Layer 2 - JWT decode:       sub, tenant_id, role, ver - all required, missing -> 401
Layer 3 - Middleware:       JWT tenant_id cross-validated against DB value
Layer 4 - Principal build:  raises ValueError if tenant_id is None
```

`tenant_id` is always derived from the authenticated identity. Never from request body, query params, or path params.

### UUID/string type boundary

```
DB layer      -> UUID objects   (SQLAlchemy columns, FK joins, repository args)
API/JWT/state -> string objects (request.state, JWT claims, audit logs, responses)

Cast at DB->API:  str(user.tenant_id)     - in middleware and principal builders
Cast at API->DB:  UUID(tenant_id_string)  - in repository queries
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

get_current_principal(request)           # API key OR JWT - scan/audit endpoints
require_jwt(principal)                   # JWT only - rejects API key with 403
require_role(*roles)                     # JWT + role - factory, implies require_jwt
require_admin()                          # shorthand for require_role("ADMIN") - JWT only
require_any_admin()                      # admin access from any auth type - JWT ADMIN role OR admin API key
endpoint_rate_limit(limit_setting: str)  # per-identity rate limit - factory
```

Principal is built from `request.state` - no second DB call in dependencies.

`has_permission()` raises `NotImplementedError` in v1. All guards use `has_role()` exclusively. Permission strings in `ROLE_PERMISSIONS` are defined for v2+ reference only.

`endpoint_rate_limit` is a dependency factory applied on top of the global middleware limit. It reads the effective limit from Redis cache -> DB -> `.env` (same 3-tier chain as the global limit). Identity key: `key_id` from `request.state` with IP fallback. Bucket key: `endpoint:{path}:{identity}` - per-endpoint, per-identity, never shared across endpoints. Fails open if Redis is unavailable.

### Endpoint protection matrix

```
Public:            GET /health, /health/ready, /health/live, GET /metrics
                   POST /v1/auth/login, POST /v1/auth/refresh

JWT any role:      POST /v1/auth/logout, GET /v1/auth/me, POST /v1/auth/change-password

JWT + ADMIN:       ALL /v1/admin/users/*
                   PUT /v1/admin/tenant
                   POST/PUT/DELETE /v1/admin/departments/*
                   POST/PUT/DELETE /v1/admin/applications/*
                   PUT /v1/settings/*
                   POST /v1/keys, PUT /v1/keys/{id}, DELETE /v1/keys/{id}
                   POST /v1/keys/{id}/rotate

Admin (any auth):  PUT /v1/settings/proxy   (require_any_admin - JWT ADMIN or admin API key)

API key OR JWT:    POST /v1/ai/request, POST /v1/chat/completions
                   GET /v1/ai/requests/*, GET /v1/audit/*
                   GET /v1/settings/*, GET/DELETE /v1/settings/proxy*
                   GET /v1/keys, GET /v1/keys/{id}
                   GET /v1/admin/tenant, GET /v1/admin/departments/*
                   GET /v1/admin/applications/*
                   GET /v1/proxy/interactions/*
                   GET /health/config
```

Implementation: every endpoint has an explicit FastAPI dependency - no endpoint relies
solely on middleware for access control. Middleware enforces auth globally; dependencies
enforce RBAC per-endpoint.

Breaking change: `PUT /v1/settings/*` requires JWT + ADMIN - admin API key no longer accepted.
Breaking change: `POST/PUT/DELETE /v1/keys/*` requires JWT + ADMIN - API key no longer accepted.

---

## Rate Limiting

Seven rate limit layers apply to different surfaces. They are additive - a request may be checked by multiple layers in sequence.

### Layer overview

```
Layer 1 - Global middleware      RateLimitMiddleware in api/v1/middleware/rate_limit.py
                                 Applies to all non-public paths before auth runs.
                                 Keyed by key_id (if present) or IP.
                                 Limit: DB -> Redis cache -> .env (RATE_LIMIT_PER_MINUTE, default 60/min).

Layer 2 - Trial key limit        Inline in ai.py, after auth.
                                 Applies only to key_type = "trial".
                                 Keyed by trial:key:{key_id}.
                                 Limit: TRIAL_RATE_LIMIT_PER_MINUTE (env-only, default 10/min).

Layer 3 - Debug mode limit       Inline in ai.py, after the admin guard.
                                 Applies only when debug=true (admin keys only).
                                 Keyed by debug:key:{key_id}.
                                 Limit: DEBUG_RATE_LIMIT_PER_MINUTE (env-only, default 10/min).

Layer 4 - Admin write limit      endpoint_rate_limit dependency on admin write endpoints.
                                 Applies to: POST /v1/admin/users
                                             PATCH /v1/admin/users/{id}
                                             POST /v1/admin/users/{id}/reset-password
                                 Keyed by endpoint:{path}:{key_id}.
                                 Limit: DB -> Redis cache -> .env (ADMIN_WRITE_RATE_LIMIT, default 20/min).

Layer 5 - Audit export limit     endpoint_rate_limit dependency on the export endpoint.
                                 Applies to: GET /v1/audit/export
                                 Keyed by endpoint:{path}:{key_id}.
                                 Limit: DB -> Redis cache -> .env (AUDIT_EXPORT_RATE_LIMIT, default 5/min).

Layer 6 - Login IP limit         Inline in auth.py, before auth_service.login() is called.
                                 Applies to: POST /v1/auth/login only.
                                 Keyed by login:ip:{client_ip} - separate from global bucket.
                                 Complements per-email lockout: stops distributed guessing across
                                 many emails from one IP. Per-email lockout still fires independently.
                                 Limit: LOGIN_RATE_LIMIT_PER_MINUTE (env-only, default 10/min).

Layer 7 - Per-app limit          Inline in ai.py, after resolve_policy().
                                 Applies when app_id is known AND rate_limit_override is set on the
                                 application record.
                                 Keyed by app:{app_id} - per-application bucket.
                                 Set by PATCH /v1/applications/{id} with rate_limit_override (1-10000).
                                 Enforces admin-configured per-app throughput caps independently
                                 of the global limit. Does not raise or bypass the global limit.
```

### Redis key naming convention

```
rate_limit:{key_id or ip}              Global middleware bucket
trial:key:{key_id}                     Trial key bucket
debug:key:{key_id}                     Debug mode bucket
endpoint:{path}:{key_id or ip}         Admin write / export bucket
login:ip:{ip}                          Login endpoint IP bucket (Layer 6)
app:{app_id}                           Per-application bucket (Layer 7)
```

All keys use a 60-second sliding window via the Lua script in `cache/rate_limit_store.py`. The Lua script is atomic - no race condition possible between ZCARD and ZADD.

### Limit configuration - 3-tier chain (Layers 1, 4, 5)

```
Priority 1: Redis cache  (wrapsec:settings:rate_limit or wrapsec:settings:admin_rate_limits)
            TTL: 60 seconds - changes propagate within 1 minute on all nodes.

Priority 2: DB           (settings table, keys: "rate_limit" and "admin_rate_limits")
            Updated via PUT /v1/settings/rate_limit or PUT /v1/settings/admin_limits.
            On read: value is written back to Redis cache (cache warming).

Priority 3: .env         (RATE_LIMIT_PER_MINUTE, ADMIN_WRITE_RATE_LIMIT, AUDIT_EXPORT_RATE_LIMIT)
            Used on first startup and when no DB value exists.
```

When a PUT settings endpoint saves a new limit, it calls `redis.delete(cache_key)` immediately - the new value takes effect on the next request (within seconds, not 60 seconds).

Layers 2 and 3 (trial and debug) read directly from `settings` - no DB/Redis chain. They are env-only and require a restart to change. This is intentional: trial and debug limits are operational constants, not runtime-tunable controls.

### Fail-open policy

All seven layers fail open when Redis is unavailable. Rate limiting is silently disabled during Redis outages to preserve API availability. Monitor Redis health and alert on connection errors if strict enforcement during outages is required.

### Dashboard configuration (Layers 1, 4, 5 only)

```
GET/PUT /v1/settings/rate_limit      Global limit (Layer 1)
GET/PUT /v1/settings/admin_limits    Admin write + export limits (Layers 4, 5)
```

Changes to `admin_limits` are recorded in `admin_events` with old and new values (`action = settings_changed`). Changes to `rate_limit` are not currently logged - add audit logging there if required.

Layers 2, 3, and 6 are intentionally not dashboard-configurable. The debug and login limits are security controls - making them configurable via the dashboard would allow a compromised admin credential to raise them, defeating their purpose.

Layer 7 (per-app) is configurable per-application via `PATCH /v1/applications/{id}` - the `rate_limit_override` integer field. Range: 1-10000 req/min. Setting `null` disables the per-app bucket (inherits global limit only).

### Floor and ceiling constraints

```
ADMIN_WRITE_RATE_LIMIT:  min 5,  max 200   (floor prevents admin self-lockout)
AUDIT_EXPORT_RATE_LIMIT: min 1,  max 60
RATE_LIMIT_PER_MINUTE:   min 1,  max 10000 (must be >= TRIAL_RATE_LIMIT_PER_MINUTE)
```

Floors are enforced server-side in the Pydantic schema - not just client-side. Setting `ADMIN_WRITE_RATE_LIMIT` below 5 via `.env` bypasses the schema validation; the server will still use whatever value is in settings.

---

## Database

### Migrations (Alembic)

Schema is version-controlled with Alembic. Migrations live in `db/migrations/versions/`; the baseline (`0001_baseline.py`) captures the v1.0.11 schema.

Startup path: `api/main.py` lifespan calls `db.session.run_migrations()` which runs `alembic upgrade head` automatically. Nothing to run by hand in normal operation.

Manual commands (from repo root):

```bash
make migrate                       # alembic upgrade head
make migration MSG="add xyz col"  # alembic revision --autogenerate -m "..."
```

Adding a schema change:

1. Edit `db/models.py`.
2. Run `make migration MSG="descriptive change"` and review the generated file in `db/migrations/versions/`.
3. Commit the model change and the migration together.

The legacy `db.session.create_tables()` helper (raw `Base.metadata.create_all()`) is kept only for throwaway per-test SQLite databases; production and dev startup goes through Alembic.

### Session management

Production: `AsyncSessionFactory()` from `db/session.py` - shared async connection pool.

Test mode: `_get_db_session()` in `auth.py` middleware returns a `NullPool` engine - no connection pooling, safe across pytest event loop boundaries.

Never call `AsyncSessionFactory()` directly in middleware. Always use `_get_db_session()`.

### get_db vs get_session

All endpoints use `get_db` from `api/v1/dependencies/db.py`. It wraps the session with rollback handling on exception.

`get_session` from `db/session.py` is for internal/background use only - not endpoint dependencies.

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

Never use `WHERE email = :email` - it does not use the index and breaks case-insensitive uniqueness.

### Transaction boundaries

Each auth flow operation commits once:
- `login()` - create refresh token + update last_login -> one commit
- `refresh()` - revoke old + create new -> one commit
- `logout_all_sessions()` - increment token_version + revoke all -> one commit
- `change_password()` - update hash + flag -> commit, then logout_all -> commit

### Refresh token cleanup

Two clauses run daily via APScheduler (02:00 UTC):

```
Clause 1: DELETE WHERE expires_at < NOW() AND revoked_at IS NOT NULL
          (both expired AND revoked - audit value exhausted)

Clause 2: DELETE WHERE expires_at < NOW() - 90 days
          (prevents unbounded growth from abandoned sessions)
```

---

## Logging

### Audit events (AI security)

Written to `audit_logs` table. Every scan request. Includes decision, risk score, threats, severity, principal attribution.

### Admin events (user management and policy changes)

Written to `admin_events` table. Every user management and policy change action.

- Logging order (must follow):
  1. Perform database update
  2. Commit transaction
  3. Insert admin_event (post-commit, same session)
  4. If logging fails - log internally, do not fail request
- Synchronous within the request lifecycle, but best-effort - main operation always succeeds regardless of logging outcome
- `action` is enum-controlled via `AdminEventAction` - no free-form strings
- `dept_id` = target user's dept_id after the update (post-update state)
- For `dept_changed`: `admin_events.dept_id` = new_dept_id; metadata contains both old and new
- For `policy_override_changed`: `dept_id` = the affected department (or the app's dept_id for application-scope changes); metadata contains `scope`, `section`, and `cleared` - never contains raw policy values or encrypted keys

**Action values (full set):**

| Action | Emitted by | When |
|---|---|---|
| `user_created` | `admin/users.py` | New dashboard user created |
| `user_deactivated` | `admin/users.py` | User set to `is_active=False` |
| `user_reactivated` | `admin/users.py` | User set to `is_active=True` |
| `password_reset` | `admin/users.py` | Admin resets a user's password |
| `role_changed` | `admin/users.py` | User role changed |
| `dept_changed` | `admin/users.py` | User's department changed |
| `settings_changed` | `settings.py` | Rate limit settings changed via dashboard |
| `policy_override_changed` | `departments.py`, `applications.py` | Department or application policy override set, updated, or cleared |

### Auth events (authentication tracking)

Written to `auth_events` table. Non-blocking, separate NullPool session, best-effort.

- `tenant_id` nullable - null when user not found or token unreadable
- Prefer null over incorrect attribution. Never fake a tenant_id.
- NullPool session must be closed in `finally` block - not optional

**Action values (full set):**

| Action | Owner | When |
|---|---|---|
| `login_success` | `service.login()` | Credentials verified |
| `login_failed` | `service.login()` | Bad password, unknown user, inactive |
| `logout` | `service.logout()` | Refresh token revoked; `failure_reason` = logout reason |
| `token_refresh_success` | `service.refresh()` | Refresh token rotated |
| `token_refresh_failed` | `service.refresh()` | Token not found, version mismatch, user disabled |
| `session_expired` | `auth.py` middleware | JWT rejected; NOT logged for `/v1/auth/refresh` path |

Each action has exactly one owner. Never log the same event in two places.

**Failure reason values (full set):**

```
invalid_password    - wrong password
user_not_found      - email not registered
account_inactive    - is_active = false (internal; client sees ACCOUNT_DISABLED)
account_disabled    - administratively disabled
token_expired       - ExpiredSignatureError (JWT exp in past)
token_invalid       - InvalidTokenError (malformed/tampered, not just expired)
inactivity          - 15 min dashboard inactivity timeout
manual              - user clicked logout
expired             - user acknowledged session expiry
refresh_failed      - refresh token not found, revoked, or expired
session_invalidated - token_version mismatch
```

**Mapping: API error code -> auth_events.failure_reason**

| API error code (client) | auth_events.failure_reason (DB) |
|---|---|
| `INVALID_CREDENTIALS` | `invalid_password` or `user_not_found` |
| `ACCOUNT_DISABLED` | `account_inactive` |
| `SESSION_INVALIDATED` | `session_invalidated` |
| `ACCOUNT_LOCKED` | not stored - lockout is Redis-only |
| `UNAUTHORIZED` (expired JWT) | `token_expired` |
| `UNAUTHORIZED` (invalid JWT) | `token_invalid` |

`ACCOUNT_INACTIVE` never appears in API responses. `INVALID_CREDENTIALS` intentionally maps
to two reasons - client gets identical message (no email enumeration).

**Exception type discrimination (mandatory order in middleware):**
```python
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
try:
    payload = decode_access_token(token)
except ExpiredSignatureError:          # MUST catch first - subclass of InvalidTokenError
    reason = "token_expired"
except InvalidTokenError:
    reason = "token_invalid"
```

**Middleware skip rules:**
- Do NOT log `session_expired` when no token is present (health checks, public routes)
- Do NOT log `session_expired` for `/v1/auth/refresh` path - refresh service owns that event

### Structured logger

`logging.getLogger("wrapsec.auth")` logs auth events to stdout/file alongside DB writes.
Both coexist - do not remove the logger. Every DB write has a matching log line.

Log levels: `login_success`, `token_refresh_success`, `logout` -> `logger.info`
            `login_failed`, `token_refresh_failed`, `session_expired` -> `logger.warning`

Format: `auth_event action=login_success user_id=... tenant_id=... reason=...`

---

## User Management

### Role + dept_id consistency

Both directions enforced at DB level (`ck_users_dept_required_v2`) and application level:
```
role = ADMIN     -> dept_id MUST be NULL
role != ADMIN    -> dept_id MUST NOT be NULL
```

DB constraint added in `add_user_management.sql`. Application validation in `UserRepository.create()` and `update()`, and in the PATCH endpoint via `_validate_role_dept_consistency()`.

### PATCH - partial update, not PUT

User updates use `PATCH /v1/admin/users/{id}` - not `PUT`. Only provided fields are updated. This is intentional:

- `PUT` implies full resource replacement - client must send the complete object
- `PATCH` implies partial update - missing fields retain their current values

WrapSec uses `PUT` for settings endpoints (full replacement) and `PATCH` for user updates (partial). Do not use `PUT` on the users endpoint - it will be rejected.

### PATCH final state validation

`PATCH /v1/admin/users/{id}` validates the combined final state, not individual fields:

```python
final_role    = data.get("role",    user.role)
final_dept_id = data.get("dept_id", str(user.dept_id) if user.dept_id else None)
error = _validate_role_dept_consistency(final_role, final_dept_id)
```

Example: `PATCH {"role": "ADMIN", "dept_id": "uuid"}` -> invalid even though either field alone might be valid in context.

### dept_id tenant integrity

`UserRepository` verifies `dept_id` belongs to the same tenant on every create and update:
```python
SELECT id FROM departments WHERE id = dept_id AND tenant_id = tenant_id
```

Also enforced at DB level via composite FK (`fk_users_dept_tenant`).

### Guards

- **Self-deactivation**: checked before last-admin protection - admin cannot set `is_active=False` on their own account
- **Last-admin**: `count_active_admins()` checked before every demotion or deactivation of an ADMIN

---

## Detection Pipeline

```
Input -> [Preprocessors]   (empty in v1.1.0; OCR/transcription plug in here in v1.6.0)
      -> InputGuard (PII guardrail, regex, ~<1ms)
      -> RuleDetector (regex/heuristics, ~<1ms)
      -> MLDetector (TF-IDF + LogReg, 7 labels, ~5ms)
      -> ToxicityGuard (reads ML label 6, ~0ms additional)
      -> LLMDetector (semantic, full mode only, ~100-500ms)
      -> RiskScorer (rule x 0.40 + ml x 0.30 + llm x 0.30, guardrails excluded)
      -> PolicyEngine -> BLOCK / SANITIZE / ALLOW
```

Preprocessor slot: `DetectionPipeline(profile, preprocessors=[...])` accepts an
ordered list of `BasePreprocessor` instances that transform the text before any
detector sees it. The list defaults to empty, so v1.1.0 is behaviourally
identical to v1.0.x. A failing preprocessor logs and is skipped rather than
denying the request. See `engine/detection/preprocessors/base.py`.

Guardrail priority: PII (highest) -> Toxicity -> Detection pipeline.
Guardrails always override detection. Independent thresholds.

`SYSTEM_ERROR` at engine level -> `decision=ALLOW`, `confidence=0.0`. Clients must NOT forward to LLM when `primary_reason=SYSTEM_ERROR`.

---

## Policy Resolution

```python
system_defaults (.env)
    ↓ deep merge
DB settings table (policy_thresholds, detection_layers, llm_settings, rate_limit)
    ↓ deep merge
dept.policy_override   <- null fields inherit from above
    ↓ deep merge
app.policy_override    <- null fields inherit from above
    ↓ app.rate_limit_override (integer column, takes precedence over rate_limit.per_minute)
    ↓
resolved_policy
```

`global_policy` on the tenant table is kept in DB but not applied in resolution. DB settings table is authoritative.

When set via `PUT /v1/tenant`, `global_policy` is validated against `GlobalPolicySchema` - only the following keys are accepted (`extra="forbid"` rejects anything else):

```json
{
  "thresholds": {
    "block":    0.8,
    "sanitize": 0.4
  },
  "detection": {
    "rule_enabled": true,
    "ml_enabled":   true,
    "llm_enabled":  true
  },
  "guardrails": {
    "pii":      { "enabled": true, "block_threshold": 0.8, "sanitize_threshold": 0.4 },
    "toxicity": { "enabled": true, "block_threshold": 0.8 }
  },
  "rate_limit": {
    "per_minute": 60
  }
}
```

All fields are optional - only provided keys are stored. Invariant: `0.0 < sanitize < block <= 1.0`.

Toxicity is BLOCK-or-ALLOW only (Bedrock-style semantics). The `toxicity.sanitize_threshold` field is accepted for backward compatibility with pre-v1.0.9 stored policies but is a no-op.

`rate_limit_override` on an application is a dedicated integer column (separate from `policy_override`). When set, it overrides `policy["rate_limit"]["per_minute"]` and is enforced as a per-app bucket (key `app:{app_id}`) in `ai.py` after policy resolution. Setting it to `null` removes the per-app limit.

---

## Testing

### Running tests

```powershell
$env:TESTING = "true"
$env:PYTHONPATH = "D:\Projects\wrapsec"
pytest tests/unit tests/integration -v
# Expected: 259 passed
```

### Test infrastructure

**Event loop:** `pytest.ini` sets `asyncio_default_fixture_loop_scope = session` + `asyncio_default_test_loop_scope = session`. All tests share one event loop.

**NullPool in tests:** JWT middleware uses `_get_db_session()` which returns a `NullPool` engine when `TESTING=true`. This prevents asyncpg connection pool poisoning across the shared test event loop.

**Redis flushing:** `conftest.py` flushes `rate_limit:*`, `auth:failed:*`, `auth:locked:*` keys before and after each auth test to prevent cross-test accumulation.

**Dependency overrides:** `client` fixture clears `app.dependency_overrides` before AND after each test.

**Integration tests use real PostgreSQL** - not SQLite. JWT middleware needs real DB. Run the DB container before running integration tests.

### End-to-end validation

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\scripts\validate_e2e.ps1
```

Covers: login, auth event logging, user management, admin event logging, guards, cleanup.

---

## Adding a New Endpoint

1. Create the endpoint in `api/v1/endpoints/`
2. Use `get_current_principal` or `require_role()` from `api/v1/dependencies/auth.py`
3. Always filter queries by `principal.tenant_id` - never trust client-provided tenant_id
4. For ADMIN-role endpoints: apply dept_id filter conditionally (`if principal.dept_id`)
5. Register in `api/v1/router.py`
6. Add to the endpoint protection matrix in this document and in `api.md`

---

## Adding a New Guardrail

1. Create detector in `engine/guardrails/`
2. Add `primary_reason` values to `domain/enums.py` - use `_GUARDRAIL_BLOCK` / `_GUARDRAIL_SANITIZE` suffix
3. Add to `InputGuard.inspect()` in `engine/guardrails/input_guard.py`
4. Add to `PolicyEngine.decide()` priority order
5. Add threshold to policy schema
6. Add severity computation if needed in `domain/value_objects/severity.py`

The `_GUARDRAIL_BLOCK` suffix is used by severity computation for auto-CRITICAL classification - new guardrails get this automatically if the naming convention is followed.

---

## Non-Negotiable Conventions

These rules must be followed in all new code. Violation creates real production issues.

1. `tenant_id` always from authenticated identity - never from request body or params
2. `dept_id` always from authenticated identity - never from client input
3. Admin dept query: conditional `WHERE dept_id` - never `WHERE dept_id = NULL`
4. Wrong email and wrong password return the same error message - no enumeration
5. `verify_dummy()` must be called when user not found before raising any error
6. `_DUMMY_HASH` is hardcoded - never compute it at runtime
7. `token_version` checked on every JWT request - not only at refresh time
8. JWT `tenant_id` must be cross-validated against DB value on every request
9. JWT `dept_id` mismatch: log warning, use DB value, do not reject
10. `principal_type` written to `audit_logs` on every request
11. `user_role` always set on `request.state` in JWT path
12. `force_password_change` enforced in middleware - not just frontend
13. `normalize_email()` before every email read or write
14. `get_by_email()` must use `func.lower()` - never `WHERE email = :email`
15. Refresh token raw value never stored server-side - only SHA-256 hash
16. API key always wins if `x-api-key` header present - JWT ignored
17. `require_role()` always implies `require_jwt()` - API keys get 403
18. `has_permission()` not called in v1 guards - use `has_role()` only
19. `dept_id = NULL` for ADMIN: intentional, enforced by DB CHECK + application validation
20. Refresh cleanup: both clauses - expired+revoked AND 90-day absolute
21. Principal builders raise `ValueError` - never `assert`
22. Last-admin protection: `count_active_admins()` before every demotion/deactivation
23. Single DB commit per auth flow operation
24. Refresh token cookie `Path=/v1/auth` - if API prefix changes, cookie path must change
25. `key_id` prefixed: `user:{id}` for JWT users, `key:{id}` for API keys, `key:admin` for admin
26. `get_by_hash()` uses `SELECT FOR UPDATE` - prevents refresh token race condition
27. `dept_id` must belong to same tenant - validated on every create/update
28. `_unauthorized()` always logs reason and path - no silent 401s
29. Admin key fetches real `tenant_id` from DB - never uses placeholder strings
30. All auth events must be logged (login success/fail/lock, logout, session invalidation, password change, JWT mismatches, all 401 rejections)
31. PostgreSQL `READ COMMITTED` isolation assumed - do not change without reviewing refresh token rotation
32. JWT `dept_id` mismatch warnings must be routed to monitoring pipeline
33. 401 response always generic - frontend must treat all 401s as re-auth required
34. UUID/string boundary maintained at every layer
35. `cleanup_expired()` implements both clauses - not separate calls
36. PyJWT exceptions: use `InvalidTokenError` from `jwt.exceptions` - not `JWTError`
37. Datetimes at DB boundary: strip timezone with `_to_db()` - internal calculations stay aware
38. JWT middleware uses `_get_db_session()` - never `AsyncSessionFactory()` directly
39. Endpoints use `get_db` from dependencies - not `get_session` from `db/session.py`
40. All six rate limit layers fail open - never raise on Redis unavailability, always `except Exception: pass`
41. Rate limit Redis keys follow the naming convention - never invent new prefixes (see Rate Limiting section)
42. `endpoint_rate_limit` limit values come from settings - never hardcode a number at the call site
43. Debug rate limit and trial rate limit are env-only - never add them to the DB-backed settings chain
44. `admin_limits` changes must log a `SETTINGS_CHANGED` admin event - never skip audit logging for security control changes
45. `PUT /v1/settings/admin_limits` must invalidate `wrapsec:settings:admin_rate_limits` Redis key - new limits must take effect within seconds, not 60 seconds
46. `_parse_dt()` in `audit.py` raises `ValidationError` (400) on non-empty unparseable dates - never return `None` for invalid input, never add inline `except ValueError: pass` for date params
47. CSV export (`/v1/audit/export`) must never write raw `ip_address` or `user_id` - always hash IP (SHA-256, first 16 hex chars) and truncate user_id to 8 chars
48. Every policy override change (department or application, any endpoint) must log a `POLICY_OVERRIDE_CHANGED` admin event - metadata must not include raw policy values or `api_key_enc` fields
49. `cookie_secure` controls the `Secure` flag on the refresh token cookie - never derive it from `environment == "production"` or any other string comparison; always read from `settings.cookie_secure`
50. ML model (`ml_detector.pkl`) must never be loaded via `pickle.loads` without a matching `.sha256` integrity file - absent hash file is treated the same as a failed hash check (model not loaded, not a warning)
51. Login IP rate limit (Layer 6) must fire before `auth_service.login()` - never after; the check must not depend on DB or auth state
52. `sort_by` and `sort_order` query parameters on any sortable endpoint must use `Literal` types - never raw `str`; FastAPI returns 422 automatically on invalid values
53. Key rotation `grace_period_minutes` is bounded `ge=0, le=10080` (max 7 days) - never accept unbounded integer input for time-based security windows
54. Use `require_any_admin()` for endpoints that are admin-only but must also accept the admin API key (programmatic access). Use `require_admin()` only for dashboard-exclusive endpoints that must reject API key auth
55. All IP attribution in audit logs, admin events, and auth events must use `get_client_ip(request)` - never `request.headers.get("x-forwarded-for", ...)` directly
56. Semantic cache keys must include `tenant_id` - never key solely on prompt + mode. Without tenant scoping, an ALLOW result from one tenant can be returned to another tenant whose policy would block the same input. Use `"global"` as the tenant key for requests with no tenant_id (admin/system calls)
57. The Next.js BFF (`dashboard/app/api/auth/login/route.ts`) must forward the real client IP as `x-forwarded-for` on all backend fetch calls - without this, the backend rate limiter sees only the BFF server IP and cannot enforce per-client limits
58. The Next.js BFF must never forward the raw backend `set-cookie` header to the browser - always parse the token value and max-age, then re-issue with `Path=/api/auth`. The backend sets `Path=/v1/auth`; that path restriction means the browser will never send the cookie back to `/api/auth/*` BFF routes, breaking refresh and logout
59. Only one auth mechanism must be active at a time per session - when a user logs in via JWT (email/password), the BFF login route must clear any existing `wrapsec_api_key` cookie, and vice versa. Allowing both simultaneously creates an ambiguous fallback state where a revoked JWT session could silently continue via a still-valid API key cookie
60. API keys must never be created without a valid `tenant_id` on `request.state` - a scopeless key bypasses tenant isolation in every downstream auth check. The key creation endpoint enforces this with a 403 guard before any DB write

---

## Key Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | - | HMAC secret for JWT signing. **Startup guard rejects the example placeholder** - server will not start until set to a real value. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | JWT access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `30` | Refresh token lifetime |
| `ADMIN_API_KEY` | - | Master admin API key. **Startup guard rejects the example placeholder** - server will not start until set to a real value. Generate: `python -c "import secrets; print('wsk_admin_' + secrets.token_hex(24))"` |
| `ADMIN_EMAIL` | *(unset)* | Optional - if set alongside `ADMIN_PASSWORD`, bootstrap creates first admin on startup. Leave unset to use the dashboard `/setup` page instead |
| `ADMIN_PASSWORD` | *(unset)* | Optional - see `ADMIN_EMAIL`. Must meet password strength requirements if set |
| `TRUSTED_PROXY_IPS` | `""` | Comma-separated IPs trusted to set `X-Forwarded-For` (e.g. `127.0.0.1,10.0.0.1`) |
| `METRICS_TOKEN` | `""` | If set, `GET /metrics` requires `Authorization: Bearer <token>`. Falls back to `ADMIN_API_KEY` if unset |
| `DATA_STORAGE_MODE` | `masked` | `full` / `masked` / `none` - controls proxy text persistence |
| `DATA_RETENTION_DAYS` | `30` | Audit log retention in days (min 7, max 3650) |
| `DATA_RETENTION_DAYS_PROXY` | `7` | Proxy interaction text retention in days |
| `RETENTION_WORKER_ENABLED` | `true` | Enable/disable background retention worker |
| `RETENTION_WORKER_HOUR` | `2` | UTC hour for daily cleanup |
| `RETENTION_WORKER_MINUTE` | `0` | UTC minute for daily cleanup |
| `LOCKOUT_MAX_ATTEMPTS` | `5` | Failed login attempts before lockout |
| `LOCKOUT_DURATION_SECONDS` | `900` | Lockout duration (15 min) |
| `RATE_LIMIT_PER_MINUTE` | `60` | Global rate limit for live API keys. Also configurable via dashboard (DB-backed) |
| `ADMIN_WRITE_RATE_LIMIT` | `20` | Per-user limit on admin write ops (user create/update/reset-password). DB-backed |
| `AUDIT_EXPORT_RATE_LIMIT` | `5` | Per-caller limit on audit CSV export. DB-backed |
| `TRIAL_RATE_LIMIT_PER_MINUTE` | `10` | Rate limit for trial keys - env-only, not dashboard-configurable |
| `DEBUG_RATE_LIMIT_PER_MINUTE` | `10` | Rate limit for debug mode requests - env-only, security control |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | `10` | Per-IP rate limit on `POST /v1/auth/login` - env-only, security control. Complements per-email lockout |
| `COOKIE_SECURE` | `true` | Adds `Secure` flag to refresh token cookie. Set `false` only for local HTTP dev - must be `true` in all deployed environments |

**Load test env vars** - required when running `tests/load/` scripts:

| Variable | Description |
|---|---|
| `WRAPSEC_ADMIN_KEY` | Admin API key for load test setup calls |
| `WRAPSEC_PURCHASE_KEY` | Live API key for purchase department tests |
| `WRAPSEC_FINANCE_KEY` | Live API key for finance department tests |
| `WRAPSEC_TRIAL_KEY` | Trial API key for trial-tier tests |
| `WRAPSEC_PURCHASE_DEPT_ID` | UUID of purchase department in test instance |
| `WRAPSEC_FINANCE_DEPT_ID` | UUID of finance department in test instance |

---

## Pre-Launch Security Checklist

Items marked **[STARTUP GUARD]** are enforced by `validate_secrets()` at startup - the server will not start if they are not resolved.

### Secrets

**SECRET_KEY** - [STARTUP GUARD]
- `.env.example` ships with placeholder `your-secret-key-minimum-32-characters-here`
- Startup validation rejects this exact string
- Generate a real secret: `python -c "import secrets; print(secrets.token_hex(32))"`

**Rotating SECRET_KEY** has two consequences that require operator action:

1. **All JWT sessions are immediately invalidated** - every `wrapsec_jwt` cookie signed with the old key becomes invalid. All logged-in dashboard users are forced to re-login on their next request. This is expected and safe.

2. **Encrypted provider credentials become unreadable** - department and application proxy provider API keys are stored encrypted using `SECRET_KEY` (`api_key_enc` in `policy_override`). After rotation, decryption fails and any proxy call using a stored provider credential returns a 500 error. To restore proxy functionality: go to the dashboard -> the affected Department or Application -> Proxy Provider -> re-enter the provider API key -> Save. This re-encrypts it with the new `SECRET_KEY`.

Treat `SECRET_KEY` rotation as a planned maintenance event - notify users of the forced logout and have provider keys ready to re-enter.

**ADMIN_API_KEY** - [STARTUP GUARD]
- `.env.example` ships with placeholder `your-admin-api-key-minimum-32-chars-here`
- Startup validation rejects this exact string
- Generate a real key: `python -c "import secrets; print('wsk_admin_' + secrets.token_hex(24))"`

### Bootstrap admin (if using ADMIN_EMAIL / ADMIN_PASSWORD)

- Bootstrap always sets `force_password_change=True` - the first login requires a password change
- Do not reuse the same password across environments; even with force-change enforced, the window before rotation is exploitable
- Preferred: leave `ADMIN_EMAIL`/`ADMIN_PASSWORD` unset and use the dashboard `/setup` page for first-user creation

### ML model integrity

- If `models/ml_detector.pkl` is present, `models/ml_detector.pkl.sha256` **must** also be present
- Without the hash file, the server refuses to load the model - `pickle.loads` without verification is an RCE vector
- Generate the hash file: `sha256sum models/ml_detector.pkl > models/ml_detector.pkl.sha256`
- If deploying without a trained model, ensure the `.pkl` file is absent - the ML detector falls back cleanly

### Cookie security

- `COOKIE_SECURE=true` is the default - do not override this in staging or production
- `COOKIE_SECURE=false` is only acceptable for local HTTP development

### Metrics endpoint

- Set a dedicated `METRICS_TOKEN` separate from `ADMIN_API_KEY`
- Generate: `python -c "import secrets; print(secrets.token_hex(32))"`
- If unset, `/metrics` falls back to `ADMIN_API_KEY` - a compromised scraper credential then also grants full admin API access

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
Secrets/credentials guardrail    - fast regex for API keys, tokens in prompts
Cursor-based pagination          - replace offset pagination on audit endpoints
Per-key storage mode override    - allow individual keys to override DATA_STORAGE_MODE
tiktoken                         - per-model token counting (replaces ceil(len/2) heuristic)
Production deployment            - domain ready, Groq instead of Ollama
OWNER role                       - single per tenant, cannot be deactivated
Email invitations                - for SaaS onboarding
Permission engine                - replace has_role() with has_permission() (v2+)
```

---

*WrapSec Developer Guide - v1.0 - May 2026*
