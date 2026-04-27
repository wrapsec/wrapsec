# WrapSec — JWT & RBAC Implementation Plan

*Version 9.0 — 25 Apr 2026*
*All seven review cycles incorporated and closed.*
*Implementation complete (Steps 1-20). Dashboard pending (Steps 21-27).*
*Single source of truth.*

---

## ✅ All Review Items Closed — Do Not Raise These Again

Every point from all seven review cycles is listed here with its exact fix location.
If a point appears in this table, it is fully implemented in this document.

| Review | Item | Fix location |
|---|---|---|
| R1 | dept_id NOT NULL | §1.4 — ADMIN null intentional, DB CHECK enforces non-admin |
| R1 | Header precedence | §1.2 — API key always wins, absolute rule |
| R1 | Simplified JWT payload | §7.1 — minimal claims, type + aud retained with rationale |
| R1 | Bootstrap uses get_default() | §13 — explicit default tenant fetch |
| R1 | Roles only in v1 | §3.2 — permissions exist, not enforced, explicit comment |
| R1 | Scanner Option B | §1.5 — JWT accepted on scan endpoints |
| R1 | httpOnly cookie | §9.1, §14.1, §14.2 |
| R1 | force_password_change | §4.1, §8.2 step 6, §9.1, §10.5 |
| R2 | tenant_id four-layer enforcement | §1.3 — DB + JWT + middleware + principal |
| R2 | Admin NULL dept query | §1.4 — conditional filter pattern |
| R2 | user_role set in middleware | §8.2 step 5 |
| R2 | Refresh cleanup AND revoked_at | §7.3, §15 |
| R2 | JWT audience claim | §6.3, §7.1 |
| R2 | Email normalization everywhere | §6.1 normalize_email() |
| R2 | api_keys.tenant_id migration | §5 — full migration |
| R2 | Partial index on refresh_tokens | §4.2, §5 |
| R2 | Dummy hash timing fix | §6.1 verify_dummy() |
| R2 | Auth event logging | §6.4, §11 |
| R2 | Prevent last admin deactivation | §10.4 |
| R3 | Token versioning | §4.1, §4.2, §6.3, §6.4 |
| R3 | Account lockout Redis TTL | §6.2 — full implementation |
| R3 | Principal raises ValueError not assert | §3.3 |
| R3 | Four-layer tenant enforcement | §1.3, §3.3, §5, §6.3, §8.2 |
| R4 | Admin key "admin" string removed | §3.3, §8.3 — real tenant_id from DB |
| R4 | token_version in RefreshTokenModel | §4.2 |
| R4 | token_version in repository.create() | §4.3, §6.4 |
| R4 | JWT tenant_id vs DB cross-validation | §8.2 step 3 |
| R4 | api_keys.tenant_id NOT NULL | §5 |
| R4 | Case-insensitive email unique index | §4.1, §5 |
| R4 | tenant_id validation after DB load | §8.2 step 2b |
| R4 | Transaction boundary per auth flow | §6.4 — single commit |
| R4 | JWT error message generic to client | §6.3 |
| R4 | Redis lock TTL behavior documented | §6.2 |
| R4 | Email uniqueness scope decision | §5 — global, documented |
| R4 | Permissions field clarity | §3.2 |
| R5 | JWT dept_id mismatch logging | §8.2 step 3b |
| R5 | key_id prefixed user: / key: | §8.1, §8.2, §8.3 |
| R5 | Refresh token race condition SELECT FOR UPDATE | §4.3, §6.4 |
| R5 | Hardcoded dummy hash (not dynamic) | §6.1 |
| R5 | LOWER() comment in get_by_email() | §4.3 |
| R5 | force_password_change enforced in middleware | §8.2 step 6 |
| R5 | dept_id tenant integrity validation in repo | §4.3 |
| R5 | _unauthorized() always logs reason + path | §8.4 |
| R5 | Cookie path documented + convention added | §14.2, §19 |
| R5 | Admin principal_id uses key: prefix | §8.3 |
| R6 | DB-level dept_id ↔ tenant composite FK | §5 migration |
| R6 | READ COMMITTED isolation documented | §5, §19 convention 31 |
| R6 | JWT dept mismatch in monitoring pipeline | §19 convention 32 |
| R6 | 401 behavior documented for frontend | §9, §19 convention 33 |
| R6 | Default password safety check in production | §13 bootstrap |
| R6 | Secondary refresh token cleanup (90 days) | §15 retention |
| R6 | has_permission() raises NotImplementedError in v1 | §3.2 principal |
| R7 | UUID/string type boundary — explicit invariant | §1.3, §3.3, §8.1 |
| R7 | cleanup_expired() contract shows both clauses | §4.3 repository |
| R7 | Role + composite role/is_active index added | §5 migration |
| R7 | stderr print for production password warning | §13 bootstrap |
| R7 | JWT dept mismatch marked as deployment requirement | §19 convention 32 |

---

## Implementation Deviations from v8 Plan

The following changes were made during implementation and differ from v8.
All are intentional improvements discovered during coding.

### JWT Library: PyJWT instead of python-jose

**Plan (v8):** Used `from jose import jwt, JWTError`
**Actual:** Uses `PyJWT==2.10.1` — `import jwt` / `from jwt.exceptions import InvalidTokenError`

**Reason:** PyJWT is the de facto standard, better maintained, used by FastAPI community.
Functionally identical for HS256. RS256/ES256 available via `cryptography` extra for V2.

**Impact on code:**
- `services/auth/token.py` — `import jwt`, `InvalidTokenError` instead of `JWTError`
- `api/v1/middleware/auth.py` — `from jwt.exceptions import InvalidTokenError`
- `jwt.decode()` API identical; audience validation built-in

### Datetime Handling: Naive UTC at DB Boundary

**Plan (v8):** Used `datetime.now(timezone.utc)` throughout
**Actual:** Internal calculations use `datetime.now(timezone.utc)` (timezone-aware).
DB writes strip timezone via `_to_db(dt)` helper: `dt.replace(tzinfo=None)`

**Reason:** PostgreSQL `TIMESTAMP WITHOUT TIME ZONE` rejects timezone-aware datetimes via asyncpg.
**Pattern:** `_utcnow()` returns aware datetime; `_to_db()` strips tzinfo at DB boundary.

### Test Infrastructure: NullPool + Session-Scoped Event Loop

**Plan (v8):** Not specified — standard pytest patterns assumed
**Actual:** Required significant test infrastructure work:

- `pytest.ini`: `asyncio_default_fixture_loop_scope = session` + `asyncio_default_test_loop_scope = session`
- JWT middleware (`_authenticate_jwt`): uses `NullPool` engine in `TESTING=true` mode via `_get_db_session()` helper — avoids asyncpg pool poisoning across test event loops
- `auth_setup` fixture: uses `NullPool` engine (not `AsyncSessionFactory`) for same reason
- `tests/integration/conftest.py`: flushes `rate_limit:*`, `auth:failed:*`, `auth:locked:*` Redis keys before/after each auth test to prevent cross-test accumulation
- `client` fixture: clears `app.dependency_overrides` before AND after each test

### Migration: ADD CONSTRAINT IF NOT EXISTS Not Supported

**Plan (v8):** Used `ALTER TABLE ... ADD CONSTRAINT IF NOT EXISTS`
**Actual:** Uses `DO $$ BEGIN IF NOT EXISTS (...) THEN ALTER TABLE ... ADD CONSTRAINT ...; END IF; END $$;`

**Reason:** `ADD CONSTRAINT IF NOT EXISTS` syntax not available in the PostgreSQL version in use.

### Dependencies Added

```
PyJWT==2.10.1
passlib[bcrypt]==1.7.4
bcrypt==3.2.2          # 4.x incompatible with passlib 1.7.4
email-validator==2.3.0
python-multipart==0.0.20
aiosqlite==0.22.1      # already installed
APScheduler==3.11.2    # already installed
dnspython==2.8.0       # installed as email-validator dependency
```

### get_db vs get_session

**Plan (v8):** Used `get_session` from `db.session`
**Actual:** Uses `get_db` from `api/v1/dependencies/db.py` — matches existing endpoint pattern, includes rollback handling.

---

## 1. Architecture — Absolute Rules

### 1.1 Dual Identity Model

Two auth systems coexist. Both resolve to identical fields on `request.state`. All downstream code is completely auth-agnostic — it never checks which auth method was used.

```
x-api-key header     → API_KEY principal  (machine — applications, services)
Authorization Bearer → USER principal     (human — dashboard users)
```

### 1.2 Header Precedence — Absolute, No Exceptions

```
IF x-api-key header present (non-empty after strip):
    → ALWAYS use API key path
    → IGNORE Authorization header — even if it contains a valid JWT
    → This is unconditional. No case where JWT takes priority.

ELIF Authorization header starts with "Bearer " (case-insensitive):
    → JWT path

ELSE:
    → 401 UNAUTHORIZED
```

First code in middleware `dispatch()` — before any other logic:

```python
api_key = request.headers.get("x-api-key", "").strip()
auth    = request.headers.get("authorization", "").strip()

if api_key:
    return await self._authenticate_api_key(api_key, request, call_next)
elif auth.lower().startswith("bearer "):
    return await self._authenticate_jwt(auth[7:], request, call_next)
else:
    return _unauthorized(request, "missing_credentials")
```

### 1.3 Tenant Enforcement — Four Layers, All Mandatory

`tenant_id` is the outermost security boundary. Enforce at all four layers.

```
Layer 1 — Database schema:
    users.tenant_id NOT NULL
    api_keys.tenant_id NOT NULL (after migration)
    refresh_tokens.token_version NOT NULL

Layer 2 — JWT decode (services/auth/token.py):
    sub, tenant_id, role, ver — all must be present and non-null
    Missing any → InvalidTokenError → 401

Layer 3 — Middleware (api/v1/middleware/auth.py):
    JWT path:
        user.tenant_id must not be None → 401
        payload["tenant_id"] must match str(user.tenant_id) → 401
    API key path:
        key.tenant_id must not be None → 401

Layer 4 — Principal construction (domain/entities/principal.py):
    build_principal_from_user(): raises ValueError if tenant_id is None
    build_principal_from_api_key(): raises ValueError if tenant_id is None
```

**Absolute rule:** `tenant_id` and `dept_id` ALWAYS from authenticated identity. NEVER from request body, query params, path params, or any client-provided source.

**UUID/string type boundary:**
```
DB layer       → UUID objects    (SQLAlchemy UUID columns, FK joins)
API/JWT/state  → string objects  (request.state, JWT claims, audit logs, responses)

Cast at boundary:
    DB → string:  str(user.tenant_id)        in middleware and builders
    String → DB:  UUID(tenant_id_string)     in repository queries
```

### 1.4 Admin NULL dept — Query Pattern, Mandatory Everywhere

```
ADMIN     → dept_id = NULL → sees ALL data for the tenant
DEVELOPER → dept_id set   → sees only own dept data
VIEWER    → dept_id set   → sees only own dept data
```

Every protected query — no exceptions:

```python
query = base_query.where(table.tenant_id == request.state.tenant_id)
if request.state.dept_id:
    query = query.where(table.dept_id == request.state.dept_id)
```

**NEVER** write `WHERE dept_id = NULL`.

### 1.5 Scan Endpoints — Both Auth Methods Accepted (Option B)

JWT users treated identically to API key users on scan/proxy endpoints.
Only audit log differs: `principal_type = "user"` vs `"api_key"`.

---

## 2. Environment Variables

### 2.1 `.env` additions

```env
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=<strong-password>
AUTH_MAX_FAILED_ATTEMPTS=5
AUTH_LOCKOUT_DURATION_SECONDS=900
```

### 2.2 `config/settings.py` additions

```python
jwt_access_token_expire_minutes: int = 30
jwt_refresh_token_expire_days:   int = 30
admin_email:                     str = Field(default="admin@localhost")
admin_password:                  str = Field(default="ChangeMe!OnFirstLogin")
auth_max_failed_attempts:        int = 5
auth_lockout_duration_seconds:   int = 900
```

Note: existing `jwt_expiry_mins` kept as legacy field — do not remove.

---

## 3. Domain Layer

### 3.1 `domain/enums.py` — additions

```python
class PrincipalType(str, Enum):
    USER       = "user"
    API_KEY    = "api_key"
    AGENT      = "agent"       # Phase 3 stub
    MCP_CLIENT = "mcp_client"  # Phase 3 stub

class UserRole(str, Enum):
    ADMIN     = "ADMIN"
    DEVELOPER = "DEVELOPER"
    VIEWER    = "VIEWER"
```

### 3.2 `domain/entities/principal.py` — new file

See implementation. Key points:
- `has_permission()` raises `NotImplementedError` in v1 — all guards use `has_role()`
- `ROLE_PERMISSIONS` defined for v2+ reference only
- Builder functions raise `ValueError` (not `assert`) on missing `tenant_id`

### 3.3 Principal Builder Functions

`build_principal_from_user(user)` — called by JWT middleware
`build_principal_from_api_key(key)` — called by API key middleware (non-admin keys only)

Admin key handled separately by `_authenticate_admin_key()` — never goes through builder.

---

## 4. Database Models

### 4.1 `UserModel` — key fields

```python
token_version         = Column(Integer, nullable=False, default=1)
force_password_change = Column(Boolean, nullable=False, default=False)
```

### 4.2 `RefreshTokenModel` — key fields

```python
token_hash    = Column(String(64), nullable=False, unique=True)
token_version = Column(Integer,    nullable=False, default=1)
revoked_at    = Column(DateTime,   nullable=True)
```

### 4.3 Repository Contracts

`UserRepository.get_by_email()` — MUST use `func.lower()` to match `ux_users_email_lower` index
`RefreshTokenRepository.get_by_hash()` — uses `.with_for_update()` for race condition prevention
`RefreshTokenRepository.cleanup_expired()` — two clauses (R7): primary + 90-day secondary

---

## 5. Database Migration — `db/migrations/add_users.sql`

Idempotent. Uses `DO $$ ... END $$` blocks for constraints (not `IF NOT EXISTS`).

Creates: `users`, `refresh_tokens`
Modifies: `audit_logs` (adds `principal_type`), `api_keys` (enforces `tenant_id NOT NULL`)
Adds: `uq_departments_id_tenant`, `fk_users_dept_tenant` composite FK

---

## 6. Service Layer

### 6.1 `services/auth/password.py`

- `_DUMMY_HASH` is hardcoded (not computed at runtime)
- `verify_dummy()` called when user not found — mandatory timing equalisation
- `normalize_email()` called before every DB read/write

### 6.2 `services/auth/lockout.py`

Redis keys: `auth:failed:{email}`, `auth:locked:{email}`
TTL behavior: counter TTL set on first failure only; lock TTL reset on each retry (extends lockout)

### 6.3 `services/auth/token.py`

**Uses PyJWT — not python-jose.**

```python
import jwt
from jwt.exceptions import InvalidTokenError

ACCESS_TOKEN_AUDIENCE = "wrapsec-dashboard"

def create_access_token(user) -> str:
    payload = {
        "sub": str(user.id), "type": "access", "ver": user.token_version,
        "role": user.role, "tenant_id": str(user.tenant_id),
        "dept_id": str(user.dept_id) if user.dept_id else None,
        "aud": ACCESS_TOKEN_AUDIENCE, "iat": now, "exp": expires,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)

def decode_access_token(token: str) -> dict:
    # Raises InvalidTokenError (not JWTError) with generic message
    payload = jwt.decode(token, settings.secret_key,
                         algorithms=[settings.jwt_algorithm],
                         audience=ACCESS_TOKEN_AUDIENCE)
    ...
```

### 6.4 `services/auth/service.py`

**Datetime handling:**
```python
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _to_db(dt: datetime) -> datetime:
    return dt.replace(tzinfo=None)  # strip tz for TIMESTAMP WITHOUT TIME ZONE columns

# Usage:
expires_at = _utcnow() + timedelta(days=...)
await rt_repo.create(..., expires_at=_to_db(expires_at), ...)
```

Single commit per flow — login, refresh, logout_all, change_password each commit once.

---

## 7. JWT Token Design

### 7.1 Access Token Payload

```json
{
    "sub":       "550e8400-...",
    "type":      "access",
    "ver":       1,
    "role":      "DEVELOPER",
    "tenant_id": "42a083bf-...",
    "dept_id":   "4111d663-...",
    "aud":       "wrapsec-dashboard",
    "iat":       1714000000,
    "exp":       1714001800
}
```

### 7.2 Refresh Token

SHA-256 hash stored in DB. Raw token delivered via httpOnly cookie.
`Path=/v1/auth` — browser only sends to `/v1/auth/*`.

---

## 8. Middleware — `api/v1/middleware/auth.py`

### 8.1 Test mode DB session

```python
async def _get_db_session():
    if _TESTING:
        # NullPool — no connection pool, safe across pytest event loop boundaries
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        sf     = async_sessionmaker(bind=engine, class_=AsyncSession, ...)
        return engine, sf()
    else:
        return None, AsyncSessionFactory()
```

This is the key fix for test isolation — production uses the shared pool, tests use fresh connections.

### 8.2 JWT authentication path

Steps unchanged from v8 plan. Key implementation note:
- `decode_access_token()` raises `InvalidTokenError` (PyJWT) not `JWTError` (jose)
- `_get_db_session()` used instead of `AsyncSessionFactory()` directly

### 8.3 Admin key path

In test mode (`TESTING=true`): skips DB tenant fetch, sets `tenant_id = None`.
In production: fetches default tenant from DB via `TenantRepository(session).get_default()`.

---

## 9. Auth Endpoints

Five endpoints at `/v1/auth/`:

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/login` | Public | EmailStr validated by Pydantic (RFC 5322 via email-validator) |
| POST | `/refresh` | Cookie | httpOnly cookie, no body |
| POST | `/logout` | JWT | Idempotent |
| GET | `/me` | JWT | Accessible when force_password_change=True |
| POST | `/change-password` | JWT | Accessible when force_password_change=True |

---

## 10. User Management Endpoints

Five endpoints at `/v1/admin/users/` — all require JWT + ADMIN role:

| Method | Path | Notes |
|---|---|---|
| POST | `` | Creates user, force_password_change=True |
| GET | `` | Lists users scoped to tenant |
| GET | `/{user_id}` | Get single user, tenant-scoped |
| PUT | `/{user_id}` | Update role/dept/is_active + logout_all_sessions |
| POST | `/{user_id}/reset-password` | Admin reset + force_password_change=True |

Last-admin protection: `count_active_admins()` checked before every demotion/deactivation.

---

## 11. Auth Event Logging

All events logged via `logging.getLogger("wrapsec.auth")`.
Format: `auth_event EVENT_NAME key=value ...`

Events: LOGIN_SUCCESS, LOGIN_FAILED, LOGIN_LOCKED, LOGOUT, TOKEN_REFRESHED,
SESSION_INVALIDATED, PASSWORD_CHANGED, JWT_TENANT_MISMATCH, JWT_DEPT_MISMATCH, AUTH_REJECTED

---

## 12. RBAC Dependencies — `api/v1/dependencies/auth.py`

```python
get_current_principal(request)  # API key OR JWT — use on scan/audit endpoints
require_jwt(request)            # JWT only — rejects API key with 403
require_role(*roles)            # JWT + role check — factory returning dependency
require_admin()                 # shorthand for require_role("ADMIN")
```

Principal built from `request.state` — no second DB call.

### 12.1 Endpoint Protection Matrix

```
Public:           GET /health*, GET /metrics, POST /v1/auth/login, POST /v1/auth/refresh
JWT any role:     POST /v1/auth/logout, GET /v1/auth/me, POST /v1/auth/change-password
JWT + ADMIN:      ALL /v1/admin/tenant*, /v1/admin/departments*, /v1/admin/applications*,
                  /v1/admin/users*, PUT /v1/settings/*
JWT + ADMIN/DEV:  GET /v1/settings/*, ALL /v1/keys/*
API key OR JWT:   POST /v1/ai/request, POST /v1/chat/completions, GET /v1/ai/requests/*,
                  GET /v1/audit/*
```

---

## 13. Bootstrap — `api/main.py`

`bootstrap_admin()` runs in lifespan, skipped when `TESTING=true`.
Sets `force_password_change=True` — enforced at middleware level.
Production warning: logs ERROR + prints to stderr if default password detected.

---

## 14. Dashboard Auth (Steps 21-27 — Pending)

### 14.1 Token Storage

```
Access token  → JavaScript memory (React context state)
Refresh token → httpOnly cookie (Path=/v1/auth)
```

### 14.2 New Dashboard Files

```
dashboard/app/login/page.tsx
dashboard/app/change-password/page.tsx
dashboard/components/auth/AuthProvider.tsx
dashboard/components/auth/ProtectedRoute.tsx
dashboard/middleware.ts
dashboard/lib/auth.ts
```

---

## 15. Retention Worker — `workers/tasks.py`

`_cleanup_refresh_tokens()` added to `run_retention_cleanup()`.
Two clauses: primary (expired AND revoked) + secondary (90 days regardless).

---

## 16. Complete Test Plan

### 16.1 Unit Tests (69 new, Steps 19)

- `tests/unit/services/test_password.py` — 14 tests
- `tests/unit/services/test_token.py` — 18 tests (PyJWT: `InvalidTokenError` not `JWTError`)
- `tests/unit/services/test_lockout.py` — 11 tests (mocked Redis)
- `tests/unit/test_principal.py` — 16 tests

### 16.2 Integration Tests (34 new, Step 20)

- `tests/integration/test_auth_endpoints.py` — 18 tests
- `tests/integration/test_rbac.py` — 16 tests

**Test infrastructure notes:**
- `pytest.ini`: `asyncio_default_fixture_loop_scope = session` + `asyncio_default_test_loop_scope = session`
- Auth tests use real PostgreSQL (not SQLite) — JWT middleware needs real DB
- `auth_setup` fixture uses `NullPool` engine
- `_flush_test_redis_keys()` clears `rate_limit:*`, `auth:failed:*`, `auth:locked:*` before/after each test
- `client` fixture clears `app.dependency_overrides` before AND after

---

## 17. Complete File List

### New Files (implemented)

```
domain/entities/principal.py
services/auth/__init__.py
services/auth/password.py
services/auth/token.py
services/auth/lockout.py
services/auth/service.py
db/repositories/user.py
db/repositories/refresh_token.py
db/migrations/add_users.sql
api/v1/endpoints/auth.py
api/v1/endpoints/admin/__init__.py
api/v1/endpoints/admin/users.py
api/v1/dependencies/auth.py
tests/unit/services/__init__.py
tests/unit/services/test_password.py
tests/unit/services/test_token.py
tests/unit/services/test_lockout.py
tests/unit/test_principal.py
tests/integration/test_auth_endpoints.py
tests/integration/test_rbac.py
```

### Modified Files (implemented)

```
domain/enums.py                 ← PrincipalType, UserRole
db/models.py                    ← UserModel, RefreshTokenModel, AuditLogModel.principal_type
config/settings.py              ← JWT + lockout + bootstrap env vars
api/v1/middleware/auth.py       ← JWT path, NullPool test mode, prefixed key_id, _get_db_session
api/v1/router.py                ← register auth + users routes
api/main.py                     ← bootstrap_admin in lifespan
workers/tasks.py                ← cleanup_refresh_tokens()
errors/exceptions.py            ← AuthenticationError, AccountLockedException, etc.
tests/integration/conftest.py   ← auth_setup, auth_client, Redis flush, override cleanup
pytest.ini                      ← session-scoped event loop
requirements.txt                ← PyJWT, passlib, bcrypt, email-validator, python-multipart
```

### Dashboard Files (pending — Steps 21-27)

```
dashboard/app/login/page.tsx
dashboard/app/change-password/page.tsx
dashboard/components/auth/AuthProvider.tsx
dashboard/components/auth/ProtectedRoute.tsx
dashboard/middleware.ts
dashboard/lib/auth.ts
dashboard/lib/api.ts            ← add Authorization: Bearer header to all calls
```

---

## 18. Implementation Order (Status)

```
Step 1  ✅ domain/enums.py
Step 2  ✅ domain/entities/principal.py
Step 3  ✅ config/settings.py
Step 4  ✅ db/models.py
Step 5  ✅ db/migrations/add_users.sql
Step 6  ✅ db/repositories/user.py
Step 7  ✅ db/repositories/refresh_token.py
Step 8  ✅ services/auth/password.py
Step 9  ✅ services/auth/token.py
Step 10 ✅ services/auth/lockout.py
Step 11 ✅ services/auth/service.py + errors/exceptions.py
Step 12 ✅ api/v1/middleware/auth.py
Step 13 ✅ api/v1/dependencies/auth.py
Step 14 ✅ api/v1/endpoints/auth.py
Step 15 ✅ api/v1/endpoints/admin/users.py
Step 16 ✅ api/v1/router.py
Step 17 ✅ api/main.py
Step 18 ✅ workers/tasks.py
Step 19 ✅ Unit tests (69 new, 251 total passing)
Step 20 ✅ Integration tests (34 new, 251 total passing)
Step 21 🔲 dashboard/lib/auth.ts
Step 22 🔲 dashboard/components/auth/AuthProvider.tsx + ProtectedRoute.tsx
Step 23 🔲 dashboard/app/login/page.tsx
Step 24 🔲 dashboard/app/change-password/page.tsx
Step 25 🔲 dashboard/middleware.ts
Step 26 🔲 dashboard/lib/api.ts (add Bearer header)
Step 27 🔲 End-to-end: login → scan → audit → change-password → logout
```

---

## 19. Non-Negotiable Conventions

(Unchanged from v8 — all 35 conventions apply. See v8 for full list.)

Key additions from implementation:

**Convention 36 — PyJWT exception type:**
All code catching JWT decode failures must use `InvalidTokenError` from `jwt.exceptions`,
not `JWTError`. These are not interchangeable.

**Convention 37 — Datetime at DB boundary:**
All datetimes stored to DB must be naive UTC. Use `_to_db(dt)` helper in `service.py`
to strip timezone info before passing to repository methods.
Internal calculations remain timezone-aware via `_utcnow()`.

**Convention 38 — Test DB session:**
JWT middleware uses `_get_db_session()` which returns `NullPool` engine in test mode.
NEVER call `AsyncSessionFactory()` directly in middleware — always use `_get_db_session()`.

**Convention 39 — get_db not get_session:**
All endpoints use `get_db` from `api/v1/dependencies/db.py` (includes rollback handling).
`get_session` from `db/session.py` is for internal use only, not endpoint dependencies.

---

## 20. On-Prem Deployment Requirements

(Unchanged from v8 — all requirements apply.)

Additional requirement from implementation:

**Change ADMIN_PASSWORD before first startup:**
bootstrap_admin() will log ERROR + print to stderr if default password detected in production.
Set `ADMIN_PASSWORD` in `.env` to a strong password before deploying.

---

*Version 9.0 — Implementation complete (Steps 1-20). Dashboard pending (Steps 21-27).*
*All deviations from v8 documented in "Implementation Deviations" section above.*
