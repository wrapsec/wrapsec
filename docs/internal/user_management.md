# WrapSec — User Management Reference

*Version 1.3 — May 2026*
*Updated: session hardening + auth_events expansion (session_management.md)*
*Final. No open questions. Implementation reference.*

---

## Architecture

Three independent logging systems. No mixing.

```
audit_logs    → AI and security events (unchanged)
admin_events  → user and admin actions
auth_events   → authentication tracking (expanded — see session_management.md)
```

Reference: `docs/internal/session_management.md` covers the full auth_events expansion
(logout, token_refresh, session_expired), session lifecycle, inactivity timeout, and
frontend session hardening. This document covers user management only — auth_events
base schema and login/logout logging model.

User identity model:

```
API key → system identity (gateway, applications)
JWT     → user identity (dashboard)

Do not mix these.
```

---

## Roles

```
ADMIN     → full tenant access, user management
DEVELOPER → dept-scoped, operational access
VIEWER    → dept-scoped, read-only
```

Rules:

- ADMIN cannot deactivate themselves
- System must prevent removal of last ADMIN
- Backend enforces all rules — not the UI
- All role checks centralized — no scattered logic

Future roles (not in v1):

```
OWNER           → single per tenant, cannot be deleted, transfer only
platform:*      → platform layer for SaaS (not in v1)
```

---

## Users Table

```sql
id                    UUID PRIMARY KEY
email                 VARCHAR UNIQUE
password_hash         TEXT
role                  VARCHAR
tenant_id             UUID NOT NULL
dept_id               UUID NULL        -- NULL for ADMIN only
is_active             BOOLEAN DEFAULT true
force_password_change BOOLEAN DEFAULT true
token_version         INT DEFAULT 1
created_at            TIMESTAMP
last_login_at         TIMESTAMP
```

Rules:

- email is an identifier, not verified identity
- always use user_id internally for references
- never use email for authorization logic
- tenant_id must always be present
- dept_id NULL is valid for ADMIN only

### Email uniqueness assumption

Current implementation assumes single-tenant deployment. Email uniqueness is global for v1 — one email across the entire system. This is a known limitation. Future migration to per-tenant uniqueness is documented in the Known Future Migrations section.

### Role and dept_id consistency constraint

Enforced at backend validation and at DB level.

DB constraint:
```sql
CONSTRAINT ck_users_dept_required
CHECK (
    (role = 'ADMIN' AND dept_id IS NULL)
    OR
    (role != 'ADMIN' AND dept_id IS NOT NULL)
)
```

This enforces both directions:
- role = ADMIN → dept_id MUST be NULL
- role != ADMIN → dept_id MUST NOT be NULL

The previous constraint only enforced the second condition. Both directions must be enforced.

Backend validation mirrors the DB constraint and returns 400 VALIDATION_ERROR on violation before the DB write occurs.

### PATCH final state validation

PATCH allows multiple fields in a single request. Validation must be performed on the final state after applying all provided fields — not on individual fields independently.

Example:
```
PATCH { "role": "ADMIN", "dept_id": "uuid" }
→ final state: role = ADMIN, dept_id = uuid
→ invalid — must reject with 400
```

Do not validate role and dept_id separately. Compute final state first, then validate.

### dept_id tenant integrity

dept_id must belong to the same tenant_id as the user.

Enforced in UserRepository.create() and update() by querying:
```sql
SELECT id FROM departments WHERE id = dept_id AND tenant_id = tenant_id
```

Applies on user creation and every PATCH that changes dept_id. Violation returns 400 VALIDATION_ERROR.

---

## JWT Scope Fields

JWT access token must include all scope fields for identity enforcement:

```json
{
  "sub":       "user-uuid",
  "type":      "access",
  "ver":       1,
  "role":      "DEVELOPER",
  "tenant_id": "tenant-uuid",
  "dept_id":   "dept-uuid or null",
  "aud":       "wrapsec-dashboard"
}
```

All four fields — user_id (sub), tenant_id, dept_id, role — must be present in every JWT. Missing any field returns 401 on decode.

---

## API

### Create user

```
POST /v1/admin/users
Auth: JWT + ADMIN
```

Request:
```json
{
  "email":    "user@example.com",
  "password": "TempPassword1!",
  "role":     "DEVELOPER",
  "dept_id":  "uuid"
}
```

Behavior:
- validate role + dept_id consistency (final state)
- validate dept_id belongs to same tenant
- force_password_change = true always
- token_version = 1
- insert admin_event: user_created

---

### List users

```
GET /v1/admin/users
Auth: JWT + ADMIN
```

- filtered by tenant_id always
- never exposes users across tenants

---

### Get user

```
GET /v1/admin/users/{id}
Auth: JWT + ADMIN
```

- returns 404 if user belongs to different tenant

---

### Update user

```
PATCH /v1/admin/users/{id}
Auth: JWT + ADMIN
```

Allowed fields:
```json
{
  "role":      "VIEWER",
  "dept_id":   "uuid",
  "is_active": false
}
```

All fields optional. Only provided fields updated.

Validation order:
1. Load current user state from DB
2. Apply provided fields to produce final state
3. Validate final state (role + dept_id consistency, dept_id tenant integrity)
4. Reject with 400 if invalid — before any DB write
5. Perform DB update
6. Commit
7. Insert admin_event

Validations on update:
- final state role + dept_id must satisfy consistency constraint
- if dept_id changes, new dept_id must belong to same tenant
- admin cannot deactivate themselves
- cannot remove last ADMIN

Behavior by field:

| Field | token_version | admin_event |
|---|---|---|
| role | increment | role_changed |
| dept_id | increment | dept_changed |
| is_active = false | increment | user_deactivated |
| is_active = true | no change | user_reactivated |

Note: `user_updated` is not used. Every update emits a specific action. If a single PATCH changes both role and dept_id, emit both role_changed and dept_changed as separate admin_event rows.

---

### Reset password

```
POST /v1/admin/users/{id}/reset-password
Auth: JWT + ADMIN
```

Request:
```json
{"new_password": "TempPassword1!"}
```

Behavior:
- force_password_change = true
- token_version++
- insert admin_event: password_reset

---

## Token Version Rules

Increment on:
- password_reset
- role_changed
- dept_changed
- user_deactivated

Do NOT increment on:
- user_reactivated (no active sessions to revoke — already cleared on deactivation)

---

## admin_events Table

```sql
id             UUID PRIMARY KEY
tenant_id      UUID NOT NULL
dept_id        UUID NULL
actor_user_id  UUID NOT NULL
target_user_id UUID NULL
action         VARCHAR NOT NULL    -- enum controlled
metadata       JSONB NULL
ip_address     VARCHAR NULL
user_agent     VARCHAR NULL
created_at     TIMESTAMP NOT NULL DEFAULT NOW()
```

Indexes:
```sql
CREATE INDEX idx_admin_events_tenant_time ON admin_events (tenant_id, created_at DESC);
CREATE INDEX idx_admin_events_actor       ON admin_events (actor_user_id);
CREATE INDEX idx_admin_events_target      ON admin_events (target_user_id);
CREATE INDEX idx_admin_events_dept        ON admin_events (dept_id);
```

### dept_id rules

Tenant-scoped actions — dept_id = NULL:
- department creation
- tenant-level setting changes

Dept-scoped actions — dept_id required:
- user_created
- user_deactivated
- user_reactivated
- password_reset
- role_changed
- dept_changed

For all dept-scoped actions, dept_id = target user's dept_id **after** the update is applied.

For dept_changed specifically:
- admin_events.dept_id = new_dept_id (the dept_id after the change)
- metadata must contain both old and new values:

```json
{"old_dept_id": "uuid-before", "new_dept_id": "uuid-after"}
```

Never log old_dept_id as the row's dept_id. The row always reflects final state.

### Action enum

```
user_created
user_deactivated
user_reactivated
password_reset
role_changed
dept_changed
```

`user_updated` is intentionally excluded. Every update emits a specific action. Free-form strings not allowed — must be enum-controlled in code.

### Metadata rules

Keys must be consistent across all events of the same action type. Do not use dynamic or inconsistent key naming — inconsistent keys break future analytics queries.

Per action:

| Action | metadata keys |
|---|---|
| role_changed | old_role, new_role |
| dept_changed | old_dept_id, new_dept_id |
| password_reset | (none required) |
| user_created | role, dept_id |
| user_deactivated | (none required) |
| user_reactivated | (none required) |

Prohibited in all metadata:
- passwords
- tokens
- secrets
- any credential

### Logging model

admin_events are synchronous and part of the request lifecycle — logged post-commit within the same request:

```
1. perform database update
2. commit transaction
3. insert admin_event (same request, post-commit)
4. if logging fails → log internally, do not fail request
```

admin_events use the same DB session as the request. Best-effort — main operation succeeds regardless of logging outcome.

---

## auth_events Table

```sql
id             UUID PRIMARY KEY
tenant_id      UUID NULL           -- NULL when user not found
user_id        UUID NULL           -- NULL when user not found
action         VARCHAR NOT NULL    -- enum controlled
success        BOOLEAN NOT NULL
failure_reason VARCHAR NULL
ip_address     VARCHAR NULL
user_agent     VARCHAR NULL
created_at     TIMESTAMP NOT NULL DEFAULT NOW()
```

Indexes:
```sql
CREATE INDEX idx_auth_events_tenant_time ON auth_events (tenant_id, created_at DESC);
CREATE INDEX idx_auth_events_user        ON auth_events (user_id);
CREATE INDEX idx_auth_events_success     ON auth_events (success);
CREATE INDEX idx_auth_events_ip          ON auth_events (ip_address);
```

`idx_auth_events_ip` enables future brute-force detection and suspicious login pattern analysis without schema changes.

### tenant_id rules

| Scenario | tenant_id | user_id |
|---|---|---|
| Login success | user's tenant_id | user's id |
| Login failure — wrong password | user's tenant_id | user's id |
| Login failure — account inactive | user's tenant_id | user's id |
| Login failure — user not found | NULL | NULL |
| Logout | user's tenant_id | user's id |
| Token refresh success | user's tenant_id | user's id |
| Token refresh failed — token not found | NULL | NULL |
| Session expired — token expired | extracted from payload if possible, else NULL | extracted if possible, else NULL |
| Session expired — token invalid | NULL | NULL |

**Context extraction for session_expired:**
Even on invalid/expired tokens, middleware attempts `jwt.decode(token, options={"verify_exp": False})` to extract `sub` and `tenant_id` from payload. If extraction fails, log with NULL — never skip the event.

Prefer NULL over incorrect attribution. Never resolve a fake tenant_id.

### Action enum

```
login_success          — login succeeded
login_failed           — login failed (see failure_reason)
logout                 — user logged out (see failure_reason for logout reason)
token_refresh_success  — refresh token rotated, new access token issued
token_refresh_failed   — refresh attempt failed (see failure_reason)
session_expired        — JWT rejected by middleware (expired or invalid)
```

**Logging ownership — one owner per event, never duplicated:**

| Action | Owner | Notes |
|---|---|---|
| `login_success` | `services/auth/service.py :: login()` | |
| `login_failed` | `services/auth/service.py :: login()` | |
| `logout` | `services/auth/service.py :: logout()` | failure_reason = logout reason |
| `token_refresh_success` | `services/auth/service.py :: refresh()` | |
| `token_refresh_failed` | `services/auth/service.py :: refresh()` | |
| `session_expired` | `api/v1/middleware/auth.py` | NOT logged for /v1/auth/refresh path |

Middleware does NOT log for `/v1/auth/refresh` — refresh service owns that logging.
Middleware does NOT log when no token is present (health checks, unauthenticated access — expected noise).

### failure_reason enum

```
invalid_password    — wrong password supplied
user_not_found      — email not registered
account_disabled    — API error code returned to client when is_active = false
account_inactive    — auth_events internal reason when is_active = false
token_expired       — JWT exp claim in the past (ExpiredSignatureError)
token_invalid       — malformed or tampered JWT (InvalidTokenError, not expired)
inactivity          — 15 min client-side inactivity timer triggered logout
manual              — user clicked logout button
expired             — user acknowledged session expiry
refresh_failed      — refresh token not found, revoked, or expired
session_invalidated — token_version mismatch (password change, role change, deactivation)
```

**Critical distinction:**
- `account_inactive` is the auth_events `failure_reason` value stored in DB
- `ACCOUNT_DISABLED` is the API error code returned to the client
- These are intentionally different — `ACCOUNT_INACTIVE` never appears in API responses

**Critical distinction (token failures):**
- `token_expired` — catch `ExpiredSignatureError` (subclass of `InvalidTokenError`)
- `token_invalid` — catch `InvalidTokenError` (everything else: tampered, malformed)
- `ExpiredSignatureError` MUST be caught before `InvalidTokenError` — order is mandatory

### Logging model

auth_events are non-blocking and must not delay the response under any condition.

Implementation:

```
1. complete auth operation
2. return response to client
3. insert auth_event via NullPool session (separate from request session)
4. if logging fails → log to Python logger, do not retry, do not affect response
```

auth_events must NOT use the same session as the request. Always use a separate NullPool session.

**NullPool session pattern — mandatory:**
```python
session = None
engine  = None
try:
    engine  = create_async_engine(database_url, poolclass=NullPool)
    session = async_sessionmaker(bind=engine)()
    await repo.insert(...)
    await session.commit()
except Exception as e:
    logger.error("auth_event logging failed: %s", e)
finally:
    if session: await session.close()   # MANDATORY — NullPool does not pool
    if engine:  await engine.dispose()
```

The `finally` block is mandatory. NullPool opens a real connection per session — unclosed sessions leak connections under load.

**Dual logging rule:**
Every auth_event DB write must have a matching Python log line written in the same function:
```python
logger.info("auth_event action=%s user_id=%s reason=%s", action, user_id, reason)
```
DB write = history. App log = real-time debugging. Never split them.

### Existing logger

`logging.getLogger("wrapsec.auth")` logs all auth events to stdout/file for real-time monitoring. auth_events adds structured DB history. Both coexist intentionally — do not remove the existing logger.

Log levels:
- `login_success`, `token_refresh_success`, `logout` → `logger.info`
- `login_failed`, `token_refresh_failed`, `session_expired` → `logger.warning`

### Future usage (no schema change required)

auth_events supports without modification:
- brute-force detection via ip_address index
- rate limiting by login origin
- security analytics on failure patterns
- alerting on account_inactive or account_disabled attempts

---

## Query Enforcement

All queries enforce tenant_id and dept_id in application code. Role-based filtering is never done via SQL role comparison.

```python
# Correct pattern — application layer enforcement
query = base.where(table.tenant_id == current_user.tenant_id)
if not current_user.is_admin:
    query = query.where(table.dept_id == current_user.dept_id)
```

Rules:
- tenant_id always from authenticated identity (request.state), never from request body
- dept_id always from authenticated identity (request.state), never from request body
- is_admin derived from role in request.state, set by middleware

---

## Security Rules

- only ADMIN can access user management APIs
- admin cannot deactivate themselves
- system must prevent removal of last ADMIN
- backend enforces force_password_change (middleware, not UI)
- all session invalidation uses token_version
- dept_id must belong to same tenant on every create and update
- role and dept_id consistency enforced on final state, not individual fields

---

## Dashboard — User Management UI

### /users page (ADMIN only)

Table columns:
- Email
- Role
- Department
- Status (Active / Inactive)
- Last Login
- Actions

Actions per row:
- Edit role
- Change department
- Reset password
- Deactivate / Reactivate

Create user modal:
- Email
- Temporary password
- Role
- Department

No advanced filtering in v1.

### Nav avatar (all roles)

- Current user email and role
- Change password link → /profile
- Logout

### /profile page (all roles)

- Change own password
- View own role and department

---

## User Lifecycle

```
1. Bootstrap
   First startup → bootstrap_admin() creates first ADMIN
   force_password_change = true
   Credentials from .env

2. Admin creates user
   POST /v1/admin/users
   force_password_change = true always
   Credentials shared out-of-band

3. First login
   force_password_change detected → redirect /change-password
   User sets password → all sessions cleared → re-login required

4. Active state
   User operates within role and dept scope

5. Admin resets password
   force_password_change = true
   token_version++
   User must change password on next login

6. Deactivation
   is_active = false
   token_version++
   All sessions revoked immediately
   User cannot log in

7. Reactivation
   is_active = true
   No token_version change (no sessions to revoke)
   User must log in fresh
```

---

## Breaking Changes from Existing Implementation

| Change | Files affected |
|---|---|
| PUT → PATCH on /v1/admin/users/{id} | admin/users.py, router.py, api.ts, tests, api.md |
| DB constraint updated (both directions) | migration |
| New admin_events table | migration, models.py, new repository |
| New auth_events table | migration, models.py, new repository |
| auth logging in service.py | background task, separate DB session |

---

## What Not to Build in v1

- email verification
- invitation system
- SSO or external identity providers
- custom roles or permission engine
- user_updated as a catch-all audit action
- advanced audit UI
- multi-tenant onboarding
- billing or tenant switching
- per-session revocation UI
- suspicious login detection (schema supports it, no implementation yet)

---

## Known Future Migrations

- email uniqueness changes from global to per-tenant scope
- OWNER role introduction
- invitation system
- permission engine replacing has_role() guards
- platform layer roles for SaaS
- auth_events UI and analytics
- SCIM provisioning for enterprise

These changes do not require redesign if current rules are followed.

---

## Implementation Order

```
Step 1  — DB migration:
            admin_events table
            auth_events table (tenant_id nullable, ip_address index)
            update ck_users_dept_required constraint (both directions)

Step 2  — domain/enums.py:
            AdminEventAction enum
            AuthEventAction enum
            AuthFailureReason enum (includes account_inactive)

Step 3  — db/models.py:
            AdminEventModel
            AuthEventModel

Step 4  — db/repositories/:
            admin_event.py
            auth_event.py

Step 5  — api/v1/endpoints/admin/users.py:
            PUT → PATCH
            final state validation (role + dept_id combined)
            dept_id tenant integrity validation
            self-deactivation guard
            admin_events logging (post-commit, same session)
            dept_changed: log new_dept_id as row dept_id, old+new in metadata

Step 6  — services/auth/service.py:
            auth_events logging via BackgroundTasks or separate session
            account_inactive failure_reason on is_active = false
            must not delay login response

Step 7  — api/v1/router.py:
            PATCH registration

Step 8  — dashboard/lib/api.ts:
            PUT → PATCH for updateUser

Step 9  — dashboard /users page

Step 10 — dashboard nav avatar

Step 11 — dashboard /profile page

Step 12 — tests:
            unit: admin_event repo, auth_event repo, final state validation
            integration: PATCH semantics, logging, self-deactivation,
                         last-admin protection, dept constraint

Step 13 — docs:
            api.md (PATCH, new tables, account_inactive)
            changelog
```

---

*Version 1.3 — Updated May 2026. auth_events expanded (session_management.md). No open questions.*
