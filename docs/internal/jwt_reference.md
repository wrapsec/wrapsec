# WrapSec — JWT & Authentication Reference

**Version 1.0 — April 2026**
**Authoritative Reference for JWT, Session Management, and User Identity**

*Consolidates JWT_implementation_plan.md, user_management.md, and session_management.md*
*Canonical source of truth for all authentication architecture decisions.*

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Threat Model & Security Assumptions](#threat-model--security-assumptions)
3. [Architecture Overview](#architecture-overview)
4. [JWT Token Design](#jwt-token-design)
5. [Session Lifecycle](#session-lifecycle)
6. [Tenant & Isolation Model](#tenant--isolation-model)
7. [User Management](#user-management)
8. [Authentication Flows](#authentication-flows)
9. [Session Invalidation](#session-invalidation)
10. [Auth Event Logging](#auth-event-logging)
11. [Error Handling](#error-handling)
12. [Testing Strategy](#testing-strategy)
13. [Common Patterns & Anti-Patterns](#common-patterns--anti-patterns)
14. [Deployment Checklist](#deployment-checklist)
15. [Appendix: Enums & Constants](#appendix-enums--constants)

---

## Executive Summary

WrapSec implements a dual-identity authentication system:

- **API Key** (x-api-key header) — machine identity for programmatic access
- **JWT Bearer** (Authorization: Bearer token) — human identity for dashboard users

Both identities coexist securely with absolute header precedence: **x-api-key always wins if present**.

### Key Security Decisions

| Decision | Rationale | Enforced At |
|---|---|---|
| Four-layer tenant enforcement | Defense in depth; tenant is outermost security boundary | DB schema, JWT, middleware, principal builder |
| Token versioning (ver claim) | Immediate session invalidation without Redis | Middleware on every access |
| Refresh token hashing (SHA-256) | DB breach cannot yield working refresh tokens | Token service + refresh flow |
| httpOnly cookies | Prevents XSS token theft | Browser, not JavaScript readable |
| Header precedence rule | Unambiguous, no authorization bypass | Middleware dispatch order |
| Single auth event ownership | No duplicate logging, single source of truth | Service layer only |
| NullPool in tests | Prevents asyncpg pool poisoning across test loops | pytest.ini + middleware |
| Logout reason normalization | Never return 400 for invalid input | Endpoint + service layer |

---

## Threat Model & Security Assumptions

### Threats We Defend Against

| Threat | Defense | Requirement |
|---|---|---|
| Token theft via XSS | httpOnly cookies + Secure flag | Browser SameSite=Strict |
| Session replay after password change | Token version increment | Immediate in middleware |
| Cross-site request forgery | SameSite=Strict cookie attribute | Nginx/app enforces |
| Token forgery | HMAC-SHA256 signature | Secret key never exposed |
| Token reuse across services | Audience claim (aud=wrapsec-dashboard) | JWT decode validates |
| Cross-tenant data access | Four-layer tenant enforcement | Never from request body |
| Refresh token compromise | Token hashing (SHA-256) in DB | Raw token never stored |
| Account takeover via old session | Token version mismatch → 401 | Increment on password/role/dept change |
| Brute force login | Account lockout (5 failures, 15 min) | Redis with exponential backoff |
| Timing attacks on auth | Dummy hash verification, generic errors | Prevent email enumeration |
| Connection pool poisoning in tests | NullPool engine in TESTING mode | Each test gets fresh connection |

### Threats Out of Scope

- IP-based session binding (breaks VPN, corporate proxies)
- Device fingerprinting (too many false positives)
- Behavioral biometrics (not standard for dashboards)
- Per-session revocation table (token_version sufficient in v1)

---

## Architecture Overview

### Identity Model

```
┌─────────────────────────────────────────────────────────────┐
│ Request Headers                                             │
├─────────────────────────────────────────────────────────────┤
│ x-api-key: wsk_live_... OR ADMIN_API_KEY                     │
│ Authorization: Bearer eyJhbGciOiJIUzI1NiIs...                │
└─────────────────────────────────────────────────────────────┘
                           │
                ┌──────────┴──────────┐
                │                     │
        ┌───────▼────────┐   ┌────────▼────────┐
        │ API Key Path   │   │ JWT Path        │
        ├────────────────┤   ├─────────────────┤
        │ Machine ID     │   │ Human ID        │
        │ (app/service)  │   │ (dashboard user)│
        └────────┬───────┘   └────────┬────────┘
                 │                     │
                 └──────────┬──────────┘
                            │
                ┌───────────▼──────────┐
                │  request.state       │
                ├──────────────────────┤
                │ tenant_id (always)   │
                │ dept_id (if scoped)  │
                │ user_id (JWT only)   │
                │ is_admin (boolean)   │
                │ principal_type       │
                └──────────────────────┘
```

### Isolation Boundaries

```
Tenant
  ├─ Department A
  │   ├─ User (DEVELOPER)
  │   ├─ Application
  │   └─ Audit logs
  │
  ├─ Department B
  │   └─ User (VIEWER)
  │
  └─ User (ADMIN)  [no dept_id, sees all]

Rules:
  - ADMIN: dept_id = NULL → sees entire tenant
  - DEVELOPER/VIEWER: dept_id = required → sees only own dept
  - Email: unique globally (v1 limitation)
  - Token: scoped to user_id + tenant_id + token_version
```

---

## JWT Token Design

### Access Token Payload (30 min lifetime)

```json
{
  "sub":       "550e8400-e29b-41d4-a716-446655440000",  // User UUID string
  "type":      "access",                                  // Reject refresh as access
  "ver":       2,                                         // Token version (session invalidation)
  "role":      "DEVELOPER",                               // ADMIN | DEVELOPER | VIEWER
  "tenant_id": "42a083bf-5cad-4b65-84d1-b81def88c9f3",  // Tenant scoping
  "dept_id":   "4111d663-47e3-4632-bf92-46a6b24a92f8",  // Department scoping (null for ADMIN)
  "aud":       "wrapsec-dashboard",                       // Cross-service reuse prevention
  "iat":       1714000000,                                // Issued at (standard)
  "exp":       1714001800                                 // Expiry (30 min)
}
```

### Why These Claims?

| Claim | Purpose | Validated | Required |
|---|---|---|---|
| `sub` | User ID — standard JWT subject claim | Middleware loads user from DB | Yes |
| `type` | Token type ("access" vs "refresh") | decode_access_token() checks | Yes |
| `ver` | Token version — session invalidation flag | Middleware compares to user.token_version | Yes |
| `role` | RBAC enforcement | Middleware sets request.state.is_admin | Yes |
| `tenant_id` | Tenant isolation | Cross-validated against DB tenant_id | Yes |
| `dept_id` | Department scoping | Stored in request.state for filtering | No (null for ADMIN) |
| `aud` | Prevents token reuse across services | PyJWT validates against expected audience | Yes |
| `iat`/`exp` | Standard JWT timing claims | PyJWT validates automatically | Yes |

### Why NOT These Claims?

| Claim | Reason for Exclusion |
|---|---|
| `email` | Unnecessary exposure in logs; user_id is canonical identifier |
| `permissions` | Not enforced in v1; use `role` + `has_role()` checks only |
| `session_id` | Redundant; token_version serves this purpose |
| `device_id` | Out of scope; breaks legitimate access patterns |
| `ip_address` | Changes during session; not part of token state |

### Token Lifecycle

```
1. Login (POST /v1/auth/login)
   ├─ Verify email + password
   ├─ Create access token (JWT)
   ├─ Create refresh token (opaque 32-byte string)
   ├─ Hash refresh token (SHA-256)
   ├─ Store hash in DB
   ├─ Return access token in body
   └─ Set refresh token as httpOnly cookie

2. Access (POST /v1/ai/request, etc.)
   ├─ Middleware validates JWT signature
   ├─ Middleware checks expiry
   ├─ Middleware validates audience
   ├─ Middleware loads user from DB
   ├─ Middleware cross-validates tenant_id
   ├─ Middleware checks token_version match
   └─ Request proceeds

3. Silent Refresh (Frontend timers)
   ├─ POST /v1/auth/refresh (httpOnly cookie sent automatically)
   ├─ Service validates refresh token hash against DB
   ├─ Service checks token_version (session invalidation check)
   ├─ Service revokes old refresh token
   ├─ Service creates new access + refresh tokens
   ├─ Returns new access token in body
   └─ Sets new refresh token as httpOnly cookie

4. Session Invalidation (Password change, role change, deactivation)
   ├─ Increment user.token_version
   ├─ Revoke all refresh_tokens for user
   ├─ Commit atomically
   ├─ Next access with old token → ver mismatch → 401
   └─ User must re-login

5. Logout (POST /v1/auth/logout)
   ├─ Load refresh token from httpOnly cookie
   ├─ Hash and revoke in DB
   ├─ Clear httpOnly cookie in response
   ├─ Access token expires naturally (max 30 min residual)
   └─ Next request without token → 401
```

---

## Session Lifecycle

### Duration & Timeouts

| Session Type | Hard Expiry | Inactivity Timeout | Refresh Available |
|---|---|---|---|
| JWT (access token) | 30 min (server-enforced) | 15 min (client-enforced in v1) | Yes (silent refresh) |
| Refresh token | 30 days (rotated on use) | N/A | Yes (creates new access) |
| API key | No server expiry | 15 min (client-enforced in v1) | No (re-authenticate) |

### Inactivity Timeout Flow

```
User active (mouse, keyboard, touch, scroll, tab focus)
    ├─ Reset inactivity timer to 15 min
    └─ Clear "session expiring soon" warning

Timer reaches 2 min warning threshold
    ├─ Show blocking modal: "You will be logged out in X:XX"
    ├─ [ Stay logged in ]  → resetTimer()
    └─ [ Log out now ]     → logout("manual")

Timer reaches 15 min (or expires)
    ├─ logout("inactivity") automatically
    ├─ Set isLoggingOut = true
    ├─ Clear refresh token cookie
    ├─ Redirect to /login
    └─ Display "Session expired due to inactivity"
```

### Silent Refresh Flow

```
Frontend detects 401 Unauthorized
    ├─ Check: NOT refreshing refresh endpoint (prevent loop)
    ├─ Check: isLoggingOut flag not set (prevent race)
    ├─ POST /v1/auth/refresh (cookie sent automatically)
    │
    ├─ SUCCESS: New token issued
    │   ├─ Update memory state with new access token
    │   ├─ Retry original request once
    │   └─ Continue seamlessly
    │
    └─ FAIL: Refresh rejected
        ├─ Set isLoggingOut = true (prevent concurrent refresh)
        ├─ Clear both cookies
        ├─ Redirect to /login
        └─ Display error message

Safety guards:
  ✓ Guard 1: Never refresh the refresh endpoint itself
  ✓ Guard 2: Never retry more than once (prevent infinite loops)
  ✓ Guard 3: isLoggingOut flag prevents race between logout + refresh
```

---

## Tenant & Isolation Model

### Tenant as Security Boundary

**Absolute rule:** `tenant_id` is NEVER derived from request body, query params, or user input.

```python
# ✅ CORRECT
tenant_id = request.state.tenant_id  # from authenticated identity only

# ❌ WRONG — Security violation
tenant_id = request.query_params.get("tenant_id")
tenant_id = request.json().get("tenant_id")
tenant_id = request.headers.get("x-tenant-id")
```

### Four-Layer Tenant Enforcement

**Layer 1 — Database Schema**
```sql
-- All user-facing tables
CREATE TABLE users (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    ...
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    ...
);

-- Constraint: tenant_id cannot be NULL
ALTER TABLE users ADD CONSTRAINT ck_tenant_not_null
    CHECK (tenant_id IS NOT NULL);
```

**Layer 2 — JWT Validation**
```python
def decode_access_token(token: str) -> dict:
    payload = jwt.decode(
        token,
        settings.secret_key,
        algorithms=[settings.jwt_algorithm],
        audience="wrapsec-dashboard"
    )
    
    # All these must be present and non-null
    required = ["sub", "tenant_id", "role", "ver"]
    for field in required:
        if payload.get(field) is None:
            raise InvalidTokenError("Missing required claim")
    
    return payload
```

**Layer 3 — Middleware Cross-Validation**
```python
async def _authenticate_jwt(self, token: str, request: Request, call_next):
    payload = decode_access_token(token)
    user = await UserRepository(db).get_by_id(UUID(payload["sub"]))
    
    if not user:
        return 401  # User not found
    
    if not user.tenant_id:
        return 401  # User tenant is null (schema violation)
    
    # CRITICAL: Cross-validate JWT tenant vs DB tenant
    if str(user.tenant_id) != payload["tenant_id"]:
        logger.error("SECURITY: Tenant mismatch in JWT")
        return 401  # Session hijacking attempt or token tampering
    
    request.state.tenant_id = str(user.tenant_id)
    return await call_next(request)
```

**Layer 4 — Principal Builder**
```python
def build_principal_from_user(user: UserModel) -> Principal:
    if not user.tenant_id:
        raise ValueError("User has no tenant_id (schema violation)")
    
    return Principal(
        id=f"user:{user.id}",
        tenant_id=str(user.tenant_id),  # UUID → string at boundary
        dept_id=str(user.dept_id) if user.dept_id else None,
        ...
    )
```

### Department Scoping Pattern

**Mandatory everywhere:** Never query without tenant + optional dept filter.

```python
# ✅ CORRECT — Tenant + optional dept
base_query = table.where(table.tenant_id == request.state.tenant_id)
if request.state.dept_id:  # None for ADMIN, UUID string for DEVELOPER/VIEWER
    base_query = base_query.where(table.dept_id == UUID(request.state.dept_id))

# ❌ WRONG — Tenant only, forgets dept scoping
base_query = table.where(table.tenant_id == request.state.tenant_id)
# DEVELOPER can see all depts in tenant (privilege escalation)

# ❌ WRONG — Uses request body for scoping
dept_id = request.json().get("dept_id")  # Attacker can change this
base_query = table.where(table.dept_id == dept_id)
```

### ADMIN NULL dept Rule

```python
# ADMIN users always have dept_id = NULL
if user.role == "ADMIN":
    assert user.dept_id is None  # Schema constraint enforces

# In queries, NULL dept means "all depts"
if request.state.dept_id:
    query = query.where(table.dept_id == request.state.dept_id)
# If dept_id is None (ADMIN), this filter is skipped — sees all rows
```

### Email Uniqueness (v1 Limitation)

**Current (v1):** Email is globally unique across all tenants.
```sql
CREATE UNIQUE INDEX ux_users_email_lower ON users(LOWER(email));
```

**Implication:** Cannot have `alice@example.com` in both Tenant A and Tenant B.

**Planned (v2+):** Per-tenant email uniqueness.
```sql
CREATE UNIQUE INDEX ux_users_email_tenant ON users(tenant_id, LOWER(email));
```

---

## User Management

### User Lifecycle

```
1. BOOTSTRAP
   │ First startup → bootstrap_admin()
   │ ├─ Create user with ADMIN_EMAIL, ADMIN_PASSWORD from .env
   │ ├─ force_password_change = true
   │ └─ token_version = 1
   │
   └─ SAFETY: If default password detected in production
      └─ Log ERROR + print to stderr

2. ADMIN CREATES USER
   │ POST /v1/admin/users
   │ ├─ Admin provides email, temp password, role, dept_id
   │ ├─ Validate role + dept_id consistency (both directions)
   │ ├─ Validate dept_id belongs to same tenant
   │ ├─ Create user
   │ ├─ force_password_change = true always
   │ ├─ token_version = 1
   │ └─ Log admin_event: user_created

3. FIRST LOGIN
   │ POST /v1/auth/login
   │ ├─ Middleware detects force_password_change = true
   │ ├─ Reject all endpoints except:
   │ │  ├─ /v1/auth/change-password
   │ │  ├─ /v1/auth/logout
   │ │  └─ /v1/auth/me
   │ └─ Force password change before accessing anything

4. CHANGE PASSWORD
   │ POST /v1/auth/change-password
   │ ├─ Verify current password correct
   │ ├─ Validate new password strength (≥8 chars, upper, lower, digit)
   │ ├─ Hash new password
   │ ├─ Increment token_version
   │ ├─ Revoke ALL refresh tokens
   │ ├─ Set force_password_change = false
   │ ├─ Log admin_event: password_changed
   │ └─ User must re-login (sessions invalidated)

5. ACTIVE STATE
   │ User operates within role + dept scope
   │ ├─ API requests checked against tenant_id + dept_id
   │ ├─ ADMIN sees all depts
   │ └─ DEVELOPER/VIEWER sees only own dept

6. ADMIN RESETS PASSWORD
   │ POST /v1/admin/users/{id}/reset-password
   │ ├─ Admin provides temporary password
   │ ├─ Hash and store
   │ ├─ Increment token_version
   │ ├─ Revoke ALL refresh tokens
   │ ├─ Set force_password_change = true
   │ ├─ Log admin_event: password_reset
   │ └─ User must change password on next login

7. ADMIN UPDATES ROLE/DEPT
   │ PATCH /v1/admin/users/{id}
   │ ├─ Validate final state (role + dept consistency)
   │ ├─ If role changes: increment token_version, log role_changed
   │ ├─ If dept changes: increment token_version, log dept_changed (with old+new in metadata)
   │ ├─ Revoke all sessions on change
   │ └─ User must re-login

8. DEACTIVATION
   │ PATCH /v1/admin/users/{id} { is_active: false }
   │ ├─ Guard: Admin cannot deactivate themselves
   │ ├─ Guard: Cannot deactivate last active ADMIN
   │ ├─ Increment token_version
   │ ├─ Revoke ALL refresh tokens
   │ ├─ Set force_password_change = true (for reactivation)
   │ ├─ Log admin_event: user_deactivated
   │ └─ User cannot login (is_active check in middleware)

9. REACTIVATION
   │ PATCH /v1/admin/users/{id} { is_active: true }
   │ ├─ NO token_version change (no active sessions to revoke)
   │ ├─ Set force_password_change = true
   │ ├─ Log admin_event: user_reactivated
   │ └─ User must change password on next login
```

### Roles & Permissions

```
ADMIN
  ├─ dept_id = NULL (sees all data)
  ├─ Full user management (create, read, update, delete users)
  ├─ Full settings management (thresholds, layers, LLM, retention)
  ├─ Full tenant configuration
  ├─ Full department management
  ├─ Full application management
  └─ All audit access

DEVELOPER
  ├─ dept_id = required (scoped to one dept)
  ├─ Read own dept data
  ├─ Read own dept audit logs
  ├─ Cannot create/manage users
  ├─ Cannot change settings
  ├─ Cannot change global configuration
  └─ Limited application access (own dept only)

VIEWER
  ├─ dept_id = required (scoped to one dept)
  ├─ Read-only access to own dept data
  ├─ Read own dept audit logs
  ├─ Cannot create/manage users
  ├─ Cannot change settings
  ├─ Cannot change configuration
  └─ No write access to any resource

Future (v2+):
  OWNER        — single per tenant, cannot be deleted (transfer only)
  platform:*   — platform layer for SaaS multi-tenancy
```

### Password Requirements

```python
def validate_password_strength(password: str) -> None:
    """Raises ValueError if invalid."""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
```

### Account Lockout

```
Failed login attempt
    ├─ Record failure in Redis: auth:failed:{email}
    ├─ Increment counter
    │
    └─ Counter reaches 5
        ├─ Set auth:locked:{email} with 15 min TTL
        ├─ Return 429 ACCOUNT_LOCKED with retry_after seconds
        └─ Log warning: "auth_event LOGIN_LOCKED email=... remaining_secs=..."

Successful login
    └─ Clear auth:failed:{email} from Redis

After lockout expires
    └─ auth:locked:{email} TTL expires, user can login again
```

---

## Authentication Flows

### Login Flow (POST /v1/auth/login)

```
Request
├─ Email (RFC 5322 validated by Pydantic)
└─ Password

Processing
├─ Normalize email: lowercase + trim
├─ Check account lockout (Redis)
│  └─ If locked: return 429 + retry_after
├─ Load user by email (case-insensitive index)
│  └─ If not found: verify_dummy() timing equalization
├─ Verify password hash (bcrypt)
│  └─ If wrong: record failure, may trigger lockout
├─ Check is_active
│  └─ If false: return 401 ACCOUNT_DISABLED
├─ Clear failure counter
├─ Create access token (JWT, 30 min expiry)
├─ Create refresh token (opaque 32-byte string)
├─ Hash refresh token (SHA-256)
├─ Store hash in refresh_tokens table
├─ Update user.last_login_at
├─ Commit DB transaction
├─ Log: logger.info("auth_event LOGIN_SUCCESS ...")
└─ Log: _log_auth_event(action=login_success, ...)

Response 200
├─ Body:
│  ├─ access_token: JWT string
│  ├─ token_type: "bearer"
│  ├─ expires_in: 1800 (seconds)
│  ├─ force_password_change: boolean
│  └─ user: { id, email, role, dept_id, tenant_id }
└─ Cookie: refresh_token={raw_token}
   ├─ httpOnly: true
   ├─ Secure: true (production only)
   ├─ SameSite: Strict
   ├─ Path: /v1/auth
   └─ Max-Age: 2592000 (30 days)
```

### Refresh Flow (POST /v1/auth/refresh)

```
Request
└─ Cookie: refresh_token={raw_token}

Processing
├─ Hash refresh token (SHA-256)
├─ Load from refresh_tokens by token_hash (SELECT FOR UPDATE for race prevention)
│  └─ If not found: log TOKEN_REFRESH_FAILED, return 401
├─ Load user by user_id from refresh_tokens record
│  └─ If not found or not active: revoke old token, return 401
├─ Check token_version match
│  └─ If mismatch: revoke token, return 401 SESSION_INVALIDATED
├─ Revoke old refresh token
├─ Create new access token
├─ Create new refresh token (opaque 32-byte string)
├─ Hash and store new refresh token
├─ Commit DB transaction
├─ Log: logger.info("auth_event TOKEN_REFRESH_SUCCESS ...")
└─ Log: _log_auth_event(action=token_refresh_success, ...)

Response 200
├─ Body:
│  ├─ access_token: new JWT string
│  ├─ token_type: "bearer"
│  └─ expires_in: 1800
└─ Cookie: refresh_token={new_raw_token}
   └─ [same settings as login]
```

### Logout Flow (POST /v1/auth/logout)

```
Request
├─ Header: Authorization: Bearer {access_token}
├─ Body: { "reason": "manual" | "inactivity" | "expired" }
└─ Cookie: refresh_token={raw_token} (httpOnly, sent automatically by browser)

Processing
├─ Validate JWT (same checks as normal request)
├─ Normalize reason (invalid → "manual", never raise 400)
├─ Hash refresh token from cookie
├─ Revoke in refresh_tokens table
├─ Commit DB transaction
├─ Log: logger.info("auth_event LOGOUT user_id=... reason=...")
└─ Log: _log_auth_event(action=logout, failure_reason=reason, ...)

Response 200
├─ Body: { "message": "Logged out successfully." }
└─ Cookie: refresh_token=""
   ├─ Max-Age: 0 (expires immediately)
   └─ (clears httpOnly cookie from browser)
```

### Change Password Flow (POST /v1/auth/change-password)

```
Request
├─ Header: Authorization: Bearer {access_token}
└─ Body: { "current_password": "...", "new_password": "..." }

Processing
├─ Validate JWT + load user
├─ Verify current_password against user.password_hash
│  └─ If wrong: return 401 INVALID_PASSWORD
├─ Validate new_password strength
│  └─ If weak: return 400 INVALID_REQUEST
├─ Hash new password
├─ Update user:
│  ├─ password_hash = new hash
│  ├─ force_password_change = false
│  └─ token_version++ (atomically)
├─ Revoke ALL refresh tokens for this user
├─ Commit atomically
├─ Log: logger.info("auth_event PASSWORD_CHANGED ...")
└─ logout_all_sessions() called (handled separately)

Response 200
├─ Body: { "message": "Password changed. All sessions invalidated." }
└─ Cookie: refresh_token=""
   └─ (force browser to clear cookie)
```

---

## Session Invalidation

### When Session is Invalidated

| Trigger | Action | Result |
|---|---|---|
| Password changed (user) | token_version++ | Existing tokens rejected with 401 SESSION_INVALIDATED |
| Password reset (admin) | token_version++ | All user tokens rejected immediately |
| Role changed | token_version++ | Access denied (e.g., DEVELOPER → demoted → 401) |
| Department changed | token_version++ | Data access denied (dept mismatch) |
| User deactivated | token_version++ + revoke refresh tokens | Cannot login, cannot use existing tokens |
| User reactivated | NO token_version++ | force_password_change=true, must set new password |
| Logout (manual) | Revoke refresh token only | Access token expires naturally (≤30 min) |
| Token expiry | Natural expiry | Middleware rejects with 401 TOKEN_EXPIRED |
| Account lockout | No invalidation | New login locked for 15 min |

### Implementation Pattern

```python
async def logout_all_sessions(user_id: UUID, db: AsyncSession) -> None:
    """
    Atomic operation:
    1. Increment user.token_version
    2. Revoke all refresh tokens for user
    3. Single commit
    
    Result: all existing JWTs immediately rejected (version mismatch)
    """
    user_repo = UserRepository(db)
    rt_repo = RefreshTokenRepository(db)
    
    new_ver = await user_repo.increment_token_version(user_id)
    revoked = await rt_repo.revoke_all_for_user(user_id)
    await db.commit()  # Single commit — atomicity guaranteed
    
    logger.info(
        "auth_event SESSION_INVALIDATED user_id=%s "
        "new_token_version=%d refresh_tokens_revoked=%d",
        user_id, new_ver, revoked,
    )
```

### Version Mismatch Detection

```python
# In middleware during JWT validation
if payload.get("ver") != user.token_version:
    # Token's version != user's current version
    # → token was issued before invalidation event
    # → reject with 401
    
    logger.warning(
        "auth_event SESSION_INVALIDATED user_id=%s reason=version_mismatch "
        "token_ver=%s user_ver=%s",
        user_id, payload.get("ver"), user.token_version,
    )
    return JSONResponse(
        status_code=401,
        content={"error": {
            "code": "SESSION_INVALIDATED",
            "message": "Session has been invalidated. Please log in again.",
        }},
    )
```

---

## Auth Event Logging

### Logging Ownership (Single Source of Truth)

**Each event type is logged by exactly ONE owner.** Never duplicate.

| Event | Owner | When | Details |
|---|---|---|---|
| `login_success` | `AuthService.login()` | After successful password verification | tenant_id, user_id, ip, user_agent |
| `login_failed` | `AuthService.login()` | Wrong password, user not found, account inactive | tenant_id (if known), user_id (if known), ip, user_agent |
| `logout` | `AuthService.logout()` | User calls logout endpoint or session expires | tenant_id, user_id, failure_reason = logout reason |
| `token_refresh_success` | `AuthService.refresh()` | Refresh token successfully rotated | tenant_id, user_id |
| `token_refresh_failed` | `AuthService.refresh()` | Token not found, version mismatch, user disabled | tenant_id (if resolvable), user_id (if resolvable), failure_reason |
| `session_expired` | `AuthMiddleware._log_session_expired()` | Access token expired or invalid | tenant_id (extracted from token if possible), user_id (if possible), failure_reason = token_expired\|token_invalid\|session_invalidated |

**Critical:** Middleware does NOT log for `/v1/auth/refresh` path — refresh service owns that logging.

```python
# In middleware
SKIP_AUTH_EVENT_LOGGING = {"/v1/auth/refresh"}

if request.url.path in SKIP_AUTH_EVENT_LOGGING:
    pass  # refresh service owns logging
else:
    await _log_session_expired(token, reason, path)
```

### auth_events Table Schema

```sql
CREATE TABLE auth_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NULL,              -- NULL if user not found
    user_id UUID NULL,                -- NULL if user not found
    action VARCHAR(50) NOT NULL,      -- enum: login_success, login_failed, logout, etc.
    success BOOLEAN NOT NULL,         -- true for success, false for failure
    failure_reason VARCHAR(50) NULL,  -- enum: invalid_password, token_expired, etc.
    ip_address VARCHAR(45) NULL,      -- IPv4 or IPv6
    user_agent VARCHAR(512) NULL,     -- Browser/client string
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes for analytics without schema changes
CREATE INDEX idx_auth_events_tenant_time
    ON auth_events(tenant_id, created_at DESC);
CREATE INDEX idx_auth_events_user
    ON auth_events(user_id);
CREATE INDEX idx_auth_events_success
    ON auth_events(success);
CREATE INDEX idx_auth_events_ip
    ON auth_events(ip_address);  -- Future: brute-force detection
```

### admin_events Table Schema

```sql
CREATE TABLE admin_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,              -- Who's being modified (always known)
    dept_id UUID NULL,                    -- Dept-scoped actions only
    actor_user_id UUID NOT NULL,          -- Who did the action
    target_user_id UUID NULL,             -- Who was affected (null for tenant-level actions)
    action VARCHAR(50) NOT NULL,          -- enum: user_created, role_changed, etc.
    metadata JSONB NULL,                  -- Event-specific details (role, dept_id, etc.)
    ip_address VARCHAR(45) NULL,          -- Admin's IP
    user_agent VARCHAR(512) NULL,         -- Admin's browser
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_admin_events_tenant_time
    ON admin_events(tenant_id, created_at DESC);
CREATE INDEX idx_admin_events_actor
    ON admin_events(actor_user_id);
CREATE INDEX idx_admin_events_target
    ON admin_events(target_user_id);
CREATE INDEX idx_admin_events_dept
    ON admin_events(dept_id);
```

### Logging Implementation Pattern

```python
async def _log_auth_event(
    action:         str,
    success:        bool,
    tenant_id:      UUID | None = None,
    user_id:        UUID | None = None,
    failure_reason: str | None = None,
    ip_address:     str | None = None,
    user_agent:     str | None = None,
) -> None:
    """
    Non-blocking background logging using NullPool session.
    
    MANDATORY PATTERN:
    1. Uses separate NullPool engine (not request session)
    2. No-op on failure (exception logged, never raised)
    3. Session ALWAYS closed in finally block
    4. Never delays request response
    
    Usage:
        # In AuthService login() flow
        await _log_auth_event(
            action         = "login_success",
            success        = True,
            tenant_id      = user.tenant_id,
            user_id        = user.id,
            ip_address     = request_ip,
            user_agent     = request_user_agent,
        )
    """
    session = None
    engine = None
    try:
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
        from sqlalchemy.pool import NullPool
        
        # Open fresh connection (NullPool = no pooling)
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        sf = async_sessionmaker(bind=engine, class_=AsyncSession)
        session = sf()
        
        # Insert the event
        repo = AuthEventRepository(session)
        await repo.insert(
            action         = AuthEventAction(action),
            success        = success,
            tenant_id      = tenant_id,
            user_id        = user_id,
            failure_reason = AuthFailureReason(failure_reason) if failure_reason else None,
            ip_address     = ip_address,
            user_agent     = user_agent,
        )
        await session.commit()
        
    except Exception as e:
        # Log error, NEVER propagate
        logger.error("auth_event logging failed action=%s error=%s", action, e)
    finally:
        # MANDATORY: Always close (NullPool = real connection)
        if session:
            await session.close()
        if engine:
            await engine.dispose()
```

### Logging & Monitoring

Every auth_event DB insert has a matching Python log:

```python
# Same moment, same data
logger.info(
    "auth_event action=%s user_id=%s tenant_id=%s success=%s reason=%s",
    action, user_id, tenant_id, success, failure_reason
)
await _log_auth_event(...)
```

**Log Levels:**
- `login_success`, `token_refresh_success`, `logout` → logger.info
- `login_failed`, `token_refresh_failed`, `session_expired` → logger.warning

---

## Error Handling

### HTTP Error Codes

| Code | Meaning | Example |
|---|---|---|
| 200 | Success | Login, refresh, logout |
| 201 | Created | User created |
| 400 | Bad request | Invalid password strength, invalid role |
| 401 | Unauthorized | Invalid credentials, expired token, missing token |
| 403 | Forbidden | Insufficient role, password change required |
| 404 | Not found | User not found |
| 409 | Conflict | Email already exists, duplicate request (idempotency) |
| 429 | Too many requests | Account locked (5 failed attempts) |
| 500 | Server error | Database connection failed |

### Error Response Format

```json
{
  "error": {
    "code":    "UNAUTHORIZED",
    "message": "Missing or invalid credentials",
    "trace_id": "req_01knzhh8..."  // optional ULID
  }
}
```

### Generic vs Specific Messages

**Rule:** Always return generic messages to prevent user enumeration.

```python
# ✅ CORRECT — Generic message, detailed log
try:
    user = await repo.get_by_email(email)
    if not user:
        verify_dummy()  # Timing equalization
        logger.warning("login_failed email=%s reason=user_not_found", email)
        raise AuthenticationError()  # Generic "Invalid credentials"
except:
    return 401 {"error": {"code": "INVALID_CREDENTIALS", "message": "..."}}

# ❌ WRONG — Leaks user existence
if not user:
    return 401 {"error": {"message": "User not found"}}  # Enumeration attack
```

### Exception Types

| Exception | When | HTTP | Message |
|---|---|---|---|
| `AuthenticationError` | Wrong password, user not found, account inactive | 401 | "Invalid credentials" (generic) |
| `AccountLockedException` | 5 failed login attempts | 429 | "Too many failed attempts. Account temporarily locked." + retry_after |
| `AccountDisabledException` | is_active = false | 401 | "Account disabled" |
| `InvalidTokenException` | Token not found, invalid, expired (non-access) | 401 | "Invalid token" |
| `SessionInvalidatedException` | token_version mismatch | 401 | "Session has been invalidated. Please log in again." |

---

## Testing Strategy

### Unit Tests (Services Layer)

**Test coverage:** Password hashing, token creation/validation, lockout, enums.

```python
# tests/unit/services/test_password.py
def test_hash_password_different_each_call():
    """Bcrypt generates different hashes (salt)"""
    hash1 = hash_password("password")
    hash2 = hash_password("password")
    assert hash1 != hash2
    assert verify_password("password", hash1)

def test_verify_dummy_timing():
    """Dummy verification takes ~100ms (same as real bcrypt)"""
    start = time.time()
    verify_dummy()
    elapsed = (time.time() - start) * 1000
    assert 50 < elapsed < 500  # bcrypt timing range

# tests/unit/services/test_token.py
def test_decode_access_token_requires_all_claims():
    """Missing any required claim → InvalidTokenError"""
    # Create token with missing 'ver' claim
    payload = {"sub": "...", "tenant_id": "..."}  # missing 'ver', 'role'
    token = jwt.encode(payload, settings.secret_key, algorithm="HS256")
    
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)

def test_decode_access_token_validates_audience():
    """Wrong audience → InvalidTokenError"""
    # Create token with aud = "wrong-service"
    payload = {"sub": "...", "aud": "wrong-service", ...}
    token = jwt.encode(...)
    
    with pytest.raises(InvalidTokenError):
        decode_access_token(token)

# tests/unit/services/test_lockout.py
def test_account_lockout_after_5_failures():
    """5 failed attempts trigger 15 min lockout"""
    for i in range(5):
        await record_failure("test@example.com")
    
    assert await is_locked("test@example.com")
    remaining = await get_lockout_remaining("test@example.com")
    assert 0 < remaining <= 900
```

### Integration Tests (Full Flows)

**Test coverage:** Login, refresh, logout, session invalidation, RBAC, tenant isolation.

```python
# tests/integration/test_auth_endpoints.py

@pytest.mark.asyncio
async def test_login_success_creates_auth_event():
    """Login success → auth_event row + logger + response"""
    result = await auth_service.login("user@example.com", "password123", db)
    
    assert result.access_token
    assert result.refresh_token
    
    # Check DB
    repo = AuthEventRepository(db)
    events = await repo.list_by_action("login_success", limit=1)
    assert len(events) == 1
    assert events[0].user_id == result.user.id
    assert events[0].success is True

@pytest.mark.asyncio
async def test_token_version_mismatch_rejects():
    """Increment token_version → existing JWT rejected"""
    # 1. Login
    result = await auth_service.login("user@example.com", "password123", db)
    
    # 2. Decode the JWT to get payload
    from services.auth.token import decode_access_token
    original_payload = decode_access_token(result.access_token)
    assert original_payload["ver"] == 1
    
    # 3. Increment token_version
    await auth_service.logout_all_sessions(user.id, db)
    
    # 4. Try to use old JWT
    middleware = AuthMiddleware(...)
    response = await middleware._authenticate_jwt(result.access_token, request, ...)
    assert response.status_code == 401
    assert response.content["error"]["code"] == "SESSION_INVALIDATED"

@pytest.mark.asyncio
async def test_cross_tenant_isolation():
    """User from Tenant A cannot see Tenant B data"""
    # Create two tenants
    tenant_a = await create_tenant("Tenant A")
    tenant_b = await create_tenant("Tenant B")
    
    # Create users
    user_a = await create_user(tenant_a, "alice@a.com", role="ADMIN")
    user_b = await create_user(tenant_b, "bob@b.com", role="ADMIN")
    
    # Login as alice (tenant A)
    result_a = await auth_service.login("alice@a.com", "...", db)
    
    # Decode and check tenant_id in JWT
    payload_a = decode_access_token(result_a.access_token)
    assert payload_a["tenant_id"] == str(tenant_a.id)
    
    # Try to access user_b's data via API
    # (Cannot forge request with tenant_b.id — only authenticated identity used)
    response = await client.get(
        f"/v1/admin/users/{user_b.id}",
        headers={"Authorization": f"Bearer {result_a.access_token}"}
    )
    assert response.status_code == 404  # Tenant A cannot see Tenant B user

@pytest.mark.asyncio
async def test_dept_isolation_developer():
    """DEVELOPER sees only own dept, ADMIN sees all"""
    tenant = await create_tenant("Test")
    dept_a = await create_dept(tenant, "Engineering")
    dept_b = await create_dept(tenant, "Sales")
    
    admin = await create_user(tenant, "admin@test.com", role="ADMIN", dept_id=None)
    dev_a = await create_user(tenant, "dev@a.com", role="DEVELOPER", dept_id=dept_a.id)
    
    # DEVELOPER sees only own dept
    result_dev = await auth_service.login("dev@a.com", "...", db)
    payload_dev = decode_access_token(result_dev.access_token)
    assert payload_dev["dept_id"] == str(dept_a.id)
    
    # ADMIN sees all depts (NULL dept_id)
    result_admin = await auth_service.login("admin@test.com", "...", db)
    payload_admin = decode_access_token(result_admin.access_token)
    assert payload_admin["dept_id"] is None

@pytest.mark.asyncio
async def test_nullpool_session_closes():
    """NullPool session is closed after logging (no connection leak)"""
    from unittest.mock import patch
    
    with patch('sqlalchemy.ext.asyncio.AsyncSession.close') as mock_close:
        await _log_auth_event(
            action="login_success",
            success=True,
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
        )
        assert mock_close.called  # Verify finally block ran
```

### Test Infrastructure

```python
# pytest.ini
[pytest]
asyncio_mode = auto
asyncio_default_fixture_loop_scope = session
asyncio_default_test_loop_scope = session
# Session-scoped loop prevents pool poisoning across tests
```

```python
# tests/integration/conftest.py

@pytest.fixture(scope="function")
async def db():
    """
    Provides fresh DB session for each test.
    Uses NullPool in test mode (avoid asyncpg pool reuse).
    Flushes Redis keys before/after to prevent cross-test contamination.
    """
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from sqlalchemy.pool import NullPool
    
    _flush_redis_keys()  # Clear before
    
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    sf = async_sessionmaker(bind=engine, class_=AsyncSession)
    async with sf() as session:
        yield session
        await session.rollback()
    
    await engine.dispose()
    _flush_redis_keys()  # Clear after

def _flush_redis_keys():
    """Clear test-related Redis keys to prevent cross-contamination"""
    import redis
    r = redis.Redis(host="localhost", port=6379, db=0)
    for pattern in ["rate_limit:*", "auth:failed:*", "auth:locked:*"]:
        for key in r.scan_iter(match=pattern):
            r.delete(key)
```

---

## Common Patterns & Anti-Patterns

### ✅ CORRECT PATTERNS

**1. Always validate tenant_id from request.state**
```python
tenant_id = request.state.tenant_id  # From authenticated identity
# NEVER: request.query_params, request.json(), etc.
```

**2. Validate final state on PATCH**
```python
final_role = data.get("role", user.role)
final_dept_id = data.get("dept_id", user.dept_id)
error = _validate_role_dept_consistency(final_role, final_dept_id)
# Validate BOTH together, not individually
```

**3. Increment token_version atomically**
```python
async def logout_all_sessions(user_id, db):
    new_ver = await repo.increment_token_version(user_id)
    revoked = await repo.revoke_all_for_user(user_id)
    await db.commit()  # Single commit
```

**4. Log auth events non-blocking**
```python
# After returning response
await _log_auth_event(...)  # Uses separate NullPool session
# If fails, logged and suppressed — never affects response
```

**5. Normalize and validate input**
```python
email = normalize_email(email)  # lowercase + trim
logout_reason = LogoutReason(request_reason).value  # Enum or default
# Frontend input is never trusted for critical fields
```

### ❌ ANTI-PATTERNS

**1. Mixing auth methods (WRONG)**
```python
api_key = request.json().get("api_key")  # Body, not header
if api_key:
    auth_flow = "api_key"
```
✅ **Correct:** `api_key = request.headers.get("x-api-key")`

**2. Validating fields independently (WRONG)**
```python
if "role" in data:
    # Validate role
    if data["role"] not in [...]:
        return 400
if "dept_id" in data:
    # Validate dept_id separately
    if role != "ADMIN" and not dept_id:
        return 400
```
✅ **Correct:** Compute final state, then validate together.

**3. Querying without dept filter (WRONG)**
```python
query = table.where(table.tenant_id == tenant_id)
# Returns all depts in tenant — DEVELOPER sees all colleagues
```
✅ **Correct:** Add optional dept filter for non-ADMIN.

**4. Blocking auth event logging (WRONG)**
```python
await _log_auth_event(...)  # In request context
# If DB is slow, login is slow
```
✅ **Correct:** Fire-and-forget with NullPool session.

**5. Storing raw refresh tokens (WRONG)**
```python
refresh_tokens.token = refresh_raw  # DB compromise = all tokens leaked
```
✅ **Correct:** Store SHA-256 hash only.

**6. Using request body for tenant/dept (WRONG)**
```python
tenant_id = request.json().get("tenant_id")  # Attacker can change
```
✅ **Correct:** Always from `request.state.tenant_id`.

**7. Catching InvalidTokenError without ExpiredSignatureError first (WRONG)**
```python
try:
    payload = decode_access_token(token)
except InvalidTokenError:
    # Will catch ExpiredSignatureError too (subclass)
    reason = "token_invalid"  # Wrong reason for expired token
```
✅ **Correct:** Catch `ExpiredSignatureError` before `InvalidTokenError`.

**8. Logging to auth_events from multiple places (WRONG)**
```python
# In endpoint AND in service AND in middleware
# Same event logged 3 times
```
✅ **Correct:** Single owner per event type.

---

## Deployment Checklist

### Pre-Deployment

- [ ] Change `ADMIN_PASSWORD` in `.env` to strong random value
- [ ] Change `JWT_SECRET_KEY` to random string (min 32 chars)
- [ ] Set `ENVIRONMENT = "production"` (enables Secure cookie flag)
- [ ] Verify `DATABASE_URL` points to production PostgreSQL
- [ ] Verify `REDIS_URL` points to production Redis (not localhost)
- [ ] Review password requirements in `validate_password_strength()`
- [ ] Set `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` (recommend: 30 min)
- [ ] Set `JWT_REFRESH_TOKEN_EXPIRE_DAYS` (recommend: 30 days)
- [ ] Set `AUTH_MAX_FAILED_ATTEMPTS` (recommend: 5)
- [ ] Set `AUTH_LOCKOUT_DURATION_SECONDS` (recommend: 900 = 15 min)
- [ ] Verify `AUDIT_RETENTION_DAYS` for audit log purge policy
- [ ] Run database migrations: `add_users.sql`

### At Startup

1. **Bootstrap Check**
   ```
   startup → bootstrap_admin()
   ├─ If ADMIN_PASSWORD == default
   │  └─ Log ERROR + print to stderr
   │     (deployment will fail if unattended)
   └─ Create ADMIN user with force_password_change = true
   ```

2. **Database Validation**
   ```
   ├─ users.tenant_id is NOT NULL
   ├─ api_keys.tenant_id is NOT NULL
   ├─ refresh_tokens.token_hash is UNIQUE
   ├─ users.email has LOWER() index
   └─ Constraint: role + dept_id consistency
   ```

3. **Redis Validation**
   ```
   ├─ Can connect
   ├─ AUTH (if required) works
   └─ Can set/get keys for lockout + rate limiting
   ```

4. **Settings Validation**
   ```
   ├─ jwt_secret_key is set (not default)
   ├─ admin_api_key is set (not default)
   └─ environment is "production"
   ```

### During Deployment

- [ ] Kubernetes/Docker health checks pass
- [ ] Startup logs show "bootstrap_admin completed" or "using existing admin"
- [ ] No ERROR level logs in auth module
- [ ] Database connections established
- [ ] Redis connections established

### Monitoring (Ongoing)

- [ ] Watch `auth:failed:*` Redis keys (login failures)
- [ ] Monitor `auth:locked:*` Redis keys (account lockouts)
- [ ] Alert on SYSTEM_ERROR rate in middleware (token validation failures)
- [ ] Alert on SESSION_INVALIDATED spikes (possible token theft attempts)
- [ ] Track `auth_events.success = false` by `failure_reason`
- [ ] Dashboard: user login trends, lockout events, permission changes

### Zero-Downtime Deployment

**Refresh token rotation is safe:** Old and new servers can both validate old and new tokens.

```
1. Deploy new version to canary (5% traffic)
   ├─ New server generates new refresh tokens (different hash)
   ├─ Old server still validates old refresh tokens
   └─ No token invalidation needed

2. Monitor for errors (none expected)

3. Route 100% to new version
   └─ Old refresh tokens still work (backward compatible)

4. Scale down old version
   └─ No sessions are broken
```

---

## Future Considerations & Known Limitations

### v1 Limitations

| Limitation | Impact | Planned Fix |
|---|---|---|
| Email globally unique | Cannot have same email in multiple tenants | v2: per-tenant uniqueness |
| No per-session revocation | Cannot revoke 1 of N sessions | v2: session table + per-session invalidation |
| Client-only inactivity | Server doesn't enforce inactivity | v1.1: Redis TTL per user_id |
| No OWNER role | Tenant ownership not explicit | v2: OWNER role + transfer flow |
| No permission engine | Only role-based, not permission-based | v2: fine-grained permissions |
| No SSO/SAML | No external identity providers | v2: OAuth2/OIDC integration |
| No user invitation | Admin must share credentials out-of-band | v2: email-based invitation links |
| No step-up auth | No re-authentication for sensitive actions | v2: challenge password before user updates |
| No session binding | IP/device changes don't invalidate | Deferred: low ROI, breaks legitimate users |
| No IP-based lockout | Cannot lock based on suspicious IP | v2: with analytics |

### Design Decisions That Cannot Change

These are baked into the token format and will require v2+:

- ✗ Cannot move from `ver` claim to Redis session table (format incompatible)
- ✗ Cannot change `aud` claim value without token reissue
- ✗ Cannot extend refresh token beyond 30 days without security review
- ✗ Cannot remove tenant_id from JWT (isolation depends on it)
- ✗ Cannot change token signing algorithm (security implications)

### Safe Future Extensions

These are additive and don't require token format changes:

- ✓ Add new optional JWT claims (ignored by v1, used by v2)
- ✓ Add new auth_events action types (extensible enum)
- ✓ Add new failure_reason values (extensible enum)
- ✓ Add per-tenant email uniqueness (index migration)
- ✓ Add role-based permission engine (new table)
- ✓ Add SCIM provisioning (external sync)

---

## Appendix: Enums & Constants

### AuthEventAction Enum
```python
LOGIN_SUCCESS         = "login_success"
LOGIN_FAILED          = "login_failed"
LOGOUT                = "logout"
TOKEN_REFRESH_SUCCESS = "token_refresh_success"
TOKEN_REFRESH_FAILED  = "token_refresh_failed"
SESSION_EXPIRED       = "session_expired"
```

### AuthFailureReason Enum
```python
INVALID_PASSWORD      = "invalid_password"
USER_NOT_FOUND        = "user_not_found"
ACCOUNT_DISABLED      = "account_disabled"      # is_active = false
ACCOUNT_INACTIVE      = "account_inactive"      # operational state
TOKEN_EXPIRED         = "token_expired"         # exp in past
TOKEN_INVALID         = "token_invalid"         # malformed/tampered
INACTIVITY            = "inactivity"            # 15 min no activity
MANUAL                = "manual"                # logout requested
EXPIRED               = "expired"               # logout on expiry
REFRESH_FAILED        = "refresh_failed"        # token not found/revoked
SESSION_INVALIDATED   = "session_invalidated"   # version mismatch
```

### AdminEventAction Enum
```python
USER_CREATED          = "user_created"
USER_DEACTIVATED      = "user_deactivated"
USER_REACTIVATED      = "user_reactivated"
PASSWORD_RESET        = "password_reset"
ROLE_CHANGED          = "role_changed"
DEPT_CHANGED          = "dept_changed"
```

### LogoutReason Enum
```python
MANUAL                = "manual"       # User clicked logout
INACTIVITY            = "inactivity"   # 15 min no activity
EXPIRED               = "expired"      # Session expired, user acknowledged
```

### UserRole Enum
```python
ADMIN                 = "ADMIN"
DEVELOPER             = "DEVELOPER"
VIEWER                = "VIEWER"
```

### Constants
```python
ACCESS_TOKEN_AUDIENCE           = "wrapsec-dashboard"
JWT_ALGORITHM                   = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
JWT_REFRESH_TOKEN_EXPIRE_DAYS   = 30
AUTH_MAX_FAILED_ATTEMPTS        = 5
AUTH_LOCKOUT_DURATION_SECONDS   = 900  # 15 min
REFRESH_COOKIE_NAME             = "refresh_token"
REFRESH_COOKIE_PATH             = "/v1/auth"
```

---

## References & Further Reading

- **OWASP Session Management Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- **JWT Best Practices:** https://tools.ietf.org/html/rfc8725
- **PyJWT Documentation:** https://pyjwt.readthedocs.io/
- **Bcrypt Security:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **NIST SP 800-63B (Authentication & Lifecycle):** https://pages.nist.gov/800-63-3/sp800-63b.html

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | April 2026 | Initial version — consolidates JWT_implementation_plan.md v9.0, user_management.md v1.2, session_management.md v1.0 |

---

**This document is the canonical reference for WrapSec authentication architecture.**
**All code should be reviewed against these specifications before merging.**

---

*Authoritative source of truth for JWT, session management, user identity, and auth event logging in WrapSec v1.0+*
