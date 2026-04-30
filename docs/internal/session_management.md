# WrapSec — Session & Auth Hardening Reference

*Version 1.0 — April 2026*
*Reviewed across multiple cycles. Implementation-ready.*
*Companion to: JWT_implementation_plan.md, user_management.md*

---

## Overview

This document covers session lifecycle management, auth event observability,
and frontend session hardening for the WrapSec dashboard.

It does not replace or modify the JWT implementation plan or user management
reference. All three documents must be read together.

```
JWT_implementation_plan.md  → token design, auth middleware, RBAC
user_management.md          → users table, admin_events, auth_events (login/logout)
session_management.md       → THIS DOCUMENT
                               session lifecycle, inactivity, observability expansion
```

---

## What Changed (vs Existing Implementation)

The following gaps existed before this hardening cycle:

| Gap | Impact |
|---|---|
| No inactivity timeout | Security dashboards require 15 min max |
| No silent refresh | Users abruptly kicked to login every 30 min |
| Expired session → HTML parse error | `JSON.parse("<!DOCTYPE")` crash in modal |
| middleware intercepts `/api/*` routes | Returns HTML redirect instead of JSON 401 |
| auth_events only covers login | No logout, refresh, expiry visibility |
| Logout reason not captured | Cannot distinguish manual vs inactivity vs expiry |
| NullPool sessions not explicitly closed | Connection leak under load |
| No exception type discrimination | TOKEN_EXPIRED vs TOKEN_INVALID confused |

All gaps are addressed in this document.

---

## Session Model

### Two Auth Modes (unchanged from JWT plan)

```
x-api-key header     → API_KEY session  (machine / admin convenience)
Authorization Bearer → JWT session      (human dashboard users)
```

Both modes are subject to the inactivity timeout.
JWT sessions support silent refresh. API key sessions do not.

### Session Duration

| Session type | Duration | Inactivity timeout |
|---|---|---|
| JWT access token | 30 min (hard expiry, server-enforced) | 15 min (client-enforced) |
| JWT refresh token | 30 days (rotated on use) | Revoked on logout |
| API key cookie | 8 hours (reduced from 24h) | 15 min (client-enforced) |

The 30 min JWT expiry is server-enforced and cannot be bypassed.
The 15 min inactivity timeout is client-enforced in v1.
Server-side inactivity enforcement (Redis TTL per session) is deferred to v1.1.

---

## Auth Events Expansion

### What Existed Before

```
action values:        login_success, login_failed
failure_reason values: invalid_password, user_not_found,
                       account_disabled, account_inactive, token_expired
```

### What Is Added

New action values (enum-controlled in application code):

```
logout
token_refresh_success
token_refresh_failed
session_expired
```

New failure_reason values:

```
inactivity          — inactivity timer triggered logout
manual              — user clicked logout button
expired             — session expired, user acknowledged
refresh_failed      — refresh token invalid, expired, or revoked
session_invalidated — token_version mismatch (password change, role change)
token_invalid       — malformed or tampered JWT (not just expired)
```

No schema change required. `action` and `failure_reason` are `VARCHAR(50)`.
Values are enum-controlled in application code only.

### auth_events Table (unchanged schema, extended enum values)

```sql
id             UUID PRIMARY KEY
tenant_id      UUID NULL           -- NULL when user not found or token unreadable
user_id        UUID NULL           -- NULL when user not found or token unreadable
action         VARCHAR NOT NULL    -- enum controlled (extended)
success        BOOLEAN NOT NULL
failure_reason VARCHAR NULL        -- enum controlled (extended)
ip_address     VARCHAR NULL
user_agent     VARCHAR NULL
created_at     TIMESTAMP NOT NULL DEFAULT NOW()
```

Existing indexes are sufficient. No new indexes added.

### Logging Ownership — Single Source of Truth

Each event type is logged by exactly one owner. Never duplicated.

| Event | Owner | Notes |
|---|---|---|
| `login_success` | `service.login()` | unchanged |
| `login_failed` | `service.login()` | unchanged |
| `logout` | `service.logout()` | NEW — with reason |
| `token_refresh_success` | `service.refresh()` | NEW |
| `token_refresh_failed` | `service.refresh()` | NEW |
| `session_expired` | `api/v1/middleware/auth.py` | NEW — NOT for refresh path |

Middleware does NOT log for `/v1/auth/refresh` path.
The refresh service owns logging for refresh failures.
This prevents duplicate rows for the same auth event.

### tenant_id and user_id Rules (extended from user_management.md)

| Scenario | tenant_id | user_id |
|---|---|---|
| Login success | user's tenant_id | user's id |
| Login failure — wrong password | user's tenant_id | user's id |
| Login failure — user not found | NULL | NULL |
| Logout | user's tenant_id | user's id |
| Token refresh success | user's tenant_id | user's id |
| Token refresh failed — token not found | NULL | NULL |
| Session expired — token expired | extracted from payload if possible, else NULL | extracted if possible, else NULL |
| Session expired — token invalid | NULL | NULL |

For session_expired: attempt `jwt.decode(token, options={"verify_exp": False})`
to extract `sub` and `tenant_id` from payload even if token is expired or invalid.
If extraction fails, log with NULL values. Never skip logging because context is unavailable.

### Logging Model

auth_events must be non-blocking. Same model as user_management.md §auth_events:

```
1. complete auth operation
2. return response to client
3. insert auth_event via NullPool session (separate from request session)
4. if logging fails → log to Python logger, do not retry, do not affect response
```

Every auth_event DB write must have a matching Python log line (same data, same moment):

```python
logger.info(
    "auth_event action=%s user_id=%s tenant_id=%s reason=%s",
    action.value, user_id, tenant_id, reason
)
```

Log levels:
- `login_success`, `token_refresh_success`, `logout` → `logger.info`
- `login_failed`, `token_refresh_failed`, `session_expired` → `logger.warning`

NullPool session pattern (connection leak prevention):

```python
async def _log_auth_event(...) -> None:
    session = None
    try:
        session = NullPoolAsyncSession()
        repo    = AuthEventRepository(session)
        await repo.insert(...)
        await session.commit()
    except Exception as e:
        logger.warning("auth_event logging failed: %s", e)
    finally:
        if session:
            await session.close()   # always — even on exception
```

The `finally` block is mandatory. NullPool does not pool — every unclosed session
is a real connection held open.

---

## New Enums

### domain/enums.py additions

```python
class AuthEventAction(str, Enum):
    LOGIN_SUCCESS         = "login_success"
    LOGIN_FAILED          = "login_failed"
    LOGOUT                = "logout"
    TOKEN_REFRESH_SUCCESS = "token_refresh_success"
    TOKEN_REFRESH_FAILED  = "token_refresh_failed"
    SESSION_EXPIRED       = "session_expired"

class AuthEventFailureReason(str, Enum):
    INVALID_PASSWORD    = "invalid_password"
    USER_NOT_FOUND      = "user_not_found"
    ACCOUNT_DISABLED    = "account_disabled"
    ACCOUNT_INACTIVE    = "account_inactive"
    TOKEN_EXPIRED       = "token_expired"
    TOKEN_INVALID       = "token_invalid"
    INACTIVITY          = "inactivity"
    MANUAL              = "manual"
    EXPIRED             = "expired"
    REFRESH_FAILED      = "refresh_failed"
    SESSION_INVALIDATED = "session_invalidated"

class LogoutReason(str, Enum):
    MANUAL     = "manual"
    INACTIVITY = "inactivity"
    EXPIRED    = "expired"
```

---

## Backend Changes

### services/auth/service.py

**logout() — new reason parameter:**

```python
async def logout(
    self,
    refresh_token_raw: str,
    reason: LogoutReason = LogoutReason.MANUAL,
    db: AsyncSession,
) -> None:
```

Accepts reason from endpoint. Logs LOGOUT with reason as failure_reason.
Reason is pre-validated by endpoint before reaching service — service trusts it.

**refresh() — new auth_event logging:**

```python
# success
log TOKEN_REFRESH_SUCCESS, success=True

# token not found / revoked
log TOKEN_REFRESH_FAILED, success=False, reason=REFRESH_FAILED

# version mismatch
log TOKEN_REFRESH_FAILED, success=False, reason=SESSION_INVALIDATED

# expired
log TOKEN_REFRESH_FAILED, success=False, reason=TOKEN_EXPIRED
```

### api/v1/endpoints/auth.py

**POST /v1/auth/logout — new request body:**

```python
class LogoutRequest(BaseModel):
    reason: str = "manual"
```

Validation:

```python
try:
    logout_reason = LogoutReason(request.reason)
except ValueError:
    logout_reason = LogoutReason.MANUAL   # normalize — never raise error
```

Never return 400 for invalid reason. Normalize silently to MANUAL.
Frontend input is not trusted for this field.

### api/v1/middleware/auth.py

**Exception type discrimination — mandatory order:**

```python
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

try:
    payload = decode_access_token(token)
except ExpiredSignatureError:
    reason = AuthEventFailureReason.TOKEN_EXPIRED
    # log SESSION_EXPIRED
except InvalidTokenError:
    reason = AuthEventFailureReason.TOKEN_INVALID
    # log SESSION_EXPIRED
```

`ExpiredSignatureError` is a subclass of `InvalidTokenError` (PyJWT).
Must be caught FIRST or it falls into the broader except.
Never swap the order. Never parse exception message strings.

Note: WrapSec uses PyJWT (not python-jose). Exception classes are from
`jwt.exceptions`. See JWT implementation plan §Implementation Deviations.

**Do NOT log when no token is present:**

```python
api_key = request.headers.get("x-api-key", "").strip()
auth    = request.headers.get("authorization", "").strip()

if not api_key and not auth.lower().startswith("bearer "):
    return _unauthorized(request, "missing_credentials")
    # NO auth_event logging here
    # Health checks, unauthenticated access, public routes — expected, not suspicious
```

Only log when a token is present but fails validation.

**Skip logging for refresh endpoint:**

```python
SKIP_AUTH_EVENT_LOGGING = {"/v1/auth/refresh"}

if request.url.path in SKIP_AUTH_EVENT_LOGGING:
    pass   # refresh service owns its own logging
    # do NOT log SESSION_EXPIRED here
```

Use a set for O(1) lookup. Add future paths to the set, not to conditions.

---

## Frontend Changes

### middleware.ts

Exclude all `/api/*` paths from UI auth redirect.
API routes return JSON — middleware must never intercept them.

```typescript
if (pathname.startsWith("/api/")) {
    return NextResponse.next()   // skip — API routes handle own auth
}
```

Without this: expired JWT → middleware redirects `/api/proxy/*` to `/login`
(HTML) → proxy handler never runs → `JSON.parse("<!DOCTYPE")` crash.

### lib/api.ts

**Fix 1 — Safe JSON parsing:**

```typescript
let data: any
try {
    data = await response.json()
} catch {
    // Response is not JSON (HTML error page, etc.)
    if (response.status === 401 || response.status === 403) {
        // Redirect to login — auth failure
        window.location.href = "/login"
        throw new Error("Unauthorized")
    }
    // 500/502/503 are server errors — show error, do NOT redirect to login
    throw new Error(`HTTP ${response.status}`)
}
```

Rule: not every non-JSON response is an auth failure.
500 errors are server bugs — user should see an error message, not be kicked to login.

**Fix 2 — Silent refresh on 401, with two mandatory guards:**

```typescript
// Guard 1: never retry the refresh request itself
if (url.includes("/api/auth/refresh")) {
    window.location.href = "/login"
    throw new Error("Session expired")
}

// Guard 2: never retry twice
if (options._retried) {
    window.location.href = "/login"
    throw new Error("Session expired")
}

// Attempt silent refresh
const refreshed = await fetch("/api/auth/refresh", { method: "POST" })
if (!refreshed.ok) {
    window.location.href = "/login"
    throw new Error("Session expired")
}

// Retry original request once
return request(url, { ...options, _retried: true })
```

Both guards are required. Neither alone is sufficient.
Guard 1 catches the refresh-calling-itself case.
Guard 2 catches any other potential loop.

**Fix 3 — isLoggingOut flag (inactivity/refresh race condition):**

```typescript
export let isLoggingOut = false

// In logout():
export async function logout(reason = "manual") {
    isLoggingOut = true   // set BEFORE fetch — prevents concurrent refresh
    await fetch("/api/auth/logout", {
        method: "POST",
        body: JSON.stringify({ reason }),
    })
}

// In request() before refresh attempt:
if (isLoggingOut) {
    window.location.href = "/login"
    throw new Error("Logging out")
}
```

Scenario this prevents:
- User inactive → timer fires → `logout("inactivity")`
- Simultaneously: silent refresh in-flight
- Without flag: refresh succeeds, session restored, then immediately logged out
- With flag: refresh aborted before it starts

### app/api/proxy/[...path]/route.ts

All error paths must return JSON. No HTML ever:

```typescript
// missing token
return NextResponse.json(
    { error: { code: "UNAUTHORIZED", message: "Not authenticated" } },
    { status: 401 }
)

// upstream failure
return NextResponse.json(
    { error: { code: "UPSTREAM_ERROR", message: "Provider unavailable" } },
    { status: 502 }
)

// any unhandled exception
return NextResponse.json(
    { error: { code: "INTERNAL_ERROR", message: "Internal error" } },
    { status: 500 }
)
```

Wrap the entire handler body in try/catch to guarantee the above.

### app/api/auth/logout/route.ts

Forward reason to backend:

```typescript
const body = await request.json().catch(() => ({}))
const reason = body.reason ?? "manual"

await fetch(`${API_BASE_URL}/v1/auth/logout`, {
    method: "POST",
    headers: { "Authorization": `Bearer ${jwtToken}` },
    body: JSON.stringify({ reason }),
})

// Clear all cookies regardless of backend response
```

Always clear cookies even if backend call fails.
Never leave a stale session cookie if logout was requested.

### lib/auth.ts

Updated signature:

```typescript
export async function logout(
    reason: "manual" | "inactivity" | "expired" = "manual"
): Promise<void> {
    isLoggingOut = true
    await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason }),
    })
}
```

### hooks/useInactivityTimer.ts (new)

Events tracked:

```typescript
const ACTIVITY_EVENTS = [
    "mousemove", "mousedown", "keydown",
    "touchstart", "scroll", "visibilitychange",
]
```

`visibilitychange` covers tab switching — treated as inactivity when tab is hidden.

Timer behaviour:
- Timeout: 15 minutes (900 seconds)
- Warning threshold: 2 minutes remaining (120 seconds)
- On timeout: `logout("inactivity")` → redirect `/login`

Returns: `{ showWarning, secondsRemaining, resetTimer, logoutNow }`

### components/layout/InactivityWarning.tsx (new)

Blocking modal — cannot be dismissed by clicking outside or pressing Escape.

```
"You will be logged out in X:XX due to inactivity."

[ Stay logged in ]    [ Log out now ]
```

- "Stay logged in" → `resetTimer()` → closes modal
- "Log out now" → `logout("manual")` → redirect `/login`
- Timer continues accurately while modal is open
- Blocks all interaction behind it (pointer-events: none on backdrop)

### components/layout/Shell.tsx

Wire timer and warning inside Shell component:

```typescript
const { showWarning, secondsRemaining, resetTimer, logoutNow } = useInactivityTimer()

return (
    <>
        {showWarning && (
            <InactivityWarning
                secondsRemaining={secondsRemaining}
                onStay={resetTimer}
                onLogout={logoutNow}
            />
        )}
        {/* existing Shell content */}
    </>
)
```

Applies to all authenticated pages automatically.
No per-page changes needed.

### app/api/auth/login/route.ts

API key cookie maxAge reduced from 24h to 8h:

```typescript
res.cookies.set("wrapsec_api_key", apiKey, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   60 * 60 * 8,   // 8 hours (was 24)
    path:     "/",
})
```

Reason: API key sessions are a human-facing convenience layer, not machine identity.
8h matches a standard working day. 24h is excessive for a security dashboard.

---

## useAuthMode Hook (implemented during testing)

During testing, a `useAuthMode` hook was added to detect auth mode client-side.
This is used to gate write operations in settings components.

**Problem:** `wrapsec_session` cookie was initially `httpOnly: false` to allow
JS to read auth mode. This is a security violation — all cookies must be httpOnly.

**Fix applied:**

1. `wrapsec_session` → `httpOnly: true` (cannot be read by JS)
2. New server route: `GET /api/auth/session`

```typescript
// app/api/auth/session/route.ts
export async function GET() {
    const cookieStore = await cookies()
    const hasJwt    = !!cookieStore.get("wrapsec_jwt")?.value
    const hasApiKey = !!cookieStore.get("wrapsec_api_key")?.value

    return NextResponse.json({
        authenticated: hasJwt || hasApiKey,
        auth_type:     hasJwt ? "jwt" : hasApiKey ? "api_key" : null,
        can_write:     hasJwt,
    })
}
```

3. `useAuthMode` hook calls this route — never reads `document.cookie`:

```typescript
export function useAuthMode() {
    const [session, setSession] = useState({ auth_type: null, can_write: false })
    useEffect(() => {
        fetch("/api/auth/session").then(r => r.json()).then(setSession)
    }, [])
    return { isJwt: session.auth_type === "jwt", canWrite: session.can_write }
}
```

**Write gating — applied to:**

| Component | Write operation |
|---|---|
| ThresholdForm | PUT /v1/settings/thresholds |
| LayerToggles | PUT /v1/settings/layers |
| LLMSettings | PUT /v1/settings/llm |
| RateLimitSettings | PUT /v1/settings/rate_limit |
| RetentionSettings | PUT /v1/settings/retention |
| ProxySettings | PUT /v1/settings/proxy |
| TenantSettings | PUT /v1/admin/tenant |
| Users page | POST/PATCH /v1/admin/users |

When `!isJwt`: Save button is disabled with message
"Requires admin login — sign in with email".

**PATCH export missing from proxy route:**

During testing, `PATCH` was not exported from the catch-all proxy route,
causing HTTP 405 on user status toggle. Fix:

```typescript
// app/api/proxy/[...path]/route.ts
export const GET    = handler
export const POST   = handler
export const PUT    = handler
export const PATCH  = handler   // was missing
export const DELETE = handler
```

---

## Implementation Order

### Phase 1 — Backend

```
Step 1  db/migrations/add_auth_event_expansion.sql
        — add documentation comment for new action/failure_reason values
        — no schema change needed

Step 2  domain/enums.py
        — AuthEventAction (extended)
        — AuthEventFailureReason (extended)
        — LogoutReason (new)

Step 3  db/repositories/auth_event.py
        — insert() with NullPool session
        — explicit session.close() in finally block
        — existing model, new repository file

Step 4  services/auth/service.py
        — logout(): add reason param, log LOGOUT + reason
        — refresh(): log TOKEN_REFRESH_SUCCESS/FAILED + reason

Step 5  api/v1/endpoints/auth.py
        — POST /v1/auth/logout: accept reason body, normalize, pass to service

Step 6  api/v1/middleware/auth.py
        — ExpiredSignatureError before InvalidTokenError (order matters)
        — skip logging when no token present
        — skip logging for SKIP_AUTH_EVENT_LOGGING paths
        — NullPool session with finally: session.close()
```

### Phase 2 — Frontend

```
Step 7  dashboard/middleware.ts
        — exclude /api/* from redirect

Step 8  dashboard/lib/api.ts
        — safe JSON parsing (status-aware)
        — silent refresh with two guards
        — isLoggingOut flag check before refresh

Step 9  dashboard/app/api/proxy/[...path]/route.ts
        — wrap handler in try/catch
        — guarantee JSON on all error paths

Step 10 dashboard/app/api/auth/logout/route.ts
        — forward reason to backend

Step 11 dashboard/lib/auth.ts
        — logout(reason) signature
        — isLoggingOut flag

Step 12 dashboard/hooks/useInactivityTimer.ts
        — new hook

Step 13 dashboard/components/layout/InactivityWarning.tsx
        — new component

Step 14 dashboard/components/layout/Shell.tsx
        — wire timer + warning

Step 15 dashboard/app/api/auth/login/route.ts
        — API key maxAge 24h → 8h
```

### Phase 3 — Testing

```
Backend:
  ✓ login_success → auth_events row, correct fields
  ✓ login_failed  → auth_events row, correct reason
  ✓ logout manual → action=logout, reason=manual
  ✓ logout inactivity → action=logout, reason=inactivity
  ✓ logout expired → action=logout, reason=expired
  ✓ logout invalid reason → normalized to manual, no error
  ✓ refresh success → action=token_refresh_success
  ✓ refresh failed → correct reason per failure type
  ✓ JWT expired → action=session_expired, reason=token_expired
  ✓ JWT tampered → action=session_expired, reason=token_invalid
  ✓ version mismatch → action=session_expired, reason=session_invalidated
  ✓ no duplicate rows for same auth event
  ✓ NullPool session closed in finally block (no connection leak)
  ✓ missing token → no auth_event row logged
  ✓ refresh path → no session_expired row from middleware

Frontend:
  ✓ JWT expires → silent refresh → continues seamlessly
  ✓ JWT + refresh both expired → /login redirect, no crash
  ✓ 500 from backend → error message shown, no /login redirect
  ✓ 15 min inactivity → warning at 2 min → logout(inactivity)
  ✓ tab switch → visibilitychange → counts as inactivity
  ✓ "Stay logged in" → timer reset, no logout
  ✓ request modal with expired session → /login (no HTML parse error)
  ✓ API key session → same inactivity behaviour
  ✓ proxy route → no HTML response under any path
  ✓ inactivity logout cancels pending refresh (isLoggingOut flag)
  ✓ PATCH requests forwarded correctly by proxy route
  ✓ API key session → write buttons disabled with message
  ✓ JWT session → write buttons active
  ✓ wrapsec_session cookie → httpOnly (document.cookie returns empty)
```

---

## Files Changed

### Backend (new)

```
db/migrations/add_auth_event_expansion.sql
db/repositories/auth_event.py
```

### Backend (modified)

```
domain/enums.py
services/auth/service.py
api/v1/endpoints/auth.py
api/v1/middleware/auth.py
```

### Frontend (new)

```
dashboard/hooks/useInactivityTimer.ts
dashboard/hooks/useAuthMode.ts
dashboard/components/layout/InactivityWarning.tsx
dashboard/app/api/auth/session/route.ts
```

### Frontend (modified)

```
dashboard/middleware.ts
dashboard/lib/api.ts
dashboard/lib/auth.ts
dashboard/app/api/proxy/[...path]/route.ts
dashboard/app/api/auth/logout/route.ts
dashboard/app/api/auth/login/route.ts
dashboard/components/layout/Shell.tsx
dashboard/components/settings/ThresholdForm.tsx
dashboard/components/settings/LayerToggles.tsx
dashboard/components/settings/LLMSettings.tsx
dashboard/components/settings/RateLimitSettings.tsx
dashboard/components/settings/RetentionSettings.tsx
dashboard/components/settings/ProxySettings.tsx
dashboard/components/settings/TenantSettings.tsx
dashboard/app/users/page.tsx
```

---

## Deferred to v1.1

```
Server-side inactivity enforcement
  Redis key: session:activity:{user_id} TTL 15 min
  Updated on every authenticated request in auth middleware
  Reject if key expired → 401 SESSION_INACTIVE
  Files: api/v1/middleware/auth.py, cache/redis_client.py
  Not required now — JWT hard expiry (30 min) covers the window.
  Required when session lifetime > token lifetime.

trace_id in auth_events
  Correlate auth_events ↔ audit_logs ↔ proxy_interactions
  Schema change: ADD COLUMN trace_id VARCHAR(50) NULL

Configurable inactivity timeout via admin settings UI
  Store in DB settings table
  Read in Shell on mount

Rate limiting on refresh endpoint
  Login already has Redis lockout (5 failures → 15 min)
  Refresh: sliding window per user_id (Redis)

Step-up re-authentication for sensitive actions
  Re-prompt password before user management changes
```

## Not Implementing

```
IP / User-Agent session binding
  Breaks legitimate users (VPN, mobile, corporate proxies)
  False positive rate is high — drops active users unexpectedly
  Covered by: httpOnly + SameSite=Strict + token_version

Session table
  JWT + token_version is sufficient for v1
  No per-session revocation UI needed

Remember me / persistent sessions
  Security dashboards must never persist sessions across browser restarts
  No implementation planned
```

---

## Conventions (additions to JWT plan §19)

These apply in addition to all conventions in JWT_implementation_plan.md §19.

```
36. auth_event logging: every DB write has a matching Python log line.
    If one fires, both must fire. Never split them.

37. auth_event ownership: each event type logged by exactly one owner.
    See Logging Ownership table. Never duplicate.

38. NullPool session: always close in finally block.
    if session: await session.close()
    The finally block is mandatory — not optional.

39. Exception discrimination: catch ExpiredSignatureError before InvalidTokenError.
    Order is mandatory — never swap.

40. No logging when no token present.
    Only log SESSION_EXPIRED when a token exists but fails validation.

41. Logout reason validation: normalize invalid input to MANUAL.
    Never raise 400 for invalid reason. Frontend input not trusted.

42. isLoggingOut flag: set to true before logout() fetch.
    api.ts request() checks flag before refresh attempt.
    Prevents refresh after logout decision is made.

43. proxy route: all error paths return JSON.
    No HTML ever returned from /api/proxy/*.

44. /api/* excluded from middleware redirect.
    API routes handle their own auth and return JSON 401.

45. wrapsec_session cookie: httpOnly: true.
    Auth mode detected via GET /api/auth/session (server-side).
    Never via document.cookie.

46. Silent refresh: two guards required (url check + _retried flag).
    Neither alone is sufficient. Both must be present.
```

---

*Version 1.0 — April 2026*
*Reviewed and implementation-ready.*
*No open questions.*
