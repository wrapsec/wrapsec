# WrapSec API Reference

Version: 1.0  
Base URL: `http://your-host:8000`  
Operations served: 99 - of which **28 are the published public contract**  
Documented here: 82 (public and non-public alike)  
Last updated: May 2026

---

## Public Contract Boundary

**This page documents more than the public API. Do not read all 82 documented
operations as the integrator contract.**

WrapSec serves two kinds of HTTP surface, and they carry different promises:

| | Published contract | Everything else |
|---|---|---|
| Operations | **28** | 71 |
| Authority | `docs/openapi.json` - generated, machine-readable, versioned | this page only |
| Audience | SDKs, the protocol adapter, documented integrations | the dashboard, operators, first-run setup, monitoring |
| Stability | changes are contract changes | may change with the surface that uses it |
| In `/docs` and `/openapi.json` | yes | no |

`docs/openapi.json` is the authority for the 28. It is generated from the OSS
core build by `scripts/gen_openapi.py`, contains no plugin routes, and a test
holds it to exactly this boundary in both directions. Where this page and the
schema disagree about a public operation, **the schema is correct**.

Every endpoint heading below is labelled `PUBLIC` or `NOT PUBLIC`. The published
28 are:

| Area | Operations |
|---|---|
| Health | `GET /health`, `/health/live`, `/health/ready`, `/health/config` |
| Capabilities | `GET /v1/capabilities` |
| Scanning | `POST /v1/ai/request`, `POST /v1/ai/scan-batch` |
| Read-back | `GET /v1/ai/requests/{trace_id}`, `GET /v1/agent-runs/{run_id}` |
| Audit | `GET /v1/audit/logs`, `/v1/audit/stats`, `/v1/audit/export` |
| Proxy | `POST /v1/chat/completions`, `GET /v1/proxy/interactions`, `GET /v1/proxy/interactions/{trace_id}` |
| Proxy settings | `GET` / `PUT` / `DELETE /v1/settings/proxy` |
| Detection policy | `GET` + `PUT` on `/v1/settings/thresholds`, `/layers`, `/llm`, `/rate_limit` |
| API keys | `GET /v1/keys`, `POST /v1/keys` |

**`NOT PUBLIC` is a documentation boundary, never an access control.** Those
routes are served exactly as before, with the same authentication, the same
authorization and the same behaviour; they are simply not advertised in the
machine-readable contract, so they are not something an integration should build
against. Nothing about a route's visibility keeps a caller out of it - the auth
middleware and the RBAC checks do that, and they are unchanged.

Two published operations are deliberate special cases: `GET /v1/audit/export`
returns CSV rather than JSON, and `POST /v1/chat/completions` follows the
OpenAI-compatible request and response shapes rather than WrapSec's own.

---

## Authentication

WrapSec supports two authentication methods. Both resolve to identical internal state - downstream code is auth-agnostic.

**Which one an integration uses is settled: the API key.** Every published
operation accepts `x-api-key`, the SDKs and the protocol adapter send it, and no
integration needs a JWT to reach the public contract. JWT is the human session
mechanism - a person signing into the dashboard - which is why the `/v1/auth/*`
family that mints and refreshes tokens is documented here but is not part of the
published schema. It stays fully served, supported, and described below under
[Auth Endpoints](#auth-endpoints); it is simply not an integrator surface.

The one place this matters in practice: a few published operations accept a JWT
but refuse an API key for WRITES (`PUT /v1/settings/*` requires JWT + ADMIN), and
`POST /v1/chat/completions` is the reverse - API key only. The table under
[Endpoint Auth Requirements](#endpoint-auth-requirements) is authoritative per
route.

### API Key

```
x-api-key: your-api-key
```

Used by applications and services. Three key types:

**Admin key** - full access. All endpoints. No dept scoping.

**Standard key** (`wsk_live_...`) - scoped to the department/application the key belongs to. `tenant_id` is always derived from the key - never from request body.

**Trial key** (`wsk_trial_...`) - restricted for demos.
- Input cap: 500 characters
- Rate limit: 10 req/min (enforced at endpoint level)
- Proxy mode: disabled - `POST /v1/chat/completions` returns `403 trial_proxy_disabled` in the OpenAI-compatible envelope; `POST /v1/ai/request` with `execution_mode: proxy` returns `403 FEATURE_UNAVAILABLE`

### JWT Bearer

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Used by dashboard users, and by an operator driving an admin-only write. Issued
via `POST /v1/auth/login`, refreshed via `POST /v1/auth/refresh` - both fully
documented under [Auth Endpoints](#auth-endpoints), neither in the published
schema. Obtaining a token is unchanged: post credentials to the login endpoint
and read `access_token` from the response.

- Access token: HS256 JWT, 30 min, audience=`wrapsec-dashboard`
- Refresh token: opaque, 30 days, httpOnly cookie `Path=/v1/auth`
- Roles: `ADMIN` / `DEVELOPER` / `VIEWER`
- API key cookie: 8 hours (httpOnly, dashboard sessions only)

**Session timeouts (dashboard):**
- JWT hard expiry: 30 min (server-enforced)
- Inactivity timeout: 15 min (client-enforced, dashboard only) - warning at 2 min remaining
- Silent refresh: on any 401, dashboard attempts `POST /api/auth/refresh` before redirecting to login

**Header precedence:** `x-api-key` always wins. If both headers are present, JWT is ignored.

### Endpoint Auth Requirements

| Endpoints | API key | JWT |
|---|---|---|
| `GET /health`, `/health/ready`, `/health/live` | no public | no public |
| `GET /metrics` | token Bearer `METRICS_TOKEN` (falls back to `ADMIN_API_KEY`) | token Bearer `METRICS_TOKEN` |
| `GET /health/config` | yes any key | yes any role |
| `POST /v1/auth/login`, `POST /v1/auth/refresh` | no public/cookie | no public/cookie |
| `POST /v1/auth/logout`, `GET /v1/auth/me`, `POST /v1/auth/change-password` | no | yes any role |
| `POST /v1/ai/request`, `POST /v1/ai/scan-batch` | yes | yes any role |
| `POST /v1/chat/completions` | yes (live keys only) | no - `403 PROXY_REQUIRES_API_KEY` |
| `GET /v1/ai/requests/{trace_id}` | yes | yes any role |
| `GET /v1/agent-runs/{run_id}` | yes | yes any role |
| `GET /v1/audit/*` | yes | yes any role |
| `GET /v1/proxy/interactions/*` | yes | yes any role |
| `GET /v1/capabilities` | yes | yes any role |
| `GET /v1/settings/*` | yes live keys only (trial rejected) | yes ADMIN, DEVELOPER, AUDITOR (`settings:read`); VIEWER rejected |
| `PUT /v1/settings/*` | no | yes ADMIN only |
| `GET/PUT/DELETE /v1/settings/proxy*` | admin API key only | yes ADMIN only |
| `GET /v1/admin/tenant/usage` | yes | yes any role |
| `ALL /v1/admin/tenants*` | admin API key only (platform operator) | no |
| `GET /v1/keys` | yes | yes any role |
| `GET /v1/keys/{id}` | yes | yes any role |
| `POST /v1/keys`, `PUT /v1/keys/{id}`, `DELETE /v1/keys/{id}`, `POST /v1/keys/{id}/rotate` | no | yes ADMIN only |
| `GET /v1/keys/{id}/addresses` | no | yes ADMIN only |
| `GET /v1/admin/tenant`, `GET /v1/admin/departments/*`, `GET /v1/admin/applications/*` | yes | yes any role |
| `PUT /v1/admin/tenant` | no | yes ADMIN only |
| `POST/PUT/DELETE /v1/admin/departments/*` | no | yes ADMIN only |
| `POST/PUT/DELETE /v1/admin/applications/*` | no | yes ADMIN only |
| `ALL /v1/admin/users/*` | no | yes ADMIN only |
| `GET /v1/admin/webhooks`, `GET /v1/admin/webhooks/{id}` | no | yes ADMIN only |
| `POST/PUT/DELETE /v1/admin/webhooks/*`, `POST /v1/admin/webhooks/{id}/rotate-secret` | no | yes ADMIN only |

**Notes:**
- `GET /v1/keys` requires auth but accepts API key - CLI `wrapsec keys list` uses this
- `PUT /v1/settings/*` requires JWT + ADMIN - admin API key not accepted
- `/v1/settings/proxy*` scoped per `tenant_id` - one proxy config shared across all API keys for the tenant. All proxy-settings operations (including reads) require admin: configuring an outbound provider changes what leaves the system
- `POST /v1/chat/completions` is API-key only. Dashboard (JWT) sessions receive `403 PROXY_REQUIRES_API_KEY` regardless of role
- `GET /v1/settings/*` requires the `settings:read` permission: ADMIN, DEVELOPER, and AUDITOR roles hold it; VIEWER does not. Trial API keys are rejected
- `/v1/admin/tenants*` is the platform-operator control plane (tenant provisioning and lifecycle). Master admin API key only. Like every other non-public surface it is excluded from the OpenAPI schema - see [Public Contract Boundary](#public-contract-boundary); it is not uniquely hidden
- If a tenant is suspended, every request under its credentials returns `403 TENANT_SUSPENDED`. The same applies when the tenant's status cannot be established: suspension enforcement fails closed, so a datastore outage refuses authenticated traffic rather than serving it on the assumption the tenant is active. A tenant row that simply does not exist is a definite answer and is not treated as suspended
- All write endpoints on admin resources require JWT (no API key writes)

---


## HTTP Method Conventions

| Method | Usage | Example |
|---|---|---|
| `GET` | Read resource | `GET /v1/admin/users` |
| `POST` | Create resource or action | `POST /v1/admin/users` |
| `PATCH` | Partial update - only provided fields are changed | `PATCH /v1/admin/users/{id}` |
| `PUT` | Full replacement - replaces the entire resource | `PUT /v1/settings/thresholds` |
| `DELETE` | Remove or deactivate resource | `DELETE /v1/keys/{id}` |

WrapSec uses `PATCH` for user updates and `PUT` for settings and configuration. These are not interchangeable - `PATCH` validates the final combined state of all provided fields, while `PUT` replaces the full resource.

---

## Standard Headers

**Request:**

| Header | Description |
|---|---|
| `x-api-key` | API key authentication |
| `Authorization` | `Bearer {jwt_token}` - dashboard user auth |
| `Content-Type` | `application/json` for POST/PUT |
| `Idempotency-Key` | UUID - honoured on `POST /v1/ai/request` and `POST /v1/chat/completions` |

**Response:**

| Header | Description |
|---|---|
| `x-trace-id` | Trace ID, `req_` + 32 hex characters (`req_33ab7464f5014936b07af2e828b274a9`) |
| `X-RateLimit-Limit` | Requests per minute |
| `X-RateLimit-Remaining` | Remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when window resets |
| `X-Idempotency-Replayed` | `true` when response is from cache |

---

## Input Limits

| Limit | Value | Enforcement |
|---|---|---|
| Max characters | 8,000 | Schema -> 422 |
| Estimated token limit | 4,000 | `ceil(len/2) > 4000` -> 422 |
| Max payload | 64KB | Nginx -> 413 |

---

## Error Format

```json
{
  "error": {
    "code":     "VALIDATION_ERROR",
    "message":  "Input exceeds estimated token limit of 4000",
    "trace_id": "req_01knzhh8..."
  }
}
```

Security and proxy errors additionally include a `wrapsec` key:

```json
{
  "error":   {"code": "input_blocked", "message": "...", "trace_id": "..."},
  "wrapsec": {"decision": "BLOCK", "input_threats": ["PROMPT_INJECTION"], ...}
}
```

**Error codes:**

| Code | HTTP | Meaning |
|---|---|---|
| `UNAUTHORIZED` | 401 | Missing or invalid credentials |
| `INVALID_CREDENTIALS` | 401 | Wrong email or password (same message for both - no enumeration) |
| `ACCOUNT_DISABLED` | 401 | User `is_active = false` - always returned to the client when login is rejected due to a deactivated account |
| `SESSION_INVALIDATED` | 401 | Token version mismatch - re-login required |
| `FORBIDDEN` | 403 | Valid credentials, insufficient role |
| `PASSWORD_CHANGE_REQUIRED` | 403 | Must change password before accessing this resource |
| `TENANT_SUSPENDED` | 403 | The tenant has been suspended by the platform operator - all its traffic is rejected until reactivation |
| `PROXY_REQUIRES_API_KEY` | 403 | `POST /v1/chat/completions` called with a JWT session - the proxy accepts API keys only |
| `FEATURE_UNAVAILABLE` | 403 | The requested capability is not served for this caller. `params.feature` names it. The cause - a credential class, a detection layer disabled by policy - is deliberately not distinguished, so the response never reveals tenant configuration |
| `IP_NOT_ALLOWED` | 403 | The API key was presented from an address outside its `ip_allowlist`. Returned on every endpoint the key can reach, in that endpoint's envelope shape |
| `NOT_FOUND` | 404 | Resource does not exist. `params.resource` names which kind, as a stable token (see below) |
| `CONFLICT` | 409 | Duplicate (e.g. email already registered) |
| `IDEMPOTENCY_CONFLICT` | 409 | Same Idempotency-Key, different body |
| `VALIDATION_ERROR` | 422 | Body failed validation |
| `ACCOUNT_LOCKED` | 429 | Too many failed login attempts - includes `retry_after` seconds |
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit exceeded - includes `retry_after` seconds |
| `LLM_UNAVAILABLE` | 502 | `POST /v1/ai/request` with `execution_mode: proxy`: the scan completed, the provider did not return a usable answer. No `output` is returned; the scan itself is audited and readable at the `trace_id` in the error |
| `INTERNAL_ERROR` | 500 | Unexpected server error |
| `input_blocked` | 400 | Proxy: input blocked by policy |
| `output_blocked` | 400 | Proxy: output blocked by policy |
| `provider_timeout` | 504 | Proxy: provider timed out |
| `provider_unreachable` | 502 | Proxy: provider connection failed |
| `proxy_not_configured` | 400 | Proxy: no provider configured |
| `invalid_model_format` | 400 | Proxy: model must be `provider/model` |
| `trial_proxy_disabled` | 403 | Proxy: not available for trial keys |

**Convention:** `UPPERCASE` = platform/infrastructure errors. `lowercase` = security/proxy runtime errors.

**`NOT_FOUND` resource tokens:** a `NOT_FOUND` carries `error.params.resource`, naming what was
not found. It is a stable machine-readable localization token, not presentation text: it is
lowercase, unspaced, and does not change with the caller's language. Display
`error.message`, which is already resolved, or resolve your own label from the token. Do not
render `params.resource` directly.

| Token | Returned by |
|---|---|
| `request` | `GET /v1/ai/requests/{trace_id}` |
| `application` | `POST /v1/keys` |
| `department` | `POST /v1/keys` |
| `interaction` | `GET /v1/proxy/interactions/{trace_id}` |
| `proxy_provider` | `GET /v1/settings/proxy`, `DELETE /v1/settings/proxy` |

The vocabulary is add-only: a new resource may appear, an existing token is not renamed or
repurposed. Treat an unrecognised token as opaque and fall back to `error.message`.

---

## Idempotency

`POST /v1/ai/request` supports `Idempotency-Key`. Scoped per API key - two keys with the same value do not collide.

| Scenario | Behaviour |
|---|---|
| First request | Process normally, cache response (60s TTL) |
| Same key + same body | Return cached response, `X-Idempotency-Replayed: true` |
| Same key + different body | `409 IDEMPOTENCY_CONFLICT` |

`POST /v1/chat/completions` supports idempotency too: a client retry with the same `Idempotency-Key` and body replays the cached response instead of calling the paid provider a second time.

---

## Capabilities

***Published.***

### GET /v1/capabilities

*PUBLIC - in the published OpenAPI contract.*

Which optional plugin capabilities are active in this deployment. The dashboard uses this to show or hide the corresponding UI. Informational only - this endpoint is never an authorization control; features enforce their own gates at request time.

**Auth:** any valid principal (API key or JWT).

**Response 200:**
```json
{"edition": "oss", "capabilities": []}
```

The OSS edition always returns an empty set. An enterprise deployment lists the capabilities its installed plugin registered (filtered by the `WRAPSEC_FEATURES` deployment ceiling, if set). `edition` is display metadata, not an authorization claim.

---

## Setup Endpoints

*First-run deployment. **No operation in this section is published**; the installer and the dashboard use them.*

### GET /v1/setup/status

*NOT PUBLIC - first-run deployment. Served and supported; outside the published contract.*

Returns whether the system has been initialized. Used by the dashboard to determine whether to redirect to `/setup` on first visit. Redis-cached after initialization - no DB load on subsequent calls.

**Auth:** Public.

**Response:**
```json
{"initialized": true}
```

---

### POST /v1/setup

*NOT PUBLIC - first-run deployment. Served and supported; outside the published contract.*

Creates the first admin user. Only succeeds when no users exist. Returns `404` once initialized - permanently self-disabled after first use.

**Auth:** Public.

**Request:**
```json
{"email": "admin@example.com", "password": "YourPassword1!"}
```

**Response `201`:**
```json
{"message": "Setup complete. You can now sign in."}
```

**Response `404`:** System already initialized.

**Response `422`:** Validation error - weak password or invalid email.

---

## Auth Endpoints

*Human session flow. **No operation in this section is published.** They remain served and supported - this is how a dashboard user or an operator obtains and refreshes a JWT - but an integration authenticates with an API key instead.*

### POST /v1/auth/login

*NOT PUBLIC - human session flow. Served and supported; outside the published contract.*

Authenticate with email and password. Returns JWT access token. Sets refresh token as httpOnly cookie.

**Auth:** Public.

**Request:**
```json
{"email": "admin@example.com", "password": "YourPassword1!"}
```

Email is validated (RFC 5322) before reaching the service.

**Response 200:**
```json
{
  "access_token":          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type":            "bearer",
  "expires_in":            1800,
  "force_password_change": false,
  "user": {
    "id":        "681e5017-22f3-40bc-8731-f0bb3a98c26d",
    "email":     "admin@example.com",
    "role":      "ADMIN",
    "dept_id":   null,
    "tenant_id": "42a083bf-5cad-4b65-84d1-b81def88c9f3"
  }
}
```

Sets cookie: `refresh_token=<raw>; HttpOnly; Secure; SameSite=Strict; Path=/v1/auth; Max-Age=2592000`

> `Secure` is present when `COOKIE_SECURE=true` (default). Set `COOKIE_SECURE=false` only for local HTTP dev environments. All deployed environments must leave this at its default.

**When `force_password_change: true`:** The access token is valid but middleware blocks all endpoints except `/v1/auth/change-password`, `/v1/auth/logout`, and `/v1/auth/me`. User must change password before doing anything else.

**Errors:**

| Code | HTTP | Condition |
|---|---|---|
| `INVALID_CREDENTIALS` | 401 | Wrong email or wrong password - same message for both |
| `ACCOUNT_DISABLED` | 401 | User `is_active = false` - always returned to the client when login is rejected due to a deactivated account |
| `ACCOUNT_LOCKED` | 429 | 5 failed attempts. Body includes `retry_after` seconds. |

---

### POST /v1/auth/refresh

*NOT PUBLIC - human session flow. Served and supported; outside the published contract.*

Issues a new access token using the refresh token cookie. Rotates the refresh token - old token is immediately revoked.

**Auth:** httpOnly cookie (`refresh_token`, `Path=/v1/auth`). No body required.

**Response 200:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type":   "bearer",
  "expires_in":   1800
}
```

Sets a new rotated `refresh_token` cookie. Parallel refresh requests with the same token: first wins, second gets 401.

**Errors:**

| Code | HTTP | Condition |
|---|---|---|
| `INVALID_TOKEN` | 401 | Cookie missing, token expired, or already revoked |
| `SESSION_INVALIDATED` | 401 | Token version mismatch (password changed, role changed, etc.) |

---

### POST /v1/auth/logout

*NOT PUBLIC - human session flow. Served and supported; outside the published contract.*

Revokes the refresh token. Access token expires naturally (max 30 min residual). Clears cookie.

**Auth:** JWT Bearer required.

**Request body (optional):**
```json
{"reason": "manual"}
```

`reason` values: `manual` (default) | `inactivity` | `expired`

Invalid reason values are normalized to `manual` - never returns 400 for bad reason.
Reason is stored in `auth_events.failure_reason` for audit and debugging.

**Response 200:**
```json
{"message": "Logged out successfully."}
```

Idempotent - safe to call multiple times.

---

### GET /v1/auth/me

*NOT PUBLIC - human session flow. Served and supported; outside the published contract.*

Returns the current user's profile. Accessible even when `force_password_change = true`.

**Auth:** JWT Bearer required.

**Response 200:**
```json
{
  "id":                    "681e5017-22f3-40bc-8731-f0bb3a98c26d",
  "email":                 "admin@example.com",
  "role":                  "ADMIN",
  "dept_id":               null,
  "tenant_id":             "42a083bf-5cad-4b65-84d1-b81def88c9f3",
  "is_active":             true,
  "force_password_change": false,
  "last_login_at":         "2026-04-25T10:05:18.240865"
}
```

---

### POST /v1/auth/change-password

*NOT PUBLIC - human session flow. Served and supported; outside the published contract.*

Changes the user's password. Immediately invalidates all active sessions (all refresh tokens revoked, token_version incremented). Accessible even when `force_password_change = true`.

**Auth:** JWT Bearer required.

**Request:**
```json
{"current_password": "OldPassword1!", "new_password": "NewPassword2026!"}
```

Password requirements: minimum 8 chars, at least 1 uppercase, 1 lowercase, and 1 digit.

**Response 200:**
```json
{"message": "Password changed. All sessions have been invalidated."}
```

Clears the refresh token cookie. User must log in again.

**Errors:**

| Code | HTTP | Condition |
|---|---|---|
| `INVALID_PASSWORD` | 401 | Current password incorrect |
| `INVALID_REQUEST` | 400 | New password too weak |

---

## User Management

*Membership administration, dashboard surface. **No operation in this section is published.***

All `/v1/admin/users` endpoints require **JWT + ADMIN role**. API keys cannot access these endpoints.

### POST /v1/admin/users

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Creates a new dashboard user. `force_password_change` is always set to `true` - user must change password on first login.

**Request:**
```json
{
  "email":    "dev@example.com",
  "password": "TempPassword1!",
  "role":     "DEVELOPER",
  "dept_id":  "4111d663-47e3-4632-bf92-46a6b24a92f8"
}
```

`dept_id` is required for `DEVELOPER` and `VIEWER`. `ADMIN` users have `dept_id = null` and see all department data.

**Response 201:**
```json
{
  "id":                    "d4d555e7-e81c-45bf-b753-b690e244c98d",
  "email":                 "dev@example.com",
  "role":                  "DEVELOPER",
  "dept_id":               "4111d663-47e3-4632-bf92-46a6b24a92f8",
  "tenant_id":             "42a083bf-5cad-4b65-84d1-b81def88c9f3",
  "is_active":             true,
  "force_password_change": true,
  "created_at":            "2026-04-25T10:05:59.490874",
  "last_login_at":         null
}
```

**Errors:** `409 CONFLICT` - email already registered. `400 INVALID_REQUEST` - weak password, invalid role, missing dept_id, dept from different tenant.

---

### GET /v1/admin/users

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Lists all users for the tenant. Scoped to caller's `tenant_id` - never cross-tenant.

**Query params:** `role`, `is_active`, `limit` (default 50), `offset`

**Response 200:**
```json
{
  "total": 3,
  "users": [
    {
      "id":                    "...",
      "email":                 "dev@example.com",
      "role":                  "DEVELOPER",
      "dept_id":               "...",
      "tenant_id":             "...",
      "is_active":             true,
      "force_password_change": false,
      "created_at":            "2026-04-25T10:05:59.490874",
      "last_login_at":         "2026-04-25T10:10:00.000000"
    }
  ]
}
```

---

### GET /v1/admin/users/{user_id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Returns a single user. Returns `404` if user belongs to a different tenant.

**Response 200:** Same shape as individual item in list above.

---

### PATCH /v1/admin/users/{user_id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Partially updates `role`, `dept_id`, or `is_active`. All fields optional - only provided fields are updated. Validation is performed on the **final state** (combined role + dept_id), not individual fields independently.

**Request:**
```json
{"role": "VIEWER", "dept_id": "4111d663-...", "is_active": true}
```

**Validation rules:**
- `role = ADMIN` -> `dept_id` must be absent or null
- `role != ADMIN` -> `dept_id` must not be null
- `dept_id` must belong to the same tenant as the user

**Side effects by field:**

| Field | token_version | Session invalidated |
|---|---|---|
| `role` changed | ++ | Yes |
| `dept_id` changed | ++ | Yes |
| `is_active = false` (deactivate) | ++ | Yes |
| `is_active = true` (reactivate) | unchanged | No |

**Guards:**
- **Self-deactivation:** Admin cannot set `is_active = false` on their own account. Returns `400 INVALID_REQUEST`.
- **Last-admin protection:** Cannot demote or deactivate the last active ADMIN. Returns `400 INVALID_REQUEST`.

**Response 200:** Updated user object (same shape as GET).

---

### POST /v1/admin/users/{user_id}/reset-password

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Admin resets a user's password. Sets `force_password_change = true`. Invalidates all active sessions.

**Request:**
```json
{"new_password": "TempPassword1!"}
```

**Response 200:**
```json
{
  "message": "Password reset. User must change password on next login.",
  "user_id": "d4d555e7-e81c-45bf-b753-b690e244c98d"
}
```

---

## Gateway

***Every operation in this section is published.** This is the core integrator surface.*

### POST /v1/ai/request

*PUBLIC - in the published OpenAPI contract.*

Scan-only mode. Inspect input, get a security decision, then forward to your LLM if ALLOW or SANITIZE.

**Auth:** API key OR JWT Bearer.

**Request:**
```json
{
  "input":          "string - required, 1-8000 chars",
  "detection_mode": "fast | full  (default: fast)",
  "execution_mode": "scan_only  (default)",
  "input_source":   "user_prompt (default) | tool_output | retrieved_document | external_content | agent_tool_call",
  "session_id":     "string - optional, opaque, groups a multi-turn conversation",
  "turn_index":     "int - optional, 0-based turn within session_id",
  "run_id":         "string - optional, opaque, one agent execution",
  "metadata": {
    "user_id": "string - optional, self-reported, stored in audit",
    "source":  "string - optional, audit label"
  },
  "options": {
    "debug": false
  }
}
```

`debug: true` requires the admin key. Returns extra `debug` block with per-layer scores.

**detection_mode:**
- `fast` - rule + ML only (~5ms)
- `full` - rule + ML + LLM semantic (~100-500ms additional)

**input_source** is the trust-boundary provenance of `input`: where the text came from. Use `tool_output`, `retrieved_document`, or `external_content` for content an agent pulled in (the indirect prompt-injection surface); `agent_tool_call` for arguments a model composed for a tool invocation; `user_prompt` (the default) for the end user's own message. It never relaxes detection - identical content scores identically whatever origin it claims. It can, opt-in, tighten the *policy* thresholds applied to untrusted origins (see [Source-aware policy posture](#source-aware-policy-posture)); off by default.

**session_id / turn_index / run_id** are optional correlation identifiers, persisted on the audit record. `run_id` groups one agent execution; its turns are returned as a timeline by `GET /v1/agent-runs/{run_id}`.

**Response 200:**
```json
{
  "trace_id":             "req_01knzhh81wrwg2r8r7wnwq139y",
  "decision":             "BLOCK",
  "decision_version":     "v1.0",
  "risk_score":           0.85,
  "primary_reason":       "RULE_DETECTOR",
  "confidence":           0.75,
  "confidence_band":      "HIGH",
  "threats":              ["PROMPT_INJECTION"],
  "sanitization_applied": false,
  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only"
  },
  "assessment": {
    "decision":        "BLOCK",
    "risk_score":      0.85,
    "risk_level":      "HIGH",
    "primary_reason":  "RULE_DETECTOR",
    "confidence":      0.75,
    "confidence_band": "HIGH",
    "threats":         ["PROMPT_INJECTION"],
    "layers": [
      { "name": "rule_score", "score": 0.85, "decision": "BLOCK" },
      { "name": "ml_score",   "score": 0.20, "decision": "ALLOW" }
    ]
  }
}
```

The `assessment` object is an always-present, self-contained security verdict - the decision, reasons, threats, and confidence, plus per-layer detector contributions (the full layer bag, not just the fixed keys). Agents and the MCP tool consume this single object; the top-level fields remain for backward compatibility.

**Per-layer scores are restricted.** `assessment` is always present for every caller, and so is every entry in `assessment.layers` with its `name` and its `decision`. The numeric `score` on each entry is returned only to callers holding `settings:read` and not using a trial key -- the same boundary `GET /v1/settings` and `GET /health/config` apply. A live API key resolves to `DEVELOPER` and holds it; trial keys and `VIEWER` do not.

The predicate is `holds_permission(request, "settings:read")`, which answers the
same question `GET /v1/settings` enforces: the principal holds `settings:read`
**and** the request is not on a trial key. Caller by caller:

| Caller | Holds `settings:read` | `layers[].score` |
|---|---|---|
| `ADMIN` (JWT) | yes | returned |
| `DEVELOPER` (JWT) | yes | returned |
| Live API key (`wsk_live_...`, resolves to `DEVELOPER`) | yes | returned |
| `AUDITOR` (JWT) | yes - read-only, but carries `settings:read` | returned |
| `VIEWER` (JWT) | no | **omitted** |
| Trial API key (`wsk_trial_...`) | refused regardless of role | **omitted** |

**Restricted callers see the field absent, not null.** Each entry in
`assessment.layers` still carries `name` and `decision`; the `score` key is not
present at all. A client must treat a missing `score` as "not authorized to see
it", never as a zero or a missing detection:

```json
// settings:read, live key            // VIEWER or trial key
{ "name": "rule_score",               { "name": "rule_score",
  "score": 0.85,                        "decision": "BLOCK" }
  "decision": "BLOCK" }
```

Nothing else changes: `decision`, `risk_score`, `primary_reason`, `confidence`, `threats`, and each layer's classification are returned to everyone. The same restriction applies to `detection_scores` and `guardrail_scores` on `GET /v1/ai/requests/{trace_id}`, which persist the same numbers -- otherwise a caller reads back from the audit record what the scan response withheld.

**Why.** A per-layer score is a targeting signal: it says how much each detector contributed, so an author reworking a payload learns which layer to work against and how far it has to move. That is what makes evasion cheaper, and it is why the `debug` block carrying the same numbers is admin-gated and separately rate-limited.

**What this is not.** It is not threshold confidentiality. `risk_score` and `decision` are returned to every caller, and a binary search over them recovers a threshold to six decimal places in about two dozen probes without reading any layer field. Nor does it end targeting: the classification is preserved deliberately, so a caller can still see which layer sits in which bucket. The signal narrows from a float to three states. Both limits are stated because a control defended with a claim that does not hold is one that gets removed the first time someone checks.

`sanitized_input` is present only when `decision = SANITIZE`. Use it instead of the original input when forwarding to your LLM.

`policy_source` is **not** in the scan response - it appears only in `GET /v1/ai/requests/{trace_id}`.

**Decision values:** `ALLOW` | `BLOCK` | `SANITIZE`

**Primary reason values:**

| Value | Trigger |
|---|---|
| `RULE_DETECTOR` | Rule detector highest score |
| `ML_DETECTOR` | ML classifier highest score |
| `LLM_DETECTOR` | LLM semantic detector highest score |
| `PII_GUARDRAIL_BLOCK` | PII score at or above block threshold |
| `PII_GUARDRAIL_SANITIZE` | PII score at or above sanitize threshold |
| `TOXICITY_GUARDRAIL_BLOCK` | Toxicity score at or above block threshold (BLOCK-only tier; see note below) |
| `NO_THREAT_DETECTED` | All detectors ran, no threat found |
| `SYSTEM_ERROR` | Detector failure or exception |

**Confidence bands:**

| Band | Range |
|---|---|
| `HIGH` | 0.7 - 1.0 |
| `MEDIUM` | 0.4 - 0.7 |
| `LOW` | 0.0 - 0.4 |

**`SYSTEM_ERROR` behaviour is FAIL-CLOSED.** When a detector or guardrail cannot run, the request is REFUSED: `decision = BLOCK`, `risk_score = 1.0`, `primary_reason = SYSTEM_ERROR`, `confidence = 0.0`, `confidence_band = LOW`. This covers a detector that times out and a detector that fails internally - detectors do not propagate exceptions, they report a fault on the result they return, and the gateway treats the two identically. A request that could not be inspected is never forwarded to an LLM, and a provider response the output guard could not inspect is never returned to the caller.

`SYSTEM_ERROR` is a `primary_reason`, never a `decision` value -- do not branch on a `SYSTEM_ERROR` decision, because there is none. Honouring `decision` is sufficient: it is already `BLOCK`. Use `primary_reason` to tell a refusal caused by a detector failure from one caused by content, since the two are indistinguishable from `decision` alone.

**`risk_score = 0.0` does not mean safe.** Guardrails can BLOCK with `risk_score = 0.0`. Always check `decision`.

**Toxicity guardrail is BLOCK-or-ALLOW only.** Unlike PII (which has an ANONYMIZE / SANITIZE tier), toxic content cannot be safely rewritten by pattern substitution without changing meaning. Toxicity above the block threshold returns `decision = BLOCK` with `primary_reason = TOXICITY_GUARDRAIL_BLOCK`; below it, the toxicity guardrail does not fire (the request may still SANITIZE or BLOCK via PII or detection tiers). This mirrors AWS Bedrock content filter semantics.

---

### POST /v1/ai/scan-batch

*PUBLIC - in the published OpenAPI contract.*

Scan many items in one request. Every item runs the same pipeline as
`POST /v1/ai/request` (scan-only; no proxy/LLM forwarding) and is audited
independently, so batch scans appear in the audit trail and timeline exactly
like single scans. Built for retrieval-augmented flows: scan a page of retrieved
chunks and drop the ones that come back `BLOCK`.

**Auth:** API key OR JWT Bearer.

**Rate limit:** a batch is charged as N units (one per item), not 1, so it cannot
amplify throughput past the per-minute limit. Item count is capped by
`MAX_BATCH_ITEMS` (default 50). The semantic cache is bypassed.

**Request:**
```json
{
  "detection_mode": "fast | full  (default: fast)",
  "items": [
    { "input": "string - required, 1-8000 chars",
      "input_source": "user_prompt (default) | tool_output | retrieved_document | external_content | agent_tool_call",
      "id": "string - optional, echoed back on the matching result" }
  ]
}
```

**Response 200:**
```json
{
  "count": 2,
  "summary": {
    "blocked":           1,
    "sanitized":         0,
    "allowed":           1,
    "highest_risk":      0.91,
    "highest_risk_item": "chunk-7",
    "threats":           ["PROMPT_INJECTION"]
  },
  "results": [
    { "id": "chunk-3", "trace_id": "req_...", "decision": "ALLOW", "assessment": { } },
    { "id": "chunk-7", "trace_id": "req_...", "decision": "BLOCK", "assessment": { } }
  ]
}
```

`results` preserve input order; each carries the same `assessment` object as a
single scan. Read `summary` for a quick health check (and jump to the riskiest
item via `highest_risk_item`), then drop the `results` whose `decision == BLOCK`.

SDK helpers wrap this endpoint: `scan_batch()` plus the per-source sugar
`scan_documents()` / `scan_tool_outputs()` / `scan_external()`, and
`filter_safe()` which returns only the inputs safe to use.

---

### GET /v1/agent-runs/{run_id}

*PUBLIC - in the published OpenAPI contract.*

Return every scan belonging to one agent run (shared `run_id`), ordered as a timeline (`turn_index`, then `created_at`). Read-only, derived from `audit_logs`. Models the run as a first-class agentic resource (aligned with OpenTelemetry GenAI / LangSmith / OpenAI-Assistants run semantics).

**Auth:** API key OR JWT Bearer.

**Scoping:** tenant/department scoped. A `run_id` outside the caller's scope returns an empty timeline (never another tenant's rows).

**Query params:**
- `limit` - int, 1-1000 (default 500)

**Response 200:**
```json
{
  "run_id": "run_2d14a30194b1",
  "count":  4,
  "turns": [
    {
      "trace_id":       "req_...",
      "turn_index":     0,
      "decision":       "ALLOW",
      "input_source":   "user_prompt",
      "primary_reason": "NO_THREAT_DETECTED",
      "risk_score":     0.02,
      "timestamp":      "2026-08-04T18:51:00.000Z"
    }
  ]
}
```

Each turn is a full audit item (same shape as `GET /v1/audit/logs` items), including `input_source`, `session_id`, and `turn_index`.

---

### GET /v1/ai/requests/{trace_id}

*PUBLIC - in the published OpenAPI contract.*

Retrieve a stored request by trace ID. For proxy requests, joins `proxy_interactions` and returns the full lifecycle in a `proxy` key.

**Auth:** API key OR JWT Bearer.

**Scoping:** Non-admin identities can only retrieve records from their own department. Cross-department lookups return `404 NOT_FOUND`.

**Response 200 - scan_only:**
```json
{
  "trace_id":       "req_01knzhh81wrwg2r8r7wnwq139y",
  "timestamp":      "2026-04-20T01:29:46.000000",
  "execution_mode": "scan_only",
  "is_proxy":       false,
  "severity":       "HIGH",
  "decision":       "BLOCK",
  "risk_score":     0.85,
  "primary_reason": "RULE_DETECTOR",
  "confidence":     0.75,
  "confidence_band": "HIGH",
  "threats":        ["PROMPT_INJECTION"],
  "input_hash":     "sha256:abc123...",
  "input_length":   42,
  "detection_scores":  {"rule": 0.9, "ml": 0.8, "llm": 0.0},
  "guardrail_scores":  {"pii": 0.0},
  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "policy_source":  "department_override"
  },
  "attribution": {
    "tenant_id":           "42a083bf-...",
    "dept_id":             "4111d663-...",
    "dept_name":           "Engineering",
    "app_id":              "7a576570-...",
    "app_name":            "Code Assistant",
    "source":              "code-assistant",
    "user_id":             "user_123",
    "key_id":              "key:wsk_live_eng_...",
    "ip_address":          "10.0.0.1",
    "user_agent":          "Mozilla/5.0...",
    "attribution_verified": false
  }
}
```

**Response 200 - proxy request (adds `proxy` key):**
```json
{
  "trace_id":       "req_01...",
  "execution_mode": "proxy",
  "is_proxy":       true,
  "decision":       "SANITIZE",
  "...":            "all scan_only fields present",
  "proxy": {
    "provider":              "openai",
    "model":                 "gpt-4o",
    "provider_latency_ms":   350,
    "total_latency_ms":      412,
    "execution_status":      "SUCCESS",
    "input_primary_reason":  "PII_GUARDRAIL_SANITIZE",
    "input_confidence":      0.75,
    "input_threats":         ["PII"],
    "input_attack_type":     null,
    "input_raw":             "my email is [EMAIL REDACTED], ...",
    "input_sanitized":       "my email is [EMAIL REDACTED], ...",
    "output_decision":       "ALLOW",
    "output_primary_reason": "NO_THREAT_DETECTED",
    "output_confidence":     1.0,
    "output_threats":        [],
    "output_raw":            "4",
    "output_sanitized":      null,
    "behavior_flag":         null,
    "output_flags":          null
  }
}
```

Note: `input_decision` is absent from the `proxy` block. The top-level `decision` field is the canonical input verdict.

**Execution status values:**

| Status | Condition |
|---|---|
| `SUCCESS` | Input ALLOW/SANITIZE, provider responded, output ALLOW/SANITIZE |
| `BLOCKED` | Input was BLOCK - provider never called |
| `OUTPUT_BLOCKED` | Input clean, provider responded, output was BLOCK |
| `FAILED` | Provider call failed (network/auth/HTTP 5xx) |
| `TIMEOUT` | Provider did not respond within `timeout_seconds` |

**`input_raw` field:** Stores text according to `DATA_STORAGE_MODE` - not always the original unmodified text. In `masked` mode it contains PII-redacted text.

---

## Source-aware policy posture

Trust-boundary provenance (`input_source`) can, opt-in, tighten the **policy**
thresholds applied to untrusted origins. It is off by default and never touches
detection: the same content produces the same risk score and the same per-layer
contributions regardless of the source it claims. Source changes only how
strictly WrapSec *acts* on that score, so a caller cannot weaken detection by
misdeclaring a source.

**How it works.** A Source Registry classifies each `input_source` into a trust
tier (`trusted` / `untrusted` / `unknown`); for an untrusted tier a Policy
Adapter lowers the block and sanitize thresholds by a configured delta (both by
the same amount, preserving `block > sanitize`). The policy engine then decides
on those effective thresholds. When a source actually shifts the thresholds, the
scan `assessment` gains a `posture` block:

```json
"posture": {
  "dimension":          "source",
  "input_source":       "retrieved_document",
  "tier":               "untrusted",
  "applied_delta":      0.1,
  "effective_block":    0.6,
  "effective_sanitize": 0.3
}
```

**Configuration** (all environment variables; feature off when the delta is 0):

| Var | Default | Meaning |
|---|---|---|
| `UNTRUSTED_THRESHOLD_DELTA` | `0.0` | Amount to lower block/sanitize thresholds for untrusted sources. `0` disables the feature. |
| `TRUSTED_INPUT_SOURCES` | `["user_prompt"]` | Sources classified as trusted. |
| `UNTRUSTED_INPUT_SOURCES` | `["tool_output","retrieved_document","external_content"]` | Sources classified as untrusted. |
| `TREAT_UNKNOWN_AS_UNTRUSTED` | `false` | Treat a source in neither list as untrusted (full Zero-Trust) instead of base posture. |

**Calibration note.** On the current FAST-mode detector the aggregated risk
score is bimodal (near 0 or near 1), so a threshold delta has little to move -
`tests/eval/calibrate_source_posture.py` measures this against the RAG corpus.
Keep the default `0` until graded/mid-band scoring lands; the delta is the knob
for operators who want a stricter stance on untrusted content once it does.

---

## Proxy - AI Interaction Firewall

WrapSec acts as a drop-in replacement for the OpenAI API.

```python
# Before
client = OpenAI(api_key="sk-openai-...", base_url="https://api.openai.com/v1")
response = client.chat.completions.create(model="gpt-4o", messages=[...])

# After - point at WrapSec
client = OpenAI(api_key="wsk_live_...", base_url="http://localhost:8000/v1")
response = client.chat.completions.create(model="openai/gpt-4o", messages=[...])
```

**Model format:** `{provider}/{model}` - always required. Examples: `openai/gpt-4o`, `ollama/gemma3:4b`.

### POST /v1/chat/completions

*PUBLIC - in the published OpenAPI contract.*

**Auth:** live API key only. Trial keys: `403 trial_proxy_disabled`. JWT (dashboard) sessions: `403 PROXY_REQUIRES_API_KEY` regardless of role.

**Request (OpenAI-compatible):**
```json
{
  "model":       "openai/gpt-4o",
  "messages":    [{"role": "user", "content": "What is the capital of France?"}],
  "temperature": 0.7,
  "max_tokens":  500
}
```

**Accepted parameters - this is the complete list:**

| Field | Type | Notes |
|---|---|---|
| `messages` | array | Required |
| `model` | string | `provider/model` format, e.g. `openai/gpt-4o`. A bare `gpt-4` is rejected with `invalid_model_format` |
| `temperature` | float | Optional |
| `max_tokens` | int | Optional |
| `top_p` | float | Optional |

The request schema forbids unknown fields, so **any other parameter returns `422`**,
including `stream`, `tools`, `tool_choice`, `functions`, `response_format`, `seed`,
`stop`, `n`, `presence_penalty`, `frequency_penalty`, `logit_bias`, `logprobs`, and
`user`. This is deliberate: every one of them either changes the response shape the
guardrails inspect or opens a path that bypasses output scanning. Streaming in
particular cannot be supported while the response is scanned before it is returned.

Client libraries built for the OpenAI API often set some of these by default - most
commonly `stream` - so a drop-in base-URL swap may need those options disabled
explicitly.

Message **roles** are validated too, and separately: `tool` and any unrecognised role are
rejected with `422` even when no tool-calling parameter is present. See "What gets
scanned" below.

**Two errors on this route are NOT OpenAI-shaped.** A request that fails schema
validation (`422`) is answered by the gateway's global validation handler, and a
dashboard session (`403 PROXY_REQUIRES_API_KEY`) is refused before the
OpenAI-compatible path begins. Both carry the standard WrapSec error envelope
rather than `{"error": {message, type, code}}`. Every other error on this
endpoint is OpenAI-shaped.

**Response differences from the OpenAI schema:**

- `usage` is **optional**. The provider's own token counts are passed through
  unchanged when it sends them, and the field is absent when it does not. Treat it
  as optional rather than guaranteed. The numbers are observability only: nothing
  in WrapSec prices, budgets, or bills against them.
- There is no `created` field.
- `id` is `wrapsec-{trace_id}`, which correlates with the audit trail rather than
  matching an upstream provider id.
- Each choice carries `index`, `message`, and `finish_reason` only.
- A response the security guard cannot inspect is **not forwarded**. A tool-call
  reply carries a null `content`, which cannot be scanned, so it is rejected with
  `provider_response_unsupported` rather than returned unchecked.

**WrapSec request headers:**

| Header | Default | Description |
|---|---|---|
| `X-WrapSec-Mode` | `fast` | Detection mode: `fast` or `full` |
| `X-WrapSec-Scan-All-Messages` | `false` | Scan every eligible message rather than the last one only (see "What gets scanned") |
| `X-WrapSec-Inline-Meta` | `false` | Include `wrapsec` key in response body |

**What gets scanned:**

A message is scanned according to the role that carries it, and the role also fixes how
far its content is trusted:

| Role | Accepted | Scanned | Trust classification |
|---|---|---|---|
| `user` | yes | yes | `user_prompt` |
| `assistant` | yes | **only when assistant scanning is enabled** | `external_content` |
| `system` | yes | no | - |
| anything else, `tool` included | **no - `422`** | - | - |

**Assistant scanning is off by default.** With the default configuration the proxy scans
`user` turns only, and assistant turns are accepted and forwarded without being inspected.
A message whose `content` is null or not a string carries no text and is skipped.

Set `SCAN_ASSISTANT_MESSAGES=true` to enable it. It is a global setting, not per tenant.

Enabling it is a real security gain: a conversation history is an injection surface, since
text a previous turn returned -- or that a caller placed in an assistant turn -- reaches
the model exactly as a user turn does, and an agent replaying tool output or a retrieved
page into an assistant turn is putting attacker-reachable content there.

It is off by default because of a measured cost, not caution. **The current detector flags
68% of ordinary assistant prose (15 of 22 benign cases; run
`python tests/eval/run_assistant_eval.py`).** An assistant turn quotes and explains what
was asked, so a refusal to a jailbreak contains the jailbreak and an answer about prompt
injection contains prompt injection. Turning this on today would refuse roughly two thirds
of normal replies. It will default on once that rate reaches 12%; until then, enable it
only after measuring what it does to your own traffic.

When enabled, an assistant turn that comes back `SANITIZE` is rewritten **in place** --
that message and no other -- and the rewritten text is what reaches the model.

**A role outside that table is refused with `422`, and the whole request is refused with
it** - the offending message is not dropped so the rest can proceed, because sending a
different conversation than the one asked for is not a safe default. The check is exact,
so `Tool` and `TOOL` are refused too, and a message with no `role` at all is refused.

The refusal is the standard validation envelope, with `invalid_params[].field` set to
`messages`. It does not name which message was at fault, so check the whole array against
the table above.

`tool` is refused rather than forwarded. Tool-mediated content is deferred in this
version, and a deferred feature has to fail loudly: forwarding a `tool` message would put
text the proxy never inspected in front of the model, which is the outcome the proxy
exists to prevent. This is a separate control from the rejection of native tool calling
(`tools`, `tool_choice`, `functions`) - each is refused on its own, and neither depends on
the other being reached first.

`system` is accepted and **forwarded to the provider without being inspected**, on the
basis that it is written by the application operator rather than supplied by an end user.
That is worth knowing before you build on it: if your application forwards
user-controlled text into a system message, that content reaches the model uninspected.
Put such content in a `user` or `assistant` message if you want it scanned.

Messages are scanned **individually and never concatenated**. Joining them would force
one trust classification onto content of differing origins, and would misreport
provenance whichever origin it picked.

- **Without** `X-WrapSec-Scan-All-Messages` (the default): the **last eligible** message
  is scanned. That is the last `user` or `assistant` message, whichever comes last -- not
  necessarily the last `user` message.
- **With** the header: every eligible message is scanned, in conversation order.

Each scanned message produces its own audit row carrying its own trust classification, so
a decision can be traced to the message that caused it. Those rows use a trace id derived
from the request's, suffixed with the message's position; `X-WrapSec-Trace-Id` remains the
request-level id.

**How several messages become one decision:**

The **strictest** message decides the request: `BLOCK` beats `SANITIZE` beats `ALLOW`, and
a higher risk score breaks a tie so the reported evidence names the most severe finding
rather than the first one seen. The response headers describe that message. A request is
only as safe as its worst message.

`SANITIZE` rewrites the offending message **in place**, assistant messages included; the
rest of the conversation is forwarded unchanged.

**Limits when scanning every message:**

Scanning is bounded at **10 eligible messages** per request (`MAX_SCAN_ALL_MESSAGES`).
Over that, the request is **rejected** with `400 too_many_messages` rather than truncated:
silently scanning part of a conversation would report a decision that did not cover what
was sent. A conversation with no eligible message at all is rejected with
`400 invalid_messages`.

Each scanned message costs a detection run and an audit-chain append, so **N scanned
messages consume N rate-limit units**, not one. A request scanning ten messages draws ten
units from the bucket for the presented key.

The maximum is deliberately low. The audit chain takes a per-tenant lock, so concurrent
requests from one tenant serialise on it, and the cost of a large fan-out lands on the
caller's own latency. Raise it only against a measurement of your own traffic.

**If you run the optional transformer build, measure before relying on Scan-All under
concurrency.** Detection is fail-closed: a detector that runs out of time is treated as a
failure and the message is blocked, and that block is indistinguishable from one caused by
the content. On the default build this does not arise. With the Tier-2 transformer
installed it does, at high concurrency, with nothing blocked on content.

The levers are `BATCH_CONCURRENCY`, `DETECTOR_TIMEOUT_SECONDS`, and a lower
`MAX_SCAN_ALL_MESSAGES`. `BATCH_CONCURRENCY` is the effective one, and its direction is
counter-intuitive -- lowering it improves refusals and latency together. See "Tuning
`BATCH_CONCURRENCY`" in `docs/developer_guide.md` before changing any of them.
`tests/load/scan_all_load.py` reports the rate for your own hardware, and takes
`--no-transformer` to compare build shapes.

**WrapSec response headers:**

`X-WrapSec-Trace-Id` accompanies every response **this endpoint produces**, including its early error exits (invalid model format, trial key rejection, provider config errors). Refusals that happen before the endpoint runs - authentication, the IP allowlist, a suspended tenant, an idempotency conflict, request validation, the gateway rate limiter - carry `X-Trace-Id` and the same value in `error.trace_id` instead. Correlate on either. All other `X-WrapSec-*` headers are present only when the request reached the detection pipeline.

| Header | Description |
|---|---|
| `X-WrapSec-Trace-Id` | Trace ID, `req_` + 32 hex characters - on every response the endpoint itself produces |
| `X-WrapSec-Input-Decision` | `ALLOW` / `BLOCK` / `SANITIZE` |
| `X-WrapSec-Input-Primary-Reason` | Primary reason for input decision |
| `X-WrapSec-Input-Confidence` | Input confidence (0.0-1.0) |
| `X-WrapSec-Input-Sanitized` | `true` if input was sanitized |
| `X-WrapSec-Output-Decision` | `ALLOW` / `BLOCK` / `SANITIZE` |
| `X-WrapSec-Output-Sanitized` | `true` if output was sanitized |
| `X-WrapSec-Execution-Status` | Execution status |
| `X-WrapSec-Provider` | Provider used |
| `X-WrapSec-Model` | Model name |
| `X-WrapSec-Latency-Ms` | Total end-to-end latency |

**Response 200 (OpenAI-compatible):**
```json
{
  "id":      "wrapsec-req_01...",
  "object":  "chat.completion",
  "model":   "gpt-4o",
  "choices": [{"index": 0, "message": {"role": "assistant", "content": "Paris."}, "finish_reason": "stop"}]
}
```

**Response 200 with `X-WrapSec-Inline-Meta: true`:**
```json
{
  "id":      "wrapsec-req_01...",
  "object":  "chat.completion",
  "model":   "gpt-4o",
  "choices": [...],
  "wrapsec": {
    "trace_id":             "req_01...",
    "decision":             "ALLOW",
    "input_primary_reason": "NO_THREAT_DETECTED",
    "input_confidence":     1.0,
    "input_was_sanitized":  false,
    "output_decision":      "ALLOW",
    "output_was_sanitized": false,
    "execution_status":     "SUCCESS",
    "provider":             "openai",
    "model":                "gpt-4o",
    "total_latency_ms":     412
  }
}
```

**Input blocked (400):**
```json
{
  "error": {"message": "Request blocked by security policy.", "type": "invalid_request_error", "code": "input_blocked"},
  "wrapsec": {
    "trace_id":             "req_01...",
    "decision":             "BLOCK",
    "input_primary_reason": "RULE_DETECTOR",
    "input_threats":        ["PROMPT_INJECTION"],
    "input_confidence":     0.96,
    "execution_status":     "BLOCKED"
  }
}
```

**Output blocked (400):**
```json
{
  "error": {"message": "Model response blocked.", "type": "invalid_request_error", "code": "output_blocked"},
  "wrapsec": {
    "trace_id":              "req_01...",
    "decision":              "ALLOW",
    "output_decision":       "BLOCK",
    "output_primary_reason": "PII_GUARDRAIL_BLOCK",
    "execution_status":      "OUTPUT_BLOCKED"
  }
}
```

**When an output BLOCK fires, and when it cannot.** The response is refused when
the PII score reaches `OUTPUT_BLOCK_THRESHOLD` (default `0.95`); between
`OUTPUT_SANITIZE_THRESHOLD` (default `0.01`) and that, the response is returned
with the values redacted instead. The two outcomes are different: SANITIZE
returns the model's answer with the personal data removed, BLOCK returns no
answer at all.

The default block threshold sits exactly on the highest score the PII detector
can produce, so BLOCK fires only at that maximum -- a response has to carry
enough distinct PII types to reach it, and a single credit-card number does not.
**Raising `OUTPUT_BLOCK_THRESHOLD` above `0.95` disables output blocking
entirely**, leaving SANITIZE as the strongest outcome, with nothing in the
response or the logs to say so. Lower it if you want blocking to trigger more
readily; there is no headroom above.

**Output scanning is PII-only, and is not symmetric with input detection.** The
output guard runs the PII detector and redactor, and nothing else. Every other
layer that inspects a prompt -- the rule, machine-learning, transformer, and LLM
detection tiers, and the toxicity guardrail -- runs on input only. A model
response is therefore never scored for prompt injection, jailbreak content, or
toxicity on its way back to you, and the only results it can produce are
`PII_GUARDRAIL_SANITIZE`, `PII_GUARDRAIL_BLOCK`, `NO_THREAT_DETECTED`, and
`SYSTEM_ERROR` when the guard could not run at all.

This is a capability limit, not a configuration one: no setting widens it. Read
`output_decision` as "the response was checked for personal data", not as "the
response was judged by the same pipeline as the prompt". If your threat model
includes what the model itself emits -- content policy, or output that a
downstream agent or tool will act on -- that check belongs outside the proxy
today.

---

## Proxy Interactions

***Both operations here are published.***

Read-only view of proxy request lifecycle records.

### GET /v1/proxy/interactions

*PUBLIC - in the published OpenAPI contract.*

Lists proxy interaction records.

**Auth:** API key OR JWT Bearer.

**Query params:** `execution_status`, `limit` (default 50, max 200), `offset`

**Response 200:**
```json
{
  "total":  142,
  "limit":  50,
  "offset": 0,
  "items": [
    {
      "id":                    "uuid",
      "trace_id":              "req_01...",
      "created_at":            "2026-04-25T10:00:00Z",
      "key_id":                "key_abc123",
      "user_id":               null,
      "input_decision":        "ALLOW",
      "input_primary_reason":  "NO_THREAT_DETECTED",
      "input_confidence":      1.0,
      "input_threats":         [],
      "input_attack_type":     null,
      "provider":              "openai",
      "model":                 "gpt-4o",
      "provider_latency_ms":   350,
      "execution_status":      "SUCCESS",
      "output_decision":       "ALLOW",
      "output_primary_reason": "NO_THREAT_DETECTED",
      "output_confidence":     1.0,
      "output_threats":        [],
      "behavior_flag":         null,
      "output_flags":          null,
      "total_latency_ms":      412
    }
  ]
}
```

Note: `input_raw`, `input_sanitized`, `output_raw`, `output_sanitized` are **not** included in list items.

### GET /v1/proxy/interactions/{trace_id}

*PUBLIC - in the published OpenAPI contract.*

Returns full interaction detail including raw text fields (subject to `DATA_STORAGE_MODE`).

**Response 200:** Same as list item plus:
```json
{
  "...": "all list fields",
  "input_raw":       "original or masked input text",
  "input_sanitized": "sanitized input or null",
  "output_raw":      "original or masked output text",
  "output_sanitized": "sanitized output or null"
}
```

Returns `404 NOT_FOUND` if trace_id not found.

---

## Proxy Settings

***Mixed section.** `GET`, `PUT` and `DELETE /v1/settings/proxy` are published; `GET /v1/settings/proxy/health` is an operator probe and is not.*

All proxy-settings operations - including reads and the health probe - require admin (JWT ADMIN or the admin API key): configuring an outbound provider and its credentials changes what leaves the system.

### PUT /v1/settings/proxy

*PUBLIC - in the published OpenAPI contract.*

Configure the LLM provider for proxy mode. One configuration per tenant, shared across all API keys. Replaces existing configuration entirely.

**Request:**
```json
{
  "provider":      "openai",
  "base_url":      "https://api.openai.com/v1",
  "api_key":       "sk-openai-...",
  "default_model": "gpt-4o",
  "timeout":       60
}
```

**providers:** `openai` (also covers Groq, Azure, Together AI, any OpenAI-compatible) | `ollama` | `custom`

`api_key` is required for `openai` and `custom` providers. `ollama` does not require one.

Provider API key is encrypted AES-256-GCM at rest. Never returned in responses - masked as `sk-...7890`.

**Response 200:**
```json
{
  "provider":        "openai",
  "base_url":        "https://api.openai.com/v1",
  "api_key_masked":  "sk-...7890",
  "default_model":   "gpt-4o",
  "timeout_seconds": 60,
  "created_at":      "2026-04-25T10:00:00Z",
  "updated_at":      "2026-04-25T10:00:00Z"
}
```

### GET /v1/settings/proxy

*PUBLIC - in the published OpenAPI contract.*

Returns current configuration (API key masked).

**Response 200:** Same shape as PUT response. `404 NOT_FOUND` if not configured.

### DELETE /v1/settings/proxy

*PUBLIC - in the published OpenAPI contract.*

Removes the proxy provider configuration. Returns `204 No Content` on success, `404 NOT_FOUND` if not configured.

### GET /v1/settings/proxy/health

*NOT PUBLIC - operator probe. Served and supported; outside the published contract.*

Tests connectivity to the configured provider.

**Response 200:**
```json
{
  "provider":      "openai",
  "base_url":      "https://api.openai.com/v1",
  "default_model": "gpt-4o",
  "reachable":     true,
  "latency_ms":    234
}
```

When unreachable, `reachable: false` and an `error` string are returned - still HTTP 200.

---

## Audit

***Mixed section.** `logs`, `stats` and `export` are published; `attribution`, `analytics` and `by-source` are dashboard analytics and are not.*

All audit endpoints scope non-admin identities to their own department - the `dept_id` query param is ignored for non-admin callers.

**Date parameters (`from`, `to`):** All audit endpoints that accept date filters require ISO 8601 format (e.g. `2026-01-15T00:00:00Z`). Malformed values return `400 INVALID_REQUEST` - they are not silently ignored. Empty or absent values apply no date filter.

### GET /v1/audit/logs

*PUBLIC - in the published OpenAPI contract.*

List audit log records.

**Auth:** API key OR JWT Bearer.

**Query params:**

| Param | Description |
|---|---|
| `trace_id` | Partial match |
| `decision` | `BLOCK` / `SANITIZE` / `ALLOW` |
| `threat_category` | e.g. `PROMPT_INJECTION`, `PII` |
| `primary_reason` | e.g. `RULE_DETECTOR`, `PII_GUARDRAIL_BLOCK` |
| `confidence_band` | `HIGH` / `MEDIUM` / `LOW` |
| `execution_mode` | `scan_only` / `proxy` |
| `key_id` | Filter by API key |
| `user_id` | Partial match on user_id |
| `source` | Partial match on source label |
| `dept_id` | Admin only |
| `app_id` | Filter by application |
| `from` | ISO datetime |
| `to` | ISO datetime |
| `sort_by` | `created_at` (default) / `risk_score` / `latency_ms` / `decision` |
| `sort_order` | `desc` (default) / `asc` |
| `limit` | Default 50, max 500 |
| `offset` | Default 0 |

**Response 200:**
```json
{
  "total": 1250,
  "items": [
    {
      "trace_id":             "req_01...",
      "timestamp":            "2026-04-20T01:29:46Z",
      "tenant_id":            "42a083bf-...",
      "decision":             "BLOCK",
      "primary_reason":       "RULE_DETECTOR",
      "risk_score":           0.85,
      "confidence":           0.75,
      "confidence_band":      "HIGH",
      "threats":              ["PROMPT_INJECTION"],
      "input_hash":           "sha256:abc123...",
      "detection_mode":       "fast",
      "execution_mode":       "scan_only",
      "latency_ms":           2.1,
      "severity":             "HIGH",
      "key_id":               "key_abc123",
      "dept_id":              "4111d663-...",
      "app_id":               "7a576570-...",
      "user_id":              "user_123",
      "source":               "code-assistant",
      "ip_address":           "10.0.0.1",
      "attribution_verified": false,
      "policy_source":        "department_override",
      "input_length":         42
    }
  ]
}
```

The example is abbreviated. Every item also carries `dept_name`, `app_name`,
`output_decision`, `provider`, `model` (the last three null unless the request
went through the proxy), `session_id`, `turn_index`, `run_id`, `input_source`,
`record_hash` and `prev_hash`. It is the same item `GET /v1/agent-runs/{run_id}`
returns as a turn -- one projection, one schema (`AuditItem`).

No match returns `{"total": 0, "items": []}`, never a 404. Fields that do not
apply are present and null; nothing is omitted.

### GET /v1/audit/stats

*PUBLIC - in the published OpenAPI contract.*

Aggregate statistics for a time range.

**Query params:** `tenant_id` (admin only), `from`, `to`

**Response 200:**
```json
{
  "period_from":     "2026-04-01T00:00:00Z",
  "period_to":       "2026-04-25T00:00:00Z",
  "total_requests":  1250,
  "block_count":     107,
  "sanitize_count":  64,
  "allow_count":     1079,
  "block_rate":      0.0856,
  "sanitize_rate":   0.0512,
  "allow_rate":      0.8632,
  "avg_latency_ms":  5.4,
  "p95_latency_ms":  12.1,
  "avg_risk":        0.1204,
  "top_threats":     [{"category": "PROMPT_INJECTION", "count": 87}],
  "severity_counts": {"CRITICAL": 12, "HIGH": 95, "MEDIUM": 64, "LOW": 1079}
}
```

Use the raw counts, not `rate * total_requests`: the rates are rounded to four
decimals, so a reconstructed count drifts by one against
`GET /v1/audit/logs?decision=BLOCK`.

A range matching nothing returns this same shape with every count, rate and
severity zeroed and `top_threats: []` -- not a 404, and not a shorter body.

**Severity values:**

| Severity | Condition |
|---|---|
| `CRITICAL` | `BLOCK` + (`risk_score >= 0.9` OR `primary_reason` ends with `_GUARDRAIL_BLOCK`) |
| `HIGH` | `BLOCK` + `risk_score < 0.9` |
| `MEDIUM` | `SANITIZE` (any reason) |
| `LOW` | `ALLOW` |

A `SYSTEM_ERROR` refusal is **`CRITICAL`**, not `HIGH`: fail-closed forces `risk_score = 1.0`, which meets the CRITICAL condition above. Alert rules that expect detector failures at `HIGH` will not match them.

Severity is computed at write time and stored in `audit_logs.severity`. Never returned in scan responses - audit and SIEM use only.

### GET /v1/audit/attribution

*NOT PUBLIC - dashboard analytics. Served and supported; outside the published contract.*

Attribution breakdown grouped by API key, department, application, primary reason, and confidence band.

**Query params:** `dept_id` (admin only), `limit` (default 10, max 100)

**Response 200:**
```json
{
  "by_key": [
    {
      "key_id":         "key_abc123",
      "source":         "code-assistant",
      "total":          450,
      "blocked":        38,
      "block_rate":     0.084,
      "avg_latency_ms": 5.2
    }
  ],
  "by_department": [
    {"dept_id": "4111d663-...", "total": 450, "blocked": 38, "block_rate": 0.084}
  ],
  "by_application": [
    {"app_id": "7a576570-...", "total": 200, "blocked": 17, "block_rate": 0.085, "avg_latency_ms": 5.1}
  ],
  "by_primary_reason": [
    {"primary_reason": "NO_THREAT_DETECTED", "count": 980},
    {"primary_reason": "RULE_DETECTOR", "count": 180}
  ],
  "by_confidence_band": [
    {"band": "HIGH", "count": 1100},
    {"band": "MEDIUM", "count": 120}
  ]
}
```

### GET /v1/audit/analytics

*NOT PUBLIC - dashboard analytics. Served and supported; outside the published contract.*

Time-series trend data grouped by time period.

**Query params:**

| Param | Description |
|---|---|
| `from` | ISO date |
| `to` | ISO date |
| `group_by` | `hour` / `day` (default) / `week` / `month` |
| `dept_id` | Admin only |

**Response 200:**
```json
{
  "group_by":   "day",
  "dept_id":    null,
  "from":       "2026-04-01",
  "to":         "2026-04-25",
  "total":      1250,
  "block_rate": 0.0856,
  "trend": [
    {
      "period":         "2026-04-25T00:00:00",
      "total":          142,
      "blocked":        12,
      "sanitized":      8,
      "allowed":        122,
      "block_rate":     0.085,
      "avg_risk_score": 0.12,
      "avg_latency_ms": 5.4
    }
  ]
}
```

### GET /v1/audit/by-source

*NOT PUBLIC - dashboard analytics. Served and supported; outside the published contract.*

Security by Source: audit aggregates grouped by `input_source` (trust-boundary
provenance), plus a Top Attack Origins ranking. Read-only over data already on
`audit_logs`; groups by whatever sources exist, so a new source appears with no
code change. Tenant/department scoped like `/stats`.

**Query params:** `from`, `to` (ISO dates), `dept_id` (admin only).

**Response 200:**
```json
{
  "period_from": "2026-08-01T00:00:00Z",
  "period_to":   "2026-08-05T00:00:00Z",
  "dept_id":     null,
  "sources": [
    {
      "input_source":    "retrieved_document",
      "total":           320,
      "blocked":         41,
      "sanitized":       3,
      "allowed":         276,
      "block_rate":      0.1281,
      "avg_risk":        0.18,
      "max_risk":        0.99,
      "high_risk_count": 44,
      "attacks":         44,
      "threats":         { "PROMPT_INJECTION": 38, "DATA_EXFILTRATION": 6 }
    }
  ],
  "top_attack_origins": [
    { "input_source": "retrieved_document", "attacks": 44, "total": 320 }
  ]
}
```

`attacks` is enforced-decision volume (BLOCK + SANITIZE). `top_attack_origins`
lists only sources that delivered attacks, ranked descending.

### GET /v1/audit/export

*PUBLIC - in the published OpenAPI contract.*

Exports audit logs as CSV.

**Returns:** `text/csv`, `Content-Disposition: attachment; filename=wrapsec_audit_export.csv`

**Known schema mismatch.** The published OpenAPI entry for this route currently
advertises `application/json` with an empty schema, because a route with no
response model gets that default. **This page is correct and the schema is not:
the body is CSV.** The response itself is unaffected - the advertised schema is
empty and constrains nothing - and the media type is scheduled to be corrected on
the route, after which the schema will say `text/csv`.

**Query params:** `dept_id`, `app_id`, `decision`, `primary_reason`, `confidence_band`, `from`, `to`, `limit` (default 1000, max 10000)

**CSV columns:** `trace_id`, `timestamp`, `decision`, `risk_score`, `confidence`, `confidence_band`, `primary_reason`, `threats`, `tenant_id`, `dept_id`, `app_id`, `key_id`, `source`, `user_id_prefix`, `ip_address_hash`, `policy_source`, `detection_mode`, `latency_ms`

**Privacy note:** `ip_address` is SHA-256 hashed (first 16 hex chars) and exported as `ip_address_hash`. `user_id` is truncated to the first 8 characters and exported as `user_id_prefix`. Both fields retain enough entropy for correlation within an export without exposing raw PII. Full values remain available in the database for authorized access.

---

## Settings

***Mixed section.** `thresholds`, `layers`, `llm` and `rate_limit` are published - the detection policy an integration reads. `retention`, `storage` and `admin_limits` are deployment configuration and are not.*

Settings are tenant-scoped: each tenant reads and writes its own values, layered over platform defaults. Reads require the `settings:read` permission (ADMIN, DEVELOPER, AUDITOR roles, or a live API key; VIEWER and trial keys are rejected). Writes require JWT + ADMIN.

### GET /v1/settings/thresholds

*PUBLIC - in the published OpenAPI contract.*

Returns current detection thresholds.

**Response 200:**
```json
{"block_threshold": 0.7, "sanitize_threshold": 0.4}
```

### PUT /v1/settings/thresholds

*PUBLIC - in the published OpenAPI contract.*

Updates detection thresholds. `block_threshold` must be greater than `sanitize_threshold`.

**Request:**
```json
{"block_threshold": 0.8, "sanitize_threshold": 0.5}
```

**Response 200:**
```json
{"block_threshold": 0.8, "sanitize_threshold": 0.5, "updated_at": "2026-04-25T10:00:00Z"}
```

### GET /v1/settings/layers

*PUBLIC - in the published OpenAPI contract.*

Returns current detection layer configuration.

**Response 200:**
```json
{"rule_enabled": true, "ml_enabled": true, "llm_enabled": true}
```

### PUT /v1/settings/layers

*PUBLIC - in the published OpenAPI contract.*

Enables or disables rule, ML, and LLM detection layers.

**Request:**
```json
{"rule_enabled": true, "ml_enabled": true, "llm_enabled": false}
```

**Response 200:**
```json
{"rule_enabled": true, "ml_enabled": true, "llm_enabled": false, "updated_at": "..."}
```

### GET /v1/settings/llm

*PUBLIC - in the published OpenAPI contract.*

Returns LLM detector configuration (detection layer only - separate from proxy provider).

**Response 200:**
```json
{"provider": "ollama", "model": "llama3.2", "base_url": "http://localhost:11434", "timeout": 30, "llm_trigger": 0.2, "api_key_masked": null}
```

`api_key_masked` is always present: `null` when no provider key is stored, a mask such as `sk-...7890` when one is, and `****` when a stored key cannot be decrypted with the current `SECRET_KEY`. The key itself is never returned.

### PUT /v1/settings/llm

*PUBLIC - in the published OpenAPI contract.*

Updates LLM detector configuration. Provider must be `ollama`, `openai`, or `groq`. Timeout 5-120 seconds.

**Request:**
```json
{"provider": "openai", "model": "gpt-4o-mini", "base_url": "https://api.openai.com/v1", "timeout": 30, "llm_trigger": 0.2}
```

### GET /v1/settings/retention

*NOT PUBLIC - deployment configuration. Served and supported; outside the published contract.*

Returns audit log retention period.

**Response 200:**
```json
{"retention_days": 30, "source": "database"}
```

`source` is `"database"` if explicitly set, `"environment"` if using the default.

### PUT /v1/settings/retention

*NOT PUBLIC - deployment configuration. Served and supported; outside the published contract.*

Sets audit log retention period. Min 7 days, max 3650 days (10 years).

**Request:**
```json
{"retention_days": 90}
```

### GET /v1/settings/rate_limit

*PUBLIC - in the published OpenAPI contract.*

Returns the current global rate limit for live keys.

**Response 200:**
```json
{"per_minute": 60, "source": "database"}
```

`source` is `"database"` if explicitly set, `"environment"` if using the default.

### PUT /v1/settings/rate_limit

*PUBLIC - in the published OpenAPI contract.*

Updates the global rate limit for live keys. Takes effect within 5 minutes (Redis cache TTL). Live key limit cannot be set below the trial key limit. Trial key limit is set via `TRIAL_RATE_LIMIT_PER_MINUTE` env var.

**Request:**
```json
{"per_minute": 120}
```

**Response 200:**
```json
{"per_minute": 120, "source": "database", "updated_at": "..."}
```

### GET /v1/settings/storage

*NOT PUBLIC - deployment configuration. Served and supported; outside the published contract.*

Returns data storage mode and proxy text retention period. Read-only - configured via environment variables.

**Response 200:**
```json
{"storage_mode": "masked", "retention_days_proxy": 7}
```

**`storage_mode` values:**

| Mode | Behaviour |
|---|---|
| `full` | Store text as-is |
| `masked` | PII-redact before storing (production default) |
| `none` | Never persist text - always `null` |

Text is purged (set to `null`) after `retention_days_proxy` days regardless of mode. Security metadata (decisions, threats, scores) is retained permanently.

---

## API Keys

***Mixed section.** `GET /v1/keys` and `POST /v1/keys` are published. The per-key operations - read, update, delete, rotate, addresses - are dashboard key administration and are not.*

### POST /v1/keys

*PUBLIC - in the published OpenAPI contract.*

Creates a new API key. Returns the raw key value once - store it securely, it cannot be retrieved again.

**Request:**
```json
{
  "name":     "Production Key",
  "dept_id":  "4111d663-47e3-4632-bf92-46a6b24a92f8",
  "app_id":   null,
  "key_type": "live",
  "ip_allowlist": ["10.0.0.0/8", "203.0.113.7/32"]
}
```

Provide `app_id` for app-scoped keys (dept and tenant derived from app). Provide `dept_id` for dept-scoped keys. `key_type`: `live` (default) or `trial`. Optional `expires_at` (ISO-8601): the key stops authenticating after this instant; omitted or `null` means no expiry. The response echoes the stored value.

Optional `ip_allowlist`: the source addresses or CIDR blocks this key may be used from. Omitted, `null`, or `[]` means no restriction. Entries are canonicalised on the way in, and a malformed entry is rejected with `422` rather than stored and silently skipped at enforcement time. A prefix length of zero (`0.0.0.0/0`, `::/0`) is rejected: it is a restriction that restricts nothing, so an empty list is the way to allow every address. A request presenting the key from an address outside the list is refused with `403`, and the refusal is recorded against that key. Rotation preserves the list.

The restriction is enforced at **authentication**, so it applies to **every** request that presents the key, on every endpoint, and a refused request reaches no handler: no policy resolution, no detection, no upstream call. The address is the one the connection actually came from -- a forwarded header is believed only when the immediate peer is a configured trusted proxy (`TRUSTED_PROXY_IPS`), so a caller cannot present an approved address by claiming one. An IPv4 client reaching a dual-stack listener arrives as an IPv4-mapped IPv6 address (`::ffff:203.0.113.5`); it is matched against IPv4 entries as the IPv4 address it is, so `203.0.113.5/32` covers it and no separate entry is needed.

Two credentials are not subject to it: a dashboard session (JWT), because an allowlist belongs to an API key and a signed-in user has none; and the platform-operator admin key (`ADMIN_API_KEY`), which is not an `api_keys` row and so has no list to attach one to.

**The admin key is the most privileged credential in the system and cannot be confined to a network by WrapSec.** That is a property of what it is, not an oversight, but it is worth acting on: restrict it at the network layer instead - a firewall rule or a reverse proxy in front of the API - and prefer a dashboard session for routine administration, so the key is reserved for automation whose source address you control.

The refusal is shaped for the caller it is sent to, but identified the same way everywhere. On `POST /v1/chat/completions` it is an OpenAI-shaped error, because the callers there are OpenAI client libraries that parse the body before the status; everywhere else it is the standard envelope. **Both carry `code: IP_NOT_ALLOWED`**, so a rule keyed on the code catches this denial on every route rather than only where its author happened to look. It is deliberately distinct from the generic `FORBIDDEN` used for permission failures: being refused for where you are is a different event from being refused for who you are. Neither shape names the permitted networks - whoever holds the key is not necessarily whoever may know the network layout.

**Response 201:**
```json
{
  "key_id":    "key_abc123",
  "name":      "Production Key",
  "api_key":   "wsk_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "key_type":  "live",
  "app_id":    null,
  "dept_id":   "4111d663-...",
  "tenant_id": "42a083bf-...",
  "created_at": "2026-04-25T10:00:00Z",
  "expires_at": null
}
```

### GET /v1/keys

*PUBLIC - in the published OpenAPI contract.*

Lists all active (non-revoked, non-expired-grace-period) keys with department and application names.

**Response 200:**
```json
{
  "keys": [
    {
      "key_id":       "key_abc123",
      "name":         "Production Key",
      "app_id":       null,
      "dept_id":      "4111d663-...",
      "dept_name":    "Engineering",
      "app_name":     null,
      "key_type":     "live",
      "created_at":   "2026-04-25T10:00:00Z",
      "expires_at":   null,
      "last_used_at": "2026-04-25T10:05:00Z"
    }
  ]
}
```

### GET /v1/keys/{key_id}

*NOT PUBLIC - dashboard key administration. Served and supported; outside the published contract.*

Returns a single key by `key_id`. `404 NOT_FOUND` if not found.

**Response 200:**
```json
{
  "key_id":       "key_abc123",
  "name":         "Production Key",
  "app_id":       null,
  "dept_id":      "4111d663-...",
  "tenant_id":    "42a083bf-...",
  "key_type":     "live",
  "is_admin":     false,
  "revoked":      false,
  "created_at":   "2026-04-25T10:00:00",
  "expires_at":   null,
  "last_used_at": "2026-04-25T10:05:00",
  "ip_allowlist": ["10.0.0.0/8"]
}
```

`ip_allowlist` is returned to an ADMIN only. For any other role the field is absent from the response, which is not the same as `[]`: absent means "not shown to you", `[]` means the key is unrestricted.

### PUT /v1/keys/{key_id}

*NOT PUBLIC - dashboard key administration. Served and supported; outside the published contract.*

Updates the key name, and optionally the addresses it may be used from.

**Request:** `{"name": "New Name", "ip_allowlist": ["10.0.0.0/8"]}`

`ip_allowlist` is optional and its absence is meaningful: omitting the field leaves the existing restriction untouched, while sending `[]` removes it. Both setting and removing a restriction are recorded as administrative events; the key secret never appears in them. ADMIN only.

**Response 200:**
```json
{"key_id": "key_abc123", "name": "New Name", "ip_allowlist": ["10.0.0.0/8"], "updated_at": "..."}
```

### GET /v1/keys/{key_id}/addresses

*NOT PUBLIC - dashboard key administration. Served and supported; outside the published contract.*

Where this key has recently been used from, and where it has been refused. This is the evidence for setting `ip_allowlist`: setting one from memory is how a working deployment gets locked out.

ADMIN only, and scoped to the caller's tenant (`404 NOT_FOUND` otherwise, matching the other key endpoints). A revoked key is not found.

**Query:** `days` (default 30, clamped to 1..365).

**Response 200:**
```json
{
  "key_id":      "key_abc123",
  "window_days": 30,
  "observed": [
    {"ip_address": "203.0.113.10", "count": 412, "last_seen": "2026-04-25T10:05:00.000Z"}
  ],
  "denied": [
    {"ip_address": "198.51.100.9", "count": 3, "last_seen": "2026-04-25T09:00:00.000Z"}
  ]
}
```

`observed` is drawn from the request trail and `denied` from the credential event log, each aggregated to one row per address, most recent first, capped at 20 rows per list. An address appearing in `denied` was turned away by the current restriction: it may be a service that moved to a new egress address, or it may be someone else holding the key, so it is not evidence that the address should be allowed.
### DELETE /v1/keys/{key_id}

*NOT PUBLIC - dashboard key administration. Served and supported; outside the published contract.*

Revokes a key immediately. If the key was in a grace period (from a rotation), it is revoked immediately with a warning.

**Response 200:**
```json
{
  "key_id":       "key_abc123",
  "revoked":      true,
  "revoked_at":   "2026-04-25T10:00:00+00:00",
  "was_in_grace": false,
  "warning":      null
}
```

### POST /v1/keys/{key_id}/rotate

*NOT PUBLIC - dashboard key administration. Served and supported; outside the published contract.*

Generates a new key secret while preserving all metadata. The old key remains valid for a configurable grace period to allow seamless migration.

**Request:**
```json
{"grace_period_minutes": 60}
```

**Response 201:**
```json
{
  "new_key_id":           "key_def456",
  "new_api_key":          "wsk_live_YYYYYYYYYYYYYYYYYYYYYYY",
  "old_key_id":           "key_abc123",
  "old_expires_at":       "2026-04-25T11:00:00",
  "grace_period_minutes": 60,
  "name":                 "Production Key",
  "app_id":               null,
  "dept_id":              "4111d663-...",
  "created_at":           "2026-04-25T10:00:00",
  "message":              "New key created. Old key expires in 60 minutes."
}
```

Cannot rotate a key that is already in a grace period or already expired.

---

## Tenant

*Tenant self-administration, dashboard surface. **No operation in this section is published.***

### GET /v1/admin/tenant

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Returns the caller's tenant profile. Scoped to the authenticated principal's tenant.

**Response 200:**
```json
{
  "id":            "42a083bf-5cad-4b65-84d1-b81def88c9f3",
  "slug":          "default",
  "name":          "My Organisation",
  "description":   null,
  "contact_email": null,
  "status":        "active",
  "created_at":    "2026-04-01T00:00:00Z",
  "locale":        null
}
```

`status` is `active` or `suspended` (set via the platform-operator endpoints). `locale` is the tenant's default BCP-47 locale, or `null` to inherit the system default.

### PUT /v1/admin/tenant

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Updates tenant name, description, contact email, or default locale. All fields are optional - only provided fields are updated. Unknown fields are rejected (422).

Policy configuration is NOT part of the tenant profile. Detection thresholds, layers, guardrails, and rate limits are managed through `/v1/settings/*` (tenant-scoped) and per-department or per-application policy overrides.

**Request:**
```json
{"name": "Acme Corp", "contact_email": "security@acme.com"}
```

### GET /v1/admin/tenant/usage

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Tenant-scoped usage aggregate over the audit trail: scan and proxy request counts and blocked/sanitized decisions, totalled and broken down by day. Every request that was **inspected** writes an audit row -- scan, batch, proxy, and cache hit alike -- so these figures are complete for inspected traffic.

They deliberately exclude requests refused **before** inspection: a malformed model string, an unconfigured provider, a conversation over the scan-all maximum, a trial key on the proxy, an unsupported message role, or a credential presented from an address outside its source-network list. Those have no decision, no risk score and no input hash, so a row would have to invent them, and `decision` feeds the blocked/sanitized figures directly. They are counted on `wrapsec_proxy_rejected_total` (labelled by reason) and `wrapsec_api_key_ip_denied_total` instead, so if you need "how many requests did we turn away", read those rather than expecting them here.

**Auth:** any valid principal (API key or JWT).

**Query params:** `from`, `to` - ISO-8601 timestamps; the window is `[from, to)`. Defaults to the last 30 days.

**Response 200:**
```json
{
  "from":   "2026-07-16T00:00:00Z",
  "to":     "2026-08-15T00:00:00Z",
  "totals": {"scan": 1240, "proxy": 310, "blocked": 57, "sanitized": 12, "total": 1550},
  "by_day": [
    {"day": "2026-07-16", "scan": 40, "proxy": 11, "blocked": 2, "sanitized": 0, "total": 51}
  ]
}
```

**Errors:** `400 INVALID_REQUEST` - malformed timestamps or `from` not before `to`.

---

## Platform Operator - Tenant Lifecycle

*Control plane, master admin key only. **No operation in this section is published** - it was excluded from the schema before this boundary existed.*

Tenant provisioning and lifecycle management. **Master admin API key only** (the platform-operator principal) - tenant credentials, including tenant ADMIN JWTs, are rejected. These endpoints are excluded from the OpenAPI schema.

On a single-tenant self-hosted installation these endpoints are normally not needed: the default tenant is created at startup and the first admin via `/v1/setup`.

### POST /v1/admin/tenants

*NOT PUBLIC - platform operator. Served and supported; outside the published contract.*

Creates a tenant.

**Request:**
```json
{"slug": "acme", "name": "Acme Corp", "description": null}
```

`slug`: 2-50 chars, lowercase alphanumeric or hyphen, must start alphanumeric. Unique across the installation.

**Response 201:**
```json
{
  "id":           "3f6b1f9a-3c1c-4a3f-9a44-9be1a1d0e930",
  "slug":         "acme",
  "name":         "Acme Corp",
  "description":  null,
  "status":       "active",
  "plan":         null,
  "suspended_at": null,
  "created_at":   "2026-08-15T00:00:00Z"
}
```

**Errors:** `400 INVALID_REQUEST` - bad slug. `409 CONFLICT` - slug already exists.

### GET /v1/admin/tenants

*NOT PUBLIC - platform operator. Served and supported; outside the published contract.*

Lists all tenants with lifecycle status.

**Response 200:** `{"total": 2, "tenants": [ ... ]}` - same tenant shape as create.

### GET /v1/admin/tenants/{tenant_id}

*NOT PUBLIC - platform operator. Served and supported; outside the published contract.*

Returns one tenant. `404 NOT_FOUND` if it does not exist.

### POST /v1/admin/tenants/{tenant_id}/suspend

*NOT PUBLIC - platform operator. Served and supported; outside the published contract.*

Suspends the tenant. All traffic under its credentials (API keys and user sessions) is rejected with `403 TENANT_SUSPENDED` until reactivation. Takes effect immediately (the cached lifecycle status is invalidated on change).

**Response 200:** the tenant with `"status": "suspended"` and `suspended_at` set.

### POST /v1/admin/tenants/{tenant_id}/reactivate

*NOT PUBLIC - platform operator. Served and supported; outside the published contract.*

Restores a suspended tenant. **Response 200:** the tenant with `"status": "active"`.

### POST /v1/admin/tenants/{tenant_id}/bootstrap-admin

*NOT PUBLIC - platform operator. Served and supported; outside the published contract.*

Creates the FIRST admin user of a tenant (identity plus ADMIN membership). Refuses once the tenant has any member. The created user has `force_password_change = true` - they must rotate the operator-set password on first login.

**Request:**
```json
{"email": "admin@acme-corp.com", "password": "TemporaryPass1!"}
```

**Response 201:**
```json
{"id": "d8b1...", "email": "admin@acme-corp.com", "role": "ADMIN"}
```

**Errors:** `400 INVALID_REQUEST` - weak password. `409 CONFLICT` - tenant already has members, or the email is already registered. `404 NOT_FOUND` - unknown tenant.

---

## Departments

*Organisation structure, dashboard surface. **No operation in this section is published.***

### POST /v1/admin/departments

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Creates a department under the default tenant.

**Request:**
```json
{
  "slug":            "engineering",
  "name":            "Engineering",
  "description":     "Backend engineering team",
  "policy_override": null,
  "contact_email":   null
}
```

**Response 201:** Department object.

### GET /v1/admin/departments

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Lists all departments for the default tenant.

**Response 200:** `{"departments": [...]}`

### GET /v1/admin/departments/{dept_id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Returns a single department. `404 NOT_FOUND` if not found.

### PUT /v1/admin/departments/{dept_id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Updates department fields. Pass `policy_override: null` to explicitly clear overrides.

**Request:** Any subset of `name`, `description`, `policy_override`, `contact_email`, `is_active`.

### DELETE /v1/admin/departments/{dept_id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Deactivates a department (`is_active = false`).

**Response 200:** `{"dept_id": "...", "deactivated": true}`

### GET /v1/admin/departments/{dept_id}/stats

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Returns aggregated request statistics for the department.

**Response 200:**
```json
{
  "dept_id":        "4111d663-...",
  "total":          1250,
  "decisions":      {"BLOCK": 107, "SANITIZE": 64, "ALLOW": 1079},
  "block_rate":     0.0856,
  "avg_latency_ms": 5.4,
  "top_threats":    [{"category": "PROMPT_INJECTION", "count": 87}]
}
```

### GET /v1/admin/departments/{dept_id}/policy

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Returns the fully resolved effective policy for the department. Merges: system defaults -> DB settings -> department override.

**Response 200:**
```json
{
  "dept_id":         "4111d663-...",
  "dept_name":       "Engineering",
  "policy_source":   "department_override",
  "override_set":    true,
  "policy_override": {"guardrails": {"pii": {"block_threshold": 0.8}}},
  "resolved_policy": {...}
}
```

---

## Applications

*Organisation structure, dashboard surface. **No operation in this section is published.***

### POST /v1/admin/applications

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Creates an application under a department.

**Request:**
```json
{
  "dept_id":     "4111d663-...",
  "slug":        "code-assistant",
  "name":        "Code Assistant",
  "description": null,
  "environment": "production",
  "policy_override":     null,
  "rate_limit_override": null
}
```

**Response 201:** Application object.

### GET /v1/admin/applications

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Lists applications. Optional `dept_id` query param filters by department.

**Response 200:** `{"applications": [...]}`

### GET /v1/admin/applications/{app_id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Returns a single application. `404 NOT_FOUND` if not found.

### PUT /v1/admin/applications/{app_id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Updates application fields.

### DELETE /v1/admin/applications/{app_id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Deactivates an application (`is_active = false`).

**Response 200:** `{"app_id": "...", "deactivated": true}`

### GET /v1/admin/applications/{app_id}/policy

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Returns the fully resolved effective policy. Merges: system -> DB settings -> department -> application.

**Response 200:**
```json
{
  "app_id":          "7a576570-...",
  "app_name":        "Code Assistant",
  "dept_id":         "4111d663-...",
  "policy_source":   "application_override",
  "override_set":    false,
  "policy_override": null,
  "resolved_policy": {...}
}
```

### PUT /v1/admin/applications/{app_id}/policy

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Sets or updates the application-level policy override. Pass `policy_override: null` to clear.

**Request:**
```json
{"policy_override": {"guardrails": {"pii": {"block_threshold": 0.8}}}}
```

**Response 200:** Resolved policy object (same shape as GET policy).

### DELETE /v1/admin/applications/{app_id}/policy

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Resets application policy override to null. Application inherits from department.

**Response 200:**
```json
{"app_id": "...", "app_name": "...", "policy_override": null, "reset": true, "message": "Application policy override removed. Inheriting from department."}
```

---

## Webhooks (Outbound)

*Outbound delivery configuration, dashboard surface. **No operation in this section is published.***

WrapSec pushes an event to configured destinations on every BLOCK and
SANITIZE decision (ALLOW is not emitted). Delivery is asynchronous: the scan
response never blocks on webhook I/O. Events retry on failure
(5s -> 5m -> 30m -> 2h -> 5h -> 10h -> 10h) and dead-letter when exhausted; an
endpoint that fails continuously for 120h is auto-disabled by the circuit
breaker. All routes require the ADMIN role.

Two endpoint kinds:

- **Generic webhook** (`connector_type` null): WrapSec POSTs the raw
  audit-shaped JSON body signed with HMAC-SHA256. The signing secret is
  generated server-side and returned once at create. Verify deliveries with
  the `webhook-id`, `webhook-timestamp`, and `webhook-signature` headers.
- **SIEM connector** (`connector_type` set): WrapSec formats the event for a
  specific SIEM and authenticates with the customer-supplied ingest token
  (never echoed back). Supported: `splunk_hec`, `datadog_logs`,
  `sentinel_logs_ingestion`, `elastic_ecs`.

| connector_type | auth (`secret`) | required `config` keys |
|----------------|-----------------|------------------------|
| `splunk_hec` | HEC token | (none; `index`/`sourcetype` optional) |
| `datadog_logs` | API key | (none; `service`/`ddsource`/`tags` optional) |
| `sentinel_logs_ingestion` | app-registration client secret | `dcr_immutable_id`, `stream_name`, `tenant_id`, `client_id` |
| `elastic_ecs` | base64 API key | `index` |

Webhook egress is locked down secure-by-default (distinct from the LLM proxy
target, which is often an internal service and stays permissive). The
destination host is resolved at connect time and the delivery is blocked if it
maps to a private/loopback/link-local/metadata address, and `https` is required.
To send to an on-prem SIEM on a private address, allowlist its host or CIDR via
`WEBHOOK_EGRESS_ALLOWLIST` (see `.env.example`).

### POST /v1/admin/webhooks

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Create a generic webhook (secret generated and returned once):

```json
{"url": "https://example.com/hook", "event_types": ["wrapsec.request.blocked"]}
```

```json
{"id": "...", "url": "...", "connector_type": null, "config": null,
 "status": "active", "secret": "<plaintext, shown once>", "secret_masked": "abc1...wxyz"}
```

Create a connector endpoint (`secret` is the ingest token; not echoed back):

```json
{"url": "https://es.example.com:9243", "connector_type": "elastic_ecs",
 "secret": "<elastic api key>", "config": {"index": "logs-wrapsec.security-default"}}
```

Validation (422) rejects: unknown `connector_type`, a connector without
`secret`, missing required `config` keys, a generic endpoint with a supplied
`secret`, and `config` on a generic endpoint.

### GET /v1/admin/webhooks, GET /v1/admin/webhooks/{id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

List/read endpoints. Secrets are always masked. Each row carries a computed
`status`: `active`, `failing` (in a failure window), or `auto_disabled`
(circuit breaker retired it).

### PUT /v1/admin/webhooks/{id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Update `url`, `description`, `event_types`, `config`. `connector_type` is
immutable after create; `secret` and lifecycle flags are not settable here.

### POST /v1/admin/webhooks/{id}/rotate-secret

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Rotate the generic signing secret with a grace window (`grace_hours`, default
24) during which the old secret still verifies. Returns a fresh plaintext
secret once. Returns 400 for connector endpoints (rotation is HMAC-signing
specific; delete and recreate to change a connector token).

### DELETE /v1/admin/webhooks/{id}

*NOT PUBLIC - dashboard administration. Served and supported; outside the published contract.*

Hard-delete the endpoint.

---

## Health

***All four operations here are published.***

### GET /health

*PUBLIC - in the published OpenAPI contract.*

```json
{"status": "ok", "version": "1.2.0"}
```

### GET /health/ready

*PUBLIC - in the published OpenAPI contract.*

```json
{
  "status": "ready",
  "checks": {
    "database":             "ok",
    "redis":                "ok",
    "tfidf_detector":       "healthy",
    "transformer_detector": "healthy"
  }
}
```

`status` is `"degraded"` if any check is not `"ok"` or `"healthy"`. Detector checks return `"healthy"` (not `"ok"`) when loaded. `transformer_detector` returns `"degraded"` when transformer dependencies are not installed -- Tier 1 (TF-IDF) handles all detection in this state.

**The status code is the readiness contract; the body is the detail.** They are not the same signal, because not every component is required:

| Code | Meaning | Required up | Body may read |
|---|---|---|---|
| `200` | Serving. An optional component may still be absent. | `database`, `redis`, `tfidf_detector` | `"ready"` or `"degraded"` |
| `503` | Not serving. A required component is down. | - | `"degraded"` |

`transformer_detector` is optional by build and never affects the status code: the default image ships without it, so a `200` with `"status": "degraded"` is the normal state of a correctly-installed default deployment. Tier 1 is required -- with no model loaded, every request that runs the ML layer is refused fail-closed with `SYSTEM_ERROR`, so the instance is serving errors rather than serving with less signal, and a readiness probe must take it out of rotation.

A `503` here is a readiness REPORT, not a transport error: it carries the same body and names the component that is down. Both SDK clients and `wrapsec doctor` return that body rather than raising, so a health check remains readable during an outage.

### GET /health/live

*PUBLIC - in the published OpenAPI contract.*

```json
{"status": "alive"}
```

### GET /health/config

*PUBLIC - in the published OpenAPI contract.*

The configuration currently in force, for deployment verification. Does not expose API keys or secrets to any caller.

Every authenticated caller may call it, but the body varies by permission. The values it reports are the same ones `GET /v1/settings` serves behind `settings:read` with trial keys refused -- thresholds and layer status are calibration data, since they tell a caller how far under a limit a payload has to sit. Returning them here regardless of permission would have made that restriction meaningless.

| Caller | Receives |
|---|---|
| Holds `settings:read` and is not a trial key -- ADMIN, DEVELOPER, AUDITOR | the full body: thresholds, detection-layer states, LLM provider/model/trigger/timeout, rate limit, each with its `source` |
| Any other authenticated caller -- VIEWER, trial keys | `version`, plus each section reduced to its `source` marker (`database` or `environment`) |

The reduced body still answers the deployment-verification question: which build is running, and whether configuration is customised or left at environment defaults. It discloses no threshold and no layer state.

`version` is unrestricted because unauthenticated `GET /health` already returns it.

Unauthenticated callers receive `401` -- `/health/config` is not a public path, unlike `/health`, `/health/ready`, and `/health/live`.

```json
{
  "version": "1.2.0",
  "thresholds":       {"block": 0.7, "sanitize": 0.4, "source": "database"},
  "detection_layers": {"rule": true, "ml": true, "llm": true, "source": "database"},
  "llm":              {"provider": "ollama", "model": "llama3.2", "llm_trigger": 0.2, "timeout": 30, "source": "database"},
  "rate_limit":       {"per_minute": 60, "source": "database"}
}
```

---

## Metrics

*Monitoring scrape endpoint. **Not published**, and never was.*

### GET /metrics

*NOT PUBLIC - monitoring. Served and supported; outside the published contract.*

Prometheus exposition format. Requires `Authorization: Bearer <token>`.

Token resolution order: `METRICS_TOKEN` env var -> `ADMIN_API_KEY` (fallback). Set a dedicated `METRICS_TOKEN` in production so your Prometheus scraper does not need the admin key.

Scrape at `http://host:8000/metrics`. Returns `401` if no valid Bearer token is provided.

---

## Rate Limiting

Applied to gateway processing paths only: `/v1/scan`, `/v1/proxy/*`, `/v1/ai/*`. Dashboard reads, settings, auth, and health endpoints are not rate limited.

Per API key. Falls back to per-IP if no key is present. Redis sliding window.

| Key type | Limit | Enforcement |
|---|---|---|
| `live` | 60 req/min (configurable via `PUT /v1/settings/rate_limit`) | Middleware |
| `trial` | 10 req/min (`TRIAL_RATE_LIMIT_PER_MINUTE` env var) | Endpoint level |
| Admin key | Same as live | Middleware |
| JWT user | Not rate limited (dashboard only) | - |

```json
{"error": {"code": "RATE_LIMITED", "message": "Rate limit exceeded.", "trace_id": "..."}}
```

---

## Failure Modes

**All detectors fail (SYSTEM_ERROR - fail CLOSED):**
```json
{
  "decision":             "BLOCK",
  "decision_version":     "v1.0",
  "risk_score":           1.0,
  "primary_reason":       "SYSTEM_ERROR",
  "confidence":           0.0,
  "confidence_band":      "LOW",
  "sanitization_applied": false,
  "threats":              []
}
```

The request is refused because it could not be inspected, not because anything was
found in it. `threats` is empty and `confidence` is 0.0 for that reason, while
`risk_score` is 1.0 because the decision is forced rather than scored.

To the caller this is indistinguishable from a content block on `decision` alone;
`primary_reason` is what separates them. Alert on it -- a rising rate means
detection is degraded, not that attacks are increasing.

**SYSTEM_ERROR monitoring thresholds:**

| Signal | Threshold | Action |
|---|---|---|
| Single occurrence | Any | Log and investigate |
| Rate > 0.1% | Over 5 min | Page on-call |
| Rate > 1% | Over 1 min | Immediate incident |
| All requests | Any | Service outage - escalate |

---

## Decision Model Reference

```
risk_score   = weighted combination of rule, ML, LLM scores (0.0-1.0)
               PII guardrail can BLOCK with risk_score=0.0
               Always use decision as the authoritative verdict

confidence   = agreement between active detectors (0.0-1.0)
               Not probability of attack
               Single-detector paths may yield confidence=1.0 - expected

SYSTEM_ERROR = detectors failed (exception, timeout, internal error)
               FAIL-CLOSED: always returns decision=BLOCK, risk_score=1.0
               Always returns confidence=0.0, confidence_band=LOW
               A primary_reason, never a decision value
               Audit severity is CRITICAL (the forced risk_score is 1.0)
```

---

## Changelog

### V1.6 (May 2026) - First-run Setup + Hardening

- `GET /v1/setup/status` - initialization check, Redis-cached after first use
- `POST /v1/setup` - creates first admin user on fresh install, permanently self-disables after use
- `ADMIN_EMAIL` / `ADMIN_PASSWORD` are now optional - setup page is the primary first-run flow
- `/metrics` endpoint now requires `Authorization: Bearer <token>` (METRICS_TOKEN or ADMIN_API_KEY)
- CORS `allow_credentials` only enabled when `CORS_ALLOWED_ORIGINS` is explicitly configured
- All hardcoded detection thresholds moved to `config/settings.py` (configurable via env vars)

---

### V1.5 (May 2026) - Session Hardening + Auth Observability

**Auth event observability (backend):**
- `auth_events` expanded: `logout`, `token_refresh_success`, `token_refresh_failed`, `session_expired` action values added
- New `failure_reason` values: `token_invalid`, `inactivity`, `manual`, `expired`, `refresh_failed`, `session_invalidated`
- `POST /v1/auth/logout` now accepts optional `{ reason }` body - logged in auth_events
- Middleware logs `session_expired` on token failure - skipped when no token present, skipped for `/v1/auth/refresh` path
- NullPool session pattern enforced - explicit `session.close()` in finally block

**Endpoint auth hardening:**
- All endpoints now have explicit FastAPI auth dependencies (no implicit middleware-only auth)
- `PUT /v1/settings/*` - changed from admin API key to JWT + ADMIN only (breaking)
- `POST/PUT/DELETE /v1/admin/departments/*` and `/applications/*` - now JWT + ADMIN only
- `GET /v1/admin/departments/*`, `/applications/*`, `/tenant` - now accept API key (read)
- `GET /v1/keys` - remains API key-accessible (CLI needs this)
- `POST/PUT/DELETE /v1/keys/*` - JWT + ADMIN only
- `/health/config` - now requires auth (exposes system config)

**Dashboard session hardening:**
- Inactivity timeout: 15 min, warning modal at 2 min, `logout("inactivity")` on expiry
- Silent refresh: 401 -> attempt refresh -> retry once -> redirect to login
- Three refresh guards: url check, `_retried` flag, `isLoggingOut` flag
- `/api/*` excluded from Next.js middleware redirect (was causing HTML parse errors)
- Proxy route guarantees JSON on all error paths - no HTML ever returned
- API key cookie maxAge: 24h -> 8h
- All cookies httpOnly - auth mode detected via `GET /api/auth/session` server route

**Security hardening (env vars):**
- `METRICS_TOKEN` - dedicated Bearer token for `/metrics` endpoint scraping. Falls back to `ADMIN_API_KEY` if unset. `/metrics` is no longer unauthenticated.
- `TRUSTED_PROXY_IPS` - comma-separated list of trusted reverse proxy IPs/CIDRs. `x-forwarded-for` is trusted only when the direct connection IP matches this list. It decides HOW the client address is derived, and every control that reads that address inherits the answer -- not audit attribution alone: `audit_logs.ip_address` and `auth_events.ip_address`, API-key source-network restrictions, and the per-IP rate-limit bucket. It is NOT an access-control list and shares nothing with one: this names the PROXIES allowed to state who the client is, while an API key's `ip_allowlist` names the CLIENT networks that key may be used from. The two never hold the same value -- a proxy address in a key's allowlist would admit every caller behind that proxy, and a client range here would let those clients forge any address they like. An entry matching every address (`0.0.0.0/0`, `::/0`) is ignored with a warning, since it would trust a forwarded header from any peer. Leave empty (default) to always use the direct connection IP - safe when not behind a proxy. Example: `TRUSTED_PROXY_IPS=10.0.0.1,172.16.0.0/12`

---

### V1.4 (April 2026) - User Management

**Breaking change:**
- `PUT /v1/admin/users/{id}` -> `PATCH /v1/admin/users/{id}` (partial update semantics)

**User management additions:**
- Self-deactivation guard - admin cannot deactivate their own account
- Final state validation on PATCH - role + dept_id consistency validated on combined result
- `dept_id` must belong to same tenant - validated on every create/update
- `role = ADMIN` -> `dept_id` forced null; `role != ADMIN` -> `dept_id` required (both directions)
- `token_version` incremented on role change, dept change, deactivation - NOT on reactivation

**New DB tables:**
- `admin_events` - logs all user management actions (user_created, role_changed, dept_changed, user_deactivated, user_reactivated, password_reset). Synchronous, post-commit, best-effort.
- `auth_events` - logs login success and failure. Non-blocking, separate DB session, best-effort. `tenant_id` nullable (null when user not found).

**New error codes:**
- `ACCOUNT_INACTIVE` - login failure when `is_active = false`

**auth_events action values:** `login_success`, `login_failed`, `logout`, `token_refresh_success`, `token_refresh_failed`, `session_expired`

**auth_events failure_reason values:** `invalid_password`, `user_not_found`, `account_inactive`, `account_disabled`, `token_expired`, `token_invalid`, `inactivity`, `manual`, `expired`, `refresh_failed`, `session_invalidated`

Note: `account_inactive` is the `auth_events.failure_reason` value when `is_active = false`. The API error code returned to the client is always `ACCOUNT_DISABLED` - `ACCOUNT_INACTIVE` never appears in API responses.

**DB schema:**
- `admin_events` table - tenant_id, dept_id (nullable), actor_user_id, target_user_id, action, metadata (JSONB), ip_address, user_agent
- `auth_events` table - tenant_id (nullable), user_id (nullable), action, success, failure_reason, ip_address, user_agent
- `users.ck_users_dept_required` -> `ck_users_dept_required_v2` (both directions enforced)

---

### V1.3 (April 2026) - JWT + RBAC

**New endpoints (+10):**
- `POST /v1/auth/login` - email/password login, JWT + httpOnly cookie
- `POST /v1/auth/refresh` - rotate refresh token, new access token
- `POST /v1/auth/logout` - revoke refresh token
- `GET  /v1/auth/me` - current user profile
- `POST /v1/auth/change-password` - change password, invalidate all sessions
- `POST /v1/admin/users` - create dashboard user (ADMIN only)
- `GET  /v1/admin/users` - list users
- `GET  /v1/admin/users/{id}` - get user
- `PATCH /v1/admin/users/{id}` - update user (partial, see V1.4 for breaking change note)
- `POST /v1/admin/users/{id}/reset-password` - admin password reset

**Authentication changes:**
- JWT Bearer now accepted on all scan/audit/proxy endpoints alongside API key
- Header precedence: `x-api-key` always wins over `Authorization: Bearer`
- `principal_type` added to `audit_logs` - `api_key` | `user`

**Security features:**
- Token versioning - session invalidated immediately on password/role change
- Account lockout - 5 failed attempts -> 15 min lockout (Redis TTL)
- `force_password_change` enforced at middleware level
- Last-admin protection - cannot deactivate/demote last active ADMIN
- Timing equalisation - prevents email enumeration via response time

**DB schema:**
- `users` table - id, tenant_id, dept_id, email, password_hash, role, is_active, force_password_change, token_version
- `refresh_tokens` table - token_hash (SHA-256), token_version, expires_at, revoked_at
- `audit_logs.principal_type` column added
- `api_keys.tenant_id` enforced NOT NULL

**New error codes:** `INVALID_CREDENTIALS`, `ACCOUNT_DISABLED`, `ACCOUNT_LOCKED`, `SESSION_INVALIDATED`, `PASSWORD_CHANGE_REQUIRED`, `CONFLICT`

**Total endpoints:** 53 -> 63

---

### V1.2 (April 2026) - Security & Isolation

- Dept scoping on all audit endpoints and `GET /v1/ai/requests/{trace_id}`
- `severity` field in `audit_logs` - CRITICAL / HIGH / MEDIUM / LOW
- Trial keys (`wsk_trial_...`) - 500 char input cap, 10 req/min, proxy disabled
- `POST /v1/keys/{key_id}/rotate` - grace period key rotation
- `GET/PUT /v1/settings/rate_limit` - DB-backed live key rate limit
- Application-level policy overrides wired into resolution chain
- Toxicity guardrail - `TOXICITY_GUARDRAIL_BLOCK` / `TOXICITY_GUARDRAIL_SANITIZE` (SANITIZE tier removed in v1.0.9)
- `api_keys.key_type` column - `live` | `trial`
- Idempotency scoped per API key

---

### V1.1 (April 2026) - Proxy Mode

- `POST /v1/chat/completions` - OpenAI-compatible proxy
- Provider support: OpenAI, Groq, Azure, Together AI, Ollama, custom
- AES-256-GCM encrypted provider API keys
- Input + output PII guardrail
- `X-WrapSec-*` response headers
- `DATA_STORAGE_MODE`: full / masked / none
- `proxy_interactions` table - full lifecycle data

---

### V1.0 (April 2026)

- Rule, ML, LLM detectors
- PII guardrail (30+ types)
- Idempotency-Key
- Trace IDs on every request and response
- Rate limiting per API key
- Policy resolution chain

---

*API version: 1.0*  
*Total endpoints: 63*  
*Authentication: `x-api-key` OR `Authorization: Bearer {jwt}`*  
*Last updated: May 2026*
