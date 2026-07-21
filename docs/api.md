# WrapSec API Reference

> See [Core Concepts](core_concepts.md) for canonical definitions of decision model, SYSTEM_ERROR, and scoring semantics.

Version: 1.0  
Base URL: `http://your-host:8000`  
Total endpoints: 63  
Last updated: May 2026

---

## Authentication

WrapSec supports two authentication methods. Both resolve to identical internal state - downstream code is auth-agnostic.

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
- Proxy mode: disabled - returns `403 trial_proxy_disabled`

### JWT Bearer

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Used by dashboard users. Issued via `POST /v1/auth/login`.

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
| `POST /v1/ai/request`, `POST /v1/chat/completions` | yes | yes any role |
| `GET /v1/ai/requests/{trace_id}` | yes | yes any role |
| `GET /v1/audit/*` | yes | yes any role |
| `GET /v1/proxy/interactions/*` | yes | yes any role |
| `GET /v1/settings/*` | yes | yes any role |
| `PUT /v1/settings/*` | no | yes ADMIN only |
| `GET/PUT/DELETE /v1/settings/proxy*` | yes | yes any role |
| `GET /v1/keys` | yes | yes any role |
| `GET /v1/keys/{id}` | yes | yes any role |
| `POST /v1/keys`, `PUT /v1/keys/{id}`, `DELETE /v1/keys/{id}`, `POST /v1/keys/{id}/rotate` | no | yes ADMIN only |
| `GET /v1/admin/tenant`, `GET /v1/admin/departments/*`, `GET /v1/admin/applications/*` | yes | yes any role |
| `PUT /v1/admin/tenant` | no | yes ADMIN only |
| `POST/PUT/DELETE /v1/admin/departments/*` | no | yes ADMIN only |
| `POST/PUT/DELETE /v1/admin/applications/*` | no | yes ADMIN only |
| `ALL /v1/admin/users/*` | no | yes ADMIN only |

**Notes:**
- `GET /v1/keys` requires auth but accepts API key - CLI `wrapsec keys list` uses this
- `PUT /v1/settings/*` requires JWT + ADMIN - admin API key not accepted
- `/v1/settings/proxy*` scoped per `tenant_id` - one proxy config shared across all API keys for the tenant
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
| `Idempotency-Key` | UUID - idempotent `POST /v1/ai/request` only |

**Response:**

| Header | Description |
|---|---|
| `x-trace-id` | ULID trace ID (`req_01knzhh8...`) |
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
| `NOT_FOUND` | 404 | Resource does not exist |
| `CONFLICT` | 409 | Duplicate (e.g. email already registered) |
| `IDEMPOTENCY_CONFLICT` | 409 | Same Idempotency-Key, different body |
| `VALIDATION_ERROR` | 422 | Body failed validation |
| `ACCOUNT_LOCKED` | 429 | Too many failed login attempts - includes `retry_after` seconds |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `INTERNAL_ERROR` | 500 | Unexpected server error |
| `input_blocked` | 400 | Proxy: input blocked by policy |
| `output_blocked` | 400 | Proxy: output blocked by policy |
| `provider_timeout` | 504 | Proxy: provider timed out |
| `provider_unreachable` | 502 | Proxy: provider connection failed |
| `proxy_not_configured` | 400 | Proxy: no provider configured |
| `invalid_model_format` | 400 | Proxy: model must be `provider/model` |
| `trial_proxy_disabled` | 403 | Proxy: not available for trial keys |

**Convention:** `UPPERCASE` = platform/infrastructure errors. `lowercase` = security/proxy runtime errors.

---

## Idempotency

`POST /v1/ai/request` supports `Idempotency-Key`. Scoped per API key - two keys with the same value do not collide.

| Scenario | Behaviour |
|---|---|
| First request | Process normally, cache response (60s TTL) |
| Same key + same body | Return cached response, `X-Idempotency-Replayed: true` |
| Same key + different body | `409 IDEMPOTENCY_CONFLICT` |

`POST /v1/chat/completions` does **not** support idempotency - provider calls have side effects.

---

## Setup Endpoints

### GET /v1/setup/status

Returns whether the system has been initialized. Used by the dashboard to determine whether to redirect to `/setup` on first visit. Redis-cached after initialization - no DB load on subsequent calls.

**Auth:** Public.

**Response:**
```json
{"initialized": true}
```

---

### POST /v1/setup

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

### POST /v1/auth/login

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

Changes the user's password. Immediately invalidates all active sessions (all refresh tokens revoked, token_version incremented). Accessible even when `force_password_change = true`.

**Auth:** JWT Bearer required.

**Request:**
```json
{"current_password": "OldPassword1!", "new_password": "NewPassword2026!"}
```

Password requirements: ≥8 chars, ≥1 uppercase, ≥1 lowercase, ≥1 digit.

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

All `/v1/admin/users` endpoints require **JWT + ADMIN role**. API keys cannot access these endpoints.

### POST /v1/admin/users

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

Returns a single user. Returns `404` if user belongs to a different tenant.

**Response 200:** Same shape as individual item in list above.

---

### PATCH /v1/admin/users/{user_id}

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

### POST /v1/ai/request

Scan-only mode. Inspect input, get a security decision, then forward to your LLM if ALLOW or SANITIZE.

**Auth:** API key OR JWT Bearer.

**Request:**
```json
{
  "input":          "string - required, 1-8000 chars",
  "detection_mode": "fast | full  (default: fast)",
  "execution_mode": "scan_only  (default)",
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
  }
}
```

`sanitized_input` is present only when `decision = SANITIZE`. Use it instead of the original input when forwarding to your LLM.

`policy_source` is **not** in the scan response - it appears only in `GET /v1/ai/requests/{trace_id}`.

**Decision values:** `ALLOW` | `BLOCK` | `SANITIZE`

**Primary reason values:**

| Value | Trigger |
|---|---|
| `RULE_DETECTOR` | Rule detector highest score |
| `ML_DETECTOR` | ML classifier highest score |
| `LLM_DETECTOR` | LLM semantic detector highest score |
| `PII_GUARDRAIL_BLOCK` | PII score ≥ block threshold |
| `PII_GUARDRAIL_SANITIZE` | PII score ≥ sanitize threshold |
| `TOXICITY_GUARDRAIL_BLOCK` | Toxicity score ≥ block threshold (BLOCK-only tier; see note below) |
| `NO_THREAT_DETECTED` | All detectors ran, no threat found |
| `SYSTEM_ERROR` | Detector failure or exception |

**Confidence bands:**

| Band | Range |
|---|---|
| `HIGH` | 0.7 - 1.0 |
| `MEDIUM` | 0.4 - 0.7 |
| `LOW` | 0.0 - 0.4 |

**`SYSTEM_ERROR` behaviour:** Returns `decision = ALLOW`, `confidence = 0.0`, `confidence_band = LOW`. Clients **must not** forward to LLM when `primary_reason = SYSTEM_ERROR`.

**`risk_score = 0.0` does not mean safe.** Guardrails can BLOCK with `risk_score = 0.0`. Always check `decision`.

**Toxicity guardrail is BLOCK-or-ALLOW only.** Unlike PII (which has an ANONYMIZE / SANITIZE tier), toxic content cannot be safely rewritten by pattern substitution without changing meaning. Toxicity above the block threshold returns `decision = BLOCK` with `primary_reason = TOXICITY_GUARDRAIL_BLOCK`; below it, the toxicity guardrail does not fire (the request may still SANITIZE or BLOCK via PII or detection tiers). This mirrors AWS Bedrock content filter semantics.

---

### GET /v1/ai/requests/{trace_id}

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

**Auth:** API key OR JWT Bearer. Trial keys: `403 trial_proxy_disabled`.

**Request (OpenAI-compatible):**
```json
{
  "model":       "openai/gpt-4o",
  "messages":    [{"role": "user", "content": "What is the capital of France?"}],
  "temperature": 0.7,
  "max_tokens":  500
}
```

**WrapSec request headers:**

| Header | Default | Description |
|---|---|---|
| `X-WrapSec-Mode` | `fast` | Detection mode: `fast` or `full` |
| `X-WrapSec-Scan-All-Messages` | `false` | Scan all user messages vs last only |
| `X-WrapSec-Inline-Meta` | `false` | Include `wrapsec` key in response body |

**WrapSec response headers:**

`X-WrapSec-Trace-Id` is present on **every** response from this endpoint - including early error exits (invalid model format, trial key rejection, provider config errors). All other headers are present only when the request reached the detection pipeline.

| Header | Description |
|---|---|
| `X-WrapSec-Trace-Id` | ULID trace ID - always present |
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
    "input_sanitized":      false,
    "output_decision":      "ALLOW",
    "output_sanitized":     false,
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
  "error": {"code": "input_blocked", "message": "Request blocked by security policy.", "trace_id": "req_01..."},
  "wrapsec": {
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
  "error": {"code": "output_blocked", "message": "Model response blocked.", "trace_id": "req_01..."},
  "wrapsec": {
    "decision":              "ALLOW",
    "output_decision":       "BLOCK",
    "output_primary_reason": "PII_GUARDRAIL_BLOCK",
    "execution_status":      "OUTPUT_BLOCKED"
  }
}
```

---

## Proxy Interactions

Read-only view of proxy request lifecycle records.

### GET /v1/proxy/interactions

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
      "created_at":            "2026-04-25T10:00:00",
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

### PUT /v1/settings/proxy

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
  "created_at":      "2026-04-25T10:00:00",
  "updated_at":      "2026-04-25T10:00:00"
}
```

### GET /v1/settings/proxy

Returns current configuration (API key masked).

**Response 200:** Same shape as PUT response. `404 NOT_FOUND` if not configured.

### DELETE /v1/settings/proxy

Removes the proxy provider configuration. Returns `204 No Content` on success, `404 NOT_FOUND` if not configured.

### GET /v1/settings/proxy/health

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

All audit endpoints scope non-admin identities to their own department - the `dept_id` query param is ignored for non-admin callers.

**Date parameters (`from`, `to`):** All audit endpoints that accept date filters require ISO 8601 format (e.g. `2026-01-15T00:00:00Z`). Malformed values return `400 INVALID_REQUEST` - they are not silently ignored. Empty or absent values apply no date filter.

### GET /v1/audit/logs

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
      "timestamp":            "2026-04-20T01:29:46",
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

### GET /v1/audit/stats

Aggregate statistics for a time range.

**Query params:** `tenant_id` (admin only), `from`, `to`

**Response 200:**
```json
{
  "period_from":    "2026-04-01T00:00:00",
  "period_to":      "2026-04-25T00:00:00",
  "total_requests": 1250,
  "block_rate":     0.0856,
  "sanitize_rate":  0.0512,
  "allow_rate":     0.8632,
  "avg_latency_ms": 5.4,
  "p95_latency_ms": 12.1,
  "top_threats":    [{"category": "PROMPT_INJECTION", "count": 87}]
}
```

**Severity values:**

| Severity | Condition |
|---|---|
| `CRITICAL` | `BLOCK` + (`risk_score >= 0.9` OR `primary_reason` ends with `_GUARDRAIL_BLOCK`) |
| `HIGH` | `BLOCK` + `risk_score < 0.9`, OR `primary_reason = SYSTEM_ERROR` |
| `MEDIUM` | `SANITIZE` (any reason) |
| `LOW` | `ALLOW` |

Severity is computed at write time and stored in `audit_logs.severity`. Never returned in scan responses - audit and SIEM use only.

### GET /v1/audit/attribution

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

### GET /v1/audit/export

Exports audit logs as CSV.

**Returns:** `text/csv`, `Content-Disposition: attachment; filename=wrapsec_audit_export.csv`

**Query params:** `dept_id`, `app_id`, `decision`, `primary_reason`, `confidence_band`, `from`, `to`, `limit` (default 1000, max 10000)

**CSV columns:** `trace_id`, `timestamp`, `decision`, `risk_score`, `confidence`, `confidence_band`, `primary_reason`, `threats`, `tenant_id`, `dept_id`, `app_id`, `key_id`, `source`, `user_id_prefix`, `ip_address_hash`, `policy_source`, `detection_mode`, `latency_ms`

**Privacy note:** `ip_address` is SHA-256 hashed (first 16 hex chars) and exported as `ip_address_hash`. `user_id` is truncated to the first 8 characters and exported as `user_id_prefix`. Both fields retain enough entropy for correlation within an export without exposing raw PII. Full values remain available in the database for authorized access.

---

## Settings

### GET /v1/settings/thresholds

Returns current detection thresholds.

**Response 200:**
```json
{"block_threshold": 0.7, "sanitize_threshold": 0.4}
```

### PUT /v1/settings/thresholds

Updates detection thresholds. `block_threshold` must be greater than `sanitize_threshold`.

**Request:**
```json
{"block_threshold": 0.8, "sanitize_threshold": 0.5}
```

**Response 200:**
```json
{"block_threshold": 0.8, "sanitize_threshold": 0.5, "updated_at": "2026-04-25T10:00:00+00:00"}
```

### GET /v1/settings/layers

Returns current detection layer configuration.

**Response 200:**
```json
{"rule_enabled": true, "ml_enabled": true, "llm_enabled": true}
```

### PUT /v1/settings/layers

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

Returns LLM detector configuration (detection layer only - separate from proxy provider).

**Response 200:**
```json
{"provider": "ollama", "model": "llama3.2", "base_url": "http://localhost:11434", "timeout": 30, "llm_trigger": 0.2}
```

### PUT /v1/settings/llm

Updates LLM detector configuration. Provider must be `ollama`, `openai`, or `groq`. Timeout 5-120 seconds.

**Request:**
```json
{"provider": "openai", "model": "gpt-4o-mini", "base_url": "https://api.openai.com/v1", "timeout": 30, "llm_trigger": 0.2}
```

### GET /v1/settings/retention

Returns audit log retention period.

**Response 200:**
```json
{"retention_days": 30, "source": "database"}
```

`source` is `"database"` if explicitly set, `"environment"` if using the default.

### PUT /v1/settings/retention

Sets audit log retention period. Min 7 days, max 3650 days (10 years).

**Request:**
```json
{"retention_days": 90}
```

### GET /v1/settings/rate_limit

Returns the current global rate limit for live keys.

**Response 200:**
```json
{"per_minute": 60, "source": "database"}
```

`source` is `"database"` if explicitly set, `"environment"` if using the default.

### PUT /v1/settings/rate_limit

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

### POST /v1/keys

Creates a new API key. Returns the raw key value once - store it securely, it cannot be retrieved again.

**Request:**
```json
{
  "name":     "Production Key",
  "dept_id":  "4111d663-47e3-4632-bf92-46a6b24a92f8",
  "app_id":   null,
  "key_type": "live"
}
```

Provide `app_id` for app-scoped keys (dept and tenant derived from app). Provide `dept_id` for dept-scoped keys. `key_type`: `live` (default) or `trial`.

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
  "created_at": "2026-04-25T10:00:00",
  "expires_at": null
}
```

### GET /v1/keys

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
      "created_at":   "2026-04-25T10:00:00",
      "expires_at":   null,
      "last_used_at": "2026-04-25T10:05:00"
    }
  ]
}
```

### GET /v1/keys/{key_id}

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
  "last_used_at": "2026-04-25T10:05:00"
}
```

### PUT /v1/keys/{key_id}

Updates the key name.

**Request:** `{"name": "New Name"}`

**Response 200:**
```json
{"key_id": "key_abc123", "name": "New Name", "updated_at": "..."}
```

### DELETE /v1/keys/{key_id}

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

### GET /v1/admin/tenant

Returns the default tenant configuration.

**Response 200:**
```json
{
  "id":            "42a083bf-5cad-4b65-84d1-b81def88c9f3",
  "slug":          "default",
  "name":          "My Organisation",
  "description":   null,
  "global_policy": {},
  "contact_email": null,
  "is_active":     true,
  "created_at":    "2026-04-01T00:00:00"
}
```

### PUT /v1/admin/tenant

Updates tenant name, description, contact email, or global policy. All fields are optional - only provided fields are updated.

`global_policy` is schema-validated. Accepted structure (all sub-fields optional):

```json
{
  "thresholds": { "block": 0.8, "sanitize": 0.4 },
  "detection":  { "rule_enabled": true, "ml_enabled": true, "llm_enabled": true },
  "guardrails": {
    "pii":      { "enabled": true, "block_threshold": 0.8, "sanitize_threshold": 0.4 },
    "toxicity": { "enabled": true, "block_threshold": 0.8 }
  },
  "rate_limit": { "per_minute": 60 }
}
```

Unknown keys are rejected (422). Invariant: `0.0 < sanitize < block <= 1.0`.

Toxicity is BLOCK-or-ALLOW only (see decision model section). The `toxicity.sanitize_threshold` field is accepted for backward compatibility with pre-v1.0.9 policies but is a no-op - use `toxicity.block_threshold` to tune sensitivity.

**Request:**
```json
{"name": "Acme Corp", "contact_email": "security@acme.com"}
```

---

## Departments

### POST /v1/admin/departments

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

Lists all departments for the default tenant.

**Response 200:** `{"departments": [...]}`

### GET /v1/admin/departments/{dept_id}

Returns a single department. `404 NOT_FOUND` if not found.

### PUT /v1/admin/departments/{dept_id}

Updates department fields. Pass `policy_override: null` to explicitly clear overrides.

**Request:** Any subset of `name`, `description`, `policy_override`, `contact_email`, `is_active`.

### DELETE /v1/admin/departments/{dept_id}

Deactivates a department (`is_active = false`).

**Response 200:** `{"dept_id": "...", "deactivated": true}`

### GET /v1/admin/departments/{dept_id}/stats

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

### POST /v1/admin/applications

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

Lists applications. Optional `dept_id` query param filters by department.

**Response 200:** `{"applications": [...]}`

### GET /v1/admin/applications/{app_id}

Returns a single application. `404 NOT_FOUND` if not found.

### PUT /v1/admin/applications/{app_id}

Updates application fields.

### DELETE /v1/admin/applications/{app_id}

Deactivates an application (`is_active = false`).

**Response 200:** `{"app_id": "...", "deactivated": true}`

### GET /v1/admin/applications/{app_id}/policy

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

Sets or updates the application-level policy override. Pass `policy_override: null` to clear.

**Request:**
```json
{"policy_override": {"guardrails": {"pii": {"block_threshold": 0.8}}}}
```

**Response 200:** Resolved policy object (same shape as GET policy).

### DELETE /v1/admin/applications/{app_id}/policy

Resets application policy override to null. Application inherits from department.

**Response 200:**
```json
{"app_id": "...", "app_name": "...", "policy_override": null, "reset": true, "message": "Application policy override removed. Inheriting from department."}
```

---

## Health

### GET /health

```json
{"status": "ok", "version": "1.2.0"}
```

### GET /health/ready

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

### GET /health/live

```json
{"status": "alive"}
```

### GET /health/config

Active configuration snapshot. Does not expose API keys or secrets.

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

### GET /metrics

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

**All detectors fail (SYSTEM_ERROR - fail open):**
```json
{
  "decision":             "ALLOW",
  "decision_version":     "v1.0",
  "risk_score":           0.0,
  "primary_reason":       "SYSTEM_ERROR",
  "confidence":           0.0,
  "confidence_band":      "LOW",
  "sanitization_applied": false,
  "threats":              []
}
```

Clients **must not** forward to LLM when `primary_reason = SYSTEM_ERROR`.

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
               Always returns decision=ALLOW
               Always returns confidence=0.0, confidence_band=LOW
               Client must treat as failure - never forward to LLM
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
- `TRUSTED_PROXY_IPS` - comma-separated list of trusted reverse proxy IPs/CIDRs. `x-forwarded-for` is only trusted for audit log attribution when the direct connection IP matches this list. Leave empty (default) to always use the direct connection IP - safe when not behind a proxy. Example: `TRUSTED_PROXY_IPS=10.0.0.1,172.16.0.0/12`

**New internal docs:**
- `docs/internal/session_management.md` - session lifecycle reference

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

See `docs/internal/session_management.md` for full logging ownership rules.

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
- PII guardrail (22+ types)
- Idempotency-Key
- ULID trace IDs
- Rate limiting per API key
- Policy resolution chain

---

*API version: 1.0*  
*Total endpoints: 63*  
*Authentication: `x-api-key` OR `Authorization: Bearer {jwt}`*  
*Last updated: May 2026*
