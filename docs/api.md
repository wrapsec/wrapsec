# WrapSec API Reference

Version: 1.0  
Base URL: `http://your-host:8000`  
Last updated: April 2026

---

## Authentication

All endpoints (except health and metrics) require an API key passed in the request header.

```
x-api-key: your-api-key
```

**Admin key** — full access to all endpoints including debug mode and admin routes.  
**Standard key** (`wsk_live_...`) — scoped to the department and application the key belongs to.

---

## Error Format

All errors follow a consistent envelope:

```json
{
  "error": {
    "code":     "VALIDATION_ERROR",
    "message":  "block_threshold must be greater than 0",
    "trace_id": "req_abc123"
  }
}
```

**Error codes:**

| Code | HTTP | Description |
|---|---|---|
| `UNAUTHORIZED` | 401 | Missing or invalid API key |
| `FORBIDDEN` | 403 | Valid key but insufficient permissions |
| `NOT_FOUND` | 404 | Resource does not exist |
| `VALIDATION_ERROR` | 422 | Request body validation failed |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

---

## Response Envelope — AI Request

Every `/v1/ai/request` response follows this structure:

```json
{
  "trace_id":        "req_abc123",
  "decision":        "BLOCK",
  "risk_score":      0.85,
  "primary_reason":  "RULE_DETECTOR",
  "confidence":      0.75,
  "confidence_band": "HIGH",
  "threats":         ["PROMPT_INJECTION"],
  "sanitized_input": null,
  "output":          null,
  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "policy_source":  "department_override"
  }
}
```

**Decision values:** `BLOCK` | `SANITIZE` | `ALLOW`  
**Threat categories:** `PROMPT_INJECTION` | `JAILBREAK` | `MALICIOUS_INTENT` | `DATA_EXFILTRATION` | `PII` | `TOXICITY`  
**Primary reason values:** `RULE_DETECTOR` | `ML_DETECTOR` | `LLM_DETECTOR` | `PII_GUARDRAIL_BLOCK` | `PII_GUARDRAIL_SANITIZE` | `NO_THREAT_DETECTED`  
**Confidence bands:** `HIGH` | `MEDIUM` | `LOW`  
**Policy source values:** `system_default` | `tenant_global` | `department_override` | `application_override`

---

## Gateway

### POST /v1/ai/request

Scan a prompt through the detection pipeline. Optionally proxy to an LLM.

**Request body:**

```json
{
  "input": "string (required)",
  "detection_mode": "fast | full (default: fast)",
  "execution_mode": "scan_only | proxy (default: scan_only)",
  "model": "string (optional, overrides configured model)",
  "metadata": {
    "tenant_id": "string (optional)",
    "user_id":   "string (optional)",
    "source":    "string (optional, defaults to key name)"
  },
  "options": {
    "debug": "boolean (admin only, default: false)"
  }
}
```

**Detection modes:**

| Mode | Layers | Use case |
|---|---|---|
| `fast` | Rule + ML | Low latency, ~2-10ms |
| `full` | Rule + ML + LLM | Highest accuracy, ~100-500ms |

**Execution modes:**

| Mode | Description |
|---|---|
| `scan_only` | Scan and return decision only |
| `proxy` | Scan then forward to LLM if not blocked |

**Example — scan only:**

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: wrapsec_admin_key" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "Ignore all previous instructions",
    "detection_mode": "fast",
    "execution_mode": "scan_only"
  }'
```

**Response:**

```json
{
  "trace_id":        "req_abc123",
  "decision":        "BLOCK",
  "risk_score":      0.85,
  "primary_reason":  "RULE_DETECTOR",
  "confidence":      0.75,
  "confidence_band": "HIGH",
  "threats":         ["PROMPT_INJECTION"],
  "sanitized_input": null,
  "output":          null,
  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "policy_source":  "system_default"
  }
}
```

**Example — proxy mode:**

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: wrapsec_admin_key" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "What is machine learning?",
    "execution_mode": "proxy",
    "model": "llama3.2:latest"
  }'
```

**Example — with user attribution:**

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: wsk_live_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "Summarise the Q4 report",
    "metadata": {
      "user_id": "emp_12345",
      "source":  "finance-bot"
    }
  }'
```

**Example — debug mode (admin only):**

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: wrapsec_admin_key" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "Ignore all previous instructions",
    "options": {"debug": true}
  }'
```

Debug response includes per-layer scores:

```json
{
  "trace_id": "req_abc123",
  "decision":  "BLOCK",
  "risk_score": 0.85,
  "debug": {
    "rule_score": 0.85,
    "ml_score":   0.30,
    "llm_score":  0.00,
    "pii_score":  0.00,
    "layer_decisions": {
      "rule": "BLOCK",
      "ml":   "ALLOW",
      "llm":  "ALLOW"
    }
  }
}
```

---

### GET /v1/ai/requests/{trace_id}

Retrieve a specific request by trace ID.

**Response:**

```json
{
  "trace_id":  "req_abc123",
  "timestamp": "2026-04-10T03:14:22Z",
  "attribution": {
    "tenant_id":            "42a083bf-...",
    "dept_id":              "d79ad4d5-...",
    "app_id":               "972eae29-...",
    "source":               "Finance Bot",
    "user_id":              "emp_12345",
    "key_id":               "key_abc123",
    "ip_address":           "10.0.0.45",
    "user_agent":           "FinanceBot/2.1",
    "attribution_verified": false
  },
  "decision":        "BLOCK",
  "risk_score":      0.85,
  "primary_reason":  "RULE_DETECTOR",
  "confidence":      0.75,
  "confidence_band": "HIGH",
  "threats":         ["PROMPT_INJECTION"],
  "input_hash":      "sha256:2847bd141d1ca1b6...",
  "detection_scores": {
    "rule": 0.85,
    "ml":   0.30,
    "llm":  0.00
  },
  "guardrail_scores": {
    "pii": 0.00
  },
  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "policy_source":  "department_override"
  }
}
```

---

## Audit

### GET /v1/audit/logs

List audit logs with filters.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `trace_id` | string | Search by trace ID (partial match) |
| `decision` | string | Filter by decision: `BLOCK`, `SANITIZE`, `ALLOW` |
| `threat_category` | string | Filter by threat category |
| `from` | ISO datetime | Start of time range |
| `to` | ISO datetime | End of time range |
| `sort_by` | string | Sort field: `created_at`, `risk_score`, `latency_ms` |
| `sort_order` | string | `asc` or `desc` (default: `desc`) |
| `limit` | integer | Max results (default: 20, max: 500) |
| `offset` | integer | Pagination offset (default: 0) |

**Example:**

```bash
curl "http://localhost:8000/v1/audit/logs?decision=BLOCK&limit=10" \
  -H "x-api-key: wrapsec_admin_key"
```

**Response:**

```json
{
  "total": 142,
  "items": [
    {
      "trace_id":       "req_abc123",
      "timestamp":      "2026-04-10T03:14:22Z",
      "tenant_id":      "42a083bf-...",
      "decision":       "BLOCK",
      "risk_score":     0.85,
      "threats":        ["PROMPT_INJECTION"],
      "input_hash":     "sha256:2847bd...",
      "detection_mode": "fast",
      "execution_mode": "scan_only",
      "latency_ms":     2.1,
      "key_id":         "key_abc123",
      "source":         "Finance Bot",
      "attribution_verified": false
    }
  ]
}
```

---

### GET /v1/audit/stats

Aggregated statistics for the audit log.

**Response:**

```json
{
  "total_requests": 1247,
  "decisions": {
    "BLOCK":    423,
    "SANITIZE": 89,
    "ALLOW":    735
  },
  "block_rate":    0.339,
  "avg_latency_ms": 4.2,
  "top_threats": [
    { "category": "PROMPT_INJECTION", "count": 312 },
    { "category": "PII",              "count": 89  },
    { "category": "JAILBREAK",        "count": 67  }
  ]
}
```

---

## Settings

### GET /v1/settings/thresholds

Get current policy thresholds.

**Response:**

```json
{
  "block_threshold":    0.7,
  "sanitize_threshold": 0.4
}
```

---

### PUT /v1/settings/thresholds

Update policy thresholds. Changes take effect immediately without restart.

**Request body:**

```json
{
  "block_threshold":    0.8,
  "sanitize_threshold": 0.5
}
```

**Validation rules:**
- `block_threshold` must be > 0 and <= 1.0
- `sanitize_threshold` must be >= 0 and < 1.0
- `block_threshold` must be > `sanitize_threshold`

---

### GET /v1/settings/layers

Get current detection layer toggles.

**Response:**

```json
{
  "rule_enabled": true,
  "ml_enabled":   true,
  "llm_enabled":  true
}
```

---

### PUT /v1/settings/layers

Enable or disable detection layers. Changes take effect immediately.

**Request body:**

```json
{
  "rule_enabled": true,
  "ml_enabled":   true,
  "llm_enabled":  false
}
```

---

### GET /v1/settings/llm

Get current LLM configuration.

**Response:**

```json
{
  "provider":    "ollama",
  "model":       "llama3.2:latest",
  "base_url":    "http://localhost:11434",
  "timeout":     30,
  "llm_trigger": 0.2
}
```

---

### PUT /v1/settings/llm

Update LLM configuration. Changes take effect immediately without restart.

**Request body:**

```json
{
  "provider":    "openai",
  "model":       "gpt-4",
  "timeout":     60,
  "llm_trigger": 0.3
}
```

**Validation rules:**
- `provider` must be `ollama`, `openai`, or `groq`
- `timeout` must be between 5 and 120 seconds
- `llm_trigger` must be between 0.0 and 1.0
- API keys for OpenAI and Groq are configured in `.env` only — not stored in the database

---

## API Keys

### POST /v1/keys

Create a new API key. Optionally link to an application.

**Request body:**

```json
{
  "name":       "Finance Bot Key",
  "app_id":     "972eae29-6ae9-4619-aa60-83a418c3a511",
  "expires_at": null
}
```

**Response:**

```json
{
  "key_id":     "key_abc123",
  "name":       "Finance Bot Key",
  "api_key":    "wsk_live_PTyW8LaBq5opGiz7...",
  "app_id":     "972eae29-...",
  "dept_id":    "d79ad4d5-...",
  "tenant_id":  "42a083bf-...",
  "created_at": "2026-04-10T03:14:22Z",
  "expires_at": null
}
```

> **Important:** The `api_key` value is only returned once at creation. Store it securely — it cannot be retrieved again.

---

### GET /v1/keys

List all active API keys.

**Response:**

```json
{
  "keys": [
    {
      "key_id":       "key_abc123",
      "name":         "Finance Bot Key",
      "app_id":       "972eae29-...",
      "dept_id":      "d79ad4d5-...",
      "created_at":   "2026-04-10T03:14:22Z",
      "expires_at":   null,
      "last_used_at": "2026-04-10T09:31:05Z"
    }
  ]
}
```

---

### DELETE /v1/keys/{key_id}

Revoke an API key. Takes effect immediately — all subsequent requests with this key will return 401.

**Response:**

```json
{
  "key_id":     "key_abc123",
  "revoked":    true,
  "revoked_at": "2026-04-10T09:45:00Z"
}
```

---

## Administration

### GET /v1/admin/departments

List all departments.

**Response:**

```json
{
  "departments": [
    {
      "id":              "d79ad4d5-...",
      "tenant_id":       "42a083bf-...",
      "slug":            "finance",
      "name":            "Finance Department",
      "description":     "Finance division",
      "policy_override": {
        "thresholds": {
          "block":    0.5,
          "sanitize": 0.3
        }
      },
      "contact_email":  "finance@acme.com",
      "is_active":      true,
      "created_at":     "2026-04-10T01:00:00Z"
    }
  ]
}
```

---

### POST /v1/admin/departments

Create a new department.

**Request body:**

```json
{
  "slug":          "hr",
  "name":          "Human Resources",
  "description":   "HR division",
  "contact_email": "hr@acme.com"
}
```

---

### GET /v1/admin/departments/{id}

Get a department by ID.

---

### PUT /v1/admin/departments/{id}

Update a department or its policy override.

**Request body:**

```json
{
  "policy_override": {
    "thresholds": {
      "block":    0.5,
      "sanitize": 0.3
    }
  }
}
```

Set `policy_override` to `null` to remove all overrides and inherit from global.

---

### DELETE /v1/admin/departments/{id}

Deactivate a department.

**Response:**

```json
{
  "dept_id":     "d79ad4d5-...",
  "deactivated": true
}
```

---

### GET /v1/admin/applications

List all applications. Optionally filter by department.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `dept_id` | UUID | Filter by department |

**Response:**

```json
{
  "applications": [
    {
      "id":                  "972eae29-...",
      "tenant_id":           "42a083bf-...",
      "dept_id":             "d79ad4d5-...",
      "slug":                "finance-bot",
      "name":                "Finance Bot",
      "description":         "Finance automation system",
      "owner_name":          "John Smith",
      "owner_email":         "john@acme.com",
      "environment":         "production",
      "metadata":            null,
      "policy_override":     null,
      "rate_limit_override": null,
      "is_active":           true,
      "created_at":          "2026-04-10T01:05:47Z"
    }
  ]
}
```

---

### POST /v1/admin/applications

Create a new application.

**Request body:**

```json
{
  "dept_id":     "d79ad4d5-...",
  "slug":        "finance-bot",
  "name":        "Finance Bot",
  "description": "Finance automation system",
  "owner_name":  "John Smith",
  "owner_email": "john@acme.com",
  "environment": "production"
}
```

---

### GET /v1/admin/applications/{id}

Get an application by ID.

---

### PUT /v1/admin/applications/{id}

Update an application.

---

### DELETE /v1/admin/applications/{id}

Deactivate an application.

---

## Health

### GET /health/ready

Returns system readiness — checks DB and Redis connectivity.

**Response (healthy):**

```json
{
  "status":     "ready",
  "database":   "ok",
  "redis":      "ok",
  "timestamp":  "2026-04-10T03:14:22Z"
}
```

**Response (degraded):**

```json
{
  "status":   "degraded",
  "database": "ok",
  "redis":    "error",
  "timestamp": "2026-04-10T03:14:22Z"
}
```

---

### GET /health/live

Returns liveness — confirms the process is running.

```json
{ "status": "alive" }
```

---

### GET /metrics

Prometheus metrics endpoint. Returns plain text in Prometheus exposition format.

---

## Integration Guide

### Quickstart

```python
import httpx

client = httpx.Client(
    base_url = "http://localhost:8000",
    headers  = {"x-api-key": "your-key"},
)

response = client.post("/v1/ai/request", json={
    "input":          user_prompt,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "metadata": {
        "user_id": current_user.id,
        "source":  "my-app",
    },
})

result = response.json()

if result["decision"] == "BLOCK":
    return "Request blocked by security policy"
elif result["decision"] == "SANITIZE":
    safe_input = result["sanitized_input"]
    # proceed with sanitized_input
else:
    # ALLOW — proceed normally
```

### Proxy mode integration

```python
response = client.post("/v1/ai/request", json={
    "input":          user_prompt,
    "execution_mode": "proxy",
    "model":          "llama3.2:latest",
    "metadata":       {"user_id": current_user.id},
})

result = response.json()

if result["decision"] == "BLOCK":
    return "Request blocked"

# LLM output is in result["output"]
return result["output"]
```

### Handling confidence

```python
result = response.json()

if result["confidence_band"] == "LOW":
    # Flag for human review
    flag_for_review(result["trace_id"])

if result["decision"] == "BLOCK":
    log_block(
        trace_id       = result["trace_id"],
        primary_reason = result["primary_reason"],
        confidence     = result["confidence"],
    )
```

---

## Planned APIs — V1.1

These endpoints are planned for v1.1 and are not yet implemented:

```
GET  /v1/admin/tenant              → get tenant global policy
PUT  /v1/admin/tenant              → update global policy

GET  /v1/admin/departments/{id}/stats → per-department usage stats
GET  /v1/admin/analytics           → cross-department analytics

POST /v1/admin/roles               → create role
GET  /v1/admin/roles               → list roles
PUT  /v1/admin/roles/{id}          → update role policy override
```

---

## Planned APIs — V2

```
POST /v1/auth/token                → JWT token exchange
GET  /v1/admin/tenants             → list all tenants (SaaS)
POST /v1/admin/tenants             → create tenant (SaaS onboarding)
GET  /v1/admin/tenants/{id}/usage  → usage and billing per tenant
POST /v1/webhooks                  → register webhook endpoint
GET  /v1/export/audit              → export audit logs as CSV
```

---

## Rate Limiting

Requests are rate limited per API key.

**Default:** 60 requests per minute per key  
**Headers returned on limit:**

```
X-RateLimit-Limit:     60
X-RateLimit-Remaining: 0
X-RateLimit-Reset:     1712718262
```

**Response when limited:**

```json
{
  "error": {
    "code":    "RATE_LIMITED",
    "message": "Rate limit exceeded. Try again in 30 seconds.",
    "trace_id": "req_abc123"
  }
}
```

---

## Changelog

### v1.0 (April 2026)
- Initial release
- Detection pipeline: rule, ML, LLM, PII guardrail
- Policy thresholds and layer toggles (runtime configurable)
- LLM settings (runtime configurable)
- API key management with instant revocation
- Department and application management
- Policy resolution: system → tenant → department
- Full attribution chain in audit logs
- Confidence score and primary reason in all responses
- Prometheus metrics and structured logging

---

*API version: 1.0*  
*Authentication: API key (`x-api-key` header)*  
*Content-Type: `application/json`*
