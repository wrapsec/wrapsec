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
**Standard key** (`wsk_live_...`) — scoped to the department and application the key belongs to. Tenant identity is always derived from the API key — it cannot be overridden by the caller.

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
| `RATE_LIMITED` | 429 | Rate limit exceeded |
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
  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "policy_source":  "department_override"
  }
}
```

**Response field rules:**
- `sanitized_input` — only present when `decision = SANITIZE`
- `output` — only present in proxy mode when LLM was invoked
- `threats` — always present (empty array if none)
- `confidence` — always present (1.0 for single-layer fast mode)

**Decision values:** `BLOCK` | `SANITIZE` | `ALLOW`

**Threat categories:** `PROMPT_INJECTION` | `JAILBREAK` | `MALICIOUS_INTENT` | `DATA_EXFILTRATION` | `PII` | `TOXICITY`

**Primary reason values:**

| Value | Description |
|---|---|
| `RULE_DETECTOR` | Regex or heuristic pattern was the dominant signal |
| `ML_DETECTOR` | ML classifier was the dominant signal |
| `LLM_DETECTOR` | LLM semantic analysis was the dominant signal |
| `PII_GUARDRAIL_BLOCK` | PII guardrail triggered a BLOCK decision |
| `PII_GUARDRAIL_SANITIZE` | PII guardrail triggered a SANITIZE decision |
| `NO_THREAT_DETECTED` | All scores below thresholds — clean request |

**Confidence bands:**

| Band | Range | Meaning |
|---|---|---|
| `HIGH` | 0.7 – 1.0 | Strong signal, consistent across layers |
| `MEDIUM` | 0.4 – 0.7 | Moderate signal or partial agreement between layers |
| `LOW` | 0.0 – 0.4 | Weak or conflicting signals — consider human review |

**Policy source values:**

| Value | Description |
|---|---|
| `system_default` | No overrides — using `.env` defaults |
| `tenant_global` | Tenant global policy applied |
| `department_override` | Department policy changed at least one field |
| `application_override` | Application policy changed at least one field (v1.1) |

---

## Gateway

### POST /v1/ai/request

Scan a prompt through the detection pipeline. Optionally proxy to an LLM.

**Request body:**

```json
{
  "input": "string (required, max 10000 chars)",
  "detection_mode": "fast | full (default: fast)",
  "execution_mode": "scan_only | proxy (default: scan_only)",
  "model": "string (proxy mode only — ignored in scan_only)",
  "metadata": {
    "user_id": "string (optional — self-reported, not verified)",
    "source":  "string (optional — label for audit display, defaults to key name)"
  },
  "options": {
    "debug": "boolean (admin only, default: false)"
  }
}
```

> **Security note:** `tenant_id` is not accepted in metadata. Tenant identity is always derived from the API key. This prevents caller spoofing.

> **Source field note:** `source` is an optional label for audit display only. It is never used for identity or policy decisions. If omitted, it defaults to the API key name.

**Detection modes:**

| Mode | Layers | Latency |
|---|---|---|
| `fast` | Rule + ML | ~2–10ms |
| `full` | Rule + ML + LLM (conditional) | ~100–500ms |

**Execution modes:**

| Mode | Description |
|---|---|
| `scan_only` | Scan and return decision only. `model` field ignored. |
| `proxy` | Scan then forward to LLM if not blocked. Requires LLM layer to be enabled. |

**Validation rules:**
- `proxy` mode requires LLM layer to be enabled in settings
- `model` field is ignored in `scan_only` mode
- `stream: true` only valid in `proxy` mode

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

**Response — BLOCK:**

```json
{
  "trace_id":        "req_abc123",
  "decision":        "BLOCK",
  "risk_score":      0.85,
  "primary_reason":  "RULE_DETECTOR",
  "confidence":      0.75,
  "confidence_band": "HIGH",
  "threats":         ["PROMPT_INJECTION"],
  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "policy_source":  "system_default"
  }
}
```

**Response — SANITIZE (includes sanitized_input):**

```json
{
  "trace_id":        "req_def456",
  "decision":        "SANITIZE",
  "risk_score":      0.55,
  "primary_reason":  "PII_GUARDRAIL_SANITIZE",
  "confidence":      0.75,
  "confidence_band": "HIGH",
  "threats":         ["PII"],
  "sanitized_input": "My email is [EMAIL] and SSN is [SSN]",
  "processing": {
    "latency_ms":     3.2,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "policy_source":  "department_override"
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

**Response — proxy ALLOW (includes output):**

```json
{
  "trace_id":        "req_ghi789",
  "decision":        "ALLOW",
  "risk_score":      0.0,
  "primary_reason":  "NO_THREAT_DETECTED",
  "confidence":      1.0,
  "confidence_band": "HIGH",
  "threats":         [],
  "output":          "Machine learning is a subset of AI...",
  "processing": {
    "latency_ms":     312.4,
    "llm_invoked":    true,
    "detection_mode": "fast",
    "execution_mode": "proxy",
    "policy_source":  "system_default"
  }
}
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
      "source":  "finance-dashboard"
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
  "trace_id":        "req_abc123",
  "decision":        "BLOCK",
  "risk_score":      0.85,
  "primary_reason":  "RULE_DETECTOR",
  "confidence":      0.75,
  "confidence_band": "HIGH",
  "threats":         ["PROMPT_INJECTION"],
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
  },
  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "policy_source":  "system_default"
  }
}
```

---

### GET /v1/ai/requests/{trace_id}

Retrieve a specific request by trace ID including full attribution chain.

**Response:**

```json
{
  "trace_id":  "req_abc123",
  "timestamp": "2026-04-10T03:14:22Z",
  "attribution": {
    "tenant_id":            "42a083bf-...",
    "dept_id":              "d79ad4d5-...",
    "dept_name":            "Finance Department",
    "app_id":               "972eae29-...",
    "app_name":             "Finance Bot",
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

> **Attribution note:** `attribution_verified: false` means user identity (`user_id`) is self-reported by the calling application. The API key identity (key_id, dept_id, app_id) is always cryptographically verified.

---

## Audit

### GET /v1/audit/logs

List audit logs with filters and sorting.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `trace_id` | string | Search by trace ID (partial match) |
| `decision` | string | Filter: `BLOCK`, `SANITIZE`, `ALLOW` |
| `threat_category` | string | Filter by threat category |
| `primary_reason` | string | Filter by primary reason (e.g. `RULE_DETECTOR`) |
| `confidence_band` | string | Filter: `HIGH`, `MEDIUM`, `LOW` |
| `source` | string | Filter by source (partial match) |
| `key_id` | string | Filter by API key ID |
| `dept_id` | string | Filter by department ID |
| `app_id` | string | Filter by application ID |
| `user_id` | string | Filter by user ID (partial match) |
| `from` | ISO datetime | Start of time range |
| `to` | ISO datetime | End of time range |
| `sort_by` | string | `created_at`, `risk_score`, `latency_ms` |
| `sort_order` | string | `asc` or `desc` (default: `desc`) |
| `limit` | integer | Max results (default: 20, max: 500) |
| `offset` | integer | Pagination offset (default: 0) |

**Example — filter by confidence and reason:**

```bash
curl "http://localhost:8000/v1/audit/logs?confidence_band=LOW&primary_reason=ML_DETECTOR" \
  -H "x-api-key: wrapsec_admin_key"
```

**Response:**

```json
{
  "total": 142,
  "items": [
    {
      "trace_id":              "req_abc123",
      "timestamp":             "2026-04-10T03:14:22Z",
      "tenant_id":             "42a083bf-...",
      "decision":              "BLOCK",
      "risk_score":            0.85,
      "threats":               ["PROMPT_INJECTION"],
      "input_hash":            "sha256:2847bd...",
      "detection_mode":        "fast",
      "execution_mode":        "scan_only",
      "latency_ms":            2.1,
      "key_id":                "key_abc123",
      "source":                "Finance Bot",
      "ip_address":            "10.0.0.45",
      "attribution_verified":  false
    }
  ]
}
```

---

### GET /v1/audit/stats

Aggregated statistics for the audit log.

**Query parameters:** `tenant_id`, `from`, `to`

**Response:**

```json
{
  "total_requests": 1247,
  "block_rate":     0.339,
  "sanitize_rate":  0.071,
  "allow_rate":     0.590,
  "avg_latency_ms": 4.2,
  "p95_latency_ms": 12.1,
  "top_threats": [
    { "category": "PROMPT_INJECTION", "count": 312 },
    { "category": "PII",              "count": 89  },
    { "category": "JAILBREAK",        "count": 67  }
  ]
}
```

---

### GET /v1/audit/attribution

Attribution summary — requests grouped by key, department, application, primary reason, and confidence band. Useful for security review and compliance reporting.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `dept_id` | string | Scope to a specific department |
| `limit` | integer | Max items per group (default: 10, max: 100) |

**Response:**

```json
{
  "by_key": [
    {
      "key_id":         "key_abc123",
      "source":         "Finance Bot",
      "total":          847,
      "blocked":        312,
      "block_rate":     0.368,
      "avg_latency_ms": 3.2
    }
  ],
  "by_department": [
    {
      "dept_id":    "d79ad4d5-...",
      "total":      1247,
      "blocked":    423,
      "block_rate": 0.339
    }
  ],
  "by_application": [
    {
      "app_id":         "972eae29-...",
      "total":          847,
      "blocked":        312,
      "block_rate":     0.368,
      "avg_latency_ms": 3.2
    }
  ],
  "by_primary_reason": [
    { "primary_reason": "RULE_DETECTOR",     "count": 280 },
    { "primary_reason": "PII_GUARDRAIL_BLOCK", "count": 89 },
    { "primary_reason": "NO_THREAT_DETECTED",  "count": 735 }
  ],
  "by_confidence_band": [
    { "band": "HIGH",   "count": 1190 },
    { "band": "MEDIUM", "count": 42   },
    { "band": "LOW",    "count": 15   }
  ]
}
```

---

### GET /v1/audit/export

Export audit logs as CSV for compliance reporting.

**Query parameters:** `dept_id`, `app_id`, `decision`, `primary_reason`, `confidence_band`, `from`, `to`, `limit` (max: 10000)

**Response:** CSV file download (`wrapsec_audit_export.csv`)

**CSV columns:**
```
trace_id, timestamp, decision, risk_score, confidence, confidence_band,
primary_reason, threats, tenant_id, dept_id, app_id, key_id, source,
user_id, ip_address, policy_source, detection_mode, latency_ms
```

**Example:**

```bash
curl "http://localhost:8000/v1/audit/export?dept_id=d79ad4d5-...&from=2026-04-01" \
  -H "x-api-key: wrapsec_admin_key" \
  -o audit_export.csv
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
- `block_threshold` must be > 0.0 and <= 1.0
- `sanitize_threshold` must be >= 0.0 and < 1.0
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

> **Note:** Disabling the LLM layer will prevent proxy mode from working. Proxy mode requires LLM to be enabled.

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
- API keys for OpenAI and Groq are configured in `.env` only — never stored in the database

> **LLM trigger note:** `llm_trigger` is the minimum pre-score before the LLM detector is invoked in `full` mode. Lower values invoke the LLM more frequently (higher accuracy, higher latency).

---

## API Keys

### POST /v1/keys

Create a new API key. Optionally link to an application for full attribution.

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

List all active (non-revoked) API keys.

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

### GET /v1/keys/{key_id}

Get a single API key by key ID.

**Response:**

```json
{
  "key_id":       "key_abc123",
  "name":         "Finance Bot Key",
  "app_id":       "972eae29-...",
  "dept_id":      "d79ad4d5-...",
  "tenant_id":    "42a083bf-...",
  "is_admin":     false,
  "revoked":      false,
  "created_at":   "2026-04-10T03:14:22Z",
  "expires_at":   null,
  "last_used_at": "2026-04-10T09:31:05Z"
}
```

---

### PUT /v1/keys/{key_id}

Rename an API key.

**Request body:**

```json
{ "name": "Finance Bot Primary Key" }
```

**Response:**

```json
{
  "key_id":     "key_abc123",
  "name":       "Finance Bot Primary Key",
  "updated_at": "2026-04-10T09:45:00Z"
}
```

---

### DELETE /v1/keys/{key_id}

Revoke an API key. Takes effect immediately — all subsequent requests with this key return 401.

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

### GET /v1/admin/tenant

Get current tenant information and global policy.

**Response:**

```json
{
  "id":          "42a083bf-...",
  "slug":        "default",
  "name":        "Acme Corporation",
  "description": "Single on-premise installation",
  "global_policy": {
    "detection": {
      "rule_weight": 0.4, "ml_weight": 0.3, "llm_weight": 0.3,
      "rule_enabled": true, "ml_enabled": true, "llm_enabled": true,
      "llm_trigger": 0.2
    },
    "thresholds":  { "block": 0.7, "sanitize": 0.4 },
    "guardrails":  { "pii": { "enabled": true, "block_threshold": 0.7, "sanitize_threshold": 0.4 } },
    "rate_limit":  { "per_minute": 60 }
  },
  "contact_email": "admin@acme.com",
  "is_active":     true,
  "created_at":    "2026-04-10T00:44:13Z"
}
```

---

### PUT /v1/admin/tenant

Update tenant information.

**Request body:**

```json
{
  "name":          "Acme Corporation",
  "description":   "Single on-premise WrapSec installation",
  "contact_email": "security@acme.com"
}
```

---

### GET /v1/admin/departments

List all active departments.

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
        "thresholds": { "block": 0.5, "sanitize": 0.3 }
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
    "thresholds": { "block": 0.5, "sanitize": 0.3 }
  }
}
```

Set `policy_override` to `null` to remove all overrides and inherit from global.

---

### GET /v1/admin/departments/{id}/policy

Returns the fully resolved effective policy for this department. Merges system defaults → tenant global → department override. Use this to verify what policy is actually applied to requests from this department.

**Response:**

```json
{
  "dept_id":       "d79ad4d5-...",
  "dept_name":     "Finance Department",
  "policy_source": "department_override",
  "override_set":  true,
  "policy_override": {
    "thresholds": { "block": 0.5, "sanitize": 0.3 }
  },
  "resolved_policy": {
    "detection":  { "rule_weight": 0.4, "ml_weight": 0.3, "llm_weight": 0.3, "rule_enabled": true, "ml_enabled": true, "llm_enabled": true, "llm_trigger": 0.2 },
    "thresholds": { "block": 0.5, "sanitize": 0.3 },
    "guardrails": { "pii": { "enabled": true, "block_threshold": 0.7, "sanitize_threshold": 0.4 } },
    "llm":        { "provider": "ollama", "model": "llama3.2:latest", "base_url": "http://localhost:11434", "timeout": 30 },
    "rate_limit": { "per_minute": 60 }
  }
}
```

---

### GET /v1/admin/departments/{id}/stats

Usage statistics for a specific department.

**Response:**

```json
{
  "dept_id":        "d79ad4d5-...",
  "total":          1247,
  "decisions":      { "BLOCK": 423, "SANITIZE": 89, "ALLOW": 735 },
  "block_rate":     0.339,
  "avg_latency_ms": 4.2,
  "top_threats": [
    { "category": "PROMPT_INJECTION", "count": 312 },
    { "category": "PII",              "count": 89  }
  ]
}
```

---

### DELETE /v1/admin/departments/{id}

Deactivate a department.

---

### GET /v1/admin/applications

List all applications. Optionally filter by department.

**Query parameters:** `dept_id`

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

### GET /v1/admin/applications/{id}/policy

Returns the fully resolved effective policy for this application. In v1, application-level overrides are null — the resolved policy reflects system → tenant → department chain.

**Response:**

```json
{
  "app_id":          "972eae29-...",
  "app_name":        "Finance Bot",
  "dept_id":         "d79ad4d5-...",
  "policy_source":   "department_override",
  "override_set":    false,
  "policy_override": null,
  "resolved_policy": { ... }
}
```

> **V1.1 note:** Application-level policy overrides (`PUT /v1/admin/applications/{id}/policy`) will be available in v1.1.

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
  "status": "ready",
  "checks": {
    "database": "ok",
    "redis":    "ok",
    "ml_model": "ok"
  }
}
```

---

### GET /health/live

Returns liveness — confirms the process is running.

```json
{ "status": "alive" }
```

---

### GET /health/config

Returns the currently active system configuration. Useful for deployment verification. Does not expose API keys or secrets.

**Response:**

```json
{
  "version": "1.0.0",
  "thresholds": {
    "block":    0.7,
    "sanitize": 0.4,
    "source":   "database"
  },
  "detection_layers": {
    "rule":   true,
    "ml":     true,
    "llm":    true,
    "source": "database"
  },
  "llm": {
    "provider":    "ollama",
    "model":       "llama3.2:latest",
    "llm_trigger": 0.2,
    "timeout":     30,
    "source":      "database"
  },
  "rate_limit": {
    "per_minute": 60,
    "scope":      "per_api_key"
  }
}
```

---

### GET /metrics

Prometheus metrics endpoint. Returns plain text in Prometheus exposition format. No authentication required.

---

## Integration Guide

### Python quickstart

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
    # proceed with sanitized input
else:
    # ALLOW — proceed normally
    pass
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
    flag_for_review(
        trace_id       = result["trace_id"],
        primary_reason = result["primary_reason"],
        confidence     = result["confidence"],
    )

if result["decision"] == "BLOCK":
    log_block(
        trace_id       = result["trace_id"],
        primary_reason = result["primary_reason"],
        confidence     = result["confidence"],
        dept_scoped    = True,  # policy came from department
    )
```

### Compliance audit query

```python
# Export all LOW confidence decisions for review
response = client.get("/v1/audit/export", params={
    "confidence_band": "LOW",
    "from": "2026-04-01T00:00:00",
    "to":   "2026-04-30T23:59:59",
})

with open("low_confidence_audit.csv", "wb") as f:
    f.write(response.content)
```

---

## Rate Limiting

Requests are rate limited per API key using a sliding window.

**Default:** 60 requests per minute per key

**Response when limited:**

```json
{
  "error": {
    "code":     "RATE_LIMITED",
    "message":  "Rate limit exceeded. Try again in 30 seconds.",
    "trace_id": "req_abc123"
  }
}
```

---

## Planned — V1.1

```
PUT    /v1/admin/applications/{id}/policy  → application-level policy overrides
DELETE /v1/admin/applications/{id}/policy  → reset application override
POST   /v1/keys/{key_id}/rotate            → key rotation with grace period
GET    /v1/admin/analytics                 → advanced cross-department analytics
```

**Idempotency support (V1.1):**

```
Idempotency-Key: <uuid>
```

Prevents duplicate processing on retries. Response is cached for 60 seconds per key.

**Cursor-based pagination (V1.1):**

For large audit log datasets, offset pagination will be replaced with cursor-based pagination:

```
GET /v1/audit/logs?cursor=req_abc123&limit=20
```

---

## Planned — V2

```
POST /v1/auth/token                → JWT token exchange (verified user identity)
POST /v1/admin/tenants             → multi-tenant onboarding (SaaS)
GET  /v1/admin/tenants/{id}/usage  → usage and billing per tenant
POST /v1/webhooks                  → webhook notifications for BLOCK events
POST /v1/admin/roles               → role management with JWT assignment
```

---

## Changelog

### v1.0 (April 2026)

**Security:**
- `tenant_id` removed from request metadata — always derived from API key to prevent spoofing
- `model` field ignored in `scan_only` mode
- Proxy mode validates LLM layer is enabled before processing
- Debug mode restricted to admin keys only

**Detection:**
- Multi-layer pipeline: rule, ML, LLM, PII guardrail
- Confidence score with `HIGH/MEDIUM/LOW` bands
- `primary_reason` field identifying dominant detection factor
- Detection and guardrail scores stored separately in audit logs

**Policy:**
- Runtime configurable thresholds, detection layers, LLM settings (no restart)
- Policy resolution: system → tenant → department → application
- `policy_source` in every response showing which level determined the policy

**Attribution:**
- Full attribution chain: tenant → department → application → key → user → IP
- `attribution_verified: false` in v1 (self-reported user identity)
- `source` defaults to API key name if not provided

**APIs:**
- 38 endpoints across gateway, audit, settings, keys, admin, health
- Audit export as CSV for compliance reporting
- Attribution report grouped by key, department, application, reason, confidence

---

*API version: 1.0*  
*Authentication: API key (`x-api-key` header)*  
*Content-Type: `application/json`*  
*Total endpoints: 38*
