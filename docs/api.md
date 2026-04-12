# WrapSec API Reference

Version: 1.0 — Final  
Base URL: `http://your-host:8000`  
Total endpoints: 39  
Last updated: April 2026

---

## Authentication

All endpoints except `/health/*` and `/metrics` require an API key.

```
x-api-key: your-api-key
```

**Admin key** — full access including debug mode and all admin routes.

**Standard key** (`wsk_live_...`) — scoped to the department and application the key belongs to. `tenant_id` is never accepted from request metadata — always derived from the API key to prevent cross-tenant spoofing.

---

## Standard Headers

**Request:**

| Header | Required | Description |
|---|---|---|
| `x-api-key` | Yes | API key |
| `Content-Type` | Yes (POST/PUT) | `application/json` |
| `Idempotency-Key` | No | UUID for idempotent POST /v1/ai/request |

**Response (always present):**

| Header | Description |
|---|---|
| `x-trace-id` | ULID trace ID (`req_01knzhh8...`) |
| `X-RateLimit-Limit` | Requests per minute |
| `X-RateLimit-Remaining` | Remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when window resets |
| `X-Idempotency-Replayed` | `true` when response served from cache |

---

## Input Limits

| Limit | Value | Enforcement | Notes |
|---|---|---|---|
| Max characters | 8,000 | Schema → 422 | |
| Estimated token limit | 4,000 | `ceil(len/2) > 4000` → 422 | Safe for CJK |
| Max payload | 64KB | Nginx → 413 | |
| Max audit export rows | 10,000 | Param validation | |

The heuristic `ceil(len/2)` assumes 2 chars per token — conservative for all languages. Full per-model tiktoken enforcement planned for V1.1.

**Important:** Because this is a conservative estimate, inputs near the 8,000 character boundary may be rejected even if their actual token count is below 4,000. For example, 8,001 characters of English text (actual: ~2,000 tokens) will be rejected because the estimate (`ceil(8001/2) = 4001`) exceeds the limit. Integrators should treat 8,000 characters as the effective hard limit and not rely on the token estimate being accurate for their specific language or content type. V1.1 will replace this heuristic with per-model tiktoken counting.

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

**Error codes:**

| Code | HTTP | Description |
|---|---|---|
| `UNAUTHORIZED` | 401 | Missing, invalid, or revoked API key |
| `FORBIDDEN` | 403 | Valid key, insufficient permissions |
| `NOT_FOUND` | 404 | Resource does not exist |
| `VALIDATION_ERROR` | 422 | Body failed validation (includes token limit) |
| `IDEMPOTENCY_CONFLICT` | 409 | Same Idempotency-Key used with different body |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

---

## Idempotency

POST `/v1/ai/request` supports the `Idempotency-Key` header.

```
Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000
```

| Scenario | Response |
|---|---|
| First request with key | Process normally, cache response (60s TTL) |
| Same key + same body | Cached response, `X-Idempotency-Replayed: true` |
| Same key + different body | **409 CONFLICT — do not process** |

```json
// 409 response
{
  "error": {
    "code":    "IDEMPOTENCY_CONFLICT",
    "message": "Idempotency-Key was already used with a different request body.",
    "trace_id": "req_01knzhh8..."
  }
}
```

Callers must use a new UUID for each distinct operation. If Redis is unavailable → fail open.

---

## Response Envelope

```json
{
  "trace_id":             "req_01knzhh81wrwg2r8r7wnwq139y",
  "decision":             "BLOCK",
  "decision_version":     "v1.0",
  "risk_score":           0.85,
  "primary_reason":       "RULE_DETECTOR",
  "confidence":           0.75,
  "confidence_band":      "HIGH",
  "sanitization_applied": false,
  "threats":              ["PROMPT_INJECTION"],
  "processing": {
    "latency_ms": 2.1, "llm_invoked": false,
    "detection_mode": "fast", "execution_mode": "scan_only",
    "policy_source": "department_override"
  }
}
```

**Field rules:**
- `sanitized_input` — only present when `decision = SANITIZE`
- `output` — only present in proxy mode when LLM responded
- `threats` — always present (empty array if none)
- `risk_score = 0.0` when guardrail triggered (detection not involved)
- `confidence = 0.0` when `primary_reason = SYSTEM_ERROR`

**Decision values:** `BLOCK` | `SANITIZE` | `ALLOW`

**Primary reason values:**

| Value | Trigger | Confidence | Remediation |
|---|---|---|---|
| `RULE_DETECTOR` | Rule highest score | computed | Review rule patterns |
| `ML_DETECTOR` | ML highest score | computed | Review model thresholds |
| `LLM_DETECTOR` | LLM highest score | computed | Review LLM prompt |
| `PII_GUARDRAIL_BLOCK` | PII >= `guardrails.pii.block_threshold` | 0.90–0.95 | Data handling review |
| `PII_GUARDRAIL_SANITIZE` | PII >= `guardrails.pii.sanitize_threshold` | 0.70–0.84 | Monitor sanitisation |
| `NO_THREAT_DETECTED` | Detection succeeded, all scores = 0.0 | computed | No action |
| `SYSTEM_ERROR` | `detection_failed=True` OR system exception | **0.0 (LOW)** | Alert ops immediately |

**`SYSTEM_ERROR` vs `NO_THREAT_DETECTED`:**

These values are produced by mutually exclusive code paths and can never be confused:

- `NO_THREAT_DETECTED` — detectors ran successfully, no threat found
- `SYSTEM_ERROR` — detector(s) failed or system threw an exception

An ALLOW with `NO_THREAT_DETECTED` and an ALLOW with `SYSTEM_ERROR` require completely different responses. The first means the input was safe. The second means the safety check did not run properly. Compliance teams, monitoring systems, and alerting logic must distinguish these.

**Confidence bands:**

| Band | Range | Meaning |
|---|---|---|
| `HIGH` | 0.7 – 1.0 | Trust the decision |
| `MEDIUM` | 0.4 – 0.7 | Monitor |
| `LOW` | 0.0 – 0.4 | Human review or `SYSTEM_ERROR` |

**Policy source:** `system_default` | `tenant_global` | `department_override` | `application_override`

---

## Threshold Architecture

Detection thresholds and PII guardrail thresholds are independent:

```
policy["thresholds"]["block"]                    → detection BLOCK threshold
policy["thresholds"]["sanitize"]                 → detection SANITIZE threshold

policy["guardrails"]["pii"]["block_threshold"]    → PII BLOCK threshold (independent)
policy["guardrails"]["pii"]["sanitize_threshold"] → PII SANITIZE threshold (independent)
```

Changing detection thresholds never affects PII behaviour, and vice versa. Configure them under separate keys in `policy_override`.

---

## Failure Mode Responses

**All detectors fail (fail open — `SYSTEM_ERROR`, NOT `NO_THREAT_DETECTED`):**
```json
{
  "decision":        "ALLOW",
  "decision_version": "v1.0",
  "risk_score":      0.0,
  "primary_reason":  "SYSTEM_ERROR",
  "confidence":      0.0,
  "confidence_band": "LOW",
  "sanitization_applied": false,
  "threats": []
}
```

**Gateway/guardrail exception (fail closed):**
```json
{
  "decision":        "BLOCK",
  "decision_version": "v1.0",
  "risk_score":      1.0,
  "primary_reason":  "SYSTEM_ERROR",
  "confidence":      0.0,
  "confidence_band": "LOW",
  "sanitization_applied": false,
  "threats": []
}
```

**LLM timeout (detection):** continues with rule + ML, `llm_invoked = false`.

**LLM timeout (proxy):** detection decision already made, `output = "[LLM unavailable]"`.

---

## Gateway

### POST /v1/ai/request

**Request body:**

```json
{
  "input": "string (required, 1–8000 chars, estimated ≤4000 tokens)",
  "detection_mode": "fast | full  (default: fast)",
  "execution_mode": "scan_only | proxy  (default: scan_only)",
  "model": "string (proxy mode only — silently ignored in scan_only)",
  "metadata": {
    "user_id": "string (optional, self-reported)",
    "source":  "string (optional, audit label)"
  },
  "options": {
    "debug": "boolean (admin key only)"
  }
}
```

**Validation rules:**
- Input max 8,000 characters → 422
- `ceil(len(input) / 2) > 4000` → 422 (estimated token limit)
- `proxy` requires LLM layer enabled → 422
- `model` silently ignored in `scan_only`
- `debug: true` requires admin key → 403
- `tenant_id` in metadata silently ignored (always from API key)

**Detection modes:**

| Mode | Layers | Latency |
|---|---|---|
| `fast` | Rule + ML | 2–10ms |
| `full` | Rule + ML + LLM (if pre-score >= trigger) | 100–500ms |

---

**Example — scan only:**

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: your-key" \
  -d '{"input": "Ignore all previous instructions"}'
```

**Response — BLOCK:**
```json
{
  "trace_id": "req_01knzhh8...", "decision": "BLOCK", "decision_version": "v1.0",
  "risk_score": 0.85, "primary_reason": "RULE_DETECTOR",
  "confidence": 0.75, "confidence_band": "HIGH",
  "sanitization_applied": false, "threats": ["PROMPT_INJECTION"],
  "processing": {"latency_ms": 2.1, "llm_invoked": false, "detection_mode": "fast", "execution_mode": "scan_only", "policy_source": "system_default"}
}
```

---

**Response — PII BLOCK (risk_score = 0.0 — PII guardrail, not detection):**
```json
{
  "trace_id": "req_01knzhj2...", "decision": "BLOCK", "decision_version": "v1.0",
  "risk_score": 0.0, "primary_reason": "PII_GUARDRAIL_BLOCK",
  "confidence": 0.9015, "confidence_band": "HIGH",
  "sanitization_applied": false, "threats": ["PII"]
}
```

---

**Response — PII SANITIZE:**
```json
{
  "trace_id": "req_01knzhk3...", "decision": "SANITIZE", "decision_version": "v1.0",
  "risk_score": 0.0, "primary_reason": "PII_GUARDRAIL_SANITIZE",
  "confidence": 0.730, "confidence_band": "HIGH",
  "sanitization_applied": true,
  "sanitized_input": "My email is [EMAIL] and SSN is [SSN]",
  "threats": ["PII"]
}
```

---

**Response — ALLOW (clean input, detection succeeded):**
```json
{
  "trace_id": "req_01knzhl4...", "decision": "ALLOW", "decision_version": "v1.0",
  "risk_score": 0.0, "primary_reason": "NO_THREAT_DETECTED",
  "confidence": 0.999, "confidence_band": "HIGH",
  "sanitization_applied": false, "threats": []
}
```

---

**Response — ALLOW (all detectors failed — `SYSTEM_ERROR`, NOT `NO_THREAT_DETECTED`):**
```json
{
  "trace_id": "req_01knzlm5...", "decision": "ALLOW", "decision_version": "v1.0",
  "risk_score": 0.0, "primary_reason": "SYSTEM_ERROR",
  "confidence": 0.0, "confidence_band": "LOW",
  "sanitization_applied": false, "threats": []
}
```

This decision is ALLOW because the system fails open for detection failures (clean inputs should not be blocked by system errors). Confidence is 0.0 and `SYSTEM_ERROR` explicitly identifies this as a failure — not a clean result.

---

**Response — BLOCK (gateway/guardrail exception — fail closed):**
```json
{
  "trace_id": "req_01knznp6...", "decision": "BLOCK", "decision_version": "v1.0",
  "risk_score": 1.0, "primary_reason": "SYSTEM_ERROR",
  "confidence": 0.0, "confidence_band": "LOW",
  "sanitization_applied": false, "threats": []
}
```

This decision is BLOCK because guardrails fail closed — data protection must never fail open.

---

**Example — proxy with idempotency:**

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: your-key" \
  -H "Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000" \
  -d '{"input": "Summarise Q4", "execution_mode": "proxy", "model": "llama3.2:latest"}'
```

**Example — debug mode (admin):**

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: your-admin-key" \
  -d '{"input": "Ignore all previous instructions", "options": {"debug": true}}'
```

Debug adds `detection_scores` per layer:

```json
{
  "debug": {
    "rule_score": 0.85, "ml_score": 0.30, "llm_score": 0.00, "pii_score": 0.00,
    "layer_decisions": {"rule": "BLOCK", "ml": "ALLOW", "llm": "ALLOW"}
  }
}
```

**Debug mode safety:**
- Debug responses expose internal scoring details and per-layer signals
- Restricted to admin keys only — non-admin requests with `debug: true` receive 403
- Never enable `debug: true` in externally facing integrations or production client code
- Debug responses should not be forwarded to external systems or logged to shared log stores
- Use debug mode only in internal tooling, local development, or security testing environments

---

### GET /v1/ai/requests/{trace_id}

Full audit record with attribution chain and per-layer scores.

```json
{
  "trace_id": "req_01knzhh8...", "timestamp": "2026-04-12T03:14:22Z",
  "attribution": {
    "tenant_id": "42a083bf-...", "dept_id": "d79ad4d5-...",
    "dept_name": "Finance Department",
    "app_id": "972eae29-...", "app_name": "Finance Bot",
    "source": "Finance Bot", "user_id": "emp_789",
    "key_id": "key_fin_abc123", "ip_address": "10.0.0.45",
    "user_agent": "FinanceBot/2.1", "attribution_verified": false
  },
  "decision": "BLOCK", "risk_score": 0.85,
  "primary_reason": "RULE_DETECTOR", "confidence": 0.75, "confidence_band": "HIGH",
  "threats": ["PROMPT_INJECTION"], "input_hash": "sha256:2847bd...",
  "detection_scores": {"rule": 0.85, "ml": 0.30, "llm": 0.00},
  "guardrail_scores":  {"pii": 0.00},
  "processing": {"latency_ms": 2.1, "llm_invoked": false, "detection_mode": "fast", "execution_mode": "scan_only", "policy_source": "department_override"}
}
```

---

## Audit

### GET /v1/audit/logs

12 filter parameters: `trace_id`, `decision`, `threat_category`, `primary_reason`, `confidence_band`, `source`, `key_id`, `dept_id`, `app_id`, `user_id`, `from`, `to`

Sort: `sort_by` (created_at|risk_score|latency_ms), `sort_order` (asc|desc)

Pagination: `limit` (max 500), `offset`

**Example — find all system failures:**

```bash
curl "http://localhost:8000/v1/audit/logs?primary_reason=SYSTEM_ERROR" \
  -H "x-api-key: your-admin-key"
```

**Example — find all LOW confidence decisions:**

```bash
curl "http://localhost:8000/v1/audit/logs?confidence_band=LOW" \
  -H "x-api-key: your-admin-key"
```

### GET /v1/audit/stats

Aggregated totals, rates, latency, top threats. Params: `tenant_id`, `from`, `to`

### GET /v1/audit/attribution

Groups by key, department, application, primary reason, confidence band. Params: `dept_id`, `limit`

```json
{
  "by_primary_reason": [
    {"primary_reason": "NO_THREAT_DETECTED", "count": 735},
    {"primary_reason": "RULE_DETECTOR",      "count": 280},
    {"primary_reason": "SYSTEM_ERROR",       "count": 3}
  ]
}
```

### GET /v1/audit/export

CSV download. Max 10,000 rows. Params: `dept_id`, `app_id`, `decision`, `primary_reason`, `confidence_band`, `from`, `to`, `limit`

```bash
# Export all system failures for incident review
curl "http://localhost:8000/v1/audit/export?primary_reason=SYSTEM_ERROR" \
  -H "x-api-key: your-admin-key" -o system_failures.csv
```

---

## Settings

All stored in DB, applied immediately without restart.

### GET/PUT /v1/settings/thresholds

Detection thresholds only. Does NOT affect PII guardrail behaviour.

```json
{"block_threshold": 0.7, "sanitize_threshold": 0.4}
```

Validation: `block > sanitize`, `block <= 1.0`, `sanitize >= 0`

PII guardrail thresholds are configured via `policy_override.guardrails.pii.*` on departments.

### GET/PUT /v1/settings/layers

```json
{"rule_enabled": true, "ml_enabled": true, "llm_enabled": true}
```

Disabling LLM also disables proxy mode.

### GET/PUT /v1/settings/llm

```json
{"provider": "ollama", "model": "llama3.2:latest", "base_url": "http://localhost:11434", "timeout": 30, "llm_trigger": 0.2}
```

LLM API keys are `.env` only — never in DB.

Timeout behaviour:
- Detection: `llm_score=0.0`, `llm_invoked=false`, continues
- Proxy: `output="[LLM unavailable]"`

### GET/PUT /v1/settings/retention

```json
{"retention_days": 30, "source": "database"}
```

Validation: 7–3650 days. Used by `scripts/cleanup_audit_logs.py`.

---

## API Keys

### POST /v1/keys

```json
{"name": "Finance Bot Key", "app_id": "972eae29-..."}
```

Returns `api_key` only once — store securely.

### GET /v1/keys

List all active keys.

### GET /v1/keys/{key_id}

Single key — includes `is_admin`, `revoked`, `last_used_at`.

### PUT /v1/keys/{key_id}

```json
{"name": "Finance Bot Primary"}
```

### DELETE /v1/keys/{key_id}

Revoke immediately — next request with this key returns 401.

---

## Administration

### GET/PUT /v1/admin/tenant

Full tenant info + global policy (detection + PII thresholds shown separately).

### GET/POST/PUT/DELETE /v1/admin/departments/{id}

**PUT — set policy override (detection and PII configured independently):**

```json
{
  "policy_override": {
    "thresholds": {
      "block": 0.5,
      "sanitize": 0.3
    },
    "guardrails": {
      "pii": {
        "block_threshold": 0.6,
        "sanitize_threshold": 0.35
      }
    }
  }
}
```

Set `policy_override: null` to remove all overrides.

### GET /v1/admin/departments/{id}/policy

Returns fully resolved effective policy — detection and PII thresholds shown under separate keys.

```json
{
  "dept_id": "d79ad4d5-...", "dept_name": "Finance Department",
  "policy_source": "department_override", "override_set": true,
  "policy_override": {
    "thresholds": {"block": 0.5, "sanitize": 0.3},
    "guardrails": {"pii": {"block_threshold": 0.6, "sanitize_threshold": 0.35}}
  },
  "resolved_policy": {
    "thresholds": {"block": 0.5, "sanitize": 0.3},
    "guardrails": {"pii": {"enabled": true, "block_threshold": 0.6, "sanitize_threshold": 0.35}},
    "detection":  {"rule_weight": 0.4, "ml_weight": 0.3, "llm_weight": 0.3, "rule_enabled": true, "ml_enabled": true, "llm_enabled": true, "llm_trigger": 0.2},
    "llm":        {"provider": "ollama", "model": "llama3.2:latest", "timeout": 30},
    "rate_limit": {"per_minute": 60}
  }
}
```

### GET /v1/admin/departments/{id}/stats

Usage stats: total, decisions breakdown, block rate, avg latency, top threats.

### GET/POST/PUT/DELETE /v1/admin/applications/{id}

### GET /v1/admin/applications/{id}/policy

Resolved effective policy for this application. In V1, `policy_override = null`.

---

## Health

### GET /health/ready

```json
{"status": "ready", "checks": {"database": "ok", "redis": "ok", "ml_model": "ok"}}
```

### GET /health/live

```json
{"status": "alive"}
```

### GET /health/config

Active configuration — detection thresholds only. PII thresholds are department-specific.

```json
{
  "version": "1.0.0",
  "thresholds": {"block": 0.7, "sanitize": 0.4, "source": "database"},
  "detection_layers": {"rule": true, "ml": true, "llm": true, "source": "database"},
  "llm": {"provider": "ollama", "model": "llama3.2:latest", "llm_trigger": 0.2, "timeout": 30, "source": "database"},
  "rate_limit": {"per_minute": 60, "scope": "per_api_key"}
}
```

### GET /metrics

Prometheus exposition format. No auth required.

---

## Integration Guide

### Python quickstart

```python
import httpx, uuid

client = httpx.Client(
    base_url = "http://localhost:8000",
    headers  = {"x-api-key": "your-key"},
)

result = client.post(
    "/v1/ai/request",
    headers = {"Idempotency-Key": str(uuid.uuid4())},
    json    = {"input": user_prompt, "metadata": {"user_id": current_user.id}},
).json()

match result["decision"]:
    case "BLOCK":
        if result["primary_reason"] == "SYSTEM_ERROR":
            alert_ops(result["trace_id"])  # detector failure
        else:
            return "Blocked by security policy"
    case "SANITIZE":
        safe_input = result["sanitized_input"]
    case "ALLOW":
        if result["primary_reason"] == "SYSTEM_ERROR":
            alert_ops(result["trace_id"])  # all detectors failed (fail open)
        # else NO_THREAT_DETECTED — genuinely clean

if result["confidence_band"] == "LOW":
    flag_for_human_review(result["trace_id"])
```

### Compliance triage

```python
# Find system failures — distinct from clean traffic
failures = client.get("/v1/audit/logs", params={"primary_reason": "SYSTEM_ERROR"}).json()

# Find clean traffic — detection succeeded, no threat
clean    = client.get("/v1/audit/logs", params={"primary_reason": "NO_THREAT_DETECTED"}).json()

# Export LOW confidence for human review
r = client.get("/v1/audit/export", params={"confidence_band": "LOW"})
open("review.csv", "wb").write(r.content)
```

### SYSTEM_ERROR monitoring

`SYSTEM_ERROR` responses are an operational health signal and should be actively monitored in production.

```python
# Recommended alerting logic
result = client.post("/v1/ai/request", ...).json()

if result["primary_reason"] == "SYSTEM_ERROR":
    # This is not a security event — it is an infrastructure event
    # Do not treat it as a threat detection
    send_alert(
        severity  = "warning",
        message   = f"WrapSec detector failure — trace_id={result['trace_id']}",
        dashboard = "https://your-host:3001/grafana",
    )
```

**Monitoring guidance:**

| Signal | Threshold | Action |
|---|---|---|
| Single `SYSTEM_ERROR` | Any | Log and investigate |
| `SYSTEM_ERROR` rate > 0.1% | Over 5 min window | Page on-call |
| `SYSTEM_ERROR` rate > 1% | Over 1 min window | Immediate incident |
| All requests `SYSTEM_ERROR` | Any | Service outage — escalate |

**What SYSTEM_ERROR indicates:**
- Individual detector crash (rule, ML, or LLM) — single occurrence is tolerable
- ML model file corrupt or missing — all ML requests fail
- LLM provider unreachable — LLM detector always fails
- Database connection lost — policy resolution may fail
- Memory/resource exhaustion — cascading detector failures

Use `GET /health/ready` to check subsystem status and `GET /metrics` for Prometheus alerting rules.

A low but non-zero SYSTEM_ERROR rate (< 0.1%) is expected in production (transient LLM timeouts, occasional ML edge cases). A sustained or rising rate requires investigation.

---

## Rate Limiting

Per API key, Redis sliding window, 60 req/min default.

```json
{"error": {"code": "RATE_LIMITED", "message": "Rate limit exceeded.", "trace_id": "..."}}
```

---

## Planned — V1.1

```
PUT/DELETE /v1/admin/applications/{id}/policy  → application policy overrides
POST       /v1/keys/{key_id}/rotate            → rotate with grace period
GET        /v1/admin/analytics                 → cross-department analytics
```

Token limit V1.1: per-model tiktoken enforcement (replaces `ceil(len/2)` heuristic).

Cursor pagination V1.1: `GET /v1/audit/logs?cursor=req_01knzhh8...&limit=20`

---

## Planned — V2.0

```
POST /v1/auth/token      → JWT (attribution_verified=true)
POST /v1/admin/tenants   → SaaS multi-tenant onboarding
POST /v1/webhooks        → BLOCK event webhooks
POST /v1/admin/roles     → role management (requires JWT)
```

---

## Changelog

### V1.0 (April 2026)

**Consistency (final review fixes):**
- `SYSTEM_ERROR` is always distinct from `NO_THREAT_DETECTED` — mutually exclusive code paths
- All failure paths: `confidence=0.0`, `confidence_band=LOW`, `primary_reason=SYSTEM_ERROR`
- Input limit: 8,000 chars + `ceil(len/2) > 4000` heuristic token limit → 422
- API doc now includes all 6 primary_reason scenarios with examples

**Security:**
- `tenant_id` removed from request metadata
- Entity validation in auth middleware
- `model` silently ignored in `scan_only`
- Debug mode restricted to admin keys

**Reliability:**
- Idempotency-Key: 409 CONFLICT on same key + different body
- ULID trace IDs
- Rate limiting per API key with X-RateLimit-* headers
- Nginx 64KB payload limit
- Per-detector try/catch

**Scoring:**
- Guardrail thresholds FULLY DECOUPLED from detection thresholds
- `risk_score = rule*0.40 + ml*0.30 + llm*0.30` (PII excluded)
- `decision_version` — "v1.0" in every response
- `sanitization_applied` — explicit boolean

**Policy:**
- Detection thresholds and PII thresholds configured under separate policy keys
- Runtime configurable: all settings, no restart
- Audit log retention configurable via Settings UI (stored in DB)

---

*API version: 1.0 — Final*  
*Authentication: `x-api-key` header*  
*Total endpoints: 39*  
*Last updated: April 2026*
