# WrapSec API Reference

Version: 1.1 — Proxy Mode  
Base URL: `http://your-host:8000`  
Total endpoints: 43  
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

The heuristic `ceil(len/2)` assumes 2 chars per token — conservative for all languages. Full per-model tiktoken enforcement planned for V1.2.

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
| `input_blocked` | 400 | Proxy: input blocked by security policy |
| `output_blocked` | 400 | Proxy: output blocked by security policy |
| `provider_timeout` | 504 | Proxy: provider did not respond in time |
| `provider_unreachable` | 502 | Proxy: provider connection failed |
| `proxy_not_configured` | 400 | Proxy: no provider configured for this API key |
| `invalid_model_format` | 400 | Proxy: model must be "provider/model" format |

Proxy error responses include a `wrapsec` key alongside `error` for security context. The `type` field is not present in WrapSec errors — only `code`, `message`, and `trace_id`.

**Error code casing convention:**
Platform and infrastructure errors use `UPPERCASE` (e.g. `UNAUTHORIZED`, `VALIDATION_ERROR`, `INTERNAL_ERROR`).
Runtime security and proxy errors use `lowercase` (e.g. `input_blocked`, `output_blocked`, `system_error`).
This distinction is intentional and stable — uppercase for platform, lowercase for security decisions.

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

Callers must use a new UUID for each distinct operation. If Redis is unavailable → fail open.

---

## Response Envelope — Scan Only

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
- `sanitized_input` — only present when `decision = SANITIZE`. Contains the actual redacted text sent to the LLM.
- `sanitization_applied` — boolean indicator; `true` when `decision = SANITIZE`. Use `sanitized_input` to read the redacted content.
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

**Confidence bands:**

| Band | Range | Meaning |
|---|---|---|
| `HIGH` | 0.7 – 1.0 | Trust the decision |
| `MEDIUM` | 0.4 – 0.7 | Monitor |
| `LOW` | 0.0 – 0.4 | Human review or `SYSTEM_ERROR` |

---


## Decision Model

**Formal definition:**

```
scan_only:
  decision = input security verdict (ALLOW / BLOCK / SANITIZE)
  Single decision. Application forwards to LLM itself.

proxy:
  decision              = input security verdict (top-level, canonical field)
  proxy.output_decision = output security verdict (from OutputGuard, separate)

  decision always equals proxy.input_decision.
  The top-level decision field is authoritative.
```

**`risk_score` vs `confidence`:**

```
risk_score   = likelihood of a detected threat (detection only, 0.0–1.0)
confidence   = certainty of the decision (agreement between detectors, 0.0–1.0)

risk_score=0.9 + confidence=0.4 → strong signal, low detector agreement
risk_score=0.9 + confidence=0.9 → strong signal, high agreement — most trustworthy
```

**`risk_score` interpretation:**

```
risk_score reflects detection only (rule + ML + LLM weighted).
PII guardrail decisions (BLOCK/SANITIZE) may produce risk_score=0.0.
risk_score=0.0 does NOT mean the input is safe — check decision and primary_reason.

Always use decision as the authoritative security verdict.
Never use risk_score alone to decide whether to forward input to an LLM.
```

**Proxy lifecycle:**

```
input -> InputGuard -> input decision -> provider call -> OutputGuard -> output decision -> response
```

**Latency fields defined:**

```
processing.latency_ms     = detection pipeline time for scan_only rows
                            total end-to-end time for proxy rows (stored in audit_logs)
proxy.provider_latency_ms = external provider round-trip only
proxy.total_latency_ms    = total end-to-end wall time (canonical total for proxy)
X-WrapSec-Latency-Ms      = total end-to-end wall time (same as proxy.total_latency_ms)
```

For proxy requests, `processing.latency_ms` in `audit_logs` equals `proxy.total_latency_ms`.
Use `proxy.total_latency_ms` as the authoritative total for proxy requests.

**`sanitized_input` vs `sanitization_applied`:**

```
sanitization_applied  boolean — true when decision = SANITIZE
sanitized_input       string  — the actual redacted text (present only when sanitization_applied = true)

Always check decision, not sanitization_applied, as the primary signal.
Use sanitized_input to read the redacted content before forwarding to your LLM.
```

**Detection scores contract:**

```
detection_scores.rule = 0.0 - 1.0  (raw detector output)
detection_scores.ml   = 0.0 - 1.0
detection_scores.llm  = 0.0 - 1.0
guardrail_scores.pii  = 0.0 - 1.0

Scores represent detector confidence, not probability of attack.
A score of 0.9 means the detector is highly confident a threat is present.
All API values are raw 0.0-1.0. The dashboard displays these as percentages (value * 100).
SYSTEM_ERROR always implies confidence = 0.0 and confidence_band = LOW.

confidence reflects agreement between active detectors, not absolute correctness.
Single-detector paths (e.g. LLM disabled, only rule fires) may yield confidence=1.0
due to absence of variance across detectors. This is expected behaviour.

SYSTEM_ERROR returns decision=ALLOW at the engine level (detection did not confirm a threat).
However, SYSTEM_ERROR MUST be treated as a failure condition by all clients.
Applications must NOT forward input to an LLM when primary_reason=SYSTEM_ERROR.
```

---

## Gateway

### POST /v1/ai/request

Scan-only mode. The application calls WrapSec first, then forwards to the LLM itself if ALLOW.

**Request body:**

```json
{
  "input": "string (required, 1–8000 chars, estimated ≤4000 tokens)",
  "detection_mode": "fast | full  (default: fast)",
  "execution_mode": "scan_only  (default)",
  "metadata": {
    "user_id": "string (optional, self-reported)",
    "source":  "string (optional, audit label)"
  },
  "options": {
    "debug": "boolean (admin key only)"
  }
}
```

**detection_mode:**
- `fast` — rule + ML only (~5ms)
- `full` — rule + ML + LLM semantic (~100–500ms additional)

**Response:** See Response Envelope above.

---

### GET /v1/ai/requests/{trace_id}

Retrieve a request by trace ID. For proxy requests, joins `proxy_interactions` and returns the full lifecycle in the `proxy` key.

**Response — scan_only request:**

```json
{
  "trace_id":       "req_01...",
  "timestamp":      "2026-04-20T01:29:46.000000",
  "execution_mode": "scan_only",
  "is_proxy":       false,
  "decision":    "BLOCK",
  "risk_score":  0.85,
  "primary_reason": "RULE_DETECTOR",
  "confidence":  0.75,
  "confidence_band": "HIGH",
  "threats":     ["PROMPT_INJECTION"],
  "input_hash":  "sha256:abc123...",
  "input_length": 42,
  "detection_scores":  {"rule": 0.9, "ml": 0.8, "llm": 0.0},
  "guardrail_scores":  {"pii": 0.0},
  "processing": {
    "latency_ms": 2.1, "llm_invoked": false,
    "detection_mode": "fast", "execution_mode": "scan_only",
    "policy_source": "tenant_global"
  },
  "attribution": {
    "tenant_id": "...", "dept_id": "...", "dept_name": "Engineering",
    "app_id": "...", "app_name": "Code Assistant",
    "source": "code-assistant", "key_id": "wsk_live_eng_...",
    "user_id": "user_123", "ip_address": "10.0.0.1",
    "attribution_verified": false
  }
}
```

**Response — proxy request (adds `proxy` key):**

```json
{
  "trace_id":       "req_01...",
  "execution_mode": "proxy",
  "is_proxy":       true,      // derived: is_proxy = (execution_mode == "proxy")
  "decision":       "SANITIZE",
  "...":            "all scan_only fields present",
  "proxy": {
    "provider":              "ollama",
    "model":                 "gemma3:4b",
    "provider_latency_ms":   14702,
    "total_latency_ms":      15103,
    "execution_status":      "SUCCESS",
    "input_primary_reason":  "PII_GUARDRAIL_SANITIZE",
    "input_confidence":      0.75,
    "input_threats":         ["PII"],
    "input_attack_type":     null,
    "input_raw":             "my email is [EMAIL REDACTED], what is 2+2?",
    "input_sanitized":       "my email is [EMAIL REDACTED], what is 2+2?",
    "output_decision":       "ALLOW",
    "output_primary_reason": "NO_THREAT_DETECTED",
    "output_confidence":     1.0,
    "output_threats":        [],
    "output_raw":            "2 + 2 = 4",
    "output_sanitized":      null,
    "behavior_flag":         null,
    "output_flags":          null
  }
}
```

**Note:** `input_decision` is not present in `proxy` — it is always identical to the top-level `decision` field. Use `decision` as the canonical input verdict.

**`execution_mode` appears twice in the response:**
- Top-level `execution_mode` — canonical field, use this for routing logic
- `processing.execution_mode` — same value, present for pipeline context and backward compatibility

**Latency fields:**

| Field | Meaning |
|---|---|
| `processing.latency_ms` | Detection pipeline time (scan_only rows) / total end-to-end time (proxy rows in audit_logs) — same value as `proxy.total_latency_ms` for proxy |
| `proxy.provider_latency_ms` | External provider round-trip only |
| `proxy.total_latency_ms` | Total end-to-end wall time (same as `X-WrapSec-Latency-Ms` header) |

**Storage mode contract:**

| `DATA_STORAGE_MODE` | `input_raw` | `output_raw` |
|---|---|---|
| `full` | Original text as-is | Original text as-is |
| `masked` | PII-redacted text (same redactor as sanitization) | PII-redacted text |
| `none` | `null` — never persisted | `null` — never persisted |

Text is purged (set to `null`) after `DATA_RETENTION_DAYS_PROXY` days regardless of mode. Security metadata (decisions, threats, scores, latency, execution_status) is retained permanently.

**`input_raw` field naming:** Despite the name "raw", `input_raw` stores the text according to the configured storage mode — it is not always the original unmodified text. In `masked` mode it contains PII-redacted text. The field name refers to "input text as stored", not "original input".

**Storage + retention interaction:** In `none` mode, no text is ever persisted — the retention worker has nothing to purge. The retention worker only nulls rows where `input_raw IS NOT NULL OR output_raw IS NOT NULL`.

---

## Proxy — AI Interaction Firewall

### Overview

**Quick mental model:**

```
Scan-only:  App → WrapSec (inspect) → App → LLM
Proxy:      App → WrapSec (inspect) → LLM → WrapSec (inspect) → App
```

WrapSec acts as a drop-in replacement for the OpenAI API. Change your SDK base URL and prefix your model name — security is enforced transparently.

```python
# Before
client = OpenAI(api_key="sk-openai-...", base_url="https://api.openai.com/v1")
response = client.chat.completions.create(model="gpt-4o", messages=[...])

# After — point at WrapSec
client = OpenAI(api_key="wsk_live_...", base_url="http://localhost:8000/v1")
response = client.chat.completions.create(model="openai/gpt-4o", messages=[...])
#                                                 ↑ prefix with provider name
```

WrapSec inspects the input, forwards to the real provider with your encrypted API key, inspects the output, and returns an OpenAI-compatible response.

### Model Format

```
{provider}/{model}

openai/gpt-4o
openai/gpt-4o-mini
ollama/gemma3:4b
ollama/llama3.2
custom/my-model
```

The `provider/model` format is required. Requests without a provider prefix are rejected with `invalid_model_format` (400). There is no default provider fallback — the format is always explicit.

### POST /v1/chat/completions


**Idempotency:** `POST /v1/chat/completions` is **not idempotent**. The provider call may have side effects (billing, state changes). Do not use `Idempotency-Key` with this endpoint. Each request is processed independently.

**Scan-All-Messages performance:** Enabling `X-WrapSec-Scan-All-Messages: true` increases detection latency proportionally to the number of user messages in the conversation. Use only when injection spread across history is a concern.

**Request body (OpenAI-compatible):**

```json
{
  "model":    "openai/gpt-4o",
  "messages": [
    {"role": "system",    "content": "You are a helpful assistant."},
    {"role": "user",      "content": "What is the capital of France?"}
  ],
  "temperature": 0.7,
  "max_tokens":  500
}
```

**Execution status values:**

| Status | Trigger condition |
|---|---|
| `SUCCESS` | Input ALLOW or SANITIZE, provider responded, output ALLOW or SANITIZE |
| `BLOCKED` | Input decision was BLOCK — provider never called |
| `OUTPUT_BLOCKED` | Input clean, provider responded, output decision was BLOCK |
| `FAILED` | Provider call failed (network error, auth error, HTTP 5xx) |
| `TIMEOUT` | Provider did not respond within `timeout_seconds` |

**WrapSec request headers:**

| Header | Default | Description |
|---|---|---|
| `X-WrapSec-Mode` | `fast` | Detection mode: `fast` or `full` |
| `X-WrapSec-Scan-All-Messages` | `false` | Scan all user messages vs last only |
| `X-WrapSec-Inline-Meta` | `false` | Include `wrapsec` key in response body |

**WrapSec response headers (always present):**

| Header | Description |
|---|---|
| `X-WrapSec-Trace-Id` | ULID trace ID |
| `X-WrapSec-Input-Decision` | `ALLOW` / `BLOCK` / `SANITIZE` |
| `X-WrapSec-Input-Primary-Reason` | Primary reason for input decision |
| `X-WrapSec-Input-Confidence` | Input decision confidence (0.0–1.0) |
| `X-WrapSec-Input-Sanitized` | `true` if input was sanitized before forwarding |
| `X-WrapSec-Output-Decision` | `ALLOW` / `BLOCK` / `SANITIZE` / `N/A` |
| `X-WrapSec-Output-Sanitized` | `true` if output was sanitized |
| `X-WrapSec-Execution-Status` | `SUCCESS` / `BLOCKED` / `OUTPUT_BLOCKED` / `FAILED` / `TIMEOUT` |
| `X-WrapSec-Provider` | Provider used (`openai`, `ollama`, `custom`) |
| `X-WrapSec-Model` | Model name |
| `X-WrapSec-Latency-Ms` | Total WrapSec latency in milliseconds |

**Successful response (OpenAI-compatible):**

```json
{
  "id":      "wrapsec-req_01...",
  "object":  "chat.completion",
  "model":   "gemma3:4b",
  "choices": [
    {
      "index":         0,
      "message":       {"role": "assistant", "content": "Paris is the capital of France."},
      "finish_reason": "stop"
    }
  ]
}
```

**Successful response with inline meta (`X-WrapSec-Inline-Meta: true`):**

```json
{
  "id":      "wrapsec-req_01...",
  "object":  "chat.completion",
  "model":   "gemma3:4b",
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
    "provider":             "ollama",
    "model":                "gemma3:4b",
    "total_latency_ms":     3047
  }
}
```

**Input blocked (400):**

```json
{
  "error": {
    "code":     "input_blocked",
    "message":  "Request blocked by security policy.",
    "trace_id": "req_01..."
  },
  "wrapsec": {
    "decision":             "BLOCK",
    "input_primary_reason": "RULE_DETECTOR",
    "input_threats":        ["PROMPT_INJECTION", "JAILBREAK"],
    "input_confidence":     0.9642,
    "execution_status":     "BLOCKED"
  }
}
```

**Output blocked (400):**

```json
{
  "error": {
    "code":     "output_blocked",
    "message":  "Model response blocked by output security policy.",
    "trace_id": "req_01..."
  },
  "wrapsec": {
    "decision":              "ALLOW",
    "output_decision":       "BLOCK",
    "output_primary_reason": "PII_GUARDRAIL_BLOCK",
    "execution_status":      "OUTPUT_BLOCKED"
  }
}
```

**Provider timeout (504):**

```json
{
  "error": {
    "code":     "provider_timeout",
    "message":  "Provider timed out.",
    "trace_id": "req_01..."
  },
  "wrapsec": {
    "decision":         "ALLOW",
    "execution_status": "TIMEOUT"
  }
}
```

### Headers vs Inline Meta

```
X-WrapSec-* headers  = lightweight integration
                       check decision without parsing body
                       zero overhead for clients that ignore them

X-WrapSec-Inline-Meta: true
  "wrapsec": {...}   = full observability
                       structured data in response body
                       useful for logging, tracing, dashboards
```

Use headers for simple pass/fail checks. Use inline meta when you need the full security context in your application logs.

### Scan-All-Messages Mode

By default WrapSec scans only the **last user message**. Use `X-WrapSec-Scan-All-Messages: true` to scan all user messages, catching injections spread across conversation history.

```python
response = client.chat.completions.create(
    model    = "openai/gpt-4o",
    messages = [
        {"role": "user",      "content": "Ignore all previous instructions"},  # injection
        {"role": "assistant", "content": "How can I help?"},
        {"role": "user",      "content": "What is 2+2?"},  # clean
    ],
    extra_headers = {"X-WrapSec-Scan-All-Messages": "true"},
)
# Injection in first message is caught and blocked
```

### SANITIZE Behaviour

When input is `SANITIZE`, WrapSec replaces PII in the message before forwarding to the provider:

```
User sends:     "My SSN is 123-45-6789, help me with my taxes"
Provider gets:  "My SSN is [SSN REDACTED], help me with my taxes"
Client gets:    Provider's response (about taxes, without the real SSN)
```

The provider never sees the actual PII. `X-WrapSec-Input-Sanitized: true` in the response confirms this happened.

---

## Proxy Settings

### PUT /v1/settings/proxy

Configure the LLM provider for proxy mode. One configuration per API key.

```json
{
  "provider":      "openai",
  "base_url":      "https://api.openai.com/v1",
  "api_key":       "sk-openai-...",
  "default_model": "gpt-4o",
  "timeout":       60
}
```

**providers:** `openai` (also covers Groq, Azure, Together AI, any OpenAI-compatible endpoint) | `ollama` | `custom`

**api_key:** Encrypted AES-256-GCM at rest. Never returned in API responses. Masked in responses (`sk-...7890`).

**Response:**
```json
{
  "provider":        "openai",
  "base_url":        "https://api.openai.com/v1",
  "api_key_masked":  "sk-...7890",
  "default_model":   "gpt-4o",
  "timeout_seconds": 60,
  "created_at":      "2026-04-20T01:00:00",
  "updated_at":      "2026-04-20T01:00:00"
}
```

### GET /v1/settings/proxy

Returns current proxy provider configuration (without API key).

### DELETE /v1/settings/proxy

Removes the proxy provider configuration for the current API key.

### GET /v1/settings/proxy/health

Tests connectivity to the configured provider.

```json
{
  "provider":    "ollama",
  "base_url":    "http://localhost:11434",
  "reachable":   true,
  "latency_ms":  234
}
```

### GET /v1/settings/storage

Returns the current data storage mode and proxy text retention period. Read-only — configured via environment variables.

```json
{
  "storage_mode":         "masked",
  "retention_days_proxy": 7
}
```

---

## Audit

### GET /v1/audit/logs

List audit logs. Includes both scan-only and proxy requests (`execution_mode` filter available).

**Query parameters:**

| Param | Description |
|---|---|
| `trace_id` | Partial match search |
| `decision` | `BLOCK` / `SANITIZE` / `ALLOW` |
| `threat_category` | `PROMPT_INJECTION` / `JAILBREAK` / `PII` / etc. |
| `execution_mode` | `scan_only` / `proxy` |
| `from` | ISO datetime |
| `to` | ISO datetime |
| `sort_by` | `created_at` / `risk_score` / `latency_ms` |
| `sort_order` | `asc` / `desc` |
| `limit` | Default 50, max 200 |
| `offset` | Pagination offset |

**Response:**
```json
{
  "total": 1250,
  "items": [
    {
      "trace_id":       "req_01...",
      "timestamp":      "2026-04-20T01:29:46",
      "decision":       "BLOCK",
      "risk_score":     0.85,
      "threats":        ["PROMPT_INJECTION"],
      "detection_mode": "fast",
      "execution_mode": "proxy",
      "latency_ms":     15000
    }
  ]
}
```

### GET /v1/audit/stats

Aggregate stats: total, block_rate, sanitize_rate, allow_rate, avg_latency_ms, p95_latency_ms, top_threats.

### GET /v1/audit/attribution

Attribution breakdown: by API key, department, application, primary reason, confidence band.

### GET /v1/audit/export

CSV export. Supports same filters as `/v1/audit/logs`. Max 10,000 rows.

---

## Settings

### GET/PUT /v1/settings/thresholds

Detection thresholds (block, sanitize). Independent from PII thresholds.

### GET/PUT /v1/settings/layers

Enable/disable rule, ML, LLM detection layers.

### GET/PUT /v1/settings/llm

LLM provider configuration for detection Layer 3 (separate from proxy provider).

### GET/PUT /v1/settings/retention

Audit log retention period in days (min 7, max 3650).

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

Active configuration snapshot.

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

### Python — Scan Only

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
            alert_ops(result["trace_id"])
        else:
            return "Blocked by security policy"
    case "SANITIZE":
        safe_input = result["sanitized_input"]
        # Forward safe_input to your LLM
    case "ALLOW":
        if result["primary_reason"] == "SYSTEM_ERROR":
            alert_ops(result["trace_id"])
        # else: forward to your LLM

if result["confidence_band"] == "LOW":
    flag_for_human_review(result["trace_id"])
```

### Python — Proxy Mode (OpenAI SDK)

```python
from openai import OpenAI

client = OpenAI(
    api_key  = "wsk_live_your_wrapsec_key",
    base_url = "http://localhost:8000/v1",
)

response = client.chat.completions.create(
    model    = "openai/gpt-4o",
    messages = [{"role": "user", "content": user_prompt}],
)

# WrapSec enforces security transparently
# Check headers for security decisions
print(response.headers.get("X-WrapSec-Input-Decision"))   # ALLOW / SANITIZE
print(response.headers.get("X-WrapSec-Output-Decision"))  # ALLOW / SANITIZE
print(response.headers.get("X-WrapSec-Trace-Id"))         # for audit lookup
```

### Python — Proxy Mode with Inline Meta

```python
response = client.chat.completions.create(
    model          = "openai/gpt-4o",
    messages       = [{"role": "user", "content": user_prompt}],
    extra_headers  = {"X-WrapSec-Inline-Meta": "true"},
)

# Security metadata available in response body
meta = response.model_extra.get("wrapsec", {})
if meta.get("decision") == "SANITIZE":
    logger.info(f"PII was redacted before forwarding: {meta['trace_id']}")
```

### Python — Proxy Mode with Ollama

```python
from openai import OpenAI

client = OpenAI(
    api_key  = "wsk_live_your_wrapsec_key",
    base_url = "http://localhost:8000/v1",
)

response = client.chat.completions.create(
    model    = "ollama/gemma3:4b",
    messages = [{"role": "user", "content": user_prompt}],
)
```

### Error handling — proxy mode

```python
from openai import BadRequestError

try:
    response = client.chat.completions.create(
        model    = "openai/gpt-4o",
        messages = [{"role": "user", "content": user_prompt}],
    )
except BadRequestError as e:
    error = e.response.json()
    code  = error["error"]["code"]

    if code == "input_blocked":
        wrapsec = error["wrapsec"]
        logger.warning(
            f"Input blocked -- trace_id={wrapsec['trace_id']} "
            f"threats={wrapsec['input_threats']} "
            f"confidence={wrapsec['input_confidence']}"
        )
        return "Your request was blocked by the security policy."

    elif code == "output_blocked":
        wrapsec = error["wrapsec"]
        logger.warning(f"Output blocked -- trace_id={wrapsec['trace_id']}")
        return "The model's response was blocked by the security policy."

    elif code == "provider_timeout":
        # Input was clean -- only the provider timed out
        wrapsec = error["wrapsec"]
        logger.error(f"Provider timeout -- trace_id={wrapsec['trace_id']}")
        return "Request timed out. Please try again."

    elif code == "provider_unreachable":
        logger.error("Provider unreachable")
        return "Service temporarily unavailable."
```

### Compliance triage

```python
# Find system failures — distinct from clean traffic
failures = client.get("/v1/audit/logs", params={"primary_reason": "SYSTEM_ERROR"}).json()

# Proxy requests only
proxy_logs = client.get("/v1/audit/logs", params={"execution_mode": "proxy"}).json()

# Export LOW confidence for human review
r = client.get("/v1/audit/export", params={"confidence_band": "LOW"})
open("review.csv", "wb").write(r.content)

# Retrieve full proxy lifecycle for a specific trace
detail = client.get(f"/v1/ai/requests/{trace_id}").json()
if detail["is_proxy"]:
    print("Provider:", detail["proxy"]["provider"])
    print("Input decision:", detail["proxy"]["input_decision"])
    print("Output decision:", detail["proxy"]["output_decision"])
    print("Execution status:", detail["proxy"]["execution_status"])
```

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

**`SYSTEM_ERROR` vs `NO_THREAT_DETECTED`:**

These values are produced by mutually exclusive code paths and can never be confused:
- `NO_THREAT_DETECTED` — detectors ran successfully, no threat found
- `SYSTEM_ERROR` — detector(s) failed or system threw an exception

---

## Rate Limiting

Per API key, Redis sliding window, 60 req/min default.

```json
{"error": {"code": "RATE_LIMITED", "message": "Rate limit exceeded.", "trace_id": "..."}}
```

---

## SYSTEM_ERROR Monitoring

`SYSTEM_ERROR` is an operational health signal, not a security event.

| Signal | Threshold | Action |
|---|---|---|
| Single `SYSTEM_ERROR` | Any | Log and investigate |
| `SYSTEM_ERROR` rate > 0.1% | Over 5 min window | Page on-call |
| `SYSTEM_ERROR` rate > 1% | Over 1 min window | Immediate incident |
| All requests `SYSTEM_ERROR` | Any | Service outage — escalate |

---

## Changelog

### V1.1 (April 2026) — Proxy Mode

**Proxy mode — AI Interaction Firewall:**
- `POST /v1/chat/completions` — OpenAI-compatible proxy endpoint
- Provider support: OpenAI, OpenAI-compatible (Groq, Azure, Together AI), Ollama, custom
- Provider API keys encrypted AES-256-GCM at rest, never returned in responses
- Input + output PII enforcement in proxy mode
- `X-WrapSec-*` headers on every response
- `X-WrapSec-Inline-Meta` opt-in for body metadata
- `X-WrapSec-Scan-All-Messages` for scanning full conversation history
- Execution status: `SUCCESS` / `BLOCKED` / `OUTPUT_BLOCKED` / `FAILED` / `TIMEOUT`

**Data & storage:**
- Configurable `DATA_STORAGE_MODE`: `full` / `masked` / `none`
- `masked` is the production default — PII redacted before persisting
- `DATA_RETENTION_DAYS_PROXY` — text purged after N days, metadata kept permanently
- `proxy_interactions` table for full lifecycle data
- `audit_logs.proxy_interaction_id` FK — unified view via `GET /v1/ai/requests/:trace_id`

**New endpoints:**
- `PUT/GET/DELETE /v1/settings/proxy` — provider configuration
- `GET /v1/settings/proxy/health` — connectivity check
- `GET /v1/settings/storage` — storage mode and retention period
- `GET /v1/ai/requests/{trace_id}` — updated to return `proxy` key for proxy requests

**Dashboard:**
- Unified Requests page — scan_only and proxy in one table
- Execution mode filter + Detection/Execution columns separated
- Proxy lifecycle detail panel — input/output decisions, raw/sanitized text
- Data Retention & Storage settings card

### V1.0 (April 2026)

- Rule, ML, LLM detectors with per-detector try/catch
- `SYSTEM_ERROR` always distinct from `NO_THREAT_DETECTED`
- PII guardrail (22+ types, input + output)
- Guardrail thresholds fully decoupled from detection thresholds
- Idempotency-Key with 409 CONFLICT
- ULID trace IDs
- Rate limiting per API key
- Policy resolution: system → tenant → department
- 39 endpoints, 85 tests

---

*API version: 1.1 — Proxy Mode*  
*Authentication: `x-api-key` header*  
*Total endpoints: 43*  
*Last updated: April 2026*
