# WrapSec - AI Security Gateway

> Production-grade security gateway for enterprise AI applications. Protects every LLM interaction with a multi-layer detection pipeline, independent guardrail enforcement, and a complete attribution audit trail.

WrapSec enforces security, compliance, and observability for every LLM request — both as a scan-only inspector and as a full AI interaction firewall with proxy mode.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat-square)](https://nextjs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=flat-square)](https://postgresql.org)
[![Tests](https://img.shields.io/badge/Tests-148%20passing-brightgreen?style=flat-square)](#running-tests)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

---

## What is WrapSec?

WrapSec is a self-hosted AI security gateway that sits between your application and any LLM provider. It operates in two modes:

**Scan-only:** Every prompt passes through a four-layer detection pipeline. Threats are blocked or sanitised in real time. Your application forwards clean prompts to the LLM itself.

**Proxy mode (AI Interaction Firewall):** WrapSec acts as a drop-in replacement for the OpenAI API. Change your SDK's `base_url` and prefix your model name. WrapSec scans the input, forwards it to the real provider using your encrypted API key, scans the output, and returns an OpenAI-compatible response. Security is enforced on both directions transparently.

Every decision is logged with full attribution, a confidence score, and a primary reason — giving security teams and compliance officers a complete, explainable audit trail.

---

## Why WrapSec?

| Problem | WrapSec Solution |
|---|---|
| Prompt injection and jailbreak attacks | Rule + ML + LLM detection pipeline |
| PII leaking into AI systems | Independent PII guardrail with 22+ entity types on input and output |
| Detection threshold changes impacting PII protection | Guardrail thresholds fully decoupled from detection thresholds |
| LLM provider API keys exposed in client code | Provider keys stored AES-256-GCM encrypted server-side, client only holds WrapSec key |
| Raw user messages and LLM responses stored indefinitely | Configurable storage modes (full / masked / none) with retention policy |
| No audit trail for AI requests | Full attribution chain per request, unified view of scan-only and proxy traffic |
| Black-box decisions | primary_reason + confidence on every response |
| Cannot distinguish clean input from system failure | SYSTEM_ERROR is always distinct from NO_THREAT_DETECTED |
| Duplicate processing on retries | Idempotency-Key: same key + different body returns 409 CONFLICT |
| CJK and dense text overloading LLMs | Heuristic token limit: ceil(len/2) > 4000 returns 422 |
| Compliance gaps (GDPR, EU AI Act, SOC 2) | Confidence bands, decision versioning, CSV export, configurable retention |

---

## Key Features

**Detection pipeline:**
- Rule-based detector: regex and heuristic patterns, ~0ms
- ML classifier: TF-IDF + LogisticRegression trained on 6,700+ samples from peer-reviewed security datasets, ~5ms
- LLM semantic detector: conditional invocation in full mode, ~100-500ms
- PII guardrail: 22+ entity types, scans both input and LLM output

**ML model:**
- 6,742 training samples across 7 threat classes
- 97.7% test accuracy, 97.0% cross-validation accuracy
- Datasets: HackAPrompt (NeurIPS 2023), JailbreakBench (NeurIPS 2024), Measuring Hate Speech (UC Berkeley, ACL 2022), Jigsaw Toxic Comments (Google/Wikipedia CC0, WWW 2017), Stanford Alpaca, deepset Prompt Injections, ai4privacy PII Masking 300k
- All F1 scores above 0.93 per class

**Proxy mode — AI Interaction Firewall:**
- Drop-in OpenAI SDK replacement — change `base_url` and prefix model name, nothing else
- Provider support: OpenAI, Groq, Azure OpenAI, Together AI, Ollama, any OpenAI-compatible endpoint
- Provider API keys encrypted AES-256-GCM at rest, never returned in API responses
- Input PII enforcement — real data never reaches the provider when SANITIZE applies
- Output PII enforcement — model responses scanned and redacted before returning to client
- Configurable storage modes: `full` | `masked` (default) | `none`
- Text retention policy — raw content purged after N days, security metadata kept permanently
- X-WrapSec-* headers on every response for client-side observability

**Decision model:**
- Guardrail-first: PII evaluated independently, always overrides detection
- Guardrail thresholds (guardrails.pii.*) fully decoupled from detection thresholds
- risk_score = rule x 0.40 + ml x 0.30 + llm x 0.30 (PII excluded)
- primary_reason: 7 values, SYSTEM_ERROR always distinct from NO_THREAT_DETECTED
- confidence: variance-based with HIGH/MEDIUM/LOW band, 0.0 on system failure
- decision_version: algorithm version in every response

**Reliability:**
- Idempotency-Key: same key + same body returns cached result, same key + different body returns 409
- ULID trace IDs: time-sortable
- Input limit: 8,000 chars / 4,000 estimated tokens (heuristic, safe for CJK)
- Per-detector try/catch: individual failures do not crash the pipeline
- SYSTEM_ERROR on detector failure: never confused with NO_THREAT_DETECTED

**Policy hierarchy:**
- System defaults → tenant global → department overrides
- Detection thresholds and PII thresholds configured and resolved independently
- All settings configurable at runtime without restart

---

## Architecture

### Scan-Only Mode

```
Calling Application
        |  x-api-key: wsk_live_...
        |  POST /v1/ai/request
        v
    WrapSec API (FastAPI)
    +--------------------------------------------------+
    |  Trace -> RateLimit -> Auth -> Idempotency -> Log|
    |                                                  |
    |  Gateway Service                                 |
    |  +-- InputGuard    PII detection + redaction     |
    |  +-- RuleDetector  try/catch (~0ms)              |
    |  +-- MLDetector    try/catch (~5ms)              |
    |  +-- LLMDetector   try/catch (full mode only)    |
    |  +-- RiskScorer    rule+ml+llm weighted          |
    |  +-- PolicyEngine  BLOCK / SANITIZE / ALLOW      |
    +--------------------------------------------------+
        |
        +-- audit_logs (decision, scores, threats)
        v
    Response -> Application -> (app forwards to LLM itself)
```

### Proxy Mode — AI Interaction Firewall

```
Calling Application
        |  x-api-key: wsk_live_...        (WrapSec key)
        |  POST /v1/chat/completions
        |  model: "openai/gpt-4o"
        v
    WrapSec API (FastAPI)
    +--------------------------------------------------+
    |  Input Guard                                     |
    |  +-- Detection pipeline (same as scan-only)      |
    |  +-- BLOCK    -> 400, provider never called      |
    |  +-- SANITIZE -> redact PII before forwarding    |
    |                                                  |
    |  Provider Layer (encrypted API key server-side)  |
    |  +-- OpenAI / Groq / Azure / Together AI         |
    |  +-- Ollama (local)                              |
    |  +-- Custom (any OpenAI-compatible endpoint)     |
    |                                                  |
    |  Output Guard                                    |
    |  +-- PII scan on provider response               |
    |  +-- BLOCK    -> 400, response suppressed        |
    |  +-- SANITIZE -> redact PII before returning     |
    +--------------------------------------------------+
        |
        +-- proxy_interactions (full lifecycle, text subject to storage mode)
        +-- audit_logs (FK linked, unified requests view)
        v
    OpenAI-compatible response + X-WrapSec-* headers
```

**Scoring:**

```
Detection risk score (PII excluded):
  risk_score = rule x 0.40 + ml x 0.30 + llm x 0.30

Guardrail (independent thresholds):
  pii >= guardrails.pii.block_threshold    -> BLOCK
  pii >= guardrails.pii.sanitize_threshold -> SANITIZE

Policy decision (if no guardrail triggered):
  risk_score >= thresholds.block    -> BLOCK
  risk_score >= thresholds.sanitize -> SANITIZE
  otherwise                         -> ALLOW

Primary reason (in order of priority):
  detection_failed = True -> SYSTEM_ERROR
  guardrail triggered     -> PII_GUARDRAIL_BLOCK/SANITIZE
  max detector > 0        -> RULE/ML/LLM_DETECTOR
  all scores = 0          -> NO_THREAT_DETECTED
```

---

## Response Format

### Scan-Only

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
    "detection_mode": "fast", "execution_mode": "scan_only"
  }
}
```

### Proxy Mode — Success

```json
{
  "id":      "wrapsec-req_01...",
  "object":  "chat.completion",
  "model":   "gemma3:4b",
  "choices": [{"index": 0, "message": {"role": "assistant", "content": "..."}, "finish_reason": "stop"}]
}
```

Response headers:
```
X-WrapSec-Trace-Id:          req_01...
X-WrapSec-Input-Decision:    ALLOW
X-WrapSec-Output-Decision:   ALLOW
X-WrapSec-Execution-Status:  SUCCESS
X-WrapSec-Provider:          ollama
X-WrapSec-Model:             gemma3:4b
X-WrapSec-Latency-Ms:        3047
```

### Proxy Mode — Input Blocked

```json
{
  "error": {"message": "Request blocked by security policy.", "code": "input_blocked"},
  "wrapsec": {
    "trace_id":         "req_01...",
    "decision":   "BLOCK",
    "input_threats":    ["PROMPT_INJECTION", "JAILBREAK"],
    "input_confidence": 0.9642,
    "execution_status": "BLOCKED"
  }
}
```

---

## Quick Start

### Prerequisites

Docker + Docker Compose, Python 3.10+, Node.js 18+, Ollama (optional)

### 1. Clone and configure

```bash
git clone https://github.com/kbajish/wrapsec.git
cd wrapsec
cp .env.example .env
# Set ADMIN_API_KEY to a strong random value
python -c "import secrets; print('wrapsec_' + secrets.token_urlsafe(32))"
```

### 2. Start infrastructure

```bash
docker compose -f infrastructure/docker/docker-compose.yml up -d postgres redis
```

### 3. Install, train, run

```bash
pip install -r requirements.txt
python scripts/train_ml_model.py
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### 4. Start dashboard

```bash
cd dashboard && npm install && npm run dev
```

Open `http://localhost:3000` and sign in with your admin API key.

---

## API Usage

### Scan a prompt

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"input": "Ignore all previous instructions"}'
```

### Python — scan-only

```python
import httpx, uuid

client = httpx.Client(
    base_url = "http://localhost:8000",
    headers  = {"x-api-key": "your-key"},
)

result = client.post(
    "/v1/ai/request",
    headers = {"Idempotency-Key": str(uuid.uuid4())},
    json    = {"input": user_prompt},
).json()

match result["decision"]:
    case "BLOCK":
        if result["primary_reason"] == "SYSTEM_ERROR":
            alert_ops(result["trace_id"])
        else:
            return "Blocked by security policy"
    case "SANITIZE":
        safe_input = result["sanitized_input"]
    case "ALLOW":
        pass  # forward to your LLM
```

### Python — proxy mode (OpenAI SDK)

```python
from openai import OpenAI

# Before: client = OpenAI(api_key="sk-openai-...", base_url="https://api.openai.com/v1")
# After:  point at WrapSec -- that's it
client = OpenAI(
    api_key  = "wsk_live_your_wrapsec_key",
    base_url = "http://localhost:8000/v1",
)

response = client.chat.completions.create(
    model    = "openai/gpt-4o",   # prefix with provider name
    messages = [{"role": "user", "content": user_prompt}],
)

# WrapSec enforces security transparently
print(response.headers.get("X-WrapSec-Input-Decision"))   # ALLOW / SANITIZE
print(response.headers.get("X-WrapSec-Output-Decision"))  # ALLOW / SANITIZE
print(response.headers.get("X-WrapSec-Trace-Id"))         # for audit lookup
```

### Python — proxy mode with Ollama

```python
client = OpenAI(
    api_key  = "wsk_live_your_wrapsec_key",
    base_url = "http://localhost:8000/v1",
)

response = client.chat.completions.create(
    model    = "ollama/gemma3:4b",
    messages = [{"role": "user", "content": user_prompt}],
)
```

### Configure proxy provider

```bash
curl -X PUT http://localhost:8000/v1/settings/proxy \
  -H "x-api-key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "provider":      "ollama",
    "base_url":      "http://localhost:11434",
    "default_model": "gemma3:4b",
    "timeout":       60
  }'
```

### Python SDK

```bash
pip install -e ./sdk/python
```

```python
import wrapsec

client = wrapsec.Client(api_key="wsk_live_...", base_url="http://localhost:8000")
result = client.scan("Ignore all previous instructions")
print(result.decision)        # BLOCK
print(result.primary_reason)  # RULE_DETECTOR
```

### CLI

```bash
wrapsec scan "Ignore all previous instructions"
wrapsec scan --mode full "What is the capital of France?"
wrapsec keys list
wrapsec audit export --format csv --output audit.csv
```

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| ADMIN_API_KEY | Yes | -- | Master admin key |
| DATABASE_URL | Yes | -- | PostgreSQL connection string |
| REDIS_URL | No | redis://localhost:6379/0 | Redis |
| LLM_PROVIDER | No | ollama | Detection LLM provider |
| LLM_MODEL | No | llama3.2:latest | Detection LLM model |
| OPENAI_API_KEY | No | -- | Required if LLM_PROVIDER = openai |
| GROQ_API_KEY | No | -- | Required if LLM_PROVIDER = groq |
| BLOCK_THRESHOLD | No | 0.7 | Detection block threshold |
| SANITIZE_THRESHOLD | No | 0.4 | Detection sanitize threshold |
| RATE_LIMIT_PER_MINUTE | No | 60 | Per API key |
| AUDIT_RETENTION_DAYS | No | 30 | Audit log retention |
| DATA_STORAGE_MODE | No | masked | Proxy text storage: full / masked / none |
| DATA_RETENTION_DAYS_PROXY | No | 7 | Days before proxy text is purged |

**Proxy provider API keys** are configured via `PUT /v1/settings/proxy` and stored encrypted in the database — not in `.env`. The detection LLM API keys (`OPENAI_API_KEY`, `GROQ_API_KEY`) are `.env` only and never stored in the database.

---

## Data Storage Modes

| Mode | input_raw / output_raw | Use case |
|---|---|---|
| `full` | Stored as-is | Development, debugging |
| `masked` | PII redacted before storing (default) | Production |
| `none` | NULL — text never persisted | Strict compliance |

Metadata (decisions, threats, scores, latency, execution_status) is always retained regardless of mode. Run the retention worker daily:

```bash
python scripts/cleanup_audit_logs.py             # uses configured retention days
python scripts/cleanup_audit_logs.py --dry-run   # preview without deleting
python scripts/cleanup_audit_logs.py --proxy-only --proxy-days 0  # purge all proxy text immediately
```

---

## Failure Modes

| Failure | Decision | Confidence | Primary Reason |
|---|---|---|---|
| One detector fails | continues | from remaining | per remaining |
| All detectors fail | ALLOW | LOW (0.0) | SYSTEM_ERROR |
| Guardrail (PII) fails | BLOCK | LOW (0.0) | SYSTEM_ERROR |
| Gateway exception | BLOCK | LOW (0.0) | SYSTEM_ERROR |
| LLM timeout (detection) | continues | from rule+ML | RULE/ML |
| Provider timeout (proxy) | 504 | -- | -- |
| Provider unreachable (proxy) | 502 | -- | -- |
| Redis unavailable | allows | -- | rate limit + idempotency disabled |

All failure paths return SYSTEM_ERROR. NO_THREAT_DETECTED is reserved exclusively for successful detection with clean results. Monitor SYSTEM_ERROR separately from security decisions.

---

## Full Docker Stack

| Service | Port | Description |
|---|---|---|
| Nginx | 80 | Reverse proxy, 64KB limit |
| API | 8000 (internal) | FastAPI |
| PostgreSQL | 5432 | Primary database |
| Redis | 6379 | Idempotency, rate limiting, cache |
| Prometheus | 9090 | Metrics |
| Grafana | 3001 | Observability |

---

## Running Tests

```bash
# Windows
$env:TESTING = "true"; pytest tests/unit tests/integration -v

# Linux/Mac
TESTING=true pytest tests/unit tests/integration -v
```

148 tests covering engine scoring, confidence, primary reason, policy resolver, proxy endpoint lifecycle, provider layer, and all API endpoints.

---

## Documentation

| Document | Description |
|---|---|
| [API Reference](docs/api.md) | All 43 endpoints with proxy mode examples |
| [Architecture](docs/architecture.md) | Entity model, policy, DB schema, proxy lifecycle |
| [Scoring Model](docs/scoring_model.md) | Detection pipeline, confidence, primary reason |
| [Implementation Plan](docs/implementation_plan.md) | Sprint breakdown and roadmap |

---

## Roadmap

**V1.2:** Per-model token counting (tiktoken), Application policy overrides, Key rotation, Cursor pagination, Background retention worker, Per-key storage mode override

**V2.0:** WildGuard over-refusal/under-refusal detection, Output evaluation engine, Security Events feed and alerting, JWT + SSO, Role-based overrides, Human review queue, SaaS multi-tenancy, SDK, Webhooks, Streaming

---

## License

MIT -- see [LICENSE](LICENSE)

## Author

Built by [@kbajish](https://github.com/kbajish)

WrapSec v1.1 -- Production-grade AI security gateway with proxy mode
