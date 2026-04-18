# WrapSec - AI Security Gateway

> Production-grade security gateway for enterprise AI applications. Protects every LLM interaction with a multi-layer detection pipeline, independent guardrail enforcement, and a complete attribution audit trail.

WrapSec enforces security, compliance, and observability for every LLM request before it reaches the model.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat-square)](https://nextjs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=flat-square)](https://postgresql.org)
[![Tests](https://img.shields.io/badge/Tests-85%20passing-brightgreen?style=flat-square)](#running-tests)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

---

## What is WrapSec?

WrapSec is a self-hosted AI security gateway that sits between your application and any LLM provider. Every prompt passes through a four-layer detection pipeline before reaching the model. Threats are blocked or sanitised in real time. Every decision is logged with full attribution, a confidence score, and a primary reason, giving security teams and compliance officers a complete, explainable audit trail.

**Where it fits:** WrapSec sits between your application and any LLM provider (OpenAI, Groq, Ollama, or any local model), acting as a security enforcement layer. Your application sends prompts to WrapSec instead of directly to the LLM. WrapSec scans, decides, and either blocks the request or forwards it to the model on your behalf.

---

## Why WrapSec?

| Problem | WrapSec Solution |
|---|---|
| Prompt injection and jailbreak attacks | Rule + ML + LLM detection pipeline |
| PII leaking into AI systems | Independent PII guardrail with 22+ entity types on input and output |
| Detection threshold changes impacting PII protection | Guardrail thresholds fully decoupled from detection thresholds |
| No audit trail for AI requests | Full attribution chain per request |
| Black-box decisions | primary_reason + confidence on every response |
| Cannot distinguish clean input from system failure | SYSTEM_ERROR is always distinct from NO_THREAT_DETECTED |
| Duplicate processing on retries | Idempotency-Key: same key + different body returns 409 CONFLICT |
| CJK and dense text overloading LLMs | Heuristic token limit: ceil(len/2) > 4000 returns 422 |
| Compliance gaps (GDPR, EU AI Act, SOC 2) | Confidence bands, decision versioning, CSV export, retention |

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

**Decision model:**
- Guardrail-first: PII evaluated independently, always overrides detection
- Guardrail thresholds (guardrails.pii.*) fully decoupled from detection thresholds
- risk_score = rule x 0.40 + ml x 0.30 + llm x 0.30 (PII excluded)
- primary_reason: 7 values, SYSTEM_ERROR always distinct from NO_THREAT_DETECTED
- confidence: variance-based with HIGH/MEDIUM/LOW band, 0.0 on system failure
- decision_version: algorithm version in every response
- sanitization_applied: explicit boolean flag

**Reliability:**
- Idempotency-Key: same key + same body returns cached result, same key + different body returns 409
- ULID trace IDs: time-sortable
- Input limit: 8,000 chars / 4,000 estimated tokens (heuristic, safe for CJK)
- Per-detector try/catch: individual failures do not crash the pipeline
- SYSTEM_ERROR on detector failure: never confused with NO_THREAT_DETECTED
- LLM timeout fallback: continues with rule + ML result

**Policy hierarchy:**
- System defaults -> tenant global -> department overrides
- Detection thresholds and PII thresholds configured and resolved independently
- All settings configurable at runtime without restart

---

## Architecture

```
Calling Application
              |  x-api-key: wsk_live_...
              |  Idempotency-Key: <uuid>
              v
      Nginx -- 64KB payload limit
              v
    WrapSec API (FastAPI)
    +--------------------------------------------------+
    |  Trace -> RateLimit(per-key) -> Auth ->          |
    |  Idempotency(Redis,60s) -> Logging               |
    |                                                  |
    |  Gateway Service                                 |
    |  +-- InputGuard    PII detection + redaction     |
    |  +-- RuleDetector  try/catch (~0ms)              |
    |  +-- MLDetector    try/catch (~5ms)              |
    |  +-- LLMDetector   try/catch (conditional)       |
    |  +-- RiskScorer    rule+ml+llm weighted          |
    |  +-- PolicyEngine                                |
    |  |     +-- PII thresholds (guardrails.pii.*)     |
    |  |     +-- Det thresholds (thresholds.*)         |
    |  +-- LLM Client    proxy mode only               |
    |  +-- OutputGuard   PII on LLM output             |
    +--------------------------------------------------+
              |
    +---------+------------------+
    |                            |
PostgreSQL                   Redis
(audit, settings,            (idempotency, rate limit,
 keys, entities,              semantic cache)
 retention policy)
```

**Scoring:**

```
Detection risk score (PII excluded):
  risk_score = rule x 0.40 + ml x 0.30 + llm x 0.30
  + boost if max(rule, ml, llm) >= 0.5

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

**Security model:**
- **Fail-open for detection:** if detectors fail, the request is allowed through with SYSTEM_ERROR + LOW confidence. Blocking clean requests due to system errors is worse than a missed detection.
- **Fail-closed for guardrails:** if the PII guardrail fails, the request is blocked. Data protection must never fail open.
- **SYSTEM_ERROR events indicate infrastructure issues**, not security threats, and must be monitored separately from detection outcomes.

---

## Response Format

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

**primary_reason values:**

| Value | Meaning |
|---|---|
| RULE_DETECTOR | Rule layer dominant |
| ML_DETECTOR | ML classifier dominant |
| LLM_DETECTOR | LLM analysis dominant |
| PII_GUARDRAIL_BLOCK | PII at block threshold |
| PII_GUARDRAIL_SANITIZE | PII at sanitize threshold |
| NO_THREAT_DETECTED | All scores below thresholds -- input genuinely clean |
| SYSTEM_ERROR | Detector(s) failed -- confidence = 0.0 (LOW) |

**SYSTEM_ERROR is never NO_THREAT_DETECTED.** An ALLOW with NO_THREAT_DETECTED means input was safe. A BLOCK with SYSTEM_ERROR means the system failed. These are different events requiring different responses.

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

### Python integration

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
            alert_ops(result["trace_id"])   # detector failure -- investigate
        else:
            return "Blocked by security policy"
    case "SANITIZE":
        safe_input = result["sanitized_input"]
    case "ALLOW":
        if result["primary_reason"] == "SYSTEM_ERROR":
            alert_ops(result["trace_id"])   # all detectors failed -- fail open
        # otherwise NO_THREAT_DETECTED -- genuinely clean

if result["confidence_band"] == "LOW":
    flag_for_human_review(result["trace_id"])
```

### Python SDK

```bash
pip install -e ./sdk/python
```

```python
import wrapsec

client = wrapsec.Client(
    api_key  = "wsk_live_...",
    base_url = "http://localhost:8000",
)

result = client.scan("Ignore all previous instructions")
print(result.decision)        # BLOCK
print(result.primary_reason)  # RULE_DETECTOR
print(result.confidence)      # 0.95
```

### CLI

```bash
wrapsec scan "Ignore all previous instructions"
wrapsec scan --mode full "What is the capital of France?"
wrapsec keys list
wrapsec audit export --format csv --output audit.csv
```

---

## Integration Examples

The `examples/` directory contains two reference architectures showing how to integrate WrapSec into real applications.

**FastAPI middleware pattern** (`examples/fastapi/`): WrapSec runs as middleware intercepting all requests to `/api/` paths. Clean requests proceed to your endpoint. Blocked requests are rejected before reaching your handler.

**LLM proxy pattern** (`examples/llm_app/`): WrapSec sits in front of your LLM (Ollama or any OpenAI-compatible endpoint). Every user message is scanned before the model sees it. Supports Ollama and OpenAI-compatible providers via the LLM_PROVIDER environment variable.

```bash
# Run the LLM proxy example
export WRAPSEC_API_KEY=wsk_live_...
export LLM_PROVIDER=ollama
uvicorn examples.llm_app.main:app --port 8090

curl -X POST http://localhost:8090/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "what is 2+2?", "user_id": "alice"}'
```

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| ADMIN_API_KEY | Yes | -- | Master admin key |
| DATABASE_URL | Yes | -- | PostgreSQL connection string |
| REDIS_URL | No | redis://localhost:6379/0 | Redis |
| LLM_PROVIDER | No | ollama | ollama or openai or groq |
| LLM_MODEL | No | llama3.2:latest | Model name |
| OPENAI_API_KEY | No | -- | Required if provider = openai |
| GROQ_API_KEY | No | -- | Required if provider = groq |
| BLOCK_THRESHOLD | No | 0.7 | Detection block threshold |
| SANITIZE_THRESHOLD | No | 0.4 | Detection sanitize threshold |
| RATE_LIMIT_PER_MINUTE | No | 60 | Per API key |
| AUDIT_RETENTION_DAYS | No | 30 | Default audit log retention |

LLM API keys are .env only and never stored in the database.

---

## Input Limits

| Limit | Value | Notes |
|---|---|---|
| Max characters | 8,000 | Hard limit in schema, returns 422 |
| Estimated token limit | 4,000 | ceil(len/2) > 4000 returns 422 |
| Max payload | 64KB | Nginx, returns 413 |
| Max export rows | 10,000 | Per request |

The heuristic ceil(len/2) is conservative. It estimates 2 chars per token, which is safe for all languages including CJK (actual: ~1 char/token) and English (actual: ~4 chars/token). Full per-model token counting with tiktoken is planned for V1.1.

Treat 8,000 characters as the effective hard limit in your integration.

---

## Failure Modes

| Failure | Decision | Confidence | Primary Reason |
|---|---|---|---|
| One detector fails | continues | from remaining | per remaining |
| All detectors fail | ALLOW | LOW (0.0) | SYSTEM_ERROR |
| Guardrail (PII) fails | BLOCK | LOW (0.0) | SYSTEM_ERROR |
| Gateway exception | BLOCK | LOW (0.0) | SYSTEM_ERROR |
| LLM timeout (detection) | continues | from rule+ML | RULE/ML |
| LLM timeout (proxy) | per detection | per detection | per detection |
| Redis unavailable | allows | -- | rate limit + idempotency disabled |

All failure paths return SYSTEM_ERROR. NO_THREAT_DETECTED is reserved exclusively for successful detection with clean results.

SYSTEM_ERROR events represent system or infrastructure issues, not security threats. Monitor them separately via `GET /v1/audit/logs?primary_reason=SYSTEM_ERROR`. A sustained rate above 0.1% warrants investigation.

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

85 tests covering engine scoring, confidence, primary reason, policy resolver, and all API endpoints.

---

## Documentation

| Document | Description |
|---|---|
| [API Reference](docs/api.md) | All 39 endpoints with examples |
| [Architecture](docs/architecture.md) | Entity model, policy, DB schema, attribution |
| [Scoring Model](docs/scoring_model.md) | Detection pipeline, confidence, primary reason |
| [Implementation Plan](docs/implementation_plan.md) | Sprint breakdown and roadmap |

---

## Roadmap

**V1.1:** Per-model token counting (tiktoken), Application policy overrides, Key rotation, Cursor pagination, ML model improvement, Toxicity guardrail

**V2.0:** JWT + SSO, Role-based overrides, Human review queue, SaaS multi-tenancy, SDK, Webhooks, Streaming

---

## License

MIT -- see [LICENSE](LICENSE)

## Author

Built by [@kbajish](https://github.com/kbajish)

WrapSec v1.0 -- Production-grade AI security for enterprise
