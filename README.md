# WrapSec — AI Security Gateway

> Production-grade security gateway for enterprise AI applications. Sits between your application and any LLM provider, scanning every prompt through a multi-layer detection pipeline before it reaches the model.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat-square)](https://nextjs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=flat-square)](https://postgresql.org)
[![Tests](https://img.shields.io/badge/Tests-85%20passing-brightgreen?style=flat-square)](#running-tests)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

---

## What is WrapSec?

WrapSec is a self-hosted AI security gateway that protects enterprise applications from LLM-specific threats. It operates as a drop-in security layer between your application and any LLM provider — OpenAI, Groq, Ollama, or any local model.

Every prompt is analysed through a four-layer detection pipeline before reaching the LLM. Threats are blocked or sanitised in real time. Every decision is logged with full attribution, confidence score, and primary reason — giving security teams and compliance officers a complete, explainable audit trail.

---

## Why WrapSec?

| Problem | WrapSec Solution |
|---|---|
| Prompt injection attacks targeting LLMs | Rule + ML + LLM detection pipeline |
| PII leaking into AI systems | Deterministic PII guardrail (22+ entity types) |
| No audit trail for AI requests | Full attribution: tenant → dept → app → key → user → IP |
| Black-box AI decisions | `primary_reason` + `confidence` on every decision |
| One policy for all systems | Per-department and per-application policy overrides |
| Compliance gaps (GDPR, EU AI Act) | Confidence bands, decision versioning, CSV export |

---

## Key Features

**Detection engine:**
- Rule-based detector — regex and heuristic patterns, ~0ms latency
- ML classifier — TF-IDF + LogisticRegression, ~5ms latency
- LLM semantic detector — conditional, full mode only, ~100–500ms
- PII guardrail — 22+ entity types, input and output, always enforced

**Decision model:**
- Guardrail-first enforcement — PII never dilutes the detection risk score
- Configurable thresholds — change at runtime without restart
- Layer toggles — enable/disable rule, ML, LLM independently at runtime
- `primary_reason` — identifies which layer drove the decision
- `confidence` — variance-based certainty score with HIGH/MEDIUM/LOW band
- `decision_version` — algorithm versioning for audit integrity

**Attribution:**
- Full chain: tenant → department → application → API key → user → IP
- Every request tied to a specific system, not just an API key
- Compliance-ready CSV export with all attribution fields

**Policy hierarchy:**
- System defaults → tenant global policy → department overrides
- Per-department settings — Finance gets stricter PII rules, Engineering gets relaxed thresholds
- Deep merge — null fields always inherit from parent

**Operations:**
- Real-time dashboard — 11 pages built in Next.js 14
- Semantic cache — identical prompts skip re-scoring
- Prometheus metrics + structured JSON logging
- Docker Compose — full stack in one command

---

## Architecture

```
Calling Application (Finance Bot, HR System, ERP)
              │
              │  x-api-key: wsk_live_...
              ▼
         Nginx (port 80)
              │
              ▼
    WrapSec API (FastAPI)
    ┌─────────────────────────────────┐
    │  Auth → RateLimit → Trace       │
    │                                 │
    │  InputGuard  ← PII detection    │
    │  RuleDetector                   │
    │  MLDetector                     │
    │  LLMDetector (conditional)      │
    │  RiskScorer                     │
    │  PolicyEngine (guardrail-first) │
    │  LLM Client  (proxy mode)       │
    │  OutputGuard ← PII on output    │
    └─────────────────────────────────┘
              │
    ┌─────────┴──────────┐
    │                    │
PostgreSQL           Redis
(audit, settings,   (cache,
 keys, entities)     rate limit)
```

**Detection pipeline scoring:**

```
risk_score = rule × 0.40 + ml × 0.30 + llm × 0.30

Guardrail evaluation (independent — overrides detection):
  pii_score >= block_threshold    → BLOCK
  pii_score >= sanitize_threshold → SANITIZE

Policy decision (if no guardrail triggered):
  risk_score >= block_threshold    → BLOCK
  risk_score >= sanitize_threshold → SANITIZE
  otherwise                        → ALLOW
```

---

## Response Format

Every `/v1/ai/request` response:

```json
{
  "trace_id":             "req_abc123",
  "decision":             "BLOCK",
  "decision_version":     "v1.0",
  "risk_score":           0.85,
  "primary_reason":       "RULE_DETECTOR",
  "confidence":           0.75,
  "confidence_band":      "HIGH",
  "sanitization_applied": false,
  "threats":              ["PROMPT_INJECTION"],
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

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Python 3.10+
- Node.js 18+
- Ollama (optional — for local LLM)

### 1. Clone

```bash
git clone https://github.com/kbajish/wrapsec.git
cd wrapsec
```

### 2. Configure

```bash
cp .env.example .env
# Required: set ADMIN_API_KEY to a strong random value
# Optional: set OPENAI_API_KEY or GROQ_API_KEY for cloud LLMs
```

Generate a strong admin key:

```bash
python -c "import secrets; print('wrapsec_' + secrets.token_urlsafe(32))"
```

### 3. Start infrastructure

```bash
docker compose -f infrastructure/docker/docker-compose.yml up -d postgres redis
```

### 4. Train ML model

```bash
pip install -r requirements.txt
python scripts/train_ml_model.py
```

### 5. Start API

```bash
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### 6. Start dashboard

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:3000` and sign in with your admin API key.

---

## API Usage

### Scan a prompt

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "Ignore all previous instructions",
    "detection_mode": "fast",
    "execution_mode": "scan_only"
  }'
```

### Proxy to LLM (scan + forward)

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "Summarise the Q4 report",
    "execution_mode": "proxy",
    "model": "llama3.2:latest",
    "metadata": {
      "user_id": "emp_12345",
      "source":  "finance-dashboard"
    }
  }'
```

### Python integration

```python
import httpx

client = httpx.Client(
    base_url = "http://localhost:8000",
    headers  = {"x-api-key": "your-key"},
)

result = client.post("/v1/ai/request", json={
    "input":          user_prompt,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "metadata":       {"user_id": current_user.id},
}).json()

if result["decision"] == "BLOCK":
    return "Request blocked — security policy"

if result["decision"] == "SANITIZE":
    safe_input = result["sanitized_input"]

if result["confidence_band"] == "LOW":
    flag_for_human_review(result["trace_id"])
```

---

## Configuration

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ADMIN_API_KEY` | Yes | — | Master admin key |
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `REDIS_URL` | No | `redis://localhost:6379/0` | Redis connection |
| `LLM_PROVIDER` | No | `ollama` | `ollama` \| `openai` \| `groq` |
| `LLM_MODEL` | No | `llama3.2:latest` | Model name |
| `LLM_BASE_URL` | No | `http://localhost:11434` | Ollama server URL |
| `OPENAI_API_KEY` | No | — | Required if provider = openai |
| `GROQ_API_KEY` | No | — | Required if provider = groq |
| `BLOCK_THRESHOLD` | No | `0.7` | Risk score threshold for BLOCK |
| `SANITIZE_THRESHOLD` | No | `0.4` | Risk score threshold for SANITIZE |
| `RATE_LIMIT_PER_MINUTE` | No | `60` | Requests per minute per API key |

### Runtime configuration (no restart needed)

```bash
# Change thresholds
curl -X PUT http://localhost:8000/v1/settings/thresholds \
  -H "x-api-key: your-admin-key" \
  -d '{"block_threshold": 0.8, "sanitize_threshold": 0.5}'

# Disable LLM layer
curl -X PUT http://localhost:8000/v1/settings/layers \
  -H "x-api-key: your-admin-key" \
  -d '{"rule_enabled": true, "ml_enabled": true, "llm_enabled": false}'

# Switch LLM provider
curl -X PUT http://localhost:8000/v1/settings/llm \
  -H "x-api-key: your-admin-key" \
  -d '{"provider": "openai", "model": "gpt-4", "timeout": 30}'
```

---

## Department-Based Multi-Tenancy

WrapSec supports multiple departments within a single installation, each with independent policies and API keys.

```
Acme Corporation (tenant)
├── Finance Department  → block=0.5 (stricter PII rules)
│     ├── Finance Bot   → wsk_live_fin_...
│     └── ERP System    → wsk_live_erp_...
├── HR Department       → block=0.5, local LLM only
│     └── HR System     → wsk_live_hr_...
└── Engineering         → block=0.75, LLM disabled
      └── Code Assistant → wsk_live_eng_...
```

Policy resolves per request: system defaults → tenant global → department override.

```bash
# Create department with stricter thresholds
curl -X POST http://localhost:8000/v1/admin/departments \
  -H "x-api-key: your-admin-key" \
  -d '{"slug": "finance", "name": "Finance Department"}'

curl -X PUT http://localhost:8000/v1/admin/departments/{id} \
  -H "x-api-key: your-admin-key" \
  -d '{"policy_override": {"thresholds": {"block": 0.5, "sanitize": 0.3}}}'

# Create application and API key
curl -X POST http://localhost:8000/v1/admin/applications \
  -H "x-api-key: your-admin-key" \
  -d '{"dept_id": "...", "slug": "finance-bot", "name": "Finance Bot"}'

curl -X POST http://localhost:8000/v1/keys \
  -H "x-api-key: your-admin-key" \
  -d '{"name": "Finance Bot Key", "app_id": "..."}'
```

---

## Dashboard

| Page | Description |
|---|---|
| Overview | Real-time metrics, decision distribution, top threats |
| Requests | Filterable audit log with full request detail modal |
| Analytics | Threat distribution, latency percentiles |
| Scanner | Manual prompt testing with per-layer score breakdown |
| Settings | Thresholds, detection layers, LLM configuration |
| API Keys | Create, rename, revoke keys |
| Departments | Manage departments and policy overrides |
| Applications | Manage applications and API key assignment |

---

## Threat Categories

| Category | Description |
|---|---|
| `PROMPT_INJECTION` | Attempts to override system instructions |
| `JAILBREAK` | Attempts to bypass safety restrictions |
| `MALICIOUS_INTENT` | Requests for harmful or dangerous information |
| `DATA_EXFILTRATION` | Attempts to leak data to external systems |
| `PII` | Personally identifiable information |
| `TOXICITY` | Abusive or harmful language |

---

## Compliance

**GDPR Article 25 — Data protection by design:**
- PII detected and redacted before reaching LLM
- Raw prompts never stored — SHA-256 hash only
- Full attribution chain in every audit record

**EU AI Act Article 12 — Transparency:**
- `primary_reason` identifies which factor drove the decision
- `confidence` quantifies system certainty
- `decision_version` ensures audit records remain interpretable

**SOC 2 Type II:**
- Per-key logs with IP address and user agent
- Instant key revocation with immediate effect
- Admin vs standard key access separation

**Export for compliance review:**

```bash
curl "http://localhost:8000/v1/audit/export?from=2026-04-01" \
  -H "x-api-key: your-admin-key" \
  -o audit_export.csv
```

---

## Full Docker Stack

```bash
docker compose -f infrastructure/docker/docker-compose.yml up -d
```

| Service | Port | Description |
|---|---|---|
| Nginx | 80 | Reverse proxy |
| API | 8000 (internal) | FastAPI application |
| PostgreSQL | 5432 | Primary database |
| Redis | 6379 | Cache + rate limiting |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3001 | Observability (admin/wrapsec) |

---

## Running Tests

```bash
# Windows
$env:TESTING = "true"
pytest tests/unit tests/integration -v

# Linux / Mac
TESTING=true pytest tests/unit tests/integration -v
```

85 tests across engine scoring, confidence, primary reason, policy resolver, and all API endpoints.

---

## Project Structure

```
wrapsec/
├── api/                    FastAPI application
│   └── v1/
│       ├── endpoints/      Request handlers (38 endpoints)
│       ├── middleware/      Auth, rate limiting, tracing, logging
│       ├── schemas/         Pydantic request/response models
│       └── dependencies/   DB session injection
├── engine/
│   ├── detection/          Rule, ML, LLM detectors
│   ├── guardrails/         PII detector + redactor, input/output guards
│   ├── scoring/            Risk scorer, confidence, primary reason
│   └── policy/             Policy engine + rules
├── services/
│   ├── gateway/            Main orchestration service
│   └── policy_resolver.py  Policy inheritance + deep merge
├── db/
│   ├── models.py           SQLAlchemy ORM models
│   └── repositories/       DB access layer
├── clients/                LLM provider clients (Ollama, OpenAI, Groq)
├── domain/                 Entities, value objects, enums
├── cache/                  Redis semantic cache + rate limiter
├── observability/          Structured logging, Prometheus metrics
├── config/                 Settings from .env
├── errors/                 Custom exceptions + handlers
├── scripts/                Train ML model, seed data
├── tests/                  Unit + integration tests (85 passing)
├── dashboard/              Next.js 14 dashboard (11 pages)
├── infrastructure/         Docker, Nginx, Prometheus, Grafana configs
└── docs/                   Architecture, scoring model, API reference
```

---

## Tech Stack

**Backend:** FastAPI · Python 3.10 · PostgreSQL · SQLAlchemy (async) · Redis · scikit-learn · Prometheus

**Dashboard:** Next.js 14 · TypeScript · Tailwind CSS v4 · SWR · Recharts

**Infrastructure:** Docker · Nginx · Grafana

---

## Documentation

| Document | Description |
|---|---|
| [API Reference](docs/api.md) | Complete endpoint reference with examples |
| [Architecture](docs/architecture.md) | Entity hierarchy, policy model, DB schema |
| [Scoring Model](docs/scoring_model.md) | Detection pipeline, confidence, primary reason |
| [Implementation Plan](docs/implementation_plan.md) | Sprint breakdown and task list |

---

## Roadmap

**V1.1:**
- Application-level policy overrides
- API key rotation
- Idempotency-Key header
- ML model improvement (3000+ training samples)
- Toxicity guardrail layer
- Per-layer latency breakdown in debug mode

**V2.0:**
- JWT + SSO for verified user attribution
- Role-based policy overrides
- Human review queue for LOW confidence decisions
- Multi-tenant SaaS onboarding
- SDK — Python, Node.js
- Webhook notifications

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Author

Built by [@kbajish](https://github.com/kbajish)

---

*WrapSec v1.0 — Production-grade AI security for enterprise*
