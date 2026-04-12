# WrapSec — AI Security Gateway

> Production-grade security gateway for enterprise AI applications. Protects every LLM interaction with a multi-layer detection pipeline, guardrail enforcement, and a complete attribution audit trail.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat-square)](https://nextjs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=flat-square)](https://postgresql.org)
[![Tests](https://img.shields.io/badge/Tests-85%20passing-brightgreen?style=flat-square)](#running-tests)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

---

## What is WrapSec?

WrapSec is a self-hosted AI security gateway that sits between your application and any LLM provider. Every prompt passes through a four-layer detection pipeline before reaching the model. Threats are blocked or sanitised in real time. Every decision is logged with full attribution, a confidence score, and a primary reason — giving security teams and compliance officers a complete, explainable audit trail.

It is not a firewall. It is not a proxy with regex rules. It is a complete AI security platform: detection, policy enforcement, attribution, observability, and management in one system.

---

## Why WrapSec?

| Problem | WrapSec Solution |
|---|---|
| Prompt injection and jailbreak attacks | Rule + ML + LLM detection pipeline |
| PII leaking into AI systems | Deterministic PII guardrail — 22+ entity types, input and output |
| No audit trail for AI requests | Full attribution chain per request |
| Black-box decisions | `primary_reason` + `confidence` on every response |
| One security policy for all departments | Per-department policy overrides with deep merge |
| Compliance gaps (GDPR, EU AI Act, SOC 2) | Confidence bands, decision versioning, CSV export, retention policy |
| Duplicate processing on client retries | Idempotency-Key header with Redis cache |
| Unknown which system made a request | One API key per application, full entity attribution |

---

## Key Features

**Detection pipeline:**
- Rule-based detector — regex and heuristic patterns, ~0ms
- ML classifier — TF-IDF + LogisticRegression, ~5ms
- LLM semantic detector — conditional invocation in full mode, ~100–500ms
- PII guardrail — 22+ entity types, scans both input and LLM output

**Decision model:**
- Guardrail-first — PII score never dilutes the detection risk score
- `risk_score = rule × 0.40 + ml × 0.30 + llm × 0.30`
- Boost mechanism — strong signals not diluted by inactive layers
- `primary_reason` — which layer drove the decision
- `confidence` — variance-based certainty with HIGH/MEDIUM/LOW band
- `decision_version` — algorithm version in every response
- `sanitization_applied` — explicit flag when input was sanitised

**Reliability:**
- Idempotency-Key header — same key returns cached response (60s TTL)
- ULID trace IDs — time-sortable, lexicographically ordered
- Failure mode contract — detection failure → ALLOW + LOW confidence, system failure → BLOCK
- LLM timeout fallback — continues with rule + ML if LLM times out

**Attribution:**
- Full chain: tenant → department → application → API key → user → IP
- `attribution_verified: false` in V1 — clearly labelled self-reported identity
- `tenant_id` never accepted from request metadata — always from API key
- Rate limiting per API key with standard headers

**Policy hierarchy:**
- System defaults → tenant global policy → department overrides
- Deep merge — null fields always inherit from parent
- Per-department settings — Finance gets stricter PII, Engineering gets relaxed thresholds
- All thresholds, layers, and LLM settings configurable at runtime without restart

**Compliance:**
- Audit log retention policy — configurable via Settings UI, stored in DB
- Cleanup script reads retention days from DB first, falls back to config
- CSV export with all attribution and decision fields
- Input limits — 10,000 chars, 64KB payload enforced at Nginx

**Operations:**
- Next.js 14 dashboard — 11 pages
- Semantic cache — identical prompts skip re-scoring
- Prometheus metrics + structured JSON logging
- Docker Compose — full stack in one command

---

## Architecture

```
Calling Application
(Finance Bot, HR System, ERP, Mobile App)
              │
              │  x-api-key: wsk_live_...
              │  Idempotency-Key: <uuid> (optional)
              ▼
      Nginx — 64KB payload limit, reverse proxy
              │
              ▼
    WrapSec API (FastAPI)
    ┌───────────────────────────────────────┐
    │  Middleware stack                      │
    │  Trace → RateLimit → Auth →           │
    │  Idempotency → Logging                │
    │                                       │
    │  Gateway Service                      │
    │  ├── InputGuard    (PII detection)    │
    │  ├── RuleDetector  (~0ms)             │
    │  ├── MLDetector    (~5ms)             │
    │  ├── LLMDetector   (conditional)      │
    │  ├── RiskScorer    (weighted)         │
    │  ├── PolicyEngine  (guardrail-first)  │
    │  ├── LLM Client    (proxy mode)       │
    │  └── OutputGuard   (PII on output)   │
    └───────────────────────────────────────┘
              │
    ┌─────────┴────────────┐
    │                      │
PostgreSQL              Redis
(audit, settings,      (semantic cache,
 keys, entities,        rate limiting,
 retention policy)      idempotency)
```

**Detection scoring:**

```
Detection risk score (detectors only — PII excluded):
  risk_score = rule × 0.40 + ml × 0.30 + llm × 0.30
  if max(rule, ml, llm) >= 0.5:
      risk_score = max(risk_score, max_score)  # boost

Guardrail evaluation (independent — always overrides):
  pii >= block_threshold    → BLOCK
  pii >= sanitize_threshold → SANITIZE

Policy decision (if no guardrail triggered):
  risk_score >= block_threshold    → BLOCK
  risk_score >= sanitize_threshold → SANITIZE
  otherwise                        → ALLOW
```

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
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "policy_source":  "department_override"
  }
}
```

**Field rules:**
- `sanitized_input` — only present when `decision = SANITIZE`
- `output` — only present in proxy mode when LLM was invoked
- `threats` — always present (empty array if none)
- `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` — always in headers

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
```

Edit `.env` — at minimum set `ADMIN_API_KEY` to a strong random value:

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

Open `http://localhost:3000` — sign in with your admin API key.

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

### Proxy to LLM

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: your-key" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000" \
  -d '{
    "input": "Summarise the Q4 report",
    "execution_mode": "proxy",
    "model": "llama3.2:latest",
    "metadata": {"user_id": "emp_12345"}
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

match result["decision"]:
    case "BLOCK":
        return "Request blocked — security policy"
    case "SANITIZE":
        safe_input = result["sanitized_input"]
        # proceed with sanitized input
    case "ALLOW":
        pass  # proceed normally

if result["confidence_band"] == "LOW":
    flag_for_human_review(result["trace_id"])
```

---

## Configuration

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ADMIN_API_KEY` | Yes | — | Master admin key — must be strong and secret |
| `DATABASE_URL` | Yes | — | `postgresql+asyncpg://user:pass@host/db` |
| `REDIS_URL` | No | `redis://localhost:6379/0` | Redis connection |
| `LLM_PROVIDER` | No | `ollama` | `ollama` \| `openai` \| `groq` |
| `LLM_MODEL` | No | `llama3.2:latest` | Model name |
| `LLM_BASE_URL` | No | `http://localhost:11434` | Ollama server URL |
| `OPENAI_API_KEY` | No | — | Required if provider = openai |
| `GROQ_API_KEY` | No | — | Required if provider = groq |
| `BLOCK_THRESHOLD` | No | `0.7` | Risk score threshold for BLOCK |
| `SANITIZE_THRESHOLD` | No | `0.4` | Risk score threshold for SANITIZE |
| `RATE_LIMIT_PER_MINUTE` | No | `60` | Requests per minute per API key |
| `AUDIT_RETENTION_DAYS` | No | `30` | Days to retain audit logs |

**API keys for LLM providers are `.env` only — never stored in the database.**

### Runtime configuration (no restart required)

```bash
# Policy thresholds
curl -X PUT http://localhost:8000/v1/settings/thresholds \
  -H "x-api-key: your-admin-key" \
  -d '{"block_threshold": 0.8, "sanitize_threshold": 0.5}'

# Detection layers
curl -X PUT http://localhost:8000/v1/settings/layers \
  -H "x-api-key: your-admin-key" \
  -d '{"rule_enabled": true, "ml_enabled": true, "llm_enabled": false}'

# LLM provider
curl -X PUT http://localhost:8000/v1/settings/llm \
  -H "x-api-key: your-admin-key" \
  -d '{"provider": "openai", "model": "gpt-4", "timeout": 30}'

# Audit retention
curl -X PUT http://localhost:8000/v1/settings/retention \
  -H "x-api-key: your-admin-key" \
  -d '{"retention_days": 90}'
```

All settings are stored in the database and configurable from the Settings page in the dashboard.

---

## Department-Based Multi-Tenancy

WrapSec supports multiple departments within a single installation, each with independent policies, applications, and API keys.

```
Acme Corporation (tenant)
├── Finance Department  → block=0.5, sanitize=0.3 (stricter PII)
│     ├── Finance Bot   → wsk_live_fin_...
│     └── ERP System    → wsk_live_erp_...
├── HR Department       → block=0.5, local LLM only
│     └── HR System     → wsk_live_hr_...
└── Engineering         → block=0.75, LLM disabled
      └── Code Assistant → wsk_live_eng_...
```

Policy resolves per request: system defaults → tenant global → department override.

Every request is attributed to the full chain: which company, which department, which application, which key, which user, from which IP.

```bash
# Create department with policy override
curl -X POST http://localhost:8000/v1/admin/departments \
  -H "x-api-key: your-admin-key" \
  -d '{"slug": "finance", "name": "Finance Department"}'

curl -X PUT http://localhost:8000/v1/admin/departments/{id} \
  -H "x-api-key: your-admin-key" \
  -d '{"policy_override": {"thresholds": {"block": 0.5, "sanitize": 0.3}}}'

# Create application + scoped API key
curl -X POST http://localhost:8000/v1/admin/applications \
  -H "x-api-key: your-admin-key" \
  -d '{"dept_id": "...", "slug": "finance-bot", "name": "Finance Bot", "owner_email": "john@acme.com"}'

curl -X POST http://localhost:8000/v1/keys \
  -H "x-api-key: your-admin-key" \
  -d '{"name": "Finance Bot Key", "app_id": "..."}'
```

---

## Dashboard

| Page | Description |
|---|---|
| Overview | Real-time metrics, decision distribution, top threats, recent requests |
| Requests | Filterable audit log — trace ID, decision, threat, date range, confidence band |
| Analytics | Threat distribution, latency percentiles |
| Scanner | Manual prompt testing — detection layers + guardrail layers breakdown |
| Settings | Thresholds, detection layers, LLM config, audit retention |
| API Keys | Create, rename, revoke — instant effect |
| Departments | Manage departments and policy overrides |
| Applications | Manage applications and API key assignment |

Every request row is clickable — shows full attribution chain, per-layer detection scores, guardrail scores, confidence, and primary reason.

---

## Threat Categories

| Category | Description |
|---|---|
| `PROMPT_INJECTION` | Attempts to override system instructions |
| `JAILBREAK` | Attempts to bypass safety restrictions |
| `MALICIOUS_INTENT` | Requests for harmful or dangerous information |
| `DATA_EXFILTRATION` | Attempts to leak data to external systems |
| `PII` | Personally identifiable information (22+ types) |
| `TOXICITY` | Abusive or harmful language |

---

## Compliance

**GDPR Article 25 — Data protection by design:**
- PII detected and redacted before reaching LLM and on LLM output
- Raw prompts never stored — SHA-256 hash only
- Full attribution chain in every audit record
- Configurable retention policy — default 30 days, enforced via scheduled cleanup

**EU AI Act Article 12 — Transparency:**
- `primary_reason` identifies the dominant factor behind every decision
- `confidence` quantifies the system's certainty
- `decision_version` ensures audit records remain interpretable as the algorithm evolves

**SOC 2 Type II:**
- Per-key logs with IP address and user agent
- Instant key revocation — takes effect on next request
- Admin vs standard key access separation
- Rate limiting per API key with standard headers

**Export for compliance:**

```bash
curl "http://localhost:8000/v1/audit/export?from=2026-04-01&confidence_band=LOW" \
  -H "x-api-key: your-admin-key" \
  -o low_confidence_decisions.csv
```

**Cleanup audit logs:**

```bash
python scripts/cleanup_audit_logs.py --dry-run
python scripts/cleanup_audit_logs.py --days 30
```

---

## Failure Modes

| Failure | Behaviour |
|---|---|
| Detection layer error | Score = 0.0, continues with available layers |
| All detection layers fail | ALLOW + `confidence_band = LOW` + `primary_reason = NO_THREAT_DETECTED` |
| Guardrail (PII) failure | BLOCK — fail closed, data protection is non-negotiable |
| LLM timeout (detection) | `llm_score = 0.0`, `llm_invoked = false`, continues with rule + ML |
| LLM timeout (proxy) | `output = "[LLM unavailable]"`, detection decision already made |
| System failure | BLOCK + `risk_score = 1.0` + `confidence_band = LOW` + `primary_reason = SYSTEM_ERROR` |

The system always fails closed — blocking is safer than allowing unknown content through.

---

## Full Docker Stack

```bash
docker compose -f infrastructure/docker/docker-compose.yml up -d
```

| Service | Port | Description |
|---|---|---|
| Nginx | 80 | Reverse proxy, 64KB payload limit |
| API | 8000 (internal) | FastAPI application |
| PostgreSQL | 5432 | Primary database |
| Redis | 6379 | Semantic cache, rate limiting, idempotency |
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

85 tests — engine scoring, confidence, primary reason, policy resolver, all API endpoints.

---

## Project Structure

```
wrapsec/
├── api/
│   └── v1/
│       ├── endpoints/      38 endpoint handlers
│       ├── middleware/      Trace, RateLimit, Auth, Idempotency, Logging
│       ├── schemas/         Pydantic request/response models
│       └── dependencies/   DB session injection
├── engine/
│   ├── detection/          Rule, ML, LLM detectors
│   ├── guardrails/         PII detector + redactor, input/output guards
│   ├── scoring/            Risk scorer, confidence, primary reason
│   └── policy/             Policy engine (guardrail-first)
├── services/
│   ├── gateway/            Main pipeline orchestration
│   └── policy_resolver.py  Deep merge policy inheritance
├── db/
│   ├── models.py           SQLAlchemy ORM
│   └── repositories/       Audit, keys, settings, tenant, dept, app
├── clients/                Ollama, OpenAI, Groq LLM clients
├── domain/                 Entities, value objects (ULID trace IDs), enums
├── cache/                  Redis semantic cache + rate limiter
├── observability/          Structured logging, Prometheus metrics
├── config/                 Settings (env + DB)
├── errors/                 Exceptions + handlers
├── scripts/                Train ML, cleanup audit logs, seed data
├── tests/                  85 unit + integration tests
├── dashboard/              Next.js 14 (11 pages)
├── infrastructure/         Docker, Nginx (64KB limit), Prometheus, Grafana
└── docs/                   API reference, architecture, scoring model
```

---

## Tech Stack

**Backend:** FastAPI · Python 3.10 · PostgreSQL · SQLAlchemy (async) · Redis · scikit-learn · Prometheus

**Dashboard:** Next.js 14 · TypeScript · Tailwind CSS v4 · SWR · Recharts

**Infrastructure:** Docker · Nginx · Grafana

---

## API Summary

38 endpoints across 8 resource groups:

```
Gateway:      POST /v1/ai/request  ·  GET /v1/ai/requests/{trace_id}
Audit:        GET  /v1/audit/logs  ·  stats  ·  attribution  ·  export (CSV)
Settings:     GET/PUT /v1/settings/thresholds  ·  layers  ·  llm  ·  retention
API Keys:     POST/GET/PUT/DELETE /v1/keys  ·  GET /v1/keys/{key_id}
Tenant:       GET/PUT /v1/admin/tenant
Departments:  POST/GET/PUT/DELETE /v1/admin/departments/{id}
              GET /v1/admin/departments/{id}/policy
              GET /v1/admin/departments/{id}/stats
Applications: POST/GET/PUT/DELETE /v1/admin/applications/{id}
              GET /v1/admin/applications/{id}/policy
Health:       GET /health  ·  /health/ready  ·  /health/live  ·  /health/config
Metrics:      GET /metrics  (Prometheus)
```

---

## Documentation

| Document | Description |
|---|---|
| [API Reference](docs/api.md) | Complete endpoint reference with request/response examples |
| [Architecture](docs/architecture.md) | Entity hierarchy, policy model, DB schema, attribution chain |
| [Scoring Model](docs/scoring_model.md) | Detection pipeline, confidence formula, primary reason logic |
| [Implementation Plan](docs/implementation_plan.md) | Sprint breakdown, task list, roadmap |

---

## Roadmap

**V1.1:**
- Application-level policy overrides (placeholder active in V1)
- API key rotation with grace period
- Cursor-based pagination for large audit datasets
- ML model improvement — 3000+ training samples from public datasets
- Toxicity guardrail layer
- Per-layer latency breakdown in debug mode

**V2.0:**
- JWT + SSO for cryptographically verified user attribution
- Role-based policy overrides
- Human review queue for LOW confidence decisions
- Multi-tenant SaaS onboarding
- SDK — Python, Node.js
- Webhook notifications for BLOCK events
- Streaming support

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Author

Built by [@kbajish](https://github.com/kbajish)

---

*WrapSec v1.0 — Production-grade AI security for enterprise*
