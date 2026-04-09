# WrapSec — AI Security Gateway

> Production-grade security gateway for AI-powered applications. Sits between your application and any LLM provider, detecting and blocking prompt injection, jailbreaks, PII leakage, and other AI-specific threats in real time.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![Next.js](https://img.shields.io/badge/Next.js-14-black)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## What is WrapSec?

WrapSec is a self-hosted AI security gateway that protects intelligent applications from LLM-specific threats. It operates as a proxy layer between your application and any LLM provider (OpenAI, Groq, Ollama, or any local model).

Every prompt is analysed through a multi-layer detection pipeline before reaching the LLM. Threats are blocked or sanitised in real time with a full audit trail for compliance.

---

## Key Features

- **Multi-layer detection** — Rule-based, ML classifier, and LLM semantic analysis
- **PII guardrail** — Detects and redacts 22+ PII types from inputs and outputs
- **Provider agnostic** — Works with OpenAI, Groq, Ollama, or any LLM
- **Proxy mode** — Sits between your app and the LLM, handles the full request lifecycle
- **Self-hosted** — Runs on-premise, air-gapped, or in your own cloud
- **Real-time dashboard** — Monitor requests, threats, and system health
- **Compliance ready** — Full audit trail with per-layer detection scores
- **EU AI Act aligned** — Transparent decision making with explainable scores

---

## Detection Pipeline

```
Request → Input Guard (PII)
        → Rule Detector    (regex patterns, ~0ms)
        → ML Classifier    (TF-IDF + LogisticRegression, ~5ms)
        → LLM Detector     (semantic analysis, conditional)
        → Risk Scorer      (weighted aggregation)
        → Policy Engine    (BLOCK / SANITIZE / ALLOW)
        → Output Guard     (PII check on LLM response)
        → Response
```

### Threat Categories

| Category | Description |
|---|---|
| `PROMPT_INJECTION` | Attempts to override system instructions |
| `JAILBREAK` | Attempts to bypass safety restrictions |
| `MALICIOUS_INTENT` | Requests for harmful or illegal information |
| `DATA_EXFILTRATION` | Attempts to leak sensitive data |
| `PII` | Personally identifiable information |
| `TOXICITY` | Harmful or abusive content |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Your Application                  │
└─────────────────────┬───────────────────────────────┘
                      │ HTTP
┌─────────────────────▼───────────────────────────────┐
│                 Nginx (port 80)                      │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│             WrapSec API (FastAPI)                    │
│                                                      │
│  Auth → RateLimit → Trace → Logging                  │
│       → SemanticCache                                │
│       → GatewayService                               │
│           → InputGuard (PII)                         │
│           → RuleDetector                             │
│           → MLDetector                               │
│           → LLMDetector (conditional)                │
│           → RiskScorer                               │
│           → PolicyEngine                             │
│           → LLM (proxy mode)                         │
│           → OutputGuard (PII)                        │
│       → PostgreSQL (audit)                           │
│       → Redis (cache + rate limit)                   │
└─────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Python 3.10+
- Node.js 18+

### 1. Clone

```bash
git clone https://github.com/kbajish/wrapsec.git
cd wrapsec
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — set ADMIN_API_KEY and LLM provider settings
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

### Scan only

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

```json
{
  "trace_id": "req_abc123",
  "decision": "BLOCK",
  "risk_score": 0.85,
  "threats": ["PROMPT_INJECTION"],
  "processing": {
    "latency_ms": 2.1,
    "detection_mode": "fast"
  }
}
```

### Proxy mode

```bash
curl -X POST http://localhost:8000/v1/ai/request \
  -H "x-api-key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "What is machine learning?",
    "execution_mode": "proxy",
    "model": "llama3.2:latest"
  }'
```

### Create API key

```bash
curl -X POST http://localhost:8000/v1/keys \
  -H "x-api-key: your-admin-key" \
  -d '{"name": "my-app"}'
```

---

## Configuration

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `ADMIN_API_KEY` | — | Master admin key (required) |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `LLM_PROVIDER` | `ollama` | LLM provider: ollama, openai, groq |
| `LLM_MODEL` | `llama3.2:latest` | Model name |
| `LLM_BASE_URL` | `http://localhost:11434` | Ollama base URL |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `GROQ_API_KEY` | — | Groq API key |
| `BLOCK_THRESHOLD` | `0.7` | Risk score threshold for BLOCK |
| `SANITIZE_THRESHOLD` | `0.4` | Risk score threshold for SANITIZE |
| `RATE_LIMIT_PER_MINUTE` | `60` | Requests per minute per IP |

### Policy thresholds

Thresholds can be changed at runtime via the dashboard or API without restart:

```bash
curl -X PUT http://localhost:8000/v1/settings/thresholds \
  -H "x-api-key: your-admin-key" \
  -d '{"block_threshold": 0.8, "sanitize_threshold": 0.5}'
```

---

## Dashboard

The Next.js dashboard provides:

- **Overview** — Real-time metrics, decision distribution, top threats
- **Requests** — Filterable audit log with per-request detail and layer scores
- **Analytics** — Threat distribution, latency analysis
- **Scanner** — Manual prompt testing with detection and guardrail layer breakdown
- **Settings** — Policy thresholds and detection layer toggles (live, no restart)
- **API Keys** — Key management with instant revocation

---

## Full Docker Stack

```bash
docker compose -f infrastructure/docker/docker-compose.yml up -d
```

| Service | Port | Description |
|---|---|---|
| `nginx` | 80 | API gateway |
| `api` | 8000 (internal) | FastAPI application |
| `postgres` | 5432 | PostgreSQL database |
| `redis` | 6379 | Cache + rate limiting |
| `prometheus` | 9090 | Metrics collection |
| `grafana` | 3001 | Observability (admin/wrapsec) |

---

## Running Tests

```bash
# Windows
$env:TESTING = "true"
pytest tests/unit tests/integration -v

# Linux / Mac
TESTING=true pytest tests/unit tests/integration -v
```

50 tests — unit + integration coverage across all components.

---

## Tech Stack

**Backend**
- FastAPI + Python 3.10
- PostgreSQL + SQLAlchemy (async)
- Redis (cache + rate limiting)
- scikit-learn (ML detector)
- Prometheus (metrics)

**Dashboard**
- Next.js 14 (App Router)
- Tailwind CSS v4
- SWR (data fetching)
- Recharts (charts)

**Infrastructure**
- Docker + Docker Compose
- Nginx (reverse proxy)
- Grafana (observability)

---

## Roadmap

- [ ] Multi-tenancy
- [ ] SDK — Python, Node.js
- [ ] Webhook support
- [ ] Custom rules API
- [ ] SSO / SAML
- [ ] Toxicity guardrail layer
- [ ] Streaming support
- [ ] Usage-based billing

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Author

Built by [@kbajish](https://github.com/kbajish)
