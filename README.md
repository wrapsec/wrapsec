<p align="center">
  <img src="https://raw.githubusercontent.com/wrapsec/wrapsec/main/dashboard/public/wrapsec-logo.svg" alt="WrapSec" width="120" />
  <h1 align="center">WrapSec</h1>
  <p align="center">
    <img src="https://img.shields.io/badge/version-1.0.0-7B2BF9" alt="version" />
    <img src="https://img.shields.io/badge/license-MIT-CD00FF" alt="license" />
    <img src="https://img.shields.io/badge/python-3.10%2B-00E1FF" alt="python" />
    <img src="https://img.shields.io/badge/node-18%2B-00B1FF" alt="node" />
    <img src="https://img.shields.io/badge/PyPI-wrapsec--python-7B2BF9" alt="pypi" />
    <img src="https://img.shields.io/badge/npm-wrapsec--node-CD00FF" alt="npm" />
  </p>
</p>


WrapSec is a production-grade AI security gateway and enforcement layer that protects applications interacting with LLMs.

It inspects every prompt and response through a multi-layer detection pipeline and enforces decisions - ALLOW, BLOCK, or SANITIZE - before anything reaches the model.


## Why WrapSec

Traditional input validation does not protect against AI-specific threats such as prompt injection, jailbreak attempts, data exfiltration, and PII leakage. WrapSec provides real-time enforcement before LLM execution, not after.

WrapSec enforces security decisions before any request reaches the LLM. Blocked requests never leave your system.

WrapSec supports two execution modes:

**Scan-only** - the application sends a prompt to WrapSec, receives a security decision (ALLOW / BLOCK / SANITIZE), and handles LLM forwarding itself.

**Proxy** - WrapSec sits in the full request path, inspects input, forwards to the LLM provider using an encrypted API key, inspects the response, and returns an OpenAI-compatible response to the application. Both input and output decisions are enforced.


## Detection Pipeline

The pipeline combines rule-based, machine learning, and optional LLM-based analysis to produce a final security decision.

**Input path (all requests):**

```
Input
  |-- InputGuard          PII detection (22+ entity types), redaction if triggered
  |-- RuleDetector        Regex and heuristic patterns, ~1ms
  |-- MLDetector          TF-IDF + logistic regression, 7 labels, ~5ms
  |   +-- ToxicityDetector    Extracts toxicity signal from ML output (no extra compute)
  |-- LLMDetector         Semantic analysis, full mode only, ~100-500ms additional
  +-- PolicyEngine        BLOCK / SANITIZE / ALLOW
```

**Output path (proxy mode only):**

```
LLM response
  +-- OutputGuard         PII detection on LLM output, redaction or BLOCK if triggered
```

Detection risk score: `rule*0.40 + ml*0.30 + llm*0.30`

Guardrails (PII, toxicity) are architecturally separate from the detection score. `ToxicityDetector` extracts its signal from the ML result but evaluates it against an independent threshold - toxicity cannot be diluted by averaging with other detector scores. Guardrails are evaluated first in the policy engine and can override any detection decision regardless of `risk_score`.


## Security Decisions

| Decision | Meaning |
|---|---|
| `ALLOW` | No threat detected. Safe to forward to LLM. |
| `BLOCK` | Threat detected. Must not forward to LLM. |
| `SANITIZE` | Sensitive content redacted. Forward `sanitized_input` to LLM, not the original. |

`risk_score = 0.0` does not mean safe. Always rely on `decision` as the authoritative verdict. Guardrails can produce `BLOCK` with `risk_score = 0.0`.

`primary_reason = SYSTEM_ERROR` means the detection pipeline failed. The returned `ALLOW` decision is not trustworthy and must not be used. Applications must treat this as a failure and must not forward input to the LLM.


## Stack

| Component | Technology |
|---|---|
| API | FastAPI, Python 3.10 |
| Database | PostgreSQL (SQLAlchemy async) |
| Cache | Redis |
| Dashboard | Next.js 16, React 19 |
| ML model | TF-IDF + logistic regression, trained on 7 threat categories |
| Observability | Prometheus, Grafana |


## Entity Model

```
tenant
  departments
    policy_override  (independent thresholds per dept)
    applications
      policy_override
      api_keys     (wsk_live_ | wsk_trial_)
```

Policy resolution: system defaults -> DB settings -> department override -> application override. Each layer deep-merges - null fields inherit from the layer above.


## API

**Scan-only:**
```
POST /v1/ai/request
```

**Proxy (OpenAI-compatible):**
```
POST /v1/chat/completions
```

Use `/v1/ai/request` for scan-only integration. Use `/v1/chat/completions` for full proxy mode - a drop-in OpenAI-compatible replacement.

Authentication: `x-api-key` header for API keys, `Authorization: Bearer` for JWT. If both are present, API key takes precedence unconditionally.

Full API reference: `docs/api.md`


## Python SDK and CLI

```bash
pip install -e sdk/python/

wrapsec config set api_key wsk_live_...
wrapsec config set base_url http://your-wrapsec-host:8000

wrapsec scan "user input"
wrapsec batch prompts.txt --summary
wrapsec audit list --decision BLOCK
wrapsec audit list --mode proxy
```

```python
import wrapsec

client = wrapsec.Client(
    api_key  = os.environ["WRAPSEC_API_KEY"],
    base_url = os.environ["WRAPSEC_BASE_URL"],
)

# Scan-only (default)
result = client.scan("user input")

if result.is_system_error:
    raise RuntimeError("Security check failed")

if result.is_blocked:
    # Do not forward to LLM
    return

input_to_forward = result.sanitized_input if result.is_sanitized else user_input

# Proxy mode - WrapSec scans and forwards to the LLM, returns the response
result = client.scan("user input", execution_mode="proxy", model="openai/gpt-4o")
if result.is_proxy:
    llm_response = result.output

# Audit
logs    = client.audit_list(decision="BLOCK", execution_mode="scan_only")
record  = client.get_request("req_01knzhh8...")
csv     = client.audit_export(decision="BLOCK", from_date="2026-05-01", limit=5000)
```

SDK documentation: `sdk/python/README.md`


## Node.js SDK

```bash
npm install wrapsec-node
```

```typescript
import WrapSec from 'wrapsec-node'

const client = new WrapSec({
  apiKey:  process.env.WRAPSEC_API_KEY,
  baseUrl: process.env.WRAPSEC_BASE_URL,
})

// Scan-only (default)
const result = await client.scan(userInput)

if (result.isBlocked) {
  // Do not forward to LLM
}

// Proxy mode
const proxyResult = await client.scan(userInput, {
  executionMode: 'proxy',
  model: 'openai/gpt-4o',
})
if (proxyResult.isProxy) {
  const llmResponse = proxyResult.output
}

// Audit
const logs   = await client.auditList({ decision: 'BLOCK', executionMode: 'scan_only' })
const record = await client.getRequest('req_01knzhh8...')
const csv    = await client.auditExport({ decision: 'BLOCK', fromDate: '2026-05-01', limit: 5000 })
```

Express and Fastify middleware included. SDK documentation: `sdk/node/README.md`


## Proxy Mode

WrapSec is an OpenAI-compatible drop-in for proxy mode:

```python
from openai import OpenAI

client = OpenAI(
    api_key  = "wsk_live_your_wrapsec_key",
    base_url = "http://your-wrapsec-host:8000/v1",
)

response = client.chat.completions.create(
    model    = "openai/gpt-4o",   # format: provider/model
    messages = [{"role": "user", "content": user_prompt}],
)
```

Proxy mode enforces both input and output security and removes the need for application-level integration. Provider API keys are stored encrypted (AES-256-GCM) and never returned in full after creation.


## Auth and Access Control

Dashboard users authenticate with email and password. JWT access tokens expire after 30 minutes. Refresh tokens are stored as SHA-256 hashes in the database - raw tokens are never persisted server-side.

| Role | Scope | Permissions |
|---|---|---|
| ADMIN | Tenant-wide | Full access - users, settings, keys, all departments |
| DEVELOPER | Department-scoped | Scan, audit, API keys, read settings |
| VIEWER | Department-scoped | Read-only audit access |

API keys are strictly for runtime machine-to-machine access. All administrative operations - user management, key creation, settings changes - require JWT-based authentication via the dashboard.

Account lockout: 5 failed login attempts triggers a 15-minute Redis-backed lockout.


## Data Storage

Three modes, set via `DATA_STORAGE_MODE` environment variable:

| Mode | Behaviour |
|---|---|
| `masked` | PII redacted before storing (default) |
| `full` | Text stored as-is |
| `none` | Text never persisted - security metadata only |

This allows deployment in regulated environments where storing raw user input is restricted. Audit logs are retained per the configured retention period (default 30 days). A background worker runs daily at 02:00 UTC.


## Observability

Prometheus scrapes `GET /metrics`. Three Grafana dashboards are included: Security Overview, Latency and Performance, Threat Intelligence.

These metrics enable real-time monitoring of threat activity, latency, and system health. Key metrics: `wrapsec_requests_total`, `wrapsec_blocked_total`, `wrapsec_request_latency_ms`, `wrapsec_system_errors_total`, `wrapsec_proxy_latency_ms`.


## Running Locally

Everything runs in Docker. Nothing is installed on the host except Docker itself.

```bash
git clone https://github.com/wrapsec/wrapsec.git
cd wrapsec
./setup.sh
```

That's it. `setup.sh` builds images, starts all services, and waits for the API to be healthy.

| Service | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| API (via Nginx) | http://localhost:80/api |
| API (direct) | http://localhost:8000 |
| Grafana | http://localhost:3001 |

```bash
./setup.sh --build   # rebuild images after code changes
./setup.sh --down    # stop all containers
```

**Tests:**

```bash
docker compose -f infrastructure/docker/docker-compose.yml exec api \
  pytest tests/unit tests/integration -v
```

**Production deployment:** see `docs/deployment.md`


## Documentation

| Document | Location |
|---|---|
| Core concepts and decision model | `docs/core_concepts.md` |
| API reference (47 endpoints) | `docs/api.md` |
| Architecture and database schema | `docs/architecture.md` |
| Risk scoring and confidence model | `docs/scoring_model.md` |
| Developer guide | `docs/developer_guide.md` |
| User guide (dashboard) | `docs/user_guide.md` |
| CLI reference | `docs/cli_reference.md` |
| Python SDK | `sdk/python/README.md` |
| Node.js SDK | `sdk/node/README.md` |


## Production Notes

- Set `WRAPSEC_BASE_URL` explicitly. The default `http://localhost:8000` must not be used in production.
- Set `DATA_STORAGE_MODE` to `masked` or `none` for regulated environments.
- Change `SECRET_KEY` and Grafana default password before first deployment.
- Set `TRUSTED_PROXY_IPS` to the IP(s) of your reverse proxy so `X-Forwarded-For` is trusted only from known sources.
- Set `METRICS_TOKEN` to require bearer token authentication on `GET /metrics` - do not expose metrics unauthenticated.
- Pin Grafana to 10.4.0 - Grafana 12 has dashboard provisioning issues.
- Prometheus target changes from `host.docker.internal:8000` to `api:8000` in Docker deployment.
- JWT department mismatch warnings (`auth_event=JWT_DEPT_MISMATCH`) must be routed to the security monitoring pipeline.

WrapSec ensures that every AI interaction in your system is inspected, controlled, and auditable by design.

## License

MIT - Copyright © 2026 WrapSec
