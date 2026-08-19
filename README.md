<p align="center">
  <img src="https://raw.githubusercontent.com/wrapsec/wrapsec/main/dashboard/public/wrapsec-logo.svg?sanitize=true" alt="WrapSec" width="70" />
  <h1 align="center">WrapSec</h1>
  <p align="center">
    <img src="https://img.shields.io/badge/license-MIT-CD00FF" alt="license" />
    <img src="https://img.shields.io/badge/python-3.10%2B-00E1FF" alt="python" />
  </p>
  <p align="center">
    <a href="https://wrapsec.com">wrapsec.com</a>
  </p>
</p>


WrapSec is a self-hosted AI security platform and enforcement layer that protects applications interacting with LLMs. It runs entirely inside your own infrastructure - including air-gapped deployments - so no prompt, response, or user data ever leaves your network for a third-party service to inspect.

It inspects every prompt and response through a multi-layer detection pipeline and enforces decisions - ALLOW, BLOCK, or SANITIZE - before anything reaches the model.


## Quickstart

Everything runs in Docker; nothing is installed on the host except Docker itself.

```bash
git clone https://github.com/wrapsec/wrapsec.git
cd wrapsec
./setup.sh
```

`setup.sh` builds the images, starts the stack, and waits for the API to be healthy. The dashboard is then at `http://localhost:3000` and the API at `http://localhost:8000`. See [Running Locally](#running-locally) for details.


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
  |-- InputGuard          PII detection (30 entity types), redaction if triggered
  |-- Normalize           Canonical form (folds homoglyph / zero-width / whitespace) + decode-views (leet, base64)
  |-- RuleDetector        Regex and heuristic patterns, ~1ms (scans canonical + views, max signal)
  |-- DetectionPipeline   Two-tier ML detection (scans canonical + views, max signal)
  |   |-- Tier 1          TF-IDF + logistic regression, always on, ~5ms
  |   |-- Tier 2          DeBERTa-v3 transformer (optional), ~20-50ms
  |   +-- ToxicityDetector    Extracts toxicity signal from ML output (no extra compute)
  |-- LLMDetector         Semantic analysis, full mode only, ~100-500ms additional (original text)
  +-- PolicyEngine        BLOCK / SANITIZE / ALLOW
```

Tier 2 is optional. Without transformer dependencies installed, Tier 1 handles all detection. Both tiers run independently - a transformer failure degrades to Tier 1 only without affecting the request.

Normalization runs after the input guard and produces a canonical form - folding cross-script homoglyphs, zero-width and bidi controls, and whitespace - plus bounded decode-views for leetspeak and base64. The rule and ML layers scan the canonical form and every view and take the strongest signal, so obfuscated attacks cannot slip past by hiding intent in an alternate encoding. It is deterministic preprocessing only: it never rewrites the prompt sent to the model (the LLM detector and proxy always use the original text) and never contributes to the risk score. Benign prompts produce no views, so normal traffic is unaffected.

> **Note on bundled models:** The Tier 1 model (`ml_detector.pkl`) shipped in this repository is trained on a curated open-source dataset for demonstration and evaluation purposes. The Tier 2 transformer uses [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) from HuggingFace. WrapSec's core focus is purpose-built ML models trained on significantly larger, more diverse, and production-representative datasets - these will be available for production deployments and are not part of this open-source release.

**Output path (proxy mode only):**

```
LLM response
  +-- OutputGuard         PII detection on LLM output, redaction or BLOCK if triggered
```

Guardrails (PII, toxicity) are architecturally separate from the detection score and are evaluated independently. A guardrail can produce `BLOCK` regardless of the detection score from other layers.


## Security Decisions

| Decision | Meaning |
|---|---|
| `ALLOW` | No threat detected. Safe to forward to LLM. |
| `BLOCK` | Threat detected. Must not forward to LLM. |
| `SANITIZE` | Sensitive content redacted. Forward `sanitized_input` to LLM, not the original. |

`risk_score = 0.0` does not mean safe. Always rely on `decision` as the authoritative verdict. Guardrails can produce `BLOCK` with `risk_score = 0.0`.

`primary_reason = SYSTEM_ERROR` means the detection pipeline failed. The returned `ALLOW` decision is not trustworthy and must not be used. Applications must treat this as a failure and must not forward input to the LLM.


## Detection Evaluation

A red-team evaluation suite scores the pipeline against a labeled adversarial corpus - prompt injection, jailbreak, encoding and obfuscation evasion, indirect injection, and data exfiltration - alongside benign and over-defense sets and a held-out out-of-distribution set. `make eval` reports catch-rate, false-positive rate (including over-defense), a per-category breakdown, and out-of-distribution generalisation, and enforces regression floors and ceilings, so a change that weakens detection or worsens over-defense fails the gate. The run is fully offline - no LLM provider, database, or Redis - and doubles as a reproducible measure of detection efficacy.

Measured 2026-08-17 on the WrapSec-authored corpus of 141 cases (86 malicious, 55 benign), with the full detector stack (rules + ML + the optional Tier-2 transformer):

| Metric | Result |
|---|---|
| Catch-rate (attacks flagged) | 96.5% (83/86) |
| False-positive rate (benign flagged) | 9.1% (5/55) |
| Over-defense on the benign-hard set | 20% (5/25) |
| Out-of-distribution catch (held-out novel attacks) | 95.0% (19/20) |

These figures are for the full stack; the base install runs Tier-1 (TF-IDF) only and scores differently. The corpus is modest and self-authored, so treat these as a reproducible internal baseline (`make eval`), not an industry benchmark. Re-run to see current numbers - they move with the code.


## Agent and MCP Integration

WrapSec is built for agentic use, not just single prompts:

- **Content provenance.** Tag each scan with `input_source` (`user_prompt`, `tool_output`, `retrieved_document`, `external_content`) so untrusted content an agent pulled in - the indirect prompt-injection surface - is labeled and audited. Scored the same whatever origin it claims; it can, opt-in, tighten **policy** thresholds for untrusted sources (source-aware posture, off by default).
- **RAG batch scanning.** `POST /v1/ai/scan-batch` scans a page of retrieved chunks in one call, each with its own `input_source`, returning per-item decisions plus a summary. SDK helpers `scan_documents()` / `scan_tool_outputs()` / `scan_external()` and `filter_safe()` (drop the poisoned chunks in one call) wrap it.
- **Security by Source.** The `/sources` dashboard and `GET /v1/audit/by-source` break the threat picture down by provenance - volume, decision mix, threats per source - plus a Top Attack Origins leaderboard showing which knowledge sources deliver attacks.
- **Security assessment.** Every scan returns a structured `assessment` (decision, risk, reasons, threats, and per-layer detector contributions) an agent can reason about, not just BLOCK/ALLOW.
- **Agent-run timeline.** `GET /v1/agent-runs/{run_id}` returns a run's scans as an ordered timeline; the dashboard renders it, showing where risk entered a multi-turn run.
- **Function-calling tool.** The Python SDK exposes `wrapsec_scan` as a function-calling tool - `openai_tool()` / `anthropic_tool()` / `scan_tool_schema()` - for any agent framework.
- **MCP server (opt-in).** `python -m mcp_server` (see `requirements-mcp.txt`) exposes `wrapsec_scan` over the Model Context Protocol so any MCP-compatible agent can call it natively.


## Stack

| Component | Technology |
|---|---|
| API | FastAPI, Python 3.10 |
| Database | PostgreSQL (SQLAlchemy async) |
| Cache | Redis |
| Dashboard | Next.js 16, React 19 |
| ML detection | Two-tier: TF-IDF + logistic regression (Tier 1, always on) + DeBERTa-v3 transformer (Tier 2, optional) |
| Observability | Prometheus, Grafana |


## Entity Model

Identity is global and roles are held per tenant through memberships, so one person can belong to more than one tenant.

```
users              global identity (unique email; owns credentials and refresh tokens)
  memberships      (user, tenant) -> role, with an optional department

tenant             lifecycle status (active / suspended), plan, data retention
  departments
    policy_override  (independent thresholds per dept)
    applications
      policy_override
      api_keys       (wsk_live_ | wsk_trial_)
```

A membership grants a role in one tenant, and the access token is minted from it. A suspended tenant is rejected at authentication.

Policy resolution: system defaults -> platform settings -> tenant settings -> department override -> application override. Each layer deep-merges - null fields inherit from the layer above.


## API

**Scan-only:**
```
POST /v1/ai/request
```

**Proxy (OpenAI-compatible):**
```
POST /v1/chat/completions
```

Use `/v1/ai/request` for scan-only integration. Use `/v1/chat/completions` for proxy mode - OpenAI-compatible for single-turn, non-streaming chat completions. It accepts `model`, `messages`, `temperature`, `max_tokens`, and `top_p`; streaming (`stream: true`), tool/function calling, `response_format`, and the other OpenAI parameters are not supported and are rejected, and the response does not include a `usage` block.

A batch variant, `POST /v1/ai/scan-batch`, scans many items in one call. `GET /v1/capabilities` reports the capability set effective for the tenant.

Authentication: scan endpoints take the API key in the `x-api-key` header, or a JWT in `Authorization: Bearer` for dashboard sessions. The proxy endpoint also accepts the API key as `Authorization: Bearer wsk_live_...`, which is what an OpenAI client sends. When both an API key and a JWT are present, the API key takes precedence unconditionally.

Full API reference: `docs/api.md`


## Python SDK and CLI

Both SDKs are distributed in this repository and are not published to PyPI or npm; install them from source.

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
npm install ./sdk/node
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

In proxy mode WrapSec speaks the OpenAI chat-completions API for single-turn, non-streaming requests, so an OpenAI client points at it by changing the base URL:

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

Proxy mode enforces both input and output security and removes the need for application-level integration. Streaming and tool calling are not supported on this path (see [API](#api) for the accepted parameters). Provider API keys are stored encrypted (AES-256-GCM) and never returned in full after creation.


## Auth and Access Control

Dashboard users authenticate with email and password. Passwords are hashed with Argon2id. JWT access tokens expire after 30 minutes and carry the tenant and role from the user's membership. Refresh tokens are stored as SHA-256 hashes in the database - raw tokens are never persisted server-side.

A role is held on a membership, not the user, so a role is always scoped to a tenant.

| Role | Scope | Permissions |
|---|---|---|
| ADMIN | Tenant-wide | Full access - users, settings, keys, all departments |
| DEVELOPER | Department-scoped | Scan, audit, API keys, read settings |
| AUDITOR | Tenant-wide or department-scoped | Read-only for audit and compliance; also reads settings and the API-key inventory |
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

This allows deployment in regulated environments where storing raw user input is restricted. Audit logs are retained per the tenant's configured retention period (default 30 days). A background worker runs daily at 02:00 UTC.


## Audit Trail

Every scan, proxy call, and administrative action is recorded to a tenant-scoped audit log. Rows are tamper-evident: each carries a SHA-256 hash computed over its payload and chained to the previous row's hash, and a database trigger rejects `UPDATE` and `DELETE` on the table. Tampering therefore breaks the chain and leaves a visible gap. Chain verification is a single pass and can run offline against a database dump.


## Webhooks and SIEM

`BLOCK` and `SANITIZE` decisions fan out to a tenant's configured destinations on a background worker, so the scan path never waits on delivery (`ALLOW` is not emitted). Generic destinations are signed with HMAC-SHA256 using a per-endpoint secret, with a grace window on rotation; native connectors format the event for Splunk HEC, Datadog Logs, Microsoft Sentinel (Azure Monitor Logs Ingestion), and Elastic (ECS). Delivery is backed by a Redis Streams queue with a fixed retry schedule and a dead-letter path, and a circuit breaker disables an endpoint that fails continuously. Destinations are SSRF-validated at connect time and require https. Configure them from the dashboard Integrations page or the `/v1/admin/webhooks` API.


## Email Notifications

Optional transactional email over SMTP sends informational, link-free security notifications - password changed, administrator reset, account locked, and account or role changes - to the affected account. Each message is enqueued in a database outbox inside the transaction that triggers it, so the record commits atomically with the change, and a background worker sends it with bounded retry and honest delivery status. An install with no SMTP configured runs normally and simply does not send. A metadata-only delivery-status view in the dashboard shows per-message state for troubleshooting.


## Localization

The dashboard renders entirely from a localization catalog and ships English and German with an in-app language switcher; a signed-in user's choice is saved to their profile and applied immediately. Every API error also carries a stable, machine-readable `code` alongside its English `message`, so clients and SIEM rules branch on the code rather than the wording.


## Observability

Prometheus scrapes `GET /metrics`. Three Grafana dashboards are included: Security Overview, Latency & Performance, Threat Intelligence.

These metrics enable real-time monitoring of threat activity, latency, and system health. Key metrics: `wrapsec_requests_total`, `wrapsec_blocked_total`, `wrapsec_request_latency_ms`, `wrapsec_system_errors_total`, `wrapsec_proxy_latency_ms`.

An optional OpenTelemetry Collector profile (`docker compose --profile otlp up -d`) bridges the same `/metrics` to any OTLP-compatible backend without re-instrumenting the application; metric names and labels are preserved as-scraped.


## Running Locally

The [Quickstart](#quickstart) above (`./setup.sh`) builds the images and starts all services. It exposes:

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

**Transformer (Tier 2) - optional:**

The base install runs TF-IDF detection only. To enable the DeBERTa-v3 transformer (~1.5GB additional image size):

```bash
# Local dev
pip install -r requirements-transformer.txt --extra-index-url https://download.pytorch.org/whl/cpu

# Docker
docker build --build-arg BUILD_ENV=transformer -f infrastructure/docker/Dockerfile .
```

Without transformer dependencies, `transformer_detector` reports `degraded` in `/health/ready` and `wrapsec doctor`. All requests are still processed via Tier 1 (TF-IDF).

> The HuggingFace transformer and the bundled TF-IDF model are suitable for evaluation. Production-grade WrapSec deployments use purpose-built models - see the note above.

**Tests:**

```bash
docker compose -f infrastructure/docker/docker-compose.yml exec api \
  pytest tests/unit tests/integration -v
```

**Production deployment:** see `docs/developer_guide.md`


## Extensibility

WrapSec is open-core. The detection pipeline, guardrails, proxy, audit trail, dashboard, and SDKs in this repository are complete and run on their own - nothing here is a crippled teaser. Optional plugins extend it through a documented, stable contract instead of a fork: a plugin can register a SIEM connector or an authentication backend, apply an additional policy ceiling, and carry its own tenant entitlements and database migrations. The base build loads no plugins. See `docs/PLUGIN_CONTRACT.md` for the contract, and `CONTRIBUTING.md` if you want to contribute upstream.


## Documentation

| Document | Location |
|---|---|
| API reference | `docs/api.md` |
| Developer guide | `docs/developer_guide.md` |
| User guide (dashboard) | `docs/user_guide.md` |
| CLI reference | `docs/cli_reference.md` |
| Plugin contract | `docs/PLUGIN_CONTRACT.md` |
| Contributing | `CONTRIBUTING.md` |
| Security policy | `SECURITY.md` |
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


## License

MIT - Copyright (c) 2026 WrapSec
