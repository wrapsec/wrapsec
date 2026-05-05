# Changelog

All notable changes to WrapSec are documented here.

## [1.0.0] — 2026-05-05

### Added
- AI Security Gateway — REST API for inspecting and proxying LLM requests
- Rule-based, ML, and LLM-backed threat detection pipeline
- Threat categories: PROMPT_INJECTION, JAILBREAK, MALICIOUS_INTENT, DATA_EXFILTRATION, PII, TOXICITY
- Output guard for PII scanning and redaction on LLM responses
- Multi-tenant architecture with per-tenant API key management
- Department-level policy configuration (block/sanitize/allow thresholds)
- Full audit log with per-request trace IDs
- Idempotency-Key support for safe client retries
- Rate limiting, IP allowlist/blocklist, abuse detection middleware
- Session hardening: token rotation, concurrent session limits, auth event logging
- Admin REST API for tenant, user, department, and key management
- Next.js dashboard with request overview, threat analytics, and audit explorer
- Python SDK (`wrapsec-sdk`) with typed client and CLI (`wrapsec doctor`, `wrapsec scan`)
- Node.js SDK (`@wrapsec/sdk`) with identical API surface
- Prometheus metrics endpoint with per-key and per-tenant counters
- Health endpoints: `/health/live`, `/health/ready`, `/health/config`
- OpenAPI documentation at `/docs`
