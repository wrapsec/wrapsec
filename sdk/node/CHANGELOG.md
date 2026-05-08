# Changelog

## 1.0.0 — 2026-05-09

Initial release.

### SDK

- `WrapSec` client class — `scan()`, `auditList()`, `auditGet()`, `auditStats()`, `auditExport()`, `settingsGet()`, `keysList()`
- Full TypeScript types: `ScanResult`, `AuditLog`, `AuditStats`, `ScanOptions`, `AuditListOptions`, `AuditExportOptions`
- `ScanResult` fields: `decision`, `riskScore`, `confidence`, `confidenceBand`, `traceId`, `threats`, `latencyMs`, `executionMode`, `sanitizationApplied`, `sanitizedInput`, `output`, convenience getters (`isBlocked`, `isSanitized`, `isAllowed`, `isProxy`)
- Retry: up to 3 attempts with exponential backoff on 5xx / transient errors
- Timeout resolution: per-call > client > `WRAPSEC_TIMEOUT` env > default (30s)
- camelCase field transformation of all API responses

### Middleware

- `wrapsec-node/middleware/express` — Express.js request scanner middleware
- `wrapsec-node/middleware/fastify` — Fastify plugin

### Exceptions

- `WrapSecError` — base class
- `WrapSecAuthError` — 401/403
- `WrapSecRateLimitError` — 429
- `WrapSecSystemError` — 5xx / timeout / connection error
- `WrapSecBlockError` — opt-in; never thrown automatically
