# Changelog

## 1.0.0 - 2026-05-09

Initial release.

### SDK

- `Client` - synchronous scan, audit, settings, and keys API
- `AsyncClient` - async mirror of `Client` using `httpx`
- `ScanResult` - typed result with `decision`, `risk_score`, `confidence`, `confidence_band`, `sanitization_applied`, `sanitized_input`, convenience properties (`is_blocked`, `is_sanitized`, `is_allowed`, `is_proxy`)
- `AuditLog` - full audit record with 28 fields including attribution, severity, proxy metadata
- `AuditStats` - aggregated statistics with severity breakdown
- Retry: up to 3 attempts with exponential backoff on 5xx / transient errors
- Timeout resolution: per-call > client > env (`WRAPSEC_TIMEOUT`) > default (30s)
- Input validation: max 8000 chars, normalisation, dense-text warning

### CLI (`wrapsec`)

- `wrapsec scan` - scan a single prompt; stdin piping supported
- `wrapsec batch` - scan a file line-by-line; `--json` outputs JSONL
- `wrapsec audit list/get/stats` - read-only audit queries
- `wrapsec config set/get/clear` - manage CLI config file
- `wrapsec settings get` - show live gateway configuration
- `wrapsec keys list` - list API keys (no secrets)
- `wrapsec ping` / `wrapsec doctor` - connectivity and config checks
- Exit codes: 0 ALLOW/SANITIZE, 1 error, 2 BLOCK

### Exceptions

- `WrapSecError` - base class
- `WrapSecAuthError` - 401/403
- `WrapSecRateLimitError` - 429
- `WrapSecSystemError` - 5xx / timeout / connection error
- `WrapSecBlockError` - opt-in; never raised automatically
