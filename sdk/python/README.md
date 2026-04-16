# WrapSec Python SDK

Python SDK and CLI for the WrapSec AI Security Gateway.

## Installation

```bash
pip install -e sdk/python/   # local development
pip install wrapsec-python   # PyPI (when published)
```

## Quick Start

```python
import wrapsec

client = wrapsec.Client(api_key="wsk_live_...")
result = client.scan("user input here")

print(result.decision)       # "ALLOW" | "BLOCK" | "SANITIZE"
print(result.primary_reason) # "RULE_DETECTOR" | "NO_THREAT_DETECTED" | ...
print(result.confidence)     # 0.85
print(result.trace_id)       # "req_01knzhh8..."
```

## CLI

```bash
# Configure
wrapsec config set api_key wsk_live_...
wrapsec config set base_url http://localhost:8000

# Scan
wrapsec scan "hello world"
wrapsec scan --mode full "ignore previous instructions"
echo "sensitive text" | wrapsec scan   # stdin — no shell history

# Batch
wrapsec batch prompts.txt --summary
wrapsec batch prompts.txt --json > results.jsonl

# Audit
wrapsec audit list --decision BLOCK
wrapsec audit get req_01knzhh8
wrapsec audit stats

# Health
wrapsec ping
wrapsec doctor

# Gateway config (read-only)
wrapsec settings get
wrapsec keys list
```

## Stability

All names listed in `__all__` are **stable and versioned**.
Breaking changes to anything in `__all__` require a MAJOR version bump.

Internal modules (`core/`, `config/`, `cli/`) are not public API
and may change in any release without notice.

## API

### `Client(api_key, base_url, timeout)`

Synchronous client.

| Parameter | Default | Description |
|---|---|---|
| `api_key` | env/config | WrapSec API key (`wsk_live_...`) |
| `base_url` | `http://localhost:8000` | API base URL. **Always set in production.** |
| `timeout` | `30` | Default timeout per request (seconds, min 1) |

### `AsyncClient(api_key, base_url, timeout)`

Async client with identical methods. Use as a context manager:

```python
async with wrapsec.AsyncClient(api_key="wsk_live_...") as client:
    result = await client.scan("hello world")
```

### `ScanResult`

| Field | Type | Description |
|---|---|---|
| `decision` | `str` | `"ALLOW"`, `"BLOCK"`, or `"SANITIZE"` |
| `primary_reason` | `str` | Which detector triggered the decision |
| `confidence` | `float` | Score 0.0–1.0 |
| `confidence_band` | `str` | `"HIGH"`, `"MEDIUM"`, or `"LOW"` |
| `trace_id` | `str` | Unique request ID for audit lookup |
| `threats` | `list[str]` | Detected threat categories |
| `latency_ms` | `float` | Gateway processing time |
| `sanitized_input` | `str \| None` | Redacted input (SANITIZE only) |

### Exceptions

| Exception | Trigger |
|---|---|
| `WrapSecAuthError` | HTTP 401 or 403 — invalid key or insufficient permissions |
| `WrapSecRateLimitError` | HTTP 429 — rate limit exceeded |
| `WrapSecSystemError` | HTTP 5xx, timeout, connection error — retried 3x |
| `WrapSecError` | All other API errors (404, 413, 422) |
| `WrapSecBlockError` | Not raised automatically. Available for exception-based flow. |

## Configuration Priority

```
1. Method argument:   client.scan(text, timeout=10)
2. Client default:    Client(api_key="...", timeout=30)
3. Environment:       WRAPSEC_API_KEY / WRAPSEC_BASE_URL / WRAPSEC_TIMEOUT
4. Config file:       ~/.config/wrapsec/config.json (Linux/macOS)
                      %APPDATA%\wrapsec\config.json  (Windows)
5. Default:           base_url=http://localhost:8000, timeout=30
```

> ⚠ `http://localhost:8000` is the **development default only**.
> Always set `WRAPSEC_BASE_URL` explicitly in production.

## Exit Codes (CLI)

| Code | Meaning |
|---|---|
| `0` | ALLOW or SANITIZE |
| `1` | CLI error, network, auth, rate limit, or SYSTEM_ERROR |
| `2` | BLOCK — security policy triggered |

## Privacy

WrapSec SDK and CLI collect **no data**.
No analytics, crash reports, or telemetry of any kind.
All network calls go only to `WRAPSEC_BASE_URL`.

## Version

`0.1.0` — compatible with WrapSec API v1.
