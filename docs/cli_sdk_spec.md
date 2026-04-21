# WrapSec - CLI & SDK Design Specification (Internal)

> See [Core Concepts](core_concepts.md) for canonical behavior definitions.
 
This document is intended for contributors and maintainers.It defines architecture, constraints, and implementation contracts.

Last updated: April 2026

---

## Overview

This document defines the naming, architecture, security posture, file structure, module boundaries, versioning, command set, and build order for the WrapSec CLI and SDK ecosystem.

**Key decisions:**
- CLI and Python SDK are built together from day one - CLI lives inside the SDK package
- No standalone single-file CLI phase - matches industry standard (AWS CLI, Anthropic SDK)
- Retry logic lives exclusively in `core/retry.py` - CLI never retries
- BLOCK is not an exception - it is a valid response returned as `ScanResult`
- ERROR > BLOCK > SUCCESS in batch exit code priority
- Field names follow each language's convention - Python snake_case, Node camelCase - this is intentional
- `http://localhost:8000` is the development default only - always set explicitly in production

---

## 1. Naming Decisions

### 1.1 CLI Tool Name

**Decision: `wrapsec`**

```bash
wrapsec scan "ignore all previous instructions"
wrapsec doctor
wrapsec audit stats
```

**Rejected alternatives:**

| Name | Reason rejected |
|---|---|
| `wrapsec-cli` | Redundant suffix, non-standard |
| `wrapsec_cli` | Underscore non-standard for CLI tools |
| `wsec` | Too cryptic |
| `wsc` | Meaningless abbreviation |

---

### 1.2 SDK Names

| Platform | Package name | Install command | Import |
|---|---|---|---|
| Python | `wrapsec-python` | `pip install wrapsec-python` | `import wrapsec` |
| Node.js | `wrapsec-node` | `npm install wrapsec-node` | `import WrapSec from 'wrapsec-node'` |
| Go | `wrapsec-go` | `go get github.com/kbajish/wrapsec-go` | `import "github.com/kbajish/wrapsec-go"` |

---

### 1.3 Repository Locations

**V1 - inside main repo:**
```
github.com/kbajish/wrapsec/
  sdk/python/     ← Python SDK + CLI
  sdk/node/       ← Node.js SDK
  examples/       ← integration examples
```

**Later - separate repos when publishing to PyPI/npm:**
```
github.com/kbajish/wrapsec-python    ← Python SDK + CLI
github.com/kbajish/wrapsec-node      ← Node.js SDK
github.com/kbajish/wrapsec-docs      ← documentation (future)
```

---

## 2. File Structure

### 2.1 Python SDK + CLI

```
sdk/python/
├── pyproject.toml              ← package config, version = "0.1.0", entry points
├── README.md
└── wrapsec/
    ├── __init__.py             ← public API surface (__all__, __version__)
    ├── cli.py                  ← thin re-export: from wrapsec.cli.main import cli
    ├── client.py               ← sync HTTP client
    ├── async_client.py         ← async HTTP client
    ├── models.py               ← ScanResult, AuditLog, AuditStats
    ├── exceptions.py           ← WrapSecError hierarchy
    ├── config/
    │   ├── __init__.py
    │   ├── loader.py           ← XDG/APPDATA path, env, file, priority chain
    │   └── schema.py           ← allowed keys, defaults, validation
    ├── core/
    │   ├── __init__.py
    │   ├── http.py             ← base request, headers, timeout, auth header
    │   ├── retry.py            ← exponential backoff, which errors retry
    │   └── validation.py       ← input limits, token estimate, charset
    └── cli/
        ├── __init__.py
        ├── main.py             ← click group, all subcommands registered
        └── commands/
            ├── __init__.py
            ├── scan.py         ← wrapsec scan
            ├── batch.py        ← wrapsec batch
            ├── audit.py        ← wrapsec audit list/get/stats
            ├── settings.py     ← wrapsec settings get (read-only gateway config)
            ├── keys.py         ← wrapsec keys list (read-only)
            ├── config.py       ← wrapsec config set/get/clear (CLI config)
            └── doctor.py       ← wrapsec ping + wrapsec doctor
```

**Entry point in `pyproject.toml`:**
```toml
[project.scripts]
wrapsec = "wrapsec.cli:cli"
```

**`wrapsec/cli.py` (thin re-export):**
```python
from wrapsec.cli.main import cli
__all__ = ["cli"]
```

This means `pyproject.toml` always points to a stable top-level path. Internal restructuring of `cli/` never requires changing `pyproject.toml`.

---

### 2.2 Node.js SDK

```
sdk/node/
├── package.json
├── tsconfig.json
├── README.md
└── src/
    ├── index.ts            ← public exports
    ├── client.ts           ← WrapSec class
    ├── types.ts            ← TypeScript interfaces
    ├── exceptions.ts       ← WrapSecError hierarchy
    └── middleware/
        ├── express.ts      ← Express middleware (64KB payload limit enforced)
        └── fastify.ts      ← Fastify plugin
```

---

### 2.3 Examples

```
examples/
├── fastapi/
│   ├── main.py             ← FastAPI app using Python SDK
│   └── README.md
├── express/
│   ├── index.js            ← Express app using Node SDK + middleware
│   └── README.md
└── llm_app/
    ├── main.py             ← End-to-end LLM proxy example
    └── README.md
```

---

## 3. Module Boundaries

These are architectural constraints, not guidelines. Violations are bugs.

```
client.py / async_client.py
  → ONLY API interaction: HTTP calls, response parsing, returning models
  → No CLI logic, no config file reading, no spinner, no print statements

core/http.py
  → Base request function, header construction, timeout resolution
  → Shared by sync and async clients

core/retry.py
  → ALL retry logic lives here - nowhere else
  → CLI commands never implement retry
  → CLI handles only the final exception after retries are exhausted
  → Section 15 (HTTP error table) reflects this behaviour

core/validation.py
  → Input length, token estimate, charset checks
  → Called by client before sending - never duplicated in CLI

config/loader.py
  → ALL configuration resolution: env → file → defaults
  → Both CLI and SDK client use this - never duplicated
  → Returns a typed config object, not raw strings

config/schema.py
  → Allowed config keys, type validation, default values

cli/commands/
  → Presentation layer ONLY
  → Calls SDK client methods - never implements HTTP directly
  → Calls config/loader - never reads config files directly
  → Calls core/validation - never duplicates validation logic

SDK isolation rule (absolute):
  sdk/python/ has ZERO imports from api/, dashboard/, or db/
  SDK behaves as an external consumer of the WrapSec API
```

**WRONG - never do this in a CLI command:**
```python
response = requests.post(url, headers=..., json={"input": text})
```

**CORRECT - CLI command calls SDK:**
```python
result = client.scan(text, mode=mode, user=user)
```

---

## 4. Public API Surface

`wrapsec/__init__.py` defines the stable public contract.

```python
from .client       import Client
from .async_client import AsyncClient
from .models       import ScanResult, AuditLog, AuditStats
from .exceptions   import (
    WrapSecError,
    WrapSecAuthError,
    WrapSecBlockError,
    WrapSecRateLimitError,
    WrapSecSystemError,
)

__version__ = "0.1.0"

__all__ = [
    "Client", "AsyncClient",
    "ScanResult", "AuditLog", "AuditStats",
    "WrapSecError", "WrapSecAuthError", "WrapSecBlockError",
    "WrapSecRateLimitError", "WrapSecSystemError",
]
```

**Stability rule:**
```
Anything in __all__      → stable and versioned
                           breaking changes require a MAJOR version bump
Anything outside __all__ → internal, may change in any release without notice
                           includes: core/, config/, cli/ internals
```

This rule is also prominently stated in `README.md`.

**Developer experience:**
```python
import wrapsec

client = wrapsec.Client(api_key="wsk_live_...")
result = client.scan("user input here")
print(result.decision)        # "ALLOW" | "BLOCK" | "SANITIZE"
print(result.primary_reason)  # "RULE_DETECTOR" | "NO_THREAT_DETECTED" | ...
print(result.confidence)      # 0.85
print(result.trace_id)        # "req_01knzhh8..."
```

**SYSTEM_ERROR handling contract for SDK consumers:**
```
SYSTEM_ERROR occurs when the detection pipeline fails (e.g., detector failure, timeout, or internal exception).
result.primary_reason == "SYSTEM_ERROR" indicates this condition.
result.decision will be "ALLOW" at the engine level — detection did not confirm a threat.

SDK consumers MUST NOT treat SYSTEM_ERROR as a clean result.
Do not forward input to an LLM when primary_reason == "SYSTEM_ERROR".
Treat it as a failure condition and apply your fail-open or fail-closed policy.

WrapSecSystemError (the exception) is raised for infrastructure failures:
  HTTP 5xx, timeout, connection error — after retries are exhausted.
This is distinct from primary_reason="SYSTEM_ERROR" (a valid scan result
where detection itself failed internally). Both require the same client
response: do not forward input.
```

**`sanitized_input` vs `sanitization_applied`:**
```
result.sanitization_applied  → boolean, True when decision = SANITIZE
result.sanitized_input       → string, present only when decision = SANITIZE

Always check result.decision as the primary signal.
`sanitized_input` is present only when `decision = SANITIZE`.
Use `sanitized_input` instead of the original input when forwarding to an LLM.
```

**`risk_score` interpretation:**
```
result.risk_score reflects detection only (rule + ML + LLM weighted).
PII guardrail decisions (BLOCK/SANITIZE) always produce risk_score = 0.0
because detection is not involved in the guardrail path.

`risk_score = 0.0` does NOT mean the input is safe.
Always use `result.decision` as the authoritative verdict.
Never use `risk_score` alone to decide whether to forward input to an LLM.
```

---

## 5. Field Naming Convention

**Field names follow each language's convention. This is intentional.**

```
API response field: primary_reason (snake_case - always)

Python SDK:  result.primary_reason   ← snake_case (Python convention)
Node SDK:    result.primaryReason    ← camelCase  (JavaScript convention)
```

The Node SDK transforms all API response field names from `snake_case` to `camelCase` as part of the SDK layer. This matches the pattern used by Stripe, Anthropic, and other SDK-first companies.

**Full mapping (API → Python → Node):**

| API field | Python SDK | Node SDK |
|---|---|---|
| `decision` | `result.decision` | `result.decision` |
| `primary_reason` | `result.primary_reason` | `result.primaryReason` |
| `confidence` | `result.confidence` | `result.confidence` |
| `confidence_band` | `result.confidence_band` | `result.confidenceBand` |
| `trace_id` | `result.trace_id` | `result.traceId` |
| `sanitized_input` | `result.sanitized_input` | `result.sanitizedInput` |
| `sanitization_applied` | `result.sanitization_applied` | `result.sanitizationApplied` |
| `threats` | `result.threats` | `result.threats` |
| `latency_ms` | `result.latency_ms` | `result.latencyMs` |

This table must be kept current as new fields are added.

---

## 6. Versioning Strategy

### 6.1 Core Principle

**API version is the source of truth.** SDK and CLI compatibility follows API versioning.

### 6.2 API Versioning

```
URL-based: /v1/ai/request, /v1/audit/logs

Rules:
  Add new response fields    → allowed (backward compatible)
  Remove or change fields    → requires /v2
  Change endpoint behaviour  → requires /v2
  Never break /v1 once published
```

### 6.3 SDK Semantic Versioning

```
MAJOR.MINOR.PATCH

0.1.0  → initial release (API v1 compatible)
0.2.0  → new features, backward compatible
0.x.x  → stable, API v1 compatible
1.0.0  → when API v2 ships OR SDK is battle-tested in production
```

| SDK version | API version | Status |
|---|---|---|
| 0.x | v1 | Compatible - primary |
| 1.x | v1 | Compatible - backward |
| 1.x | v2 | Compatible - primary |
| 0.x | v2 | Not compatible |

### 6.4 CLI Version = SDK Version

```
CLI is a thin wrapper around the SDK.
They ship together - always the same version.

wrapsec --version → 0.1.0
SDK __version__   → "0.1.0"
```

### 6.5 BASE_PATH and DEFAULT_BASE_URL - Single Constants

```python
# In client.py - the ONLY place these are defined
BASE_PATH        = "/v1"
DEFAULT_BASE_URL = "http://localhost:8000"
```

**⚠ Production warning:**
```
http://localhost:8000 is the development default only.
In staging and production environments, always set base_url explicitly:

  export WRAPSEC_BASE_URL=https://wrapsec.internal:8000

Or in code:
  client = wrapsec.Client(api_key="...", base_url="https://wrapsec.internal:8000")

Never rely on the localhost default in production deployments.
Failing to set this will silently hit a non-existent local gateway.
```

### 6.6 Version Compatibility in Doctor

```
wrapsec doctor output:

  CLI version:      0.1.0
  Expected API:     v1
  API reachable:    ✅ yes
  Compatibility:    ✅ compatible

Behaviour:
  Version mismatch → warning only, never blocks execution
  "API v2 detected, CLI expects v1. Some features may not work."
```

### 6.7 What NOT to Do in V1

```
Do NOT create v1/ v2/ folders inside SDK
Do NOT support multiple API versions simultaneously
Keep it: BASE_PATH = "/v1" - one constant, one place
```

---

## 7. Timeout Resolution

Timeout follows a strict priority chain using `is not None` checks - never falsy checks.

**Correct implementation:**
```python
def scan(self, text: str, timeout: int | None = None, ...) -> ScanResult:
    t = (
        timeout                   if timeout                   is not None
        else self._timeout        if self._timeout             is not None
        else self._config.timeout if self._config.timeout      is not None
        else 30
    )
```

**Why `is not None` and not `or`:**
```
# WRONG - timeout=0 is falsy, silently falls through to 30
t = timeout or self._timeout or self._config.timeout or 30

# CORRECT - timeout=0 is explicitly handled
t = timeout if timeout is not None else ...
```

**Validation:**
```python
if timeout is not None and timeout < 1:
    raise ValueError(f"timeout must be at least 1 second, got {timeout}")
```

`timeout=0` means "no timeout" in the `requests` library, which would cause indefinite hangs. Minimum enforced value is 1 second.

**Priority chain (highest to lowest):**
```
1. Method argument:    client.scan(text, timeout=10)
2. Client default:     Client(api_key="...", timeout=30)
3. Config loader:      WRAPSEC_TIMEOUT env var or config file value
4. Fallback default:   30 seconds
```

**Fixed timeouts - not user configurable:**
```
doctor health checks: 5s per check
ping:                 5s
```

---

## 8. SDK Error Mapping

All HTTP responses map to typed exceptions. This mapping is identical in Python and Node SDKs.

| HTTP Status | Exception | Retry | Notes |
|---|---|---|---|
| 401 | `WrapSecAuthError` | Never | Invalid or revoked API key |
| 403 | `WrapSecAuthError` | Never | Insufficient permissions |
| 404 | `WrapSecError` | Never | Endpoint not found |
| 413 | `WrapSecError` | Never | Payload exceeds 64KB |
| 422 | `WrapSecError` | Never | Validation failed - server message included |
| 429 | `WrapSecRateLimitError` | Never | Rate limit hit |
| 5xx | `WrapSecSystemError` | Up to 3x | Transient server error |
| Timeout | `WrapSecSystemError` | Up to 3x | Request timed out |
| ConnectionError | `WrapSecSystemError` | Up to 3x | Network unreachable |
| Invalid JSON | `WrapSecSystemError` | Never | Unparseable API response |

**`WrapSecBlockError` - NOT raised automatically:**
```
BLOCK is a valid API response, not an error condition.
client.scan() always returns ScanResult - callers check result.decision.

WrapSecBlockError is available in __all__ for callers who prefer
exception-based flow:

  result = client.scan(text)
  if result.decision == "BLOCK":
      raise wrapsec.WrapSecBlockError(result)

The SDK never raises WrapSecBlockError automatically.
This matches Stripe's pattern: charge.status is checked, not caught.
```

**`WrapSecSystemError` — two distinct sources:**
```
WrapSecSystemError (exception) is raised for infrastructure failures:
  HTTP 5xx, timeout, connection error — after retries are exhausted.

primary_reason = "SYSTEM_ERROR" (scan result field) means the API was reached
  successfully but all detectors failed internally. The response is valid JSON
  with decision = "ALLOW" — no exception is raised.

Both require the same client action: do not forward input to an LLM.
They are distinct failure modes with the same required handling.
```

---

## 9. Retry Logic

**All retry logic lives exclusively in `core/retry.py`. CLI commands never retry.**

```
Retried (up to 3 attempts with exponential backoff):
  HTTP 5xx
  Timeout
  ConnectionError

Never retried:
  HTTP 401, 403, 404, 413, 422  → permanent client errors
  HTTP 429                       → retrying worsens rate limit situation
  BLOCK decision                 → not an error, never retried

Backoff schedule:
  Attempt 1: immediate
  Attempt 2: wait 1s
  Attempt 3: wait 2s
  After 3 failures: raise WrapSecSystemError

CLI exit 1 on infrastructure errors means retries have already been exhausted.
The CLI never retries — it receives the final exception from core/retry.py.

Note: Section 15 (HTTP error table) reflects this behaviour.
      If retry logic in this section changes, Section 15 must be updated.
```

---

## 10. Security Posture

### 10.1 What the CLI Is - and Is Not

```
The CLI is a testing and integration verification tool.
It is NOT an administration tool.
It is NOT a policy management tool.
It is NOT a replacement for the dashboard.
```

---

### 10.2 Commands Excluded for Security Reasons

| Command | Risk | Alternative |
|---|---|---|
| `settings set-threshold` | Policy change with no audit trail | Dashboard → Settings |
| `settings enable/disable layer` | Silently weakens security posture | Dashboard → Settings |
| `keys create` | Bypasses dashboard audit | Dashboard → API Keys |
| `keys revoke` | Accidental revocation breaks production | Dashboard → API Keys |
| `departments set-policy` | No audit trail | Dashboard → Departments |
| `scan --show-scores` | Exposes internal scoring - attackers calibrate | Never implement |

---

### 10.3 Information Leakage Risks

**1. API key** - always mask (`sk_li****ef4a`), never print raw

**2. Shell history**
```bash
# DANGEROUS - stored in ~/.bash_history forever
wrapsec scan "my SSN is 123-45-6789"

# SAFE - stdin never stored in history
echo "my SSN is 123-45-6789" | wrapsec scan
```

**3. Sanitized input** - never show by default. Default: `"Input contained PII and was sanitized"`

**4. Confidence scores** - round to 1 decimal in human output. Full precision in `--json` only.

**5. OS username** - never use as `user_id`. Default `"cli"`. Opt-in via `--user` only.

**6. Base URL** - show only in `doctor`. Never in scan error messages.

**7. Rate limit numbers** - never reveal in error messages.

**8. JSON in CI** - document risk. Recommend `--quiet` for CI.

---

### 10.4 Security Rules for Implementation

```
1.  Never print raw API key - always mask
2.  Batch: file path only - no inline text argument
3.  No write operations on settings, policy, thresholds, or keys
4.  sanitized_input hidden by default
5.  --show-scores never implemented
6.  OS username never used as user_id default
7.  All errors → stderr. Normal output → stdout
8.  Confidence scores rounded to 1 decimal in human output
9.  Rate limit errors reveal no numbers - never retry on 429
10. Warn about shell history risk in scan --help
11. --quiet: stdout silent, stderr shows errors only
12. --json: pure JSON to stdout, no spinner, no extra text
13. Config file always chmod 600 (Unix) - try/except on Windows
14. SDK has zero imports from api/, dashboard/, or db/
```

---

## 11. Exit Codes

### 11.1 Exit Code Table

| Code | Meaning | Trigger |
|---|---|---|
| `0` | Success | ALLOW or SANITIZE decision |
| `1` | Error - CLI or infrastructure failure | Config error, validation, network, auth, 429, SYSTEM_ERROR |
| `2` | Blocked - security policy triggered | BLOCK decision (except SYSTEM_ERROR) |

### 11.2 SYSTEM_ERROR Rules

```
ALLOW  + NO_THREAT_DETECTED → exit 0
ALLOW  + SYSTEM_ERROR       → exit 1  (detectors failed - result unreliable)
BLOCK  + RULE_DETECTOR      → exit 2
BLOCK  + SYSTEM_ERROR       → exit 1  (infrastructure failure, not security)
SANITIZE + any              → exit 0
```

### 11.3 Batch Exit Code Priority

```
Priority: ERROR (1) > BLOCK (2) > SUCCESS (0)

Rationale:
  An error means some prompts were NOT scanned.
  Reporting exit 2 would give false confidence.
  Exit 1 signals: results are incomplete.

Implementation:
  had_error = False
  had_block = False

  for each prompt:
    on exception or SYSTEM_ERROR → had_error = True
    on BLOCK decision             → had_block = True

  at end:
    if had_error:   exit 1
    elif had_block: exit 2
    else:           exit 0
```

---

## 12. Output Modes

### 12.1 Output Mode Matrix

| Mode | stdout | stderr | Spinner | Exit codes |
|---|---|---|---|---|
| Default (TTY) | Human-readable | Errors only | Yes | Standard |
| Default (non-TTY) | Human-readable | Errors only | No | Standard |
| `--quiet` | Silent | Errors only | No | Standard |
| `--json` | Pure JSON | Errors only | No | Standard |

### 12.2 Spinner Rules and Safety

```python
show_spinner = (
    sys.stdout.isatty()
    and not json_output
    and not quiet
)

def get_spinner_frames():
    if sys.platform == "win32":
        if not (os.environ.get("WT_SESSION") or os.environ.get("TERM")):
            return ["|", "/", "-", "\\"]   # cmd.exe ASCII fallback
    return ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
```

**Safety requirements:**
```
1. Exception during scan:
   try/finally MUST call spinner.stop()
   Spinner must stop before any exception propagates

2. Ctrl+C (SIGINT):
   signal.signal(signal.SIGINT, lambda s, f: (spinner.stop(), sys.exit(1)))

3. Terminal cleanup:
   spinner.stop() writes \r\033[K (cursor return + clear line)
   NOT just \r - partial chars corrupt some terminals
```

### 12.3 Quiet Mode Contract

```
--quiet:
  stdout:  completely silent
  stderr:  errors still printed
  spinner: disabled
  exit:    standard exit codes - this is the only interface
```

### 12.4 JSON Mode Contract

```
--json:
  stdout:  pure JSON - parseable by jq
           zero additional text before or after
  stderr:  error messages (non-JSON)
  spinner: disabled

wrapsec scan --json "text" | jq .decision   ← must work
wrapsec scan --json "text" > result.json    ← must be valid JSON
```

### 12.5 SYSTEM_ERROR Output

```
Human:  Decision: ALLOW / Reason: SYSTEM_ERROR / Confidence: 0.0
        ⚠ Infrastructure error - result unreliable. Trace: req_...
        Exit: 1

Quiet:  stderr: "SYSTEM_ERROR: req_..."  /  Exit: 1

JSON:   { full response JSON }  /  Exit: 1
```

---

## 13. V1 Command Set

### 13.1 Command Summary

```
wrapsec
├── scan          Scan a single prompt
├── batch         Scan prompts from a file (JSONL output with --json)
├── audit
│   ├── list      List audit records (read-only)
│   ├── get       Get record by trace_id (read-only)
│   └── stats     Aggregated stats (read-only)
├── settings get  Show active gateway config (read-only)
├── keys list     List API key IDs and names (read-only)
├── ping          Network connectivity check (no auth)
├── doctor        Full health, auth, and version check
└── config
    ├── set       Set api_key, base_url, or timeout
    ├── get       Show current config (API key masked)
    └── clear     Remove all config (--force skips confirmation)
```

**Command naming rationale:**

| File | Command | Scope |
|---|---|---|
| `settings.py` | `wrapsec settings get` | Read-only: gateway thresholds, layers, LLM config |
| `config.py` | `wrapsec config set/get/clear` | CLI config: api_key, base_url, timeout |
| `keys.py` | `wrapsec keys list` | Read-only: API key IDs and names |

`settings` and `config` serve different purposes. `settings` reads the live gateway configuration. `config` manages the CLI's own configuration file.

---

### 13.2 Command Reference

#### `wrapsec scan`

```
wrapsec scan [TEXT] [OPTIONS]

Options:
  --mode     fast|full    Detection mode (default: fast)
  --timeout  INT          Timeout in seconds, min 1 (default: 30)
  --json                  Pure JSON output
  --user     TEXT         Attribution user ID (default: "cli")
  --quiet                 Exit code only

Token limit note:
  Server enforces ceil(len/2) > 4000 heuristic.
  CJK or dense text under 8000 chars may still be rejected.

Shell history warning in --help:
  Use stdin for sensitive content: echo "text" | wrapsec scan
```

#### `wrapsec batch`

```
wrapsec batch FILE [OPTIONS]

Streamed line by line - never fully loaded into memory.
Empty lines and # comments skipped.

Limits:
  Max file size:   10MB
  Max line length: 8000 chars (longer lines skipped with warning)

Options:
  --mode     fast|full
  --timeout  INT          Per-request timeout, min 1 (default: 30)
  --delay    INT          ms between requests (default: 0)
  --limit    INT          Max lines to process
  --summary               Counts only - no scores or trace IDs
  --json                  JSONL output (newline-delimited JSON)
  --quiet                 Exit code only

JSON output format:
  --json outputs JSONL (newline-delimited JSON, one object per line).
  Each line is independently parseable. Compatible with jq, pandas,
  BigQuery, and other streaming JSON consumers.

  wrapsec batch prompts.txt --json > results.jsonl
  cat results.jsonl | jq .decision

>100 lines without --delay:
  "Scanning N prompts with no delay. Consider --delay 100.
   Continue? [y/N]"   ← default N

Exit code priority: ERROR (1) > BLOCK (2) > SUCCESS (0)
```

#### `wrapsec audit list/get/stats`

```
wrapsec audit list [OPTIONS]
  --decision, --reason, --from, --to, --limit (max 100), --json

wrapsec audit get TRACE_ID [--json]

wrapsec audit stats [--from, --to, --json]

All read-only. Scope bounded by API key used.
```

#### `wrapsec settings get`

```
Shows active gateway configuration. Strictly read-only.
  Block/sanitize thresholds (and config source)
  Detection layers: rule, ML, LLM (enabled/disabled)
  LLM provider, model, timeout, trigger threshold
  Rate limit per minute
  API version

To change any settings: use the dashboard.
```

#### `wrapsec keys list`

```
Lists API keys visible to current key. Strictly read-only.
Shows: key_id, name, created_at, last_used_at
Does NOT show key secret.

To create or revoke: use the dashboard.
```

#### `wrapsec ping`

```
Network connectivity only. No authentication required.
Calls /health/live. Timeout: fixed 5s.

IMPORTANT: ping does NOT validate your API key.
           Use doctor for auth verification.

Exit: 0 = reachable, 1 = unreachable
Docker: HEALTHCHECK CMD wrapsec ping || exit 1
```

#### `wrapsec doctor`

```
Full connectivity, auth, and version check.
Resilient - a failed check never aborts remaining checks.
Missing or unexpected response fields show "Unknown", not a crash.

Checks:
  1. Config file found (shows masked API key and source)
  2. API reachable (/health/live)           timeout: 5s
  3. API key valid (/health/ready)          timeout: 5s
  4. Service health: database, redis, ml_model
  5. Active configuration summary
  6. Version compatibility:
       CLI version:   0.1.0
       Expected API:  v1
       API reachable: ✅
       Compatible:    ✅
  7. Timeout in use (value + source)

Version mismatch → warning only, never blocks.
Partial responses → show available data, warn about missing fields.
```

#### `wrapsec config`

```
wrapsec config set KEY VALUE
  Allowed keys: api_key, base_url, timeout (min 1)

wrapsec config get
  Shows config with API key masked

wrapsec config clear
  Interactive: "Remove your API key and all settings? [y/N]"
  Default: N

wrapsec config clear --force
  Skips confirmation - for CI environments and automation scripts

Config file location:
  Linux/macOS: $XDG_CONFIG_HOME/wrapsec/config.json
               (fallback: ~/.config/wrapsec/config.json)
  Windows:     %APPDATA%\wrapsec\config.json
  Permissions: chmod 600 (Unix) - no-op on Windows

Priority (highest to lowest):
  1. --flag on command
  2. WRAPSEC_API_KEY / WRAPSEC_BASE_URL / WRAPSEC_TIMEOUT
  3. config file
  4. defaults (base_url: http://localhost:8000, timeout: 30)

⚠ http://localhost:8000 is the development default only.
  Always set WRAPSEC_BASE_URL explicitly in production.
```

---

## 14. Platform Compatibility

### 14.1 Config File Location

**Finalised - breaking change to move after V1 release.**

```python
import os, sys
from pathlib import Path

def get_config_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or Path.home()
        return Path(base) / "wrapsec"
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "wrapsec"

CONFIG_PATH = get_config_dir() / "config.json"
```

### 14.2 File Encoding

```python
# Always UTF-8 - Windows defaults to cp1252
with open(file_path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        process(line)

if sys.platform == "win32" and hasattr(sys.stdin, "reconfigure"):
    sys.stdin.reconfigure(encoding="utf-8")
```

### 14.3 Signal Handling

```python
import signal
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
```

---

## 15. HTTP Error Handling

Retry behaviour is implemented exclusively in `core/retry.py` (Section 9). This table reflects that behaviour. If Section 9 changes, this table must be updated to match.

| HTTP Status | Exception | Retry | Message |
|---|---|---|---|
| 401 | `WrapSecAuthError` | Never | "Invalid or revoked API key." |
| 403 | `WrapSecAuthError` | Never | "Permission denied." |
| 404 | `WrapSecError` | Never | "Endpoint not found. Check your base_url." |
| 413 | `WrapSecError` | Never | "Input too large. Max payload is 64KB." |
| 422 | `WrapSecError` | Never | Server validation message |
| 429 | `WrapSecRateLimitError` | Never | "Rate limit exceeded. Try again later." |
| 5xx | `WrapSecSystemError` | Up to 3x | "Server error. WrapSec API is experiencing issues." |
| Timeout | `WrapSecSystemError` | Up to 3x | "Request timed out. Increase with --timeout." |
| ConnectionError | `WrapSecSystemError` | Up to 3x | "Cannot reach WrapSec API." |
| Invalid JSON | `WrapSecSystemError` | Never | "Invalid response from API." |

---

## 16. CI Usage

```bash
# Exit code only - recommended for CI
wrapsec scan --quiet "$(cat prompt.txt)"
[ $? -eq 2 ] && echo "Blocked" >&2 && exit 1

# JSON output
wrapsec scan --json "text" | jq .decision

# Batch - summary only
wrapsec batch prompts.txt --summary --quiet

# Batch - JSONL output (one JSON object per line)
wrapsec batch prompts.txt --json > results.jsonl
cat results.jsonl | jq .decision

# Docker health check
HEALTHCHECK CMD wrapsec ping || exit 1

# CI - no config file needed
export WRAPSEC_API_KEY=wsk_live_...
export WRAPSEC_BASE_URL=https://wrapsec.internal:8000
wrapsec scan --quiet "text"

# CI teardown - no prompt
wrapsec config clear --force
```

---

## 17. Privacy & Telemetry

**WrapSec CLI and SDK collect no data. Zero.**

```
No analytics, crash reports, or usage statistics
No prompts or inputs sent to any third party
No network calls except to WRAPSEC_BASE_URL
No phone-home during install, startup, or operation
No background processes
No hardcoded external endpoints
```

---

## 18. Node.js SDK

### 18.1 Interface

```typescript
import WrapSec from 'wrapsec-node'

const client = new WrapSec({
  apiKey:  process.env.WRAPSEC_API_KEY,
  baseUrl: 'https://wrapsec.internal:8000',  // always set in production
  timeout: 30000,
})

const result = await client.scan('ignore all previous instructions')
console.log(result.decision)        // "BLOCK"
console.log(result.primaryReason)   // "RULE_DETECTOR" (camelCase)
console.log(result.confidenceBand)  // "HIGH"

// Express middleware
import { wrapSecMiddleware } from 'wrapsec-node/middleware'
app.use('/api/ai', wrapSecMiddleware({
  apiKey:  process.env.WRAPSEC_API_KEY,
  onBlock: (req, res) => res.status(403).json({ error: "Blocked" }),
}))
```

### 18.2 Node SDK Parity Rules

```
Field names: camelCase (JavaScript convention)
  API primary_reason → result.primaryReason
  API confidence_band → result.confidenceBand
  Full mapping in Section 5

Same error classes, same retry strategy, same BASE_PATH
Same BLOCK behaviour: returned as result, not raised as exception
Same timeout priority: method → client → env/config → default
Same is not None timeout check (not falsy)
```

### 18.3 Express Middleware Limits

```typescript
const MAX_PAYLOAD_BYTES = 64 * 1024  // 64KB - enforced before API call

// If exceeded:
res.status(413).json({
  error: { code: "PAYLOAD_TOO_LARGE", message: "Input exceeds 64KB limit" }
})
```

Note: The middleware uses `PAYLOAD_TOO_LARGE` as its own error code for the
client-side 64KB check. This is enforced before the API call and is distinct
from the server-side `VALIDATION_ERROR` (422) returned by the WrapSec API.

---

## 19. V3 - Gateway Installer (After V1 is Enterprise-Ready)

**Status: Planned - do not implement until V1 is production-ready and battle-tested.**

### 19.1 Commands

```
wrapsec install / start / stop / status / logs / upgrade / uninstall
```

### 19.2 Install Steps

```
Step 1   Check prerequisites - Python 3.10+, Docker, Node.js 18+
         Exit if running as root
Step 2   Download release tarball (HTTPS + SHA-256 verified)
Step 3   Create installation directory
Step 4   Create Python virtual environment
Step 5   pip install -r requirements.txt inside venv
Step 6   Start PostgreSQL + Redis (Docker or validate existing)
Step 7   Run database schema creation
Step 8   Train ML model - warn about 70 sample limitation
Step 9   Generate admin API key (cryptographically secure)
Step 10  Create .env file (chmod 600 immediately)
Step 11  npm install + npm run build (unless --no-dashboard)
Step 12  Start gateway (uvicorn)
Step 13  Start dashboard (npm start)
Step 14  Poll /health/ready (timeout: 60s)
Step 15  Save admin key to config file (chmod 600)
Step 16  Print success - admin key shown ONCE only
```

### 19.3 Installer Security Rules

```
1.  Admin key never written to any log
2.  Admin key shown ONCE only at completion
3.  Never run as root
4.  .env + config: chmod 600 immediately
5.  Downloads: HTTPS only, SHA-256 verified
6.  Docker images: official registries only
7.  pip install: inside venv, never as root
8.  Database password: auto-generated
9.  No telemetry at any step
10. Warn if install directory is world-readable
```

---

## 20. Build Order

```
Phase 1 - Python SDK + CLI (implement now)
  Location:  sdk/python/ (inside main repo)
  Structure: wrapsec/ with config/, core/, cli/commands/
  Install:   pip install -e sdk/python/
  Entry:     wrapsec = "wrapsec.cli:cli"
  Version:   0.1.0
  Platforms: Windows + Linux + macOS

Phase 2 - Node.js SDK (after Python SDK complete)
  Location:  sdk/node/ (inside main repo)
  Parity:    same methods, errors, BASE_PATH, retry, camelCase fields
  Version:   0.1.0

Phase 3 - Integration examples
  Location:  examples/
  Uses:      Python SDK and Node SDK
  Includes:  FastAPI, Express, LLM app

Phase 4 - Publish to PyPI / npm (when ready)
  Move sdk/python/ → github.com/kbajish/wrapsec-python
  Move sdk/node/   → github.com/kbajish/wrapsec-node

Phase 5 - Gateway installer (after V1 enterprise-ready)
  wrapsec install, start, stop, status, logs, upgrade, uninstall
  Docker mode default, cross-platform
```

---

## 21. Open Questions

```
1. PyPI name availability
   Check: pip install wrapsec, pip install wrapsec-python
   Fallback: wrapsec-gateway or wrapsec-security

2. npm name availability
   Check: npm info wrapsec-node
   Fallback: @wrapsec/node

3. CLI distribution beyond PyPI
   Homebrew, winget - post Phase 4 only

4. Windows first-class testing
   Spinner in cmd.exe vs Windows Terminal vs PowerShell
   stdin piping in PowerShell
   Must pass before Phase 1 release
```

---

## 22. Non-Goals - Permanent

```
The CLI will never:
  - Change security thresholds or detection policy
  - Create, rotate, or revoke API keys
  - Manage departments or applications
  - Expose internal scoring details or layer weights
  - Perform write operations on gateway configuration
  - Collect telemetry or transmit data externally

These actions belong exclusively in the dashboard,
where every change is authenticated, audited, and attributable.
```

---

*WrapSec CLI & SDK Design Specification (Internal)*  
*Version 1.6 - April 2026*  
*Review cycles: 7 (initial + 6 external reviews)*  
*Last updated: April 2026*
