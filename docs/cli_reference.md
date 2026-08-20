# WrapSec CLI - Command Reference

CLI behavior follows [Core Concepts](core_concepts.md) for decision semantics and SYSTEM_ERROR handling.

Version: 1.0.0
Last updated: May 2026

Installation from source only. PyPI publication (`pip install wrapsec-python`) is pending.

## Installation

```bash
# Development (local repo)
pip install -e ./sdk/python

# pip install wrapsec-python
```

## Quick Start

```bash
# Install
pip install -e ./sdk/python

# Configure
wrapsec config set api_key wsk_live_...
wrapsec config set base_url http://localhost:8000

# Verify
wrapsec doctor

# Scan
wrapsec scan "hello world"
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | ALLOW or SANITIZE - input accepted |
| `1` | CLI error, network failure, auth error, rate limit, SYSTEM_ERROR |
| `2` | BLOCK - input rejected by security policy |

Network and server errors (5xx, timeout, connection failure) are retried up to 3 times with exponential backoff before exit 1 is returned. A CLI exit 1 on infrastructure errors means retries have already been exhausted.

**SYSTEM_ERROR and exit codes:**
When the API returns `primary_reason = SYSTEM_ERROR`, the API decision is `ALLOW` - the detection pipeline failed and the system defaults to allowing the request. The CLI treats this as exit code `1` (failure) regardless of the ALLOW decision. This is intentional - a failed detection is not a safe detection. Applications must not forward input to an LLM when `SYSTEM_ERROR` is returned. See `wrapsec scan` output for how SYSTEM_ERROR is surfaced.

Exit codes apply to all commands and all output modes (`--quiet`, `--json`).

## Global Options

```bash
wrapsec --version    # Show CLI version (1.0.0)
wrapsec --help       # Show help
```

## 1. `wrapsec config`

Manage CLI configuration. Stored in:
- **Linux/macOS:** `$XDG_CONFIG_HOME/wrapsec/config.json` (fallback: `~/.config/wrapsec/config.json`)
- **Windows:** `%APPDATA%\wrapsec\config.json`

Config file is created with `chmod 600` on Unix.

### `wrapsec config set KEY VALUE`

```bash
wrapsec config set api_key wsk_live_...
wrapsec config set base_url http://localhost:8000
wrapsec config set timeout 30
```

**Allowed keys:**

| Key | Description | Validation |
|---|---|---|
| `api_key` | WrapSec API key | Must start with `wsk_live_` |
| `base_url` | Gateway URL | Must start with `http://` or `https://` |
| `timeout` | Request timeout in seconds | Integer, minimum 1 |

On success:

```
  + api_key saved (wsk_li****2fck)
  + base_url saved (http://localhost:8000)
  + timeout saved (30)
```

Invalid values are rejected immediately:

```
  - api_key must start with 'wsk_live_', got 'invalid_key'   exit 1
  - timeout must be at least 1 second, got 0                 exit 1
  - base_url must start with http:// or https://             exit 1
```

### `wrapsec config get`

```bash
wrapsec config get
```

```
Config file: C:\Users\...\AppData\Roaming\wrapsec\config.json

  api_key     wsk_li****2fck                            [config file]
  base_url    http://localhost:8000                     [config file]
  timeout     30                                        [config file]
```

API key is always masked. Each value shows its source: `[config file]`, `[environment variable]`, or `[default]`.

### `wrapsec config clear`

```bash
wrapsec config clear           # interactive confirmation, default N
wrapsec config clear --force   # skip confirmation (CI use)
```

### Environment variable overrides

Environment variables take the highest priority over config file and defaults:

```bash
export WRAPSEC_API_KEY=wsk_live_...
export WRAPSEC_BASE_URL=https://wrapsec.internal:8000
export WRAPSEC_TIMEOUT=30
```

Note: `http://localhost:8000` is the development default only. Always set `WRAPSEC_BASE_URL` explicitly in production.

## 2. `wrapsec ping`

Test network connectivity. No authentication required.

```bash
wrapsec ping
```

```
WrapSec API is reachable    exit 0
```

- Calls `/health/live` only
- Fixed timeout: 5 seconds (not configurable)
- Does NOT validate your API key - use `wrapsec doctor` for auth verification

**Docker health check:**
```dockerfile
HEALTHCHECK CMD wrapsec ping || exit 1
```

## 3. `wrapsec doctor`

Full connectivity, authentication, and version check.

```bash
wrapsec doctor
```

```
wrapsec doctor

  Configuration
    config file   C:\Users\...\AppData\Roaming\wrapsec\config.json
    api key       wsk_li****2fck  (config file)
    base url      http://localhost:8000  (config file)
    timeout       30s  (config file)

  Connectivity
  + reachable    http://localhost:8000

  Authentication
  + api key valid

  Services
  + database        ok
  + redis           ok
  + ml_model        ok

  Active Configuration
    block threshold   0.7
    sanitize          0.4
    rule detector     enabled
    ml detector       enabled
    llm detector      enabled

  Version
    cli   1.0.0
    api   1.0.0
  + compatible

  all checks passed
```

- A failed check never aborts remaining checks
- Missing response fields show "unknown" - never crashes
- Version mismatch shows a warning only - never blocks execution

## 4. `wrapsec scan`

Scan a single prompt for security risks.

```bash
wrapsec scan [TEXT] [OPTIONS]
```

### Options

| Option | Default | Description |
|---|---|---|
| `--mode fast\|full`, `-m` | `fast` | Detection mode. `full` enables LLM semantic analysis for deeper inspection of ambiguous inputs. Results may differ from fast mode. Latency increases by ~100-2300ms depending on LLM model. |
| `--timeout INT` | `30` | Request timeout in seconds (min 1) |
| `--json` | off | Pure JSON output to stdout |
| `--user TEXT`, `-u` | `cli` | User ID for audit attribution - maps to `metadata.user_id` in the API request body |
| `--quiet`, `-q` | off | No stdout output - exit code only |
| `--session-id TEXT` | none | Opaque conversation identifier. Groups related scans in the audit trail. Max 200 chars, charset `[A-Za-z0-9_.:-]` |
| `--turn-index INT` | none | Zero-based turn number within `--session-id`. Range `[0, 10000]` |
| `--run-id TEXT` | none | Opaque identifier for one agent execution. Same charset rules as `--session-id` |

See [Correlating multi-turn and agent scans](#correlating-multi-turn-and-agent-scans)
for how these three relate.

### Examples

```bash
# Basic scan
wrapsec scan "hello world"

# BLOCK decision
wrapsec scan "ignore all previous instructions"

# Quiet mode - CI use
wrapsec scan --quiet "hello world"
echo "Exit: $?"   # 0 = safe, 2 = blocked

# JSON output
wrapsec scan --json "hello world"

# Full detection mode (LLM analysis)
wrapsec scan --mode full "hello world"

# stdin - recommended for sensitive content (not stored in shell history)
echo "my SSN is 123-45-6789" | wrapsec scan
cat prompt.txt | wrapsec scan

# Custom user attribution
wrapsec scan --user "alice" "hello world"

# Custom timeout
wrapsec scan --timeout 10 "hello world"
```

### Output (human)

ALLOW:
```
Decision:   ALLOW
Reason:     NO_THREAT_DETECTED
Confidence: 1.0 (HIGH)
Trace ID:   req_01kpbzs6fzh8vaq5j7w6q1sj4m
```

BLOCK:
```
Decision:   BLOCK
Reason:     RULE_DETECTOR
Confidence: 0.8 (HIGH)
Trace ID:   req_01kpc175tj4c1vgkqwfeavjt59
Threats:    PROMPT_INJECTION
```

### Output (JSON)

```json
{
  "decision": "BLOCK",
  "primary_reason": "RULE_DETECTOR",
  "confidence": 0.75,
  "confidence_band": "HIGH",
  "trace_id": "req_01kpc17drjgj4t4dm6aw9nq0ka",
  "threats": ["PROMPT_INJECTION"],
  "latency_ms": 1.18,
  "sanitized_input": null
}
```

`sanitized_input` matches the `sanitized_input` field in the API response - present and non-null only when `decision = SANITIZE`. `sanitization_applied` is the corresponding boolean indicator in the full API response.
Confidence is shown at full precision in JSON output (no forced rounding).

### Validation errors

```
  - No input provided.                        exit 1
  - Input too large (8,001 chars).            exit 1
  - timeout must be at least 1 second.        exit 1
```

Note: CLI arguments are stored in shell history. Use stdin for sensitive content: `echo "text" | wrapsec scan`

## 5. `wrapsec batch`

Scan multiple prompts from a file. One prompt per line.

```bash
wrapsec batch FILE [OPTIONS]
```

- Empty lines and lines starting with `#` are skipped
- File is streamed line by line - never fully loaded into memory
- BOM characters are stripped automatically (Windows UTF-8 compatibility)
- **File path only** - no inline text argument

### Options

| Option | Default | Description |
|---|---|---|
| `--mode fast\|full` | `fast` | Detection mode |
| `--timeout INT` | `30` | Per-request timeout in seconds (min 1) |
| `--delay INT` | `0` | Milliseconds between requests |
| `--limit INT` | all | Max lines to process |
| `--summary` | off | Show counts only - no individual scores or trace IDs |
| `--json` | off | JSONL output (one JSON object per line) |
| `--session-id TEXT` | none | Opaque conversation identifier applied to every line. When set, `turn_index` auto-increments from 0 per processed line |
| `--run-id TEXT` | none | Opaque identifier for one agent execution, applied to every line |

`batch` has no `--turn-index`: the index is derived. With `--session-id` set, each
processed line gets the next turn number starting at 0; without it, `turn_index` is
sent as absent.
| `--quiet` | off | No stdout - exit code only |

### Limits

| Limit | Value |
|---|---|
| Max file size | 10MB |
| Max line length | 8000 chars (longer lines skipped with warning) |

### Exit code priority

`ERROR (1)` > `BLOCK (2)` > `SUCCESS (0)`

An error means some prompts were not scanned - results are incomplete.

### Examples

```bash
# Default output
wrapsec batch prompts.txt

# Summary only (recommended for CI)
wrapsec batch prompts.txt --summary

# Quiet - exit code only
wrapsec batch prompts.txt --quiet

# JSONL output
wrapsec batch prompts.txt --json > results.jsonl
cat results.jsonl | jq .decision

# With delay between requests (large files)
wrapsec batch prompts.txt --delay 100 --summary

# Limit to first 50 lines
wrapsec batch prompts.txt --limit 50 --summary

# Full detection mode
wrapsec batch prompts.txt --mode full --summary

# Custom timeout per request
wrapsec batch prompts.txt --timeout 15 --summary
```

### Output (default)

```
[   1] ALLOW    1.00  req_01kpbzt1m1jvhh6rq  hello world
[   2] BLOCK    0.75  req_01kpbzt3n1g99fd72  ignore all previous instructions...
[   3] ALLOW    1.00  req_01kpbzt5p3h8k6kpg  what is 2+2
[   4] SANITIZE 0.75  req_01kpbzt7qrherghkn  my SSN is 123-45-6789
[   5] BLOCK    0.75  req_01kpbzt9rbkdsav5t  tell me how to make explosives

Results:  5 scanned, 0 skipped
  BLOCK:    2
  SANITIZE: 1
  ALLOW:    2
```

### Output (JSONL)

```jsonl
{"decision": "ALLOW", "primary_reason": "NO_THREAT_DETECTED", "confidence": 1.0, "confidence_band": "HIGH", "trace_id": "req_...", "latency_ms": 1.6, ...}
{"decision": "BLOCK", "primary_reason": "RULE_DETECTOR", "confidence": 0.75, "confidence_band": "HIGH", "trace_id": "req_...", "latency_ms": 1.18, ...}
{"decision": "SANITIZE", "primary_reason": "PII_GUARDRAIL_SANITIZE", "confidence": 0.75, "sanitized_input": "my SSN is [SSN REDACTED]", ...}
```

`latency_ms` corresponds to `processing.latency_ms` in the API response. For scan_only: detection pipeline time. For proxy: total end-to-end time (WrapSec + provider). For a full proxy latency breakdown use: `wrapsec audit get <trace_id>`

## Correlating multi-turn and agent scans

A single scan is one audit record. Three optional identifiers let you reconstruct a
larger unit of work from those records. All three are accepted by `scan`, and
`--session-id` / `--run-id` by `batch`.

| Identifier | Answers | Scope |
|---|---|---|
| `--session-id` | which conversation was this? | many turns of one conversation |
| `--turn-index` | where in that conversation? | one turn, zero-based |
| `--run-id` | which agent execution was this? | one run, which may span several scans |

```bash
# A three-turn conversation
wrapsec scan "book me a flight"        --session-id conv-42 --turn-index 0
wrapsec scan "actually, make it two"   --session-id conv-42 --turn-index 1
wrapsec scan "and add a hotel"         --session-id conv-42 --turn-index 2

# Every scan an agent run makes, tagged so the run can be replayed
wrapsec scan "$TOOL_OUTPUT" --run-id run-2026-08-20-a7
wrapsec batch retrieved_docs.txt --run-id run-2026-08-20-a7 --session-id conv-42
```

Read a run back with `GET /v1/agent-runs/{run_id}`, which returns every turn in order
with its decision and risk score. The dashboard renders the same data as a timeline.

**Rules that apply to all three:**

- Opaque and caller-chosen. WrapSec never parses them for meaning.
- Max 200 chars, charset `[A-Za-z0-9_.:-]`. `--turn-index` is `[0, 10000]`.
- **Correlation metadata only.** They are never an authorization input - supplying
  someone else's `session_id` grants nothing. Tenant isolation is enforced from the
  API key or token, not from these fields.
- **Do not put PII in them.** They are stored in the audit trail as given, and the
  audit trail is immutable.

`input_source` (content provenance, e.g. `retrieved_document`) is an API-level field
and is **not** exposed as a CLI flag. See `docs/api.md`.

## 6. `wrapsec audit`

Query audit logs. All commands are **read-only**.
Scope is bounded by the API key used.

### `wrapsec audit list`

```bash
wrapsec audit list [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--decision BLOCK\|SANITIZE\|ALLOW` | all | Filter by decision |
| `--reason TEXT` | all | Filter by primary_reason (e.g. `RULE_DETECTOR`, `PII_GUARDRAIL_SANITIZE`) |
| `--mode scan_only\|proxy` | all | Filter by execution mode |
| `--from DATE` | none | From date (YYYY-MM-DD) |
| `--to DATE` | none | To date (YYYY-MM-DD) |
| `--limit INT` | `20` | Records to return (max 100) |
| `--offset INT` | `0` | Records to skip (for pagination) |
| `--json` | off | Pure JSON output |

```bash
wrapsec audit list --limit 5
wrapsec audit list --decision BLOCK --limit 3
wrapsec audit list --decision ALLOW --limit 3
wrapsec audit list --decision SANITIZE --limit 3
wrapsec audit list --reason RULE_DETECTOR --limit 3
wrapsec audit list --mode proxy --limit 10        # proxy requests only
wrapsec audit list --mode scan_only --limit 10    # scan-only requests only
wrapsec audit list --mode proxy --decision BLOCK --limit 5  # blocked proxy requests
wrapsec audit list --from 2026-04-01 --limit 10
wrapsec audit list --from 2026-04-01 --to 2026-04-30 --limit 10
wrapsec audit list --limit 2 --json
```

**Output:**
```
TRACE ID                          DECISION    REASON                         CONF   BAND    MODE        SOURCE              CREATED
req_01kpbzwmrqqaf448mkz548g6q0    BLOCK       RULE_DETECTOR                  0.75   HIGH    scan_only   wrapsec-python      2026-04-16T20:32:00
req_01kpbzwjq7ytd0x0w9xz0h2znd    SANITIZE    PII_GUARDRAIL_SANITIZE         0.75   HIGH    proxy       wrapsec-python      2026-04-16T20:31:58
req_01kpbzw1m8xp3xhwjb5s498z9c    ALLOW       NO_THREAT_DETECTED             1.00   HIGH    scan_only   wrapsec-python      2026-04-16T20:31:40
```

### `wrapsec audit get TRACE_ID`

```bash
wrapsec audit get req_01kpbzwmrqqaf448mkz548g6q0
wrapsec audit get req_01kpbzwmrqqaf448mkz548g6q0 --json
```

**Output (human):**
```
Decision:       BLOCK
Reason:         RULE_DETECTOR
Confidence:     0.75 (HIGH)
Trace ID:       req_01kpbzwmrqqaf448mkz548g6q0
Latency:        1.5ms
Input length:   30 chars
Created:        2026-04-16T20:32:00.294110
Threats:        MALICIOUS_INTENT
Severity:       HIGH
Mode:           scan_only
Key ID:         key_bc861e102a45
Department:     7a576570-e175-4fdd-b9e9-e45615da6934
User:           cli-batch
Source:         wrapsec-python
```

**Output (JSON):**
```json
{
  "trace_id": "req_01kpbzwmrqqaf448mkz548g6q0",
  "decision": "BLOCK",
  "primary_reason": "RULE_DETECTOR",
  "risk_score": 0.92,
  "confidence": 0.75,
  "confidence_band": "HIGH",
  "threats": ["MALICIOUS_INTENT"],
  "severity": "HIGH",
  "latency_ms": 1.49,
  "input_length": 30,
  "execution_mode": "scan_only",
  "tenant_id": "tenant_abc",
  "key_id": "key_bc861e102a45",
  "dept_id": "7a576570-e175-4fdd-b9e9-e45615da6934",
  "app_id": null,
  "user_id": "cli-batch",
  "source": "wrapsec-python",
  "created_at": "2026-04-16T20:32:00.294110"
}
```

Nonexistent trace ID returns exit 1:
```
  - Audit record not found: req_nonexistent_trace_id_xyz    exit 1
```

### `wrapsec audit stats`

```bash
wrapsec audit stats
wrapsec audit stats --json
wrapsec audit stats --from 2026-04-01 --to 2026-04-30
```

**Output:**
```
Total requests:  173
Blocked:         101 (58.4%)
Sanitized:       26
Allowed:         46
Avg latency:     282.0ms
P95 latency:     2309.1ms
Severity:
  CRITICAL          38
  HIGH              63
  MEDIUM            26
  LOW               46
Top threats:
  PROMPT_INJECTION    63
  PII                 38
  MALICIOUS_INTENT    21
  JAILBREAK            1
  DATA_EXFILTRATION    1
```

Severity follows SIEM triage levels: CRITICAL (guardrail blocks or risk_score >= 0.9), HIGH (other blocks or SYSTEM_ERROR), MEDIUM (sanitized), LOW (allowed). The Severity section is omitted when all counts are zero.

## 7. `wrapsec chat`

Send a message through the WrapSec proxy to the configured LLM provider.
Scans the input, forwards to the provider if safe, scans the output, and prints the reply.

The proxy provider must be configured first via the dashboard Settings page or `PUT /v1/settings/proxy`.

```bash
wrapsec chat [MESSAGE] [OPTIONS]
```

### Options

| Option | Default | Description |
|---|---|---|
| `--model TEXT`, `-m` | from proxy settings | Provider/model string e.g. `custom/llama-3.1-8b-instant`. If omitted, uses `default_model` from proxy settings. |
| `--timeout INT` | `90` | Request timeout in seconds (min 1). LLM calls are slower than scans. |
| `--json` | off | Output full JSON response including WrapSec metadata |
| `--verbose`, `-v` | off | Show WrapSec security headers alongside the reply |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Response received |
| `1` | Error (auth, network, provider unreachable) |
| `2` | Input blocked by security policy |

### Examples

```bash
# Basic chat
wrapsec chat "What is 2+2?"

# Use a specific model
wrapsec chat --model "custom/llama-3.1-8b-instant" "Hello"

# Show security metadata
wrapsec chat --verbose "Explain quantum computing"

# Full JSON response
wrapsec chat --json "What is the capital of France?"

# Stdin input
echo "Summarise this document" | wrapsec chat

# Custom timeout (long responses)
wrapsec chat --timeout 120 "Write a detailed essay on climate change"
```

### Output (human)

```
The capital of France is Paris.
```

### Output (--verbose)

```
The capital of France is Paris.

WrapSec
  Input decision     ALLOW
  Output decision    ALLOW
  Execution          SUCCESS
  Provider           custom
  Model              openrouter/free
  Latency            1500ms
  Trace ID           req_01kreyvxn41hxvs51hqctv62nd
```

### Output (--json)

```json
{
  "id": "wrapsec-req_01kreyvxn41hxvs51hqctv62nd",
  "object": "chat.completion",
  "model": "openrouter/free",
  "choices": [
    {
      "index": 0,
      "message": {"role": "assistant", "content": "The capital of France is Paris."},
      "finish_reason": "stop"
    }
  ],
  "wrapsec": {
    "trace_id": "req_01kreyvxn41hxvs51hqctv62nd",
    "decision": "ALLOW",
    "input_primary_reason": "NO_THREAT_DETECTED",
    "input_confidence": 1.0,
    "input_sanitized": false,
    "output_decision": "ALLOW",
    "output_sanitized": false,
    "execution_status": "SUCCESS",
    "provider": "custom",
    "model": "openrouter/free",
    "total_latency_ms": 1500
  }
}
```

### Model string format

The model string uses `provider/model-name` format. The provider prefix must be one of `openai`, `ollama`, or `custom`.

| Use case | Model string |
|---|---|
| OpenRouter (any model) | `custom/openrouter/free` |
| OpenRouter (specific) | `custom/google/gemini-2.5-flash` |
| Groq | `custom/llama-3.1-8b-instant` |
| OpenAI directly | `openai/gpt-4o` |
| Local Ollama | `ollama/llama3.2` |

The part after `custom/` is sent verbatim as the model name to the upstream API.

### Notes

- Trial keys cannot use proxy mode (`403 trial_proxy_disabled`)
- No retry on proxy calls -- provider calls have side effects
- Default timeout is 90 seconds (higher than scan default of 30s)
- Use `wrapsec audit get <trace_id>` for full proxy latency breakdown

## 8. `wrapsec settings get`



Show active gateway configuration. **Read-only.**
To change any settings, use the dashboard.

```bash
wrapsec settings get
wrapsec settings get --json
```

**Output:**
```
Gateway Configuration (read-only - change via dashboard)

Detection Thresholds:
  Block threshold:     0.7
  Sanitize threshold:  0.4

Detection Layers:
  RULE     enabled
  ML       enabled
  LLM      enabled

LLM Configuration:
  Provider:    ollama
  Model:       llama3.2:latest
  Timeout:     38s
  LLM trigger: 0.2

Rate Limit:
  Live keys:   60 req/min (default)
```

## 8. `wrapsec keys list`

List API keys visible to the current key. **Read-only.**
To create, rotate, or revoke keys, use the dashboard - these operations require JWT + ADMIN login.

`GET /v1/keys` accepts API key authentication. All write operations (`POST`, `PUT`, `DELETE`) on keys require JWT + ADMIN and cannot be performed from the CLI.

```bash
wrapsec keys list
wrapsec keys list --json
```

**Output:**
```
KEY ID                     NAME                 CREATED       LAST USED
key_6e40a87d9b09           Finance Bot Primary  2026-04-16    Never
key_bc861e102a45           test key             2026-04-16    2026-04-16
key_52066e5606ae           Finance Bot Key      2026-04-10    Never
```

Does NOT show key secrets - they are never retrievable after creation.

## CI Usage Patterns

```bash
# Single scan - exit code only
wrapsec scan --quiet "$(cat prompt.txt)"
[ $? -eq 2 ] && echo "Blocked" >&2 && exit 1

# JSON output for parsing
wrapsec scan --json "text" | jq .decision

# Batch - summary only (no scores logged)
wrapsec batch prompts.txt --summary --quiet

# Batch - JSONL for downstream processing
wrapsec batch prompts.txt --json > results.jsonl
cat results.jsonl | jq .decision

# Docker health check
HEALTHCHECK CMD wrapsec ping || exit 1

# CI environment (no config file needed)
export WRAPSEC_API_KEY=wsk_live_...
export WRAPSEC_BASE_URL=https://wrapsec.internal:8000
wrapsec scan --quiet "text"

# CI teardown
wrapsec config clear --force
```

## Security Notes

```
1. Never pass sensitive content as CLI arguments - stored in shell history
   DANGEROUS: wrapsec scan "my SSN is 123-45-6789"
   SAFE:      echo "my SSN is 123-45-6789" | wrapsec scan

2. API key is always masked in output - never printed in plain text

3. --json exposes trace_id, confidence scores, and primary_reason
   Use --quiet in CI pipelines when only exit code is needed

4. sanitized_input is never shown by default in human output

5. The CLI never creates, rotates, or revokes API keys
   Use the dashboard for all key management operations

6. The CLI never changes security thresholds or detection policy
   Use the dashboard for all configuration changes
```

## What the CLI Does NOT Do

```
 Create, rotate, or revoke API keys (requires JWT + ADMIN - use dashboard)
 Change security thresholds or detection policy (requires JWT + ADMIN - use dashboard)
 Manage departments or applications
 Manage users, roles, or passwords (use the dashboard)
 JWT-based login or session management (CLI uses API keys only)
 Expose internal scoring details or layer weights
 Collect telemetry or transmit data externally
```

These actions belong in the dashboard, where every change is authenticated, audited, and attributable. The CLI authenticates exclusively with API keys - JWT auth is not supported.

## Known Behaviour Notes

```
latency_ms in scan output
  Real gateway processing time - sourced directly from the API response.
  Mapping by execution mode:
    scan_only -> processing.latency_ms (detection pipeline time only)
    proxy     -> total_latency_ms (end-to-end: detection + provider + output scan)
  Values typically 1-10ms for scan_only fast mode, 100-2300ms with full mode or proxy.
  For a full proxy latency breakdown, use: wrapsec audit get <trace_id>

confidence in human vs JSON output
  Scan human output: rounded to 1 decimal place (e.g. 0.8). Applies to scan and audit get.
  Batch human output: rounded to 2 decimal places (e.g. 0.75). Applies to batch row output.
  JSON output: full precision as returned by the API (no forced rounding).

batch on Windows (PowerShell)
  PowerShell Out-File -Encoding utf8 adds a BOM character.
  The CLI strips BOM automatically - no action needed.

--mode full
  Sends detection_mode=full to the API which invokes LLM analysis.
  Output fields are identical to fast mode.
  Latency increases by ~100-2300ms depending on the configured LLM.

"Reason" in human output
  The human-readable output label "Reason:" corresponds to the API field primary_reason.
  JSON output uses primary_reason directly - no label difference.
  Example: human shows "Reason: RULE_DETECTOR", JSON shows "primary_reason": "RULE_DETECTOR"
```

WrapSec CLI Command Reference
Version 1.0.0 - May 2026
