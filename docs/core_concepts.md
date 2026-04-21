# WrapSec - Core Concepts

This document defines the canonical behavior of WrapSec.

All other documentation (API, SDK, CLI, examples) must align with these definitions.

---

## Decision Model

WrapSec evaluates input (and optionally output) and returns a **security decision**:

```text
ALLOW     → safe to proceed
BLOCK     → unsafe, must not proceed
SANITIZE  → unsafe content redacted, safe to proceed with modified input
```

In proxy mode:

```text
decision          → input decision
output_decision   → output decision (response validation)
```

---

## SYSTEM_ERROR Semantics

WrapSec may return:

```text
primary_reason = SYSTEM_ERROR
```

This means the detection pipeline failed internally (e.g., one or more detectors threw an exception). This is distinct from a clean result — `NO_THREAT_DETECTED` is only returned when detection succeeds and all scores are 0.0.

**Important:**

* The engine returns:

  ```text
  decision = ALLOW
  confidence = 0.0
  ```

* Clients **must treat this as a failure condition**

```text
Recommended behavior:
- Middleware → fail open (allow request)
- Applications / LLM apps → fail closed (reject request)
- CLI → exit with error
```

---

## Risk Score vs Decision

```text
risk_score = likelihood of threat (detection output)
decision   = final security verdict (after guardrails)
```

Important:

* Guardrails (e.g., PII) may override detection
* Example:

```text
PII detected → decision = SANITIZE
risk_score = 0.0
```

Always rely on `decision`, not `risk_score`

---

## Confidence

```text
confidence = certainty of the decision
```

* Based on agreement between detectors
* Not a probability of attack

Edge case:

```text
Single detector → confidence = 1.0
```

This reflects lack of disagreement, not absolute correctness

---

## Sanitization

```text
sanitization_applied → boolean
sanitized_input      → redacted content (if applicable)
```

Rules:

* `sanitized_input` is present only when `sanitization_applied = true`
* When `sanitization_applied = true`, always use `sanitized_input` as the input to your LLM — not the original

---

## Execution Modes

```text
scan_only → WrapSec evaluates input only
proxy     → WrapSec sits in request path and calls LLM
```

---

## Error Model

All errors follow:

```json
{
  "error": {
    "code": "input_blocked",
    "message": "...",
    "trace_id": "req_..."
  },
  "wrapsec": {
    "reason": "...",
    "threats": [...]
  }
}
```

---

## Trace ID

```text
trace_id = unique identifier for every request
```

* Used for debugging and audit
* May be `null` if request failed before scanning

---

## Latency

```text
scan_only → latency = detection time
proxy     → latency = total end-to-end time (WrapSec + provider)
```

---

## Batch Responses

Each item contains either:

```json
{ "decision": "ALLOW" }
```

OR

```json
{ "status": "error", "error": "system_error" }
```

Use presence of `decision` as discriminator

---
