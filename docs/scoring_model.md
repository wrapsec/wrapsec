# WrapSec Risk Scoring & Confidence Model

Version: 1.0 - Final
Implementation status: Fully implemented
Last updated: April 2026

---

## Design Principles

**Separation of concerns - two independent subsystems**

Detection and guardrails are architecturally, mathematically, and operationally separate. They are stored in separate database columns, evaluated independently, and never mixed in scoring.

- **Detectors** - identify malicious intent (rule, ML, LLM - probabilistic)
- **Guardrails** - enforce data protection policies (PII, toxicity - deterministic)

**Guardrail-first enforcement**

Guardrail decisions override detection decisions unconditionally. PII and toxicity scores never contribute to the detection risk score. PII is evaluated before toxicity; toxicity is evaluated before detection.

**Threshold decoupling**

Detection thresholds (`thresholds.block`, `thresholds.sanitize`) and guardrail thresholds (`guardrails.pii.block_threshold`, `guardrails.pii.sanitize_threshold`, `guardrails.toxicity.block_threshold`, `guardrails.toxicity.sanitize_threshold`) are always independent. Changing one never affects the other.

**SYSTEM_ERROR is never NO_THREAT_DETECTED - by design and in every code path**

When detectors fail, `primary_reason = SYSTEM_ERROR`. When input is genuinely clean, `primary_reason = NO_THREAT_DETECTED`. These two values are produced by mutually exclusive code paths - they cannot be confused.

```python
# Primary reason computation - order is mandatory
if detection_failed:                return "SYSTEM_ERROR"                    # failure path
if pii_guardrail_triggered:         return "PII_GUARDRAIL_BLOCK/SANITIZE"
if toxicity_guardrail_triggered:    return "TOXICITY_GUARDRAIL_BLOCK/SANITIZE"
if max(scores) > 0:                 return dominant_detector()
return "NO_THREAT_DETECTED"         # only reachable when detection succeeded + clean
```

**SYSTEM_ERROR semantics**

SYSTEM_ERROR occurs when the detection pipeline fails (e.g., detector failure, timeout, or internal exception).

**SYSTEM_ERROR client contract**

At the engine level, `SYSTEM_ERROR` returns `decision = ALLOW` because detection did not confirm a threat. All clients - applications, SDKs, CLI - must treat `primary_reason = SYSTEM_ERROR` as a failure condition and must not forward input to an LLM. The distinction is intentional: the engine reports what it knows; the client enforces safety.

**Failure-safe confidence**

System failures always produce `confidence = 0.0` and `confidence_band = LOW`. This signals to operators that the decision came from a failure, not a detection.

**Conservative input limits**

8,000 characters / 4,000 estimated tokens (heuristic: `ceil(len/2)`). Safe for all languages including CJK. Full tiktoken enforcement in V1.2.

---

## Scoring Pipeline

```
Input
  |
  +--> [1] InputGuard
  |        PII detection (22+ entity types)
  |        Redaction if PII triggered, before detection layers run
  |
  +--> [2] Rule Detector          (try/catch)
  |        Regex + heuristic patterns ~0ms
  |        failure -> score=0.0, detection_failed=True
  |
  +--> [3] ML Classifier          (try/catch)
  |        TF-IDF + LogisticRegression ~5ms
  |        failure -> score=0.0, detection_failed=True
  |        |
  |        +--> ToxicityDetector (guardrail, ~0ms)
  |                 Extracts toxicity signal from ML label 6
  |                 Evaluated against independent toxicity thresholds
  |                 Score NOT included in detection risk score
  |
  +--> [4] LLM Detector           (try/catch, conditional)
  |        full mode AND pre_score >= llm_trigger_threshold
  |        pre_score = max(rule_score, ml_score, pii_score)
  |        failure/timeout -> score=0.0, detection_failed=True
  |
  +--> [5] Detection Risk Score
  |        risk_score = rule*0.40 + ml*0.30 + llm*0.30
  |        PII score:      0.0 contribution (excluded)
  |        Toxicity score: 0.0 contribution (excluded)
  |        boost if max(rule, ml, llm) >= 0.5
  |
  +--> [6] Guardrail Evaluation (independent, evaluated before detection)
  |        PII guardrail:
  |          pii >= pii_block_threshold    -> BLOCK    (overrides detection)
  |          pii >= pii_sanitize_threshold -> SANITIZE (overrides detection)
  |        Toxicity guardrail:
  |          tox >= tox_block_threshold    -> BLOCK    (overrides detection)
  |          tox >= tox_sanitize_threshold -> SANITIZE (overrides detection)
  |
  +--> [7] Primary Reason (strict priority order)
  |        1. detection_failed=True           -> SYSTEM_ERROR
  |        2. PII guardrail triggered         -> PII_GUARDRAIL_BLOCK / PII_GUARDRAIL_SANITIZE
  |        3. Toxicity guardrail triggered    -> TOXICITY_GUARDRAIL_BLOCK / TOXICITY_GUARDRAIL_SANITIZE
  |        4. max detector score > 0          -> RULE_DETECTOR / ML_DETECTOR / LLM_DETECTOR
  |        5. all scores = 0.0               -> NO_THREAT_DETECTED
  |           (only reachable when detection succeeded + clean)
  |
  +--> [8] Policy Engine
  |        PII guardrail decision applied first
  |        Toxicity guardrail decision applied second
  |        Detection decision if no guardrail triggered
  |
  +--> [9] Confidence Score
  |        detector path:  scaled inverse variance of invoked layers
  |        guardrail path: tiered (0.90-0.95 BLOCK, 0.70-0.84 SANITIZE)
  |                        same formula for both PII and toxicity guardrails
  |        failure path:   0.0, LOW band always
  |
  +--> [10] Response
           decision, decision_version, risk_score,
           primary_reason, confidence, confidence_band,
           sanitization_applied, threats
```

---

## 1. Input Limits

```python
# In AIRequestSchema model validator
max_chars             = 8000         # hard limit, enforced by Field
estimated_tokens      = ceil(len(input) / 2)  # conservative heuristic
max_estimated_tokens  = 4000         # enforced by validator -> 422

# Heuristic rationale:
#   ceil(len / 2) assumes 2 chars per token
#   English actual: ~4 chars/token -> estimate is 2x conservative (safe)
#   CJK actual:     ~1 char/token  -> estimate is 2x conservative (safe)
#   Both cases stay under the actual token limit
```

**Important for integrators:** Because the heuristic is conservative, inputs near the 8,000 character boundary may be rejected even if their actual token count is below 4,000. Treat 8,000 characters as the effective hard limit. V1.2 replaces this with per-model tiktoken counting.

---

## 2. Signal Normalisation

All components output a score in `[0.0 - 1.0]`.

**Detection layers (probabilistic):**
- `rule_score` - regex and heuristic patterns
- `ml_score` - TF-IDF + LogisticRegression
- `llm_score` - LLM semantic analysis (conditional)

**Guardrail layers (deterministic):**
- `pii_score` - 22+ PII entity types, input and output (InputGuard / OutputGuard)
- `toxicity_score` - extracted from ML label 6, no additional inference cost (ToxicityDetector)

**Storage - separated by concern:**
```json
"detection_scores": {"rule": 0.85, "ml": 0.30, "llm": 0.00}
"guardrail_scores": {"pii": 0.73, "toxicity": 0.0}
```

---

## 3. Detection Risk Score

```python
risk_score = (
    0.40 * rule_score +
    0.30 * ml_score   +
    0.30 * llm_score
    # pii_score: 0.0 contribution - always excluded
    # toxicity_score: 0.0 contribution - always excluded
)

# Boost: strong signal must not be diluted
max_detector = max(rule_score, ml_score, llm_score)
if max_detector >= 0.5:
    risk_score = max(risk_score, max_detector)
```

**Per-detector failure handling:**

```python
detection_failed = False

try:
    rule_result = rule_detector.detect(input)
except Exception:
    rule_result      = DetectionResult.clean()
    detection_failed = True  # tracked - drives SYSTEM_ERROR

# Same pattern for ML and LLM detectors
```

**LLM trigger pre-score:**

`pre_score = max(rule_score, ml_score, pii_score)`. PII score is included here even though it is excluded from `risk_score`. This means a high PII signal can trigger LLM semantic analysis before the guardrail decision is made.

**`risk_score` and guardrail decisions:**

`risk_score` reflects detection only. PII and toxicity guardrail decisions always produce `risk_score = 0.0` because detection is not involved in the guardrail path.

`risk_score = 0.0` does NOT mean the input is safe. A guardrail BLOCK with `risk_score = 0.0` is a fully enforced security decision. Always use `decision` and `primary_reason` as the authoritative verdict - never `risk_score` alone.

---

## 4. Guardrail Evaluation

Two guardrails run independently with their own thresholds. PII is evaluated first, toxicity second. Either can veto the detection-based decision.

```python
# -- PII guardrail -------------------------------------------------
# Thresholds from: policy["guardrails"]["pii"]
# NOT from:        policy["thresholds"]

if pii_score >= pii_block_threshold:
    decision       = "BLOCK"
    primary_reason = "PII_GUARDRAIL_BLOCK"
    return  # detection decision bypassed

elif pii_score >= pii_sanitize_threshold:
    decision       = "SANITIZE"
    primary_reason = "PII_GUARDRAIL_SANITIZE"
    return  # detection decision bypassed

# -- Toxicity guardrail --------------------------------------------
# Thresholds from: policy["guardrails"]["toxicity"]
# Score source:    ToxicityDetector.detect_from_ml() - no extra inference

if toxicity_score >= tox_block_threshold:
    decision       = "BLOCK"
    primary_reason = "TOXICITY_GUARDRAIL_BLOCK"
    return  # detection decision bypassed

elif toxicity_score >= tox_sanitize_threshold:
    decision       = "SANITIZE"
    primary_reason = "TOXICITY_GUARDRAIL_SANITIZE"
    return  # detection decision bypassed
```

**Why toxicity uses a separate guardrail rather than the detection risk score:**

The ML detector contributes toxicity at weight 0.30. A pure-toxicity input with `ml_score = 0.9` produces `risk_score = 0.27` - below the default sanitize threshold of 0.4. The toxicity guardrail reads the raw ML toxicity confidence directly, bypassing the weighted aggregation entirely, so a strong toxicity signal cannot be diluted by lower-scoring detectors.

**Guardrail failure -> BLOCK + SYSTEM_ERROR** (fail closed - data protection non-negotiable).

---

## 5. Primary Reason - Full Logic

```python
def compute_primary_reason(
    detection_failed,
    pii_guardrail_triggered,      pii_score,
    toxicity_guardrail_triggered, toxicity_score,
    rule_score, ml_score, llm_score,
    pii_block_threshold,      pii_sanitize_threshold,
    tox_block_threshold,      tox_sanitize_threshold,
) -> str:

    # Priority 1: system failure
    # MUST check before anything else
    # Returning NO_THREAT_DETECTED when detection failed is wrong
    if detection_failed:
        return "SYSTEM_ERROR"

    # Priority 2: PII guardrail override
    if pii_guardrail_triggered:
        if pii_score >= pii_block_threshold:
            return "PII_GUARDRAIL_BLOCK"
        return "PII_GUARDRAIL_SANITIZE"

    # Priority 3: toxicity guardrail override
    if toxicity_guardrail_triggered:
        tox_bt = tox_block_threshold if tox_block_threshold is not None else pii_block_threshold
        if toxicity_score >= tox_bt:
            return "TOXICITY_GUARDRAIL_BLOCK"
        return "TOXICITY_GUARDRAIL_SANITIZE"

    # Priority 4: dominant detection layer
    scores = {
        "RULE_DETECTOR": rule_score,
        "ML_DETECTOR":   ml_score,
        "LLM_DETECTOR":  llm_score,
    }
    max_score = max(scores.values())
    if max_score > 0.0:
        return max(scores, key=scores.get)

    # Priority 5: genuinely clean input
    # Only reachable when:
    #   - detection_failed is False (detectors ran successfully)
    #   - no guardrail triggered
    #   - all detection scores = 0.0
    return "NO_THREAT_DETECTED"
```

**All values and audit meaning:**

| Value | Trigger | Confidence | Remediation |
|---|---|---|---|
| `RULE_DETECTOR` | Rule highest score | computed | Review rule patterns |
| `ML_DETECTOR` | ML highest score | computed | Review model thresholds |
| `LLM_DETECTOR` | LLM highest score | computed | Review LLM prompt |
| `PII_GUARDRAIL_BLOCK` | pii_score >= pii_block_threshold | tiered 0.90-0.95 | Data handling review |
| `PII_GUARDRAIL_SANITIZE` | pii_score >= pii_sanitize_threshold | tiered 0.70-0.84 | Monitor sanitisation |
| `TOXICITY_GUARDRAIL_BLOCK` | toxicity_score >= tox_block_threshold | tiered 0.90-0.95 | Content policy review |
| `TOXICITY_GUARDRAIL_SANITIZE` | toxicity_score >= tox_sanitize_threshold | tiered 0.70-0.84 | Monitor sanitisation |
| `NO_THREAT_DETECTED` | detection succeeded, all scores = 0 | computed | No action |
| `SYSTEM_ERROR` | detection_failed=True OR system exception | 0.0 (LOW) | Alert ops immediately |

---

## 6. Confidence Score

**`risk_score` vs `confidence` - definitions:**

```
risk_score   = likelihood of a detected threat (detection only, 0.0-1.0)
confidence   = certainty of the decision (agreement between detectors, 0.0-1.0)
```

confidence reflects agreement between detectors, not probability of attack. These measure different things. A high `risk_score` with low `confidence` means detectors disagree on severity. A high `risk_score` with high `confidence` means strong, consistent signal - most trustworthy. Both fields are always present in responses.

### Detector Confidence

```python
invoked_scores = [s for s, active in [
    (rule_score, rule_enabled),
    (ml_score,   ml_enabled),
    (llm_score,  llm_invoked),
] if active]

if len(invoked_scores) <= 1:
    confidence = 1.0
else:
    variance   = statistics.variance(invoked_scores)
    confidence = 1 / (1 + variance * 5)  # scaled inverse

# Floor for strong signals
if max(invoked_scores) >= 0.8:
    confidence = max(confidence, 0.75)
```

**Single-detector confidence note:** When only one detector is active (e.g. LLM disabled, only rule fires), `len(invoked_scores) <= 1` evaluates to `True` and `confidence = 1.0`. This is expected behaviour - confidence reflects agreement between active detectors, not absolute correctness. `confidence = 1.0` from a single-detector path does not imply stronger certainty than a multi-detector path with high agreement.

### Guardrail Confidence (Tiered)

The same formula is used for both PII and toxicity guardrails. The guardrail score is passed as the input regardless of which guardrail triggered.

```python
def guardrail_confidence(score, block_threshold, sanitize_threshold) -> float:
    if score >= block_threshold:
        raw = 0.90 + (min(score, 1.0) - block_threshold) * 0.05
        return round(min(raw, 0.95), 4)

    elif score >= sanitize_threshold:
        raw = 0.70 + (score - sanitize_threshold) * 0.20
        return round(min(raw, 0.84), 4)

    return 0.0

# PII path:      guardrail_confidence(pii_score,      pii_block_threshold, pii_sanitize_threshold)
# Toxicity path: guardrail_confidence(toxicity_score, tox_block_threshold, tox_sanitize_threshold)
```

### Failure Path Confidence

```python
# All failure paths - no exceptions
confidence      = 0.0
confidence_band = "LOW"
primary_reason  = "SYSTEM_ERROR"
```

**Confidence bands:**

| Band | Range | Meaning |
|---|---|---|
| `HIGH` | >= 0.7 | Trust the decision |
| `MEDIUM` | >= 0.4 and < 0.7 | Monitor |
| `LOW` | < 0.4 | Human review or system failure |

---

## 7. Complete Response Examples

**Prompt injection BLOCK:**
```json
{
  "decision": "BLOCK", "decision_version": "v1.0",
  "risk_score": 0.85, "primary_reason": "RULE_DETECTOR",
  "confidence": 0.75, "confidence_band": "HIGH",
  "sanitization_applied": false, "threats": ["PROMPT_INJECTION"]
}
```

**PII guardrail BLOCK (risk_score = 0.0 - detection not involved):**
```json
{
  "decision": "BLOCK", "decision_version": "v1.0",
  "risk_score": 0.0, "primary_reason": "PII_GUARDRAIL_BLOCK",
  "confidence": 0.9015, "confidence_band": "HIGH",
  "sanitization_applied": false, "threats": ["PII"]
}
```

**PII guardrail SANITIZE:**
```json
{
  "decision": "SANITIZE", "decision_version": "v1.0",
  "risk_score": 0.0, "primary_reason": "PII_GUARDRAIL_SANITIZE",
  "confidence": 0.730, "confidence_band": "HIGH",
  "sanitization_applied": true,
  "sanitized_input": "My email is [EMAIL] and SSN is [SSN]",
  "threats": ["PII"]
}
```

**Toxicity guardrail BLOCK (risk_score = 0.0 - detection not involved):**
```json
{
  "decision": "BLOCK", "decision_version": "v1.0",
  "risk_score": 0.0, "primary_reason": "TOXICITY_GUARDRAIL_BLOCK",
  "confidence": 0.9015, "confidence_band": "HIGH",
  "sanitization_applied": false, "threats": ["TOXICITY"]
}
```

**Clean input - detection succeeded, all scores = 0.0:**
```json
{
  "decision": "ALLOW", "decision_version": "v1.0",
  "risk_score": 0.0, "primary_reason": "NO_THREAT_DETECTED",
  "confidence": 0.999, "confidence_band": "HIGH",
  "sanitization_applied": false, "threats": []
}
```

**All detectors failed (fail open - SYSTEM_ERROR, NOT NO_THREAT_DETECTED):**
```json
{
  "decision": "ALLOW", "decision_version": "v1.0",
  "risk_score": 0.0, "primary_reason": "SYSTEM_ERROR",
  "confidence": 0.0, "confidence_band": "LOW",
  "sanitization_applied": false, "threats": []
}
```

**Gateway/guardrail exception (fail closed):**
```json
{
  "decision": "BLOCK", "decision_version": "v1.0",
  "risk_score": 1.0, "primary_reason": "SYSTEM_ERROR",
  "confidence": 0.0, "confidence_band": "LOW",
  "sanitization_applied": false, "threats": []
}
```

---

## 8. Failure Mode Contract

| Scenario | Decision | Risk Score | Confidence | Primary Reason |
|---|---|---|---|---|
| All detectors succeed, clean | ALLOW | 0.0 | HIGH | `NO_THREAT_DETECTED` |
| All detectors succeed, threat | BLOCK/SANITIZE | > 0 | computed | RULE/ML/LLM_DETECTOR |
| One detector fails | continues | from remaining | from remaining | per remaining |
| **All detectors fail** | **ALLOW** | **0.0** | **LOW (0.0)** | **`SYSTEM_ERROR`** |
| PII guardrail fails | BLOCK | 1.0 | LOW (0.0) | `SYSTEM_ERROR` |
| Gateway exception | BLOCK | 1.0 | LOW (0.0) | `SYSTEM_ERROR` |
| LLM timeout (detection) | continues | from rule+ML | from rule+ML | RULE/ML |
| LLM timeout (proxy) | per detection | per detection | per detection | per detection |

**Critical consistency guarantee:**

`NO_THREAT_DETECTED` and `SYSTEM_ERROR` are produced by mutually exclusive code paths. `NO_THREAT_DETECTED` is only reachable when `detection_failed=False` AND all scores are 0.0 (input was clean and detectors ran). `SYSTEM_ERROR` is always returned when `detection_failed=True`. These two values can never appear for the same condition.

---

## 9. Implementation Status

### Implemented

```
Rule, ML, LLM detectors with per-detector try/catch
PII guardrail (22+ entity types, input + output via InputGuard / OutputGuard)
Toxicity guardrail (ToxicityDetector, reads ML label 6, ~0ms additional latency)
  primary_reason values: TOXICITY_GUARDRAIL_BLOCK / TOXICITY_GUARDRAIL_SANITIZE
  priority order: PII (1st) -> Toxicity (2nd) -> Detection pipeline (3rd)
detection_failed flag - SYSTEM_ERROR vs NO_THREAT_DETECTED never confused
Input limit: 8000 chars + ceil(len/2) > 4000 token heuristic -> 422
Guardrail-first enforcement
Guardrail thresholds DECOUPLED from detection thresholds
risk_score = rule*0.40 + ml*0.30 + llm*0.30 (PII and toxicity excluded)
Primary reason - 9 values, strict priority order
All failure paths return SYSTEM_ERROR + confidence=0.0 + LOW band
Confidence: scaled inverse variance + tiered guardrail + failure=0.0
decision_version - "v1.0"
sanitization_applied - explicit boolean
Idempotency-Key: 409 on same key + different body
ULID trace IDs
Rate limiting per API key with X-RateLimit-* headers
Audit log retention configurable via Settings UI
Policy resolution: system -> tenant -> department
```

### Planned

```
- Per-model token counting with tiktoken (replaces heuristic)
- Application-level policy overrides
- Per-layer latency in debug mode
- ML model improvement (3000+ samples)
```

### Future

```
- Confidence-driven adaptive thresholds
- Human review queue for LOW confidence
- Model retraining pipeline
```

---

> **Secure by default - Explainable by design - Auditable by architecture**

*Version: 1.0 - May 2026*
