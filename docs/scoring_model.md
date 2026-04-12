# WrapSec Risk Scoring & Confidence Model

Version: 1.0 — Final  
Implementation status: Fully implemented in V1  
Last updated: April 2026

---

## Design Principles

**Separation of concerns**

Detectors and guardrails are architecturally and mathematically separate. They are stored separately in the database, evaluated independently, and never mixed in scoring.

- Detectors — identify malicious intent (probabilistic signals)
- Guardrails — enforce data protection policies (deterministic rules)

**Guardrail-first enforcement**

Guardrail decisions override detection-based decisions unconditionally. Guardrail scores never contribute to the detection risk score. This is not a future plan — it is implemented and active in V1.

**Deterministic decisions**

Same input + same thresholds = same output, always. Configurable thresholds are applied from the database at request time.

**Explainability by design**

Every decision includes:
- `primary_reason` — which layer drove the decision
- `confidence` — how certain the system is
- `confidence_band` — HIGH / MEDIUM / LOW
- `decision_version` — which algorithm version produced this result
- `sanitization_applied` — explicit flag when input was sanitised

**Failure-safe behaviour**

Detection failure → ALLOW + LOW confidence (fail open — clean requests should not be blocked due to system errors)
Guardrail failure → BLOCK (fail closed — data protection is non-negotiable)
System failure → BLOCK + confidence=LOW + primary_reason=SYSTEM_ERROR

---

## Scoring Pipeline

```
Input
  │
  ├─► [1] Input Guard
  │       PII detection (22+ entity types)
  │       Redaction before detection layers run
  │
  ├─► [2] Rule Detector
  │       Regex + heuristic patterns
  │       Categories: PROMPT_INJECTION, JAILBREAK,
  │       MALICIOUS_INTENT, DATA_EXFILTRATION, TOXICITY
  │       Latency: ~0ms
  │
  ├─► [3] ML Classifier
  │       TF-IDF + LogisticRegression
  │       Latency: ~5ms
  │
  ├─► [4] LLM Detector (conditional)
  │       Only in "full" mode AND pre-score >= llm_trigger
  │       Uses configured provider (Ollama/OpenAI/Groq)
  │       Latency: ~100–500ms
  │       Timeout → llm_score=0.0, llm_invoked=false, continues
  │
  ├─► [5] Detection Risk Score
  │       Weighted aggregation — detectors only
  │       PII explicitly excluded
  │       Boost if any detector >= 0.5
  │
  ├─► [6] Guardrail Evaluation (override layer)
  │       PII evaluated independently
  │       Overrides detection decision if triggered
  │
  ├─► [7] Policy Engine
  │       Guardrail decision applied first
  │       Detection-based decision if no guardrail triggered
  │
  ├─► [8] Confidence Score
  │       Detector: scaled inverse variance of invoked layers
  │       Guardrail: tiered formula (0.90–0.95 BLOCK, 0.70–0.84 SANITIZE)
  │       Failure path: 0.0 (LOW)
  │
  └─► [9] Primary Reason + Response
          decision, decision_version, risk_score,
          primary_reason, confidence, confidence_band,
          sanitization_applied, threats
```

---

## 1. Signal Normalisation

All components output a score in `[0.0 – 1.0]`.

**Detection layers (probabilistic):**
- `rule_score` — regex and heuristic patterns
- `ml_score` — TF-IDF + LogisticRegression classifier
- `llm_score` — LLM semantic analysis (conditional)

**Guardrail layers (deterministic):**
- `pii_score` — 22+ PII entity types, input and output
- *(future: `toxicity_score`, `bias_score`, `copyright_score`)*

These two groups are stored in separate JSONB columns in `audit_logs`:
- `detection_scores: {"rule": 0.85, "ml": 0.30, "llm": 0.00}`
- `guardrail_scores: {"pii": 0.73}`

---

## 2. Detection Risk Score

Weighted aggregation of detection layer signals only. PII and guardrails are excluded — mixing them would allow a high PII score to suppress a low threat score, which is architecturally wrong.

```python
risk_score = (
    0.40 * rule_score +
    0.30 * ml_score   +
    0.30 * llm_score
)
```

**Weight rationale:**
- Rule detector is deterministic with high precision → highest weight (0.40)
- ML and LLM provide contextual and semantic signals equally (0.30 each)

**Boost mechanism:**

A strong signal from a single detector should not be diluted by lower or zero scores on inactive layers.

```python
max_detector_score = max(rule_score, ml_score, llm_score)
if max_detector_score >= 0.5:
    risk_score = max(risk_score, max_detector_score)
```

**LLM conditional invocation:**

LLM detector is only called when:
- `detection_mode = "full"`
- pre-score (max of rule + ML + PII) >= `llm_trigger` threshold (default: 0.2, configurable)

In fast mode, `llm_score = 0.0` always.

**LLM timeout behaviour:**

If LLM times out during detection:
- `llm_score = 0.0`, `llm_invoked = false`
- Detection continues with rule + ML scores only
- Warning logged with trace_id

---

## 3. Guardrail Evaluation

Guardrails enforce data protection policies independent of threat detection. They evaluate after the risk score is computed but before the policy engine applies it.

```python
# Uses the same configurable thresholds as the policy engine
if pii_score >= block_threshold:
    decision       = "BLOCK"
    primary_reason = "PII_GUARDRAIL_BLOCK"
    return  # policy engine is bypassed

elif pii_score >= sanitize_threshold:
    decision       = "SANITIZE"
    primary_reason = "PII_GUARDRAIL_SANITIZE"
    return  # policy engine is bypassed

# No guardrail triggered → proceed to policy engine
```

**Key properties:**
- Uses the same `block_threshold` and `sanitize_threshold` as the detection policy
- When thresholds change at runtime, guardrail behaviour updates immediately
- Guardrail failure → BLOCK (fail closed)
- Extensible: future guardrails (toxicity, bias) follow the same pattern

**Why split PII_GUARDRAIL_BLOCK and PII_GUARDRAIL_SANITIZE:**

These are different compliance events. A PII block means the request was stopped entirely. A PII sanitize means the request was allowed through with PII redacted. Auditors and compliance officers need to distinguish between these in reports and remediation workflows.

---

## 4. Policy Engine

Applied only when no guardrail is triggered.

```python
if risk_score >= block_threshold:
    decision       = "BLOCK"
    primary_reason = dominant_detector(rule, ml, llm)

elif risk_score >= sanitize_threshold:
    decision       = "SANITIZE"
    primary_reason = dominant_detector(rule, ml, llm)

else:
    decision       = "ALLOW"
    primary_reason = "NO_THREAT_DETECTED"
```

**Thresholds (runtime configurable — no restart):**

```
Default: block=0.7, sanitize=0.4
Validation:
  block > 0.0 and <= 1.0
  sanitize >= 0.0 and < 1.0
  block > sanitize
```

---

## 5. Primary Reason

Identifies the single dominant factor behind the decision.

```python
def compute_primary_reason(
    guardrail_triggered, pii_score,
    rule_score, ml_score, llm_score,
    block_threshold, sanitize_threshold
) -> str:

    # Guardrail takes absolute priority
    if guardrail_triggered:
        if pii_score >= block_threshold:
            return "PII_GUARDRAIL_BLOCK"
        return "PII_GUARDRAIL_SANITIZE"

    # Find dominant detector
    scores = {
        "RULE_DETECTOR": rule_score,
        "ML_DETECTOR":   ml_score,
        "LLM_DETECTOR":  llm_score,
    }
    max_score = max(scores.values())
    if max_score <= 0.0:
        return "NO_THREAT_DETECTED"

    return max(scores, key=scores.get)
```

**All values:**

| Value | Trigger |
|---|---|
| `RULE_DETECTOR` | Rule layer had the highest detection score |
| `ML_DETECTOR` | ML classifier had the highest detection score |
| `LLM_DETECTOR` | LLM semantic analysis had the highest score |
| `PII_GUARDRAIL_BLOCK` | PII score exceeded block threshold |
| `PII_GUARDRAIL_SANITIZE` | PII score exceeded sanitize threshold |
| `NO_THREAT_DETECTED` | All scores below thresholds |
| `SYSTEM_ERROR` | Unexpected failure — decision defaulted to BLOCK |

---

## 6. Confidence Score

Confidence represents the system's certainty about its decision, independent of risk level.

```
High risk + HIGH confidence → certain threat, trust the BLOCK
High risk + LOW confidence  → probable threat, flag for human review
Low risk  + HIGH confidence → certainly clean, trust the ALLOW
Low risk  + LOW confidence  → uncertain, monitor closely
```

### Detector Confidence

Measures agreement across layers that were actually invoked. Excludes layers not invoked (e.g. LLM in fast mode) to prevent false variance inflation.

```python
invoked_scores = [
    s for s, active in [
        (rule_score, rule_enabled),
        (ml_score,   ml_enabled),
        (llm_score,  llm_invoked),
    ]
    if active
]

if len(invoked_scores) <= 1:
    confidence = 1.0  # single layer — no disagreement possible
else:
    variance   = np.var(invoked_scores)
    confidence = 1 / (1 + variance * 5)  # scaled inverse — not 1-variance

# Confidence floor for strong deterministic signals
max_score = max(invoked_scores)
if max_score >= 0.8:
    confidence = max(confidence, 0.75)
```

**Why `1 / (1 + variance * 5)` not `1 - variance`:**

`1 - variance` compresses confidence into a narrow high range — even strong disagreement yields values above 0.85. The scaled inverse spreads confidence meaningfully across all three bands.

**Examples:**

```
All layers agree (full mode):
  rule=0.85, ml=0.80, llm=0.90 → variance=0.0017 → confidence=0.992 → HIGH

Fast mode (LLM excluded):
  rule=0.85, ml=0.30 → variance=0.076 → confidence=0.724
  + floor (max=0.85 >= 0.8) → confidence=max(0.724, 0.75)=0.75 → HIGH

Strong disagreement:
  rule=0.85, ml=0.10, llm=0.15 → variance=0.103 → confidence=0.660
  + floor → confidence=max(0.660, 0.75)=0.75 → HIGH

Moderate disagreement:
  rule=0.55, ml=0.15, llm=0.20 → variance=0.028 → confidence=0.877 → HIGH

Weak signals:
  rule=0.30, ml=0.10, llm=0.25 → variance=0.007 → confidence=0.966 → HIGH
  (low scores agree — system is confidently seeing nothing serious)
```

### Guardrail Confidence (Tiered)

Guardrails are deterministic. Confidence is always high but scales with how clearly the threshold was exceeded.

```python
if pii_score >= block_threshold:
    # BLOCK band: 0.90 – 0.95
    confidence = 0.90 + (min(pii_score, 1.0) - block_threshold) * 0.05
    confidence = min(confidence, 0.95)  # never claim 100%

elif pii_score >= sanitize_threshold:
    # SANITIZE band: 0.70 – 0.84
    confidence = 0.70 + (pii_score - sanitize_threshold) * 0.20
    confidence = min(confidence, 0.84)

else:
    confidence = 0.0
```

**Why 0.95 ceiling:** No automated system should claim 100% confidence. The ceiling preserves epistemic humility and prevents overconfidence in compliance reports.

**Examples:**

```
BLOCK-level PII (score=0.73, threshold=0.7):
  0.90 + (0.73-0.70)*0.05 = 0.9015 → HIGH

SANITIZE-level PII (score=0.55, threshold=0.4):
  0.70 + (0.55-0.40)*0.20 = 0.730 → HIGH

Marginal SANITIZE (score=0.41, threshold=0.4):
  0.70 + (0.41-0.40)*0.20 = 0.702 → HIGH
  (even marginal — guardrail is deterministic, certainty is appropriate)
```

### Failure Path Confidence

```python
# System error in gateway except block
confidence      = 0.0
confidence_band = "LOW"
primary_reason  = "SYSTEM_ERROR"
```

LOW confidence on system errors signals to operators that the BLOCK decision came from a failure, not a genuine threat detection.

### Final Confidence Assembly

```python
if guardrail_triggered:
    confidence = guardrail_confidence(pii_score, block_threshold, sanitize_threshold)
else:
    confidence = detector_confidence(invoked_scores)

confidence      = round(min(confidence, 1.0), 4)
confidence_band = get_confidence_band(confidence)
```

### Confidence Bands

| Band | Range | Meaning | Recommended action |
|---|---|---|---|
| `HIGH` | 0.7 – 1.0 | Strong, consistent signal | Trust automated decision |
| `MEDIUM` | 0.4 – 0.7 | Moderate or partial agreement | Automated decision + monitoring |
| `LOW` | 0.0 – 0.4 | Weak, conflicting, or failure | Flag for human review |

---

## 7. Complete Response

```json
{
  "trace_id":             "req_01knzhh81wrwg2r8r7wnwq139y",
  "decision":             "BLOCK",
  "decision_version":     "v1.0",
  "risk_score":           0.85,
  "primary_reason":       "RULE_DETECTOR",
  "confidence":           0.75,
  "confidence_band":      "HIGH",
  "sanitization_applied": false,
  "threats":              ["PROMPT_INJECTION"],
  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only",
    "policy_source":  "department_override"
  }
}
```

**PII guardrail BLOCK:**

```json
{
  "trace_id":             "req_01knzhj2...",
  "decision":             "BLOCK",
  "decision_version":     "v1.0",
  "risk_score":           0.0,
  "primary_reason":       "PII_GUARDRAIL_BLOCK",
  "confidence":           0.9015,
  "confidence_band":      "HIGH",
  "sanitization_applied": false,
  "threats":              ["PII"]
}
```

**PII guardrail SANITIZE:**

```json
{
  "trace_id":             "req_01knzhk3...",
  "decision":             "SANITIZE",
  "decision_version":     "v1.0",
  "risk_score":           0.0,
  "primary_reason":       "PII_GUARDRAIL_SANITIZE",
  "confidence":           0.730,
  "confidence_band":      "HIGH",
  "sanitization_applied": true,
  "sanitized_input":      "My email is [EMAIL] and SSN is [SSN]",
  "threats":              ["PII"]
}
```

**System failure:**

```json
{
  "trace_id":             "req_01knzhl4...",
  "decision":             "BLOCK",
  "decision_version":     "v1.0",
  "risk_score":           1.0,
  "primary_reason":       "SYSTEM_ERROR",
  "confidence":           0.0,
  "confidence_band":      "LOW",
  "sanitization_applied": false,
  "threats":              []
}
```

---

## 8. Audit Database Schema

```sql
audit_logs:

-- Decision fields
decision             VARCHAR   -- "BLOCK" | "SANITIZE" | "ALLOW"
risk_score           FLOAT     -- detection risk score (0.0–1.0)
confidence           FLOAT     -- confidence score (0.0–1.0)
confidence_band      VARCHAR   -- "HIGH" | "MEDIUM" | "LOW"
primary_reason       VARCHAR   -- dominant factor
policy_source        VARCHAR   -- which hierarchy level applied
decision_version     VARCHAR   -- "v1.0" (stored via response, not direct column)

-- Layer scores (stored separately by type)
detection_scores     JSONB     -- {"rule": 0.85, "ml": 0.30, "llm": 0.00}
guardrail_scores     JSONB     -- {"pii": 0.73}

-- Attribution
key_id               VARCHAR   -- which API key
dept_id              VARCHAR   -- which department
app_id               VARCHAR   -- which application
user_id              VARCHAR   -- self-reported (attribution_verified=false)
ip_address           VARCHAR   -- network origin
attribution_verified BOOLEAN   -- false in V1, true with JWT in V2
```

---

## 9. Failure Mode Contract

| Scenario | Decision | Risk Score | Confidence | Primary Reason |
|---|---|---|---|---|
| All detectors succeed | per scoring | computed | computed | per scoring |
| One detector fails | continues with others | from remaining | from remaining | per remaining |
| All detectors fail | ALLOW | 0.0 | LOW (0.0) | NO_THREAT_DETECTED |
| Guardrail (PII) fails | BLOCK | 1.0 | LOW (0.0) | SYSTEM_ERROR |
| Gateway exception | BLOCK | 1.0 | LOW (0.0) | SYSTEM_ERROR |
| LLM timeout (detection) | continues | from rule+ML | from rule+ML | RULE/ML_DETECTOR |
| LLM timeout (proxy) | per detection | per detection | per detection | per detection |

---

## 10. Implementation Status

### V1.0 — Fully Implemented

```
✅ Rule, ML, LLM detection layers
✅ PII guardrail (22+ entity types, input + output)
✅ Guardrail-first enforcement
   risk_score = rule*0.40 + ml*0.30 + llm*0.30
   PII not in weighted aggregation
✅ Boost mechanism (floor at max detector score >= 0.5)
✅ BLOCK / SANITIZE / ALLOW decisions
✅ Runtime configurable thresholds (no restart)
✅ Runtime configurable layer toggles (no restart)
✅ Primary reason — 7 possible values including SYSTEM_ERROR
✅ Confidence score (scaled inverse variance)
✅ Tiered guardrail confidence (0.90–0.95 BLOCK, 0.70–0.84 SANITIZE)
✅ Confidence floor for strong signals (>= 0.8 → min 0.75)
✅ confidence_band — HIGH / MEDIUM / LOW
✅ decision_version — "v1.0" in every response
✅ sanitization_applied — explicit boolean flag
✅ Failure mode confidence=LOW + primary_reason=SYSTEM_ERROR
✅ LLM timeout graceful degradation
✅ detection_scores + guardrail_scores in DB (separate JSONB)
✅ Policy resolution: system → tenant → department
✅ Department-level threshold overrides with deep merge
✅ ULID trace IDs (time-sortable)
```

### V1.1 — Planned

```
→ Application-level policy overrides
→ Per-layer latency breakdown in debug mode
→ Idempotency improved with per-key cache scoping
→ Toxicity guardrail layer
→ ML model improvement (3000+ training samples)
→ Confidence calibration from production data
```

### V2.0 — Future

```
→ Role-based policy overrides (requires JWT)
→ Confidence-driven adaptive thresholds
→ Human review queue for LOW confidence decisions
→ Model retraining pipeline from confirmed true positives
→ Multi-model ensemble scoring
→ Streaming support
```

---

## Summary

```
Detection layers (intent)
  rule × 0.40 + ml × 0.30 + llm × 0.30
  + boost if any detector >= 0.5
  → detection risk_score

Guardrail layer (data protection — always first)
  pii >= block_threshold    → BLOCK (override)
  pii >= sanitize_threshold → SANITIZE (override)

Policy engine (if no guardrail triggered)
  risk_score thresholds → BLOCK / SANITIZE / ALLOW

Confidence (certainty)
  detector: scaled inverse variance of invoked layers
  guardrail: tiered formula by threshold proximity
  failure:   0.0 (LOW)

Primary reason (explainability)
  which layer drove the decision

Response
  decision + decision_version + risk_score
  + primary_reason + confidence + confidence_band
  + sanitization_applied + threats
```

> **Secure by default · Explainable by design · Auditable by architecture**

---

*Version: 1.0 — Final*  
*All features active in V1*  
*Last updated: April 2026*
