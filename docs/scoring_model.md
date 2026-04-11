# WrapSec Risk Scoring & Confidence Model

WrapSec uses a hybrid risk scoring and confidence model to evaluate incoming requests, combining probabilistic detection signals with deterministic guardrails. This ensures decisions are accurate, explainable, and compliant with enterprise security practices.

---

## Design Principles

**Separation of concerns**
- *Detectors* identify malicious intent (probabilistic)
- *Guardrails* enforce data protection policies (deterministic)

**Guardrail-first enforcement**
- Data protection rules override all detection signals independently
- Guardrail scores are never mixed into the detection risk score

**Deterministic decisions**
- Same input always produces the same output given the same thresholds

**Explainability by design**
- Every decision includes a `primary_reason` identifying the dominant factor
- Per-layer scores are stored in the audit trail for compliance

**Confidence-aware**
- The system knows what it does not know
- Low confidence decisions are flagged for human review

---

## Scoring Pipeline Overview

```
Input
  │
  ├─► Input Guard (PII detection + redaction)
  │
  ├─► Detection Layers
  │     ├─► Rule Detector    (deterministic, ~0ms)
  │     ├─► ML Classifier    (probabilistic, ~5ms)
  │     └─► LLM Detector     (semantic, conditional)
  │
  ├─► Detection Risk Score   (weighted aggregation + boost)
  │
  ├─► Guardrail Layers
  │     ├─► PII Guardrail    (deterministic override)
  │     └─► (future: toxicity, bias, copyright)
  │
  ├─► Policy Engine          (BLOCK / SANITIZE / ALLOW)
  │
  ├─► Confidence Score       (certainty of decision)
  │
  └─► Primary Reason         (dominant factor)
```

---

## 1. Signal Normalisation

All components output a score in the range `[0.0 – 1.0]`.

**Detection layers (probabilistic):**
- `rule_score` — regex and heuristic pattern matching
- `ml_score` — TF-IDF + LogisticRegression classifier
- `llm_score` — LLM semantic analysis (conditional invocation)

**Guardrail layers (deterministic):**
- `pii_score` — PII detection across 22+ entity types
- *(future: `toxicity_score`, `bias_score`, `copyright_score`)*

**Naming convention:**
- `risk_score` — the final aggregated detection score (external API)
- `detection_scores` — per-layer detector scores (audit DB)
- `guardrail_scores` — per-layer guardrail scores (audit DB)

---

## 2. Detection Risk Score

A weighted aggregation of detector signals only. Guardrail scores are evaluated separately and never dilute or inflate the detection signal.

```python
risk_score = (
    0.40 * rule_score +
    0.30 * ml_score +
    0.30 * llm_score
)
```

**Weight rationale:**
- Rule-based detection has the highest precision → highest weight (0.40)
- ML and LLM provide contextual and semantic signals equally (0.30 each)
- PII is excluded — it is a guardrail, not a threat detector

**Boost mechanism:**

If any single detector fires with a score >= 0.5, the final risk score is floored at that value. This prevents a strong signal from being diluted by low scores on inactive or uncertain layers.

```python
max_detector_score = max(rule_score, ml_score, llm_score)
if max_detector_score >= 0.5:
    risk_score = max(risk_score, max_detector_score)
```

---

## 3. Guardrail Evaluation (Override Layer)

Guardrails enforce data protection policies independently of threat detection. A guardrail decision overrides the detection-based decision when triggered.

```python
if pii_score >= block_threshold:
    guardrail_decision  = "BLOCK"
    guardrail_triggered = True
    primary_reason      = "PII_GUARDRAIL_BLOCK"

elif pii_score >= sanitize_threshold:
    guardrail_decision  = "SANITIZE"
    guardrail_triggered = True
    primary_reason      = "PII_GUARDRAIL_SANITIZE"

else:
    guardrail_triggered = False
```

**Granular primary_reason values for PII:**

| Value | Trigger | Meaning |
|---|---|---|
| `PII_GUARDRAIL_BLOCK` | `pii_score >= block_threshold` | PII score exceeded block threshold |
| `PII_GUARDRAIL_SANITIZE` | `pii_score >= sanitize_threshold` | PII score exceeded sanitize threshold |

This distinction is important for compliance reporting — a PII block and a PII sanitize represent different risk levels and require different remediation responses.

**Extensibility — multi-guardrail resolution (future):**

```python
# Each guardrail evaluates independently
# Most restrictive decision wins
final_guardrail_decision = most_restrictive(
    pii_decision,
    toxicity_decision,
    bias_decision,
)
```

**Key property:** Guardrails use the same configurable thresholds as the policy engine. When thresholds are adjusted at runtime, guardrail behaviour adjusts immediately — no restart required.

---

## 4. Policy Engine (Detection-Based Decision)

Applied only if no guardrail override is triggered.

```python
if not guardrail_triggered:
    if risk_score >= block_threshold:
        decision       = "BLOCK"
        primary_reason = dominant_detector(rule_score, ml_score, llm_score)

    elif risk_score >= sanitize_threshold:
        decision       = "SANITIZE"
        primary_reason = dominant_detector(rule_score, ml_score, llm_score)

    else:
        decision       = "ALLOW"
        primary_reason = "NO_THREAT_DETECTED"
```

**Default thresholds (configurable at runtime, no restart):**
```
block_threshold:    0.7
sanitize_threshold: 0.4
```

**Validation rules:**
```
block_threshold    > 0.0
block_threshold    <= 1.0
sanitize_threshold >= 0.0
sanitize_threshold < 1.0
block_threshold    > sanitize_threshold
```

---

## 5. Primary Reason (Explainability)

Identifies the single dominant factor behind the decision. Used in audit logs, dashboard display, and compliance reporting.

```python
def dominant_detector(rule_score, ml_score, llm_score) -> str:
    scores = {
        "RULE_DETECTOR": rule_score,
        "ML_DETECTOR":   ml_score,
        "LLM_DETECTOR":  llm_score,
    }
    return max(scores, key=scores.get)
```

**All possible values:**

| Value | Description |
|---|---|
| `RULE_DETECTOR` | Regex or heuristic pattern was the dominant signal |
| `ML_DETECTOR` | ML classifier was the dominant signal |
| `LLM_DETECTOR` | LLM semantic analysis was the dominant signal |
| `PII_GUARDRAIL_BLOCK` | PII guardrail triggered a BLOCK decision |
| `PII_GUARDRAIL_SANITIZE` | PII guardrail triggered a SANITIZE decision |
| `NO_THREAT_DETECTED` | All scores below thresholds — clean request |

---

## 6. Confidence Score

Confidence represents the system's certainty about its assessment, independent of the risk level.

```
High risk + high confidence → certain threat, automated BLOCK
High risk + low confidence  → probable threat, flag for review
Low risk  + high confidence → certainly clean, automated ALLOW
Low risk  + low confidence  → uncertain, monitor closely
```

> **Implementation note:** Confidence is targeted for v1.1 after production traffic data is available to validate calibration. The formulas below are the specification.

### a. Detector Confidence (Agreement-Based)

Measures agreement across all invoked detection layers. Uses a scaled inverse formula for meaningful differentiation across the full confidence range.

```python
# Only include layers that were actually invoked
# Prevents false variance inflation when LLM is skipped (fast mode)
invoked_scores = [
    s for s, invoked in [
        (rule_score, rule_enabled),
        (ml_score,   ml_enabled),
        (llm_score,  llm_invoked),
    ]
    if invoked
]

variance            = np.var(invoked_scores) if len(invoked_scores) > 1 else 0.0
detector_confidence = 1 / (1 + variance * 5)
```

**Why scaled inverse over simple `1 - variance`:**

The simple formula compresses confidence into a narrow high range — even strong disagreement produces values above 0.85. The scaled inverse `1 / (1 + variance * 5)` spreads confidence meaningfully across all three bands.

**Examples:**

```
All layers agree (full mode):
  rule=0.85, ml=0.80, llm=0.90
  variance = 0.0017
  confidence = 1 / (1 + 0.0085) = 0.992 → HIGH ✅

Moderate disagreement (fast mode, LLM not invoked):
  rule=0.85, ml=0.30 (invoked only)
  variance = 0.076
  confidence = 1 / (1 + 0.38) = 0.724 → HIGH ✅

Strong disagreement (full mode, layers disagree):
  rule=0.85, ml=0.10, llm=0.15
  variance = 0.103
  confidence = 1 / (1 + 0.515) = 0.660 → MEDIUM ✅

Single layer only (rule fires, others not invoked):
  invoked = [0.85]
  variance = 0.0 (single value)
  confidence = 1.0 → HIGH ✅
```

### b. Confidence Floor for Strong Signals (Optional Enhancement)

When a deterministic rule fires with a strong signal, confidence should not be downgraded to MEDIUM purely because probabilistic layers disagree. Rules are precise — a strong rule match carries inherent high confidence.

```python
if max(rule_score, ml_score, llm_score) >= 0.8:
    detector_confidence = max(detector_confidence, 0.75)
```

This ensures strong rule detections are always reported as HIGH confidence even when ML or LLM layers are uncertain or disagree.

### c. Guardrail Confidence (Tiered)

Guardrails are deterministic. Confidence scales with how clearly the threshold was exceeded, using a tiered model that reflects the semantic difference between BLOCK and SANITIZE decisions.

```python
if pii_score >= block_threshold:
    # BLOCK-level PII: very high confidence (0.90 – 0.95)
    guardrail_confidence = 0.90 + (min(pii_score, 1.0) - block_threshold) * 0.05

elif pii_score >= sanitize_threshold:
    # SANITIZE-level PII: medium-high confidence (0.70 – 0.84)
    guardrail_confidence = 0.70 + (pii_score - sanitize_threshold) * 0.20

else:
    guardrail_confidence = 0.0
```

**Why 0.95 ceiling:** No automated system should claim 100% confidence. The 0.95 ceiling preserves epistemic humility and prevents overconfidence in audit reports.

**Examples:**

```
BLOCK-level PII (score=0.73, block_threshold=0.7):
  confidence = 0.90 + (0.73 - 0.70) * 0.05 = 0.902 → HIGH ✅

BLOCK-level PII (score=0.95, block_threshold=0.7):
  confidence = 0.90 + (0.95 - 0.70) * 0.05 = 0.913 → HIGH ✅
  (capped behaviour — stays in HIGH band)

SANITIZE-level PII (score=0.65, sanitize_threshold=0.4):
  confidence = 0.70 + (0.65 - 0.40) * 0.20 = 0.750 → HIGH ✅

SANITIZE-level PII (score=0.41, sanitize_threshold=0.4):
  confidence = 0.70 + (0.41 - 0.40) * 0.20 = 0.702 → HIGH ✅
  (even marginal SANITIZE is HIGH confidence — deterministic)
```

### d. Final Confidence

```python
if guardrail_triggered:
    confidence = guardrail_confidence
else:
    confidence = detector_confidence

confidence      = round(min(confidence, 1.0), 4)
confidence_band = get_confidence_band(confidence)
```

### e. Confidence Bands

| Band | Range | Interpretation | Action |
|---|---|---|---|
| `LOW` | 0.0 – 0.4 | Uncertain — system is not confident | Flag for human review |
| `MEDIUM` | 0.4 – 0.7 | Moderately certain | Automated decision + monitoring |
| `HIGH` | 0.7 – 1.0 | Certain | Automated decision trusted |

```python
def get_confidence_band(confidence: float) -> str:
    if confidence >= 0.7: return "HIGH"
    if confidence >= 0.4: return "MEDIUM"
    return "LOW"
```

---

## 7. Complete Decision Flow

```python
def process(request) -> Decision:

    # 1. Detection layer scores
    rule_score = rule_detector.detect(input)
    ml_score   = ml_detector.detect(input)
    llm_score  = llm_detector.detect(input)   # conditional

    # 2. Detection risk score
    risk_score = weighted_aggregate(rule_score, ml_score, llm_score)
    risk_score = apply_boost(risk_score, rule_score, ml_score, llm_score)

    # 3. Guardrail evaluation
    pii_score           = pii_guardrail.detect(input)
    guardrail_triggered = evaluate_guardrail(pii_score)

    # 4. Policy decision
    if guardrail_triggered:
        decision       = guardrail_decision
        primary_reason = guardrail_primary_reason   # PII_GUARDRAIL_BLOCK/SANITIZE
    else:
        decision       = policy_engine.decide(risk_score)
        primary_reason = dominant_detector(rule_score, ml_score, llm_score)

    # 5. Confidence
    if guardrail_triggered:
        confidence = guardrail_confidence(pii_score)
    else:
        confidence = detector_confidence(invoked_scores)
        confidence = apply_confidence_floor(confidence, rule_score, ml_score, llm_score)

    confidence_band = get_confidence_band(confidence)

    return Decision(
        decision        = decision,
        risk_score      = risk_score,
        confidence      = confidence,
        confidence_band = confidence_band,
        primary_reason  = primary_reason,
        threats         = detected_threats,
    )
```

---

## 8. API Response Structure

### Detection threat example

```json
{
  "trace_id":        "req_abc123",
  "decision":        "BLOCK",
  "risk_score":      0.85,
  "confidence":      0.724,
  "confidence_band": "HIGH",
  "primary_reason":  "RULE_DETECTOR",
  "threats":         ["PROMPT_INJECTION"],
  "signals": {
    "detectors": {
      "rule": 0.85,
      "ml":   0.30,
      "llm":  0.00
    },
    "guardrails": {
      "pii": 0.00
    }
  },
  "processing": {
    "latency_ms":     2.1,
    "llm_invoked":    false,
    "detection_mode": "fast",
    "execution_mode": "scan_only"
  }
}
```

### PII guardrail BLOCK example

```json
{
  "trace_id":        "req_def456",
  "decision":        "BLOCK",
  "risk_score":      0.00,
  "confidence":      0.902,
  "confidence_band": "HIGH",
  "primary_reason":  "PII_GUARDRAIL_BLOCK",
  "threats":         ["PII"],
  "signals": {
    "detectors": {
      "rule": 0.00,
      "ml":   0.00,
      "llm":  0.00
    },
    "guardrails": {
      "pii": 0.73
    }
  }
}
```

### PII guardrail SANITIZE example

```json
{
  "trace_id":        "req_ghi789",
  "decision":        "SANITIZE",
  "risk_score":      0.00,
  "confidence":      0.750,
  "confidence_band": "HIGH",
  "primary_reason":  "PII_GUARDRAIL_SANITIZE",
  "threats":         ["PII"],
  "signals": {
    "detectors": {
      "rule": 0.00,
      "ml":   0.00,
      "llm":  0.00
    },
    "guardrails": {
      "pii": 0.65
    }
  }
}
```

### Clean request example

```json
{
  "trace_id":        "req_jkl012",
  "decision":        "ALLOW",
  "risk_score":      0.00,
  "confidence":      1.000,
  "confidence_band": "HIGH",
  "primary_reason":  "NO_THREAT_DETECTED",
  "threats":         [],
  "signals": {
    "detectors": {
      "rule": 0.00,
      "ml":   0.00,
      "llm":  0.00
    },
    "guardrails": {
      "pii": 0.00
    }
  }
}
```

---

## 9. Audit Database Schema

Per-request scores are stored separately by layer type for compliance reporting and future model improvement.

```sql
-- audit_logs table additions for v1.1
detection_scores  JSONB   -- {"rule": 0.85, "ml": 0.30, "llm": 0.00}
guardrail_scores  JSONB   -- {"pii": 0.73}
confidence        FLOAT   -- 0.724
confidence_band   TEXT    -- "HIGH"
primary_reason    TEXT    -- "RULE_DETECTOR"
```

> `detection_scores` and `guardrail_scores` are implemented in v1.0.
> `confidence`, `confidence_band`, and `primary_reason` are targeted for v1.1.

---

## 10. Implementation Roadmap

### v1.0 (Current — implemented)
```
✅ Detection layers — rule, ML, LLM
✅ PII guardrail layer
✅ Weighted risk score with boost mechanism
✅ Policy engine — BLOCK / SANITIZE / ALLOW
✅ Configurable thresholds (runtime, no restart)
✅ Layer toggles (runtime, no restart)
✅ detection_scores + guardrail_scores in DB
✅ Extensible guardrail architecture
✅ Threshold validation (zero protection, range checks)
```

### v1.1 (Next — requires production data for calibration)
```
→ primary_reason field in API response and DB
→ Guardrail-first enforcement
   (remove PII contribution from weighted risk score)
→ Confidence score (scaled inverse variance formula)
→ Tiered guardrail confidence
→ Confidence floor for strong rule signals
→ confidence + confidence_band in API response and DB
→ Unified signals structure in API response
→ LOW confidence flagging in dashboard
```

### v2.0 (Enterprise)
```
→ Human review queue for LOW confidence decisions
→ Confidence-driven adaptive thresholds
→ Additional guardrail layers (toxicity, bias, copyright)
→ Confidence calibration from production data
→ Model retraining pipeline using low-confidence cases
→ Confidence trend analytics in dashboard
```

---

## 11. Key Mathematical Properties

**Monotonicity:** Higher threat signals always produce equal or higher risk scores.

**Idempotency:** Same input + same thresholds = same output, always.

**Bounded outputs:** All scores, confidence values, and risk scores are strictly within `[0.0, 1.0]`.

**Guardrail independence:** Guardrail decisions are never influenced by detector scores. A clean prompt with accidental PII is always treated as a data protection issue, not a threat.

**Confidence non-inflation:** Single-layer fast mode decisions are not assigned artificially low confidence due to missing layers. Only invoked layers contribute to variance.

---

## Summary

```
Detection (intent) + Guardrails (policy) → Decision
                        +
                  Confidence (certainty)
                        +
               Primary Reason (explainability)
```

WrapSec's scoring system ensures:

> **Secure by default · Explainable by design · Scalable for enterprise · Compliant by architecture**

---

*Document version: 1.1-draft*
*Confidence implementation: targeted for v1.1 post production calibration*
*Last updated: April 2026*
