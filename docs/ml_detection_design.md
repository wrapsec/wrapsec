# WrapSec ML Detection Architecture
# Two-Tier Detection, Profile Registry, and V2 Extension Path

Version: 1.0-draft
Status: Approved for implementation
Last updated: May 2026

---

## 1. Context and Goals

### Current state (pre-change)

The ML detection layer is a single TF-IDF + LogisticRegression classifier loaded from
`models/ml_detector.pkl`. It is fast (~1ms) and dependency-light but has no semantic
understanding. A rephrased attack that avoids known patterns passes through undetected.

### Goals

- Add a transformer-based second tier that understands semantic meaning, not just surface patterns
- Keep TF-IDF as a permanent baseline that always runs regardless of transformer availability
- Design the profile registry now so v2 industry-specific profiles require no architectural changes
- Define all operational behaviors explicitly: startup loading, degraded mode, timeouts, health visibility
- Do not touch the scoring pipeline, policy engine, endpoints, or SDK in this change

### Non-goals

- Industry-specific profiles (v2)
- Custom model training pipeline (v2 enterprise)
- Session-level behavioral scoring (v3)
- GPU inference (future, out of scope)

---

## 2. Architecture Overview

### V1 detection pipeline

```
request input
     |
     +-- RuleDetector        (regex patterns, ~0ms)
     |
     +-- DetectionPipeline   (owns Tier 1 + Tier 2)
     |       |
     |       +-- MLDetector (TF-IDF, Tier 1, ~1ms, always runs)
     |       |
     |       +-- TransformerDetector (DeBERTa-v3, Tier 2, ~20-50ms, runs if loaded)
     |       |
     |       +-- combined ml_result (highest-risk-wins)
     |
     +-- LLMDetector         (conditional, full mode only)
     |
     +-- RiskScorer          (unchanged)
     |
     +-- PolicyEngine        (unchanged)
```

`DetectionPipeline` is a new class introduced in v1. It owns the lifecycle of Tier 1 and
Tier 2 detectors and exposes a single `run(text)` method to `GatewayService`. This keeps
detector management out of `GatewayService` and provides a clean boundary for v2 profile
switching.

---

## 3. New Components

### 3.1 DetectionPipeline

**File:** `engine/detection/pipeline.py`

Owns Tier 1 and Tier 2 detector instances. Loaded once at startup via `GatewayService.__init__`.
Accepts a `DetectorProfile` at construction time. In v1 only the `general` profile exists.

Responsibilities:
- Load both detectors at startup using the profile configuration
- Run both detectors in parallel via `asyncio.to_thread`
- Apply 1.5 second timeout to transformer inference
- Combine results using highest-risk-wins logic
- Expose `status()` for health checks

```
DetectionPipeline
  __init__(profile: DetectorProfile)
  async run(text: str) -> DetectionResult
  status() -> dict[str, DetectorStatus]
```

The return value of `run()` is a single `DetectionResult` representing the combined output
of both tiers. `GatewayService` receives this as `ml_result` -- no changes to the
`GatewayService.process()` signature or the rest of the pipeline.

### 3.2 TransformerDetector

**File:** `engine/detection/transformer_detector.py`

Implements `BaseDetector`. Loads
`protectai/deberta-v3-base-prompt-injection-v2` from HuggingFace.

Binary classifier: INJECTION vs SAFE.

- If INJECTION with confidence >= 0.5: returns `DetectionResult` with `PROMPT_INJECTION`
  threat and the confidence score
- Otherwise: returns `DetectionResult.clean()`
- If model not loaded: returns `DetectionResult.clean()` and sets status to DEGRADED
- Model ID is received as a constructor argument, never hardcoded in this file

Loading:
- Eager load at startup inside `DetectionPipeline.__init__`
- If load fails: log `ERROR wrapsec.engine transformer model failed to load -- running in
  degraded detection mode` and set status to DEGRADED
- Never lazy-load on first request

### 3.3 DetectorStatus

**File:** `engine/detection/pipeline.py` (alongside DetectionPipeline)

```python
class DetectorStatus(str, Enum):
    HEALTHY     = "healthy"
    DEGRADED    = "degraded"      # model unavailable, using fallback
    UNAVAILABLE = "unavailable"   # detector disabled by config
```

`DetectionPipeline.status()` returns one `DetectorStatus` per detector:

```python
{
    "tfidf_detector":       DetectorStatus.HEALTHY,
    "transformer_detector": DetectorStatus.DEGRADED,
}
```

This is consumed by the health endpoint and doctor command.

### 3.4 DetectorProfile and Profile Registry

**File:** `engine/detection/profiles.py`

```python
@dataclass
class DetectorProfile:
    name:            str
    tier1_model:     Path    # path to .pkl file
    tier2_model:     str     # HuggingFace model ID
    tier2_timeout:   float   # inference timeout in seconds
    rule_patterns:   str     # pattern set key (maps to rule_detector patterns)
    model_version:   str     # version string logged to audit trail

PROFILE_REGISTRY: dict[str, DetectorProfile] = {
    "general": DetectorProfile(
        name          = "general",
        tier1_model   = REPO_ROOT / "models" / "ml_detector.pkl",
        tier2_model   = "protectai/deberta-v3-base-prompt-injection-v2",
        tier2_timeout = 1.5,
        rule_patterns = "general",
        model_version = "1.0.0",
    ),
}

def get_profile(name: str) -> DetectorProfile:
    return PROFILE_REGISTRY.get(name, PROFILE_REGISTRY["general"])
```

The `general` profile is the only profile in v1. In v2, adding a `healthcare` or `finance`
profile is a single registry entry -- no code changes in any other file.

`model_version` is logged to audit records so operators can reconstruct which model version
produced a given decision. This is a compliance requirement for regulated industry profiles.

---

## 4. Score Combination Logic

### Semantics

The combination is **highest-risk-wins enforcement logic**, not ensemble confidence averaging.
The goal is to catch threats that one tier misses, not to average uncertainty.

```
tfidf fires (0.52), transformer fires (0.81) -> score = 0.81, threat = PROMPT_INJECTION
tfidf fires (0.52), transformer clean        -> score = 0.52, threat from tfidf
tfidf clean,        transformer fires (0.81) -> score = 0.81, threat = PROMPT_INJECTION
both clean                                   -> score = 0.00, no threat
transformer not loaded (DEGRADED)            -> score = tfidf score, no degradation to pipeline
```

### Threat category

- If transformer fires: threat = PROMPT_INJECTION (binary classifier, only one category)
- If tfidf fires: threats from tfidf label map (multi-class: PROMPT_INJECTION, JAILBREAK, etc.)
- Final threat list: union, deduplicated, sorted by `.value` for deterministic ordering

```python
combined_threats = sorted(
    set(tfidf_result.threats) | set(transformer_result.threats),
    key=lambda t: t.value,
)
```

### Threat category source

TF-IDF is multi-class and identifies the specific threat category. Transformer is binary and
only contributes PROMPT_INJECTION. If transformer fires on a jailbreak that TF-IDF also caught,
the threat list correctly includes JAILBREAK from TF-IDF and PROMPT_INJECTION is not added
redundantly if JAILBREAK is already present as the dominant category.

---

## 5. Transformer Timeout and Degraded Mode

### Timeout

Transformer inference is wrapped in `asyncio.wait_for` with `timeout = profile.tier2_timeout`
(default 1.5 seconds). On timeout:

- Log: `WARNING wrapsec.engine transformer inference timed out trace_id=... -- using tfidf result`
- Use TF-IDF result as the combined `ml_result`
- Set transformer status to DEGRADED for the duration of the request
- Request continues normally -- timeout is not a system failure

### Degraded mode behavior

When transformer is DEGRADED (unavailable or timed out):
- Detection continues using TF-IDF result only
- `ml_score` in LayerScores reflects TF-IDF score only
- Health endpoint reports `transformer_detector: degraded`
- Doctor command shows degraded status with warning
- Startup log: `WARNING wrapsec.engine transformer model unavailable -- running in degraded
  detection mode`

Degraded mode is explicitly documented as reduced protection, not normal operation. It is not
silently acceptable.

---

## 6. Changes to Existing Components

### 6.1 GatewayService

`service.py` replaces direct `MLDetector` instantiation with `DetectionPipeline`:

```python
# Before
self._ml_detector = MLDetector()

# After
profile = get_profile("general")
self._detection_pipeline = DetectionPipeline(profile)
```

Step 3 in `process()` replaces `self._ml_detector.detect()` with
`await self._detection_pipeline.run(effective_input)`.

No other changes to `GatewayService`. The `process()` signature is unchanged. The rest of the
pipeline (LLMDetector, RiskScorer, PolicyEngine) is unchanged.

### 6.2 MLDetector

Accepts optional `model_path: Path` constructor argument. Defaults to the existing hardcoded
path for backwards compatibility. `DetectionPipeline` passes `profile.tier1_model` explicitly.

No behavior changes.

### 6.3 Health endpoint -- /health/ready

Add per-detector status to the checks response:

```python
# Before
"ml_model": "ok" | "unavailable"

# After
"tfidf_detector":       "healthy" | "degraded" | "unavailable"
"transformer_detector": "healthy" | "degraded" | "unavailable"
```

The `ml_model` key is removed and replaced. The overall `status: ready | degraded` logic
is unchanged -- any non-healthy check sets status to degraded.

### 6.4 Doctor command

Services section replaces `ml_model` with per-detector lines:

```
  Services
  + database              ok
  + redis                 ok
  + tfidf_detector        healthy
  ! transformer_detector  degraded   (model unavailable -- download or check models/ dir)
```

`!` icon (yellow) for degraded, `+` (green) for healthy, `-` (red) for unavailable.

---

## 7. Model Storage Strategy

### V1: Bundled in Docker image

The transformer model is downloaded into the Docker image at build time:

```dockerfile
RUN python -c "
from transformers import pipeline
pipeline('text-classification', model='protectai/deberta-v3-base-prompt-injection-v2')
"
```

HuggingFace caches to `~/.cache/huggingface` inside the image. Model is available immediately
at startup with no network call at runtime. Local development downloads on first startup.

### V2: Object storage with local cache

When industry-specific fine-tuned models are added, they will not be bundled in the image
(too large, too many variants). The strategy for v2:

- Models stored in DigitalOcean Spaces (S3-compatible)
- Downloaded to local cache on startup if not present
- Cache path: `models/cache/{profile_name}/{model_version}/`
- Startup fails with clear error if download fails and no cache exists

Custom/enterprise models follow the same pattern -- uploaded to tenant-scoped storage path,
downloaded at startup.

This strategy is not implemented in v1. v1 uses image-bundled models only.

---

## 8. Model Versioning and Audit Trail

`DetectorProfile.model_version` is a string set per profile entry in the registry.

This version string is logged to audit records when a detection decision is made. This allows
operators and compliance teams to reconstruct which exact model version produced a given
decision -- required for HIPAA and FINRA audit obligations in regulated industry profiles.

In v1 the version is static (`"1.0.0"` for the general profile). In v2 it increments when a
profile's model is retrained or replaced.

The `model_version` field is added to `AuditLog` and the `audit_logs` table as a nullable
string. Existing records without a version show NULL (pre-versioning). New records show the
profile version string.

---

## 9. Dependencies

```
torch==2.x.x+cpu      # CPU-only build -- no CUDA required
transformers==4.x.x
accelerate             # required by transformers pipeline
```

CPU-only torch is specified via the PyTorch index URL in requirements:

```
--extra-index-url https://download.pytorch.org/whl/cpu
torch
```

### Deployment impact

| Metric | Before | After |
|---|---|---|
| Docker image size | ~800MB | ~2.3GB |
| Startup memory | ~300MB | ~900MB |
| Transformer inference latency | N/A | 20-50ms (CPU) |
| TF-IDF inference latency | ~1ms | ~1ms (unchanged) |
| Startup time | ~3s | ~8-12s (model load) |

Minimum recommended production RAM: 4GB (was 2GB).

GPU support is not implemented in v1. The `pipeline()` call uses CPU by default.
Adding `device=0` in a future change enables GPU inference with no other code changes.

---

## 10. V2 Extension Path

### Adding an industry profile

1. Add a new entry to `PROFILE_REGISTRY` in `profiles.py`:

```python
"healthcare": DetectorProfile(
    name          = "healthcare",
    tier1_model   = "models/cache/healthcare/1.0.0/ml_healthcare.pkl",
    tier2_model   = "wrapsec/deberta-v3-healthcare-injection-v1",  # fine-tuned
    tier2_timeout = 1.5,
    rule_patterns = "healthcare",
    model_version = "1.0.0",
)
```

2. Add healthcare rule patterns to `engine/detection/rule_patterns/healthcare.py`

3. Train `ml_healthcare.pkl` using the existing `ml/train/pipeline.py` with healthcare data

4. Fine-tune `wrapsec/deberta-v3-healthcare-injection-v1` on PHI/HIPAA datasets

5. Add `detector_profile` field to the policy model and resolver chain

6. Dashboard: profile selector in tenant settings

No changes to `DetectionPipeline`, `TransformerDetector`, `MLDetector`, `GatewayService`,
`RiskScorer`, or `PolicyEngine`.

### Scoring contract migration (v2 only)

The current `LayerScores` dataclass has fixed named fields:

```python
LayerScores(rule_score=0.8, ml_score=0.5, llm_score=0.0, pii_score=0.3, toxicity_score=0.0)
```

This is correct for v1. In v2 with specialized detectors (PHI detector, tool misuse detector,
etc.) the fixed fields are insufficient.

The v2 migration is:

```python
# v2 LayerScores
LayerScores(
    scores={
        "rule":              0.8,
        "ml_tfidf":          0.4,
        "ml_transformer":    0.5,
        "phi_detector":      0.9,
        "tool_misuse":       0.0,
    }
)
```

This is a breaking change. Plan it at the start of v2. Do not add anything in v1 that
introduces new dependencies on the fixed field names beyond what already exists.

---

## 11. What Does NOT Change in V1

The following are explicitly out of scope for this change:

- `RiskScorer` -- weights, boost logic, scoring math
- `PolicyEngine` -- decision logic
- `GatewayService.process()` -- method signature
- `LayerScores` -- field names and structure
- All API endpoints
- All SDK code
- All existing tests (new tests added, none modified)
- `LLMDetector`
- `RuleDetector` (profile-aware patterns are v2)
- `PIIDetector` and guardrails
- Policy resolver
- Database schema (except nullable `model_version` on `audit_logs`)

---

## 12. File Summary

### New files

```
engine/detection/pipeline.py          -- DetectionPipeline, DetectorStatus
engine/detection/transformer_detector.py  -- TransformerDetector
engine/detection/profiles.py          -- DetectorProfile, PROFILE_REGISTRY, get_profile()
engine/detection/rule_patterns/
  __init__.py
  general.py                          -- current patterns moved here (no behavior change)
```

### Modified files

```
engine/detection/ml_detector.py       -- accept model_path constructor arg
services/gateway/service.py           -- use DetectionPipeline, remove MLDetector direct init
api/v1/endpoints/health.py            -- per-detector status in /health/ready
sdk/python/wrapsec/cli/commands/doctor.py  -- per-detector status in Services section
db/models.py                          -- nullable model_version on AuditLogModel
requirements.txt                      -- add torch (CPU), transformers, accelerate
```

### Unchanged files (confirmed)

```
engine/scoring/risk_scorer.py
engine/policy/engine.py
engine/detection/rule_detector.py
engine/detection/llm_detector.py
engine/guardrails/
services/policy_resolver.py
api/v1/endpoints/ai.py
api/v1/endpoints/proxy.py
All SDK client and command files except doctor.py
```
