import time
import hashlib
from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse

from api.v1.schemas.request import AIRequestSchema
from api.v1.schemas.response import GatewayResponseSchema, ProcessingSchema
from config.settings import get_settings
from domain.enums import DecisionType, ThreatCategory, DetectionMode, ExecutionMode
from domain.value_objects.risk_score import RiskScore
from domain.value_objects.trace_id import TraceId
from domain.entities.decision import GatewayDecision, LayerScores
from errors.exceptions import NotFoundError, DebugForbiddenError

router   = APIRouter()
settings = get_settings()


def is_admin(request: Request) -> bool:
    api_key = request.headers.get("x-api-key", "")
    return api_key == settings.admin_api_key


def hash_input(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()[:16] + "..."


def build_response(decision: GatewayDecision, debug: bool = False) -> dict:
    response = {
        "trace_id":        str(decision.trace_id),
        "decision":        decision.decision.value if hasattr(decision.decision, "value") else decision.decision,
        "risk_score":      decision.risk_score.value,
        "threats":         [t.value if hasattr(t, "value") else t for t in decision.threats],
        "sanitized_input": decision.sanitized_input,
        "output":          decision.output,
        "processing": {
            "latency_ms":     round(decision.latency_ms, 2),
            "llm_invoked":    decision.llm_invoked,
            "detection_mode": decision.detection_mode.value if hasattr(decision.detection_mode, "value") else decision.detection_mode,
            "execution_mode": decision.execution_mode.value if hasattr(decision.execution_mode, "value") else decision.execution_mode,
        },
    }

    if debug and decision.layer_scores:
        response["debug"] = {
            "rule_score": decision.layer_scores.rule_score,
            "ml_score":   decision.layer_scores.ml_score,
            "llm_score":  decision.layer_scores.llm_score,
            "layer_decisions": {
                "rule": DecisionType.BLOCK.value if decision.layer_scores.rule_score >= settings.block_threshold else DecisionType.SANITIZE.value if decision.layer_scores.rule_score >= settings.sanitize_threshold else DecisionType.ALLOW.value,
                "ml":   DecisionType.BLOCK.value if decision.layer_scores.ml_score   >= settings.block_threshold else DecisionType.SANITIZE.value if decision.layer_scores.ml_score   >= settings.sanitize_threshold else DecisionType.ALLOW.value,
                "llm":  DecisionType.BLOCK.value if decision.layer_scores.llm_score  >= settings.block_threshold else DecisionType.SANITIZE.value if decision.layer_scores.llm_score  >= settings.sanitize_threshold else DecisionType.ALLOW.value,
            }
        }

    return response


def mock_detect(text: str, detection_mode: str) -> tuple[float, list[ThreatCategory], LayerScores]:
    """
    Temporary mock detection — returns realistic scores.
    Will be replaced by engine/ pipeline in next step.
    """
    text_lower = text.lower()

    rule_score = 0.0
    ml_score   = 0.0
    llm_score  = 0.0
    threats    = []

    injection_patterns = [
        "ignore previous", "ignore all", "disregard",
        "bypass", "jailbreak", "dan mode", "developer mode"
    ]
    pii_patterns = [
        "social security", "credit card", "passport",
        "date of birth", "bank account"
    ]
    malicious_patterns = [
        "how to hack", "how to attack", "exploit",
        "malware", "ransomware", "phishing"
    ]

    if any(p in text_lower for p in injection_patterns):
        rule_score = 0.85
        threats.append(ThreatCategory.PROMPT_INJECTION)

    if any(p in text_lower for p in pii_patterns):
        ml_score = 0.72
        threats.append(ThreatCategory.PII)

    if any(p in text_lower for p in malicious_patterns):
        rule_score = max(rule_score, 0.78)
        ml_score   = max(ml_score, 0.65)
        threats.append(ThreatCategory.MALICIOUS_INTENT)

    if detection_mode == "full" and (rule_score > 0.2 or ml_score > 0.2):
        llm_score = min(rule_score + 0.05, 1.0)

    layer_scores = LayerScores(
        rule_score=rule_score,
        ml_score=ml_score,
        llm_score=llm_score,
    )

    final_score = max(rule_score, ml_score, llm_score)

    if not threats:
        threats = []

    return final_score, threats, layer_scores


def make_decision(score: float, settings) -> DecisionType:
    if score >= settings.block_threshold:
        return DecisionType.BLOCK
    if score >= settings.sanitize_threshold:
        return DecisionType.SANITIZE
    return DecisionType.ALLOW


# In-memory store for retrieved requests — temp until DB is ready
_request_store: dict[str, dict] = {}


@router.post("/request", response_model=None)
async def ai_request(body: AIRequestSchema, request: Request):
    start = time.perf_counter()

    # Debug mode requires admin
    if body.options.debug and not is_admin(request):
        raise DebugForbiddenError()

    trace_id = TraceId.generate()

    # Run detection
    score, threats, layer_scores = mock_detect(
        body.input,
        body.detection_mode
    )

    risk_score = RiskScore(min(score, 1.0))
    decision   = make_decision(risk_score.value, settings)

    # Sanitize input if needed
    sanitized_input = None
    if decision == DecisionType.SANITIZE:
        sanitized_input = body.input[:100] + "..." if len(body.input) > 100 else body.input

    # LLM invocation — only if proxy mode and not blocked
    output      = None
    llm_invoked = False

    if body.execution_mode == "proxy" and decision != DecisionType.BLOCK:
        llm_invoked = True
        effective_input = sanitized_input or body.input
        output = f"[Mock LLM response for: {effective_input[:50]}...]"

    latency_ms = (time.perf_counter() - start) * 1000

    gateway_decision = GatewayDecision(
        trace_id        = trace_id,
        decision        = decision,
        risk_score      = risk_score,
        threats         = threats,
        sanitized_input = sanitized_input,
        output          = output,
        layer_scores    = layer_scores,
        llm_invoked     = llm_invoked,
        detection_mode  = DetectionMode(body.detection_mode),
        execution_mode  = ExecutionMode(body.execution_mode),
        latency_ms      = latency_ms,
    )

    # Store for retrieval
    _request_store[str(trace_id)] = {
        "trace_id":       str(trace_id),
        "decision":       decision.value,
        "risk_score":     risk_score.value,
        "threats":        [t.value for t in threats],
        "input_hash":     hash_input(body.input),
        "detection_mode": body.detection_mode,
        "execution_mode": body.execution_mode,
        "llm_invoked":    llm_invoked,
        "latency_ms":     round(latency_ms, 2),
        "tenant_id":      body.metadata.tenant_id if body.metadata else None,
        "source":         body.metadata.source if body.metadata else None,
    }

    response = build_response(
        gateway_decision,
        debug=body.options.debug and is_admin(request)
    )

    return JSONResponse(content=response)


@router.get("/requests/{trace_id}")
async def get_request(trace_id: str):
    record = _request_store.get(trace_id)
    if not record:
        raise NotFoundError("request", trace_id)
    return JSONResponse(content=record)