import time
import hashlib
import logging
from dataclasses import dataclass
from domain.enums import DecisionType, ThreatCategory, DetectionMode, ExecutionMode
from domain.value_objects.risk_score import RiskScore
from domain.value_objects.trace_id import TraceId
from domain.entities.request import IncomingRequest
from domain.entities.decision import GatewayDecision, LayerScores
from domain.entities.audit_log import AuditLog
from engine.detection.rule_detector import RuleDetector
from engine.detection.ml_detector import MLDetector
from engine.detection.llm_detector import LLMDetector
from engine.detection.base import DetectionResult
from engine.guardrails.pii.detector import PIIDetector
from engine.guardrails.input_guard import InputGuard
from engine.guardrails.output_guard import OutputGuard
from engine.scoring.risk_scorer import RiskScorer
from engine.policy.engine import PolicyEngine
from engine.policy.rules import PolicyRules
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.gateway")
settings = get_settings()


@dataclass
class GatewayResult:
    decision:     GatewayDecision
    audit_log:    AuditLog


class GatewayService:
    """
    Full pipeline orchestration.

    Flow:
      1. Input guard    — PII detection + redaction
      2. Rule detector  — regex/heuristic patterns
      3. ML detector    — TF-IDF + LogisticRegression
      4. LLM detector   — semantic analysis (conditional)
      5. Risk scorer    — weighted aggregation
      6. Policy engine  — BLOCK / SANITIZE / ALLOW
      7. LLM execution  — proxy mode only, skipped if BLOCK
      8. Output guard   — PII check on LLM response
      9. Audit log      — SHA-256 hashed input
    """

    def __init__(self):
        self._rule_detector  = RuleDetector()
        self._ml_detector    = MLDetector()
        self._llm_detector   = LLMDetector()
        self._pii_detector   = PIIDetector()
        self._input_guard    = InputGuard()
        self._output_guard   = OutputGuard()
        self._risk_scorer    = RiskScorer()
        self._policy_engine  = PolicyEngine()

    def _hash_input(self, text: str) -> str:
        return "sha256:" + hashlib.sha256(text.encode()).hexdigest()[:16] + "..."

    def _call_llm(self, text: str, model: str) -> str:
        """
        Call the configured LLM provider synchronously.
        GatewayService runs in a threadpool so we need a sync wrapper.
        """
        import asyncio
        from clients import get_llm_client

        client = get_llm_client()

        system_prompt = (
            "You are a helpful AI assistant. "
            "Answer the user's question clearly and concisely."
        )

        try:
            loop     = asyncio.new_event_loop()
            response = loop.run_until_complete(
                client.complete(
                    system_prompt = system_prompt,
                    user_prompt   = text,
                    model         = model,
                )
            )
            loop.close()

            if response.content:
                return response.content
            return "[LLM returned empty response]"

        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return "[LLM unavailable]"

    def process(self, request: IncomingRequest) -> GatewayResult:
        start = time.perf_counter()

        try:
            # ── Step 1: Input guard ───────────────────────────
            input_result    = self._input_guard.inspect(request.input)
            effective_input = input_result.sanitized_text or request.input

            # ── Step 2: Rule detection ────────────────────────
            rule_result = self._rule_detector.detect(effective_input)

            # ── Step 3: ML detection ──────────────────────────
            ml_result = self._ml_detector.detect(effective_input)

            # ── Step 4: LLM detection (conditional) ───────────
            # Only invoke LLM detector if:
            # - detection_mode is FULL
            # - any score exceeds the trigger threshold
            pre_score = max(
                rule_result.score,
                ml_result.score,
                input_result.pii_result.score,
            )

            llm_result = DetectionResult.clean("llm_detector")
            if (
                request.detection_mode == DetectionMode.FULL
                and pre_score >= settings.llm_trigger_threshold
            ):
                logger.debug(
                    f"LLM detector triggered — pre_score={pre_score:.2f} "
                    f"trace_id={request.trace_id}"
                )
                llm_result = self._llm_detector.detect(effective_input)

            # ── Step 5: Risk scoring ──────────────────────────
            scoring = self._risk_scorer.score(
                rule_result = rule_result,
                ml_result   = ml_result,
                llm_result  = llm_result,
                pii_result  = input_result.pii_result,
            )

            # ── Step 6: Policy decision ───────────────────────
            policy = self._policy_engine.decide(
                risk_score = scoring.final_score,
                threats    = scoring.threats,
            )

            # ── Step 7: Sanitized input ───────────────────────
            sanitized_input = None
            if policy.decision == DecisionType.SANITIZE:
                sanitized_input = input_result.sanitized_text or effective_input

            # ── Step 8: LLM execution (proxy mode only) ───────
            output      = None
            llm_invoked = False

            if (
                request.execution_mode == ExecutionMode.PROXY
                and policy.decision != DecisionType.BLOCK
            ):
                llm_invoked   = True
                prompt        = sanitized_input or effective_input
                raw_output    = self._call_llm(prompt, request.model or settings.llm_model)

                # Output guard — check LLM response for PII
                output_result = self._output_guard.inspect(raw_output)
                output        = output_result.sanitized_text or raw_output

            # ── Step 9: Build result ──────────────────────────
            latency_ms = (time.perf_counter() - start) * 1000

            layer_scores = LayerScores(
                rule_score = scoring.rule_score,
                ml_score   = scoring.ml_score,
                llm_score  = scoring.llm_score,
                pii_score  = scoring.pii_score,
            )

            gateway_decision = GatewayDecision(
                trace_id        = request.trace_id,
                decision        = policy.decision,
                risk_score      = scoring.final_score,
                threats         = scoring.threats,
                sanitized_input = sanitized_input,
                output          = output,
                layer_scores    = layer_scores,
                llm_invoked     = llm_invoked,
                detection_mode  = request.detection_mode,
                execution_mode  = request.execution_mode,
                latency_ms      = latency_ms,
            )

            audit_log = AuditLog(
                trace_id       = request.trace_id,
                decision       = policy.decision,
                risk_score     = scoring.final_score.value,
                threats        = scoring.threats,
                input_hash     = self._hash_input(request.input),
                detection_mode = request.detection_mode,
                execution_mode = request.execution_mode,
                llm_invoked    = llm_invoked,
                latency_ms     = latency_ms,
                tenant_id      = request.metadata.tenant_id if request.metadata else None,
                source         = request.metadata.source if request.metadata else None,
                user_id        = request.metadata.user_id if request.metadata else None,
            )

            logger.info(
                f"Gateway processed — "
                f"trace_id={request.trace_id} "
                f"decision={policy.decision.value} "
                f"score={scoring.final_score.value:.2f} "
                f"latency={latency_ms:.1f}ms"
            )

            return GatewayResult(
                decision  = gateway_decision,
                audit_log = audit_log,
            )

        except Exception as e:
            logger.error(f"GatewayService failed: {e} trace_id={request.trace_id}")
            latency_ms = (time.perf_counter() - start) * 1000

            gateway_decision = GatewayDecision(
                trace_id       = request.trace_id,
                decision       = DecisionType.BLOCK,
                risk_score     = RiskScore(1.0),
                threats        = [],
                llm_invoked    = False,
                detection_mode = request.detection_mode,
                execution_mode = request.execution_mode,
                latency_ms     = latency_ms,
            )

            audit_log = AuditLog(
                trace_id       = request.trace_id,
                decision       = DecisionType.BLOCK,
                risk_score     = 1.0,
                threats        = [],
                input_hash     = self._hash_input(request.input),
                detection_mode = request.detection_mode,
                execution_mode = request.execution_mode,
                llm_invoked    = False,
                latency_ms     = latency_ms,
            )

            return GatewayResult(
                decision  = gateway_decision,
                audit_log = audit_log,
            )

    def update_policy(self, rules: PolicyRules) -> None:
        self._policy_engine.update_rules(rules)