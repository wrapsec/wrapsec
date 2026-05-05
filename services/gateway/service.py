# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import asyncio
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

logger = logging.getLogger("wrapsec.gateway")


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
        return "sha256:" + hashlib.sha256(text.encode()).hexdigest()

    async def _call_llm_async(self, text: str, model: str, llm_settings: dict | None = None) -> str:
        from clients import get_llm_client

        client = get_llm_client(llm_settings=llm_settings)

        system_prompt = (
            "You are a helpful AI assistant. "
            "Answer the user's question clearly and concisely."
        )

        try:
            response = await client.complete(
                system_prompt = system_prompt,
                user_prompt   = text,
                model         = model,
            )
            if response.content:
                return response.content
            return "[LLM returned empty response]"

        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return "[LLM unavailable]"

    async def process(
        self,
        request:                        IncomingRequest,
        block_threshold:                float | None = None,
        sanitize_threshold:             float | None = None,
        pii_block_threshold:            float | None = None,
        pii_sanitize_threshold:         float | None = None,
        toxicity_block_threshold:       float | None = None,
        toxicity_sanitize_threshold:    float | None = None,
        rule_enabled:                   bool = True,
        ml_enabled:                     bool = True,
        llm_enabled:                    bool = True,
        llm_settings:                   dict | None = None,
    ) -> GatewayResult:
        start     = time.perf_counter()
        _settings = get_settings()

        # Use provided settings or fall back to config defaults
        # Use is-None check — 0.0 is a valid threshold and must not fall back
        if block_threshold is None:
            block_threshold = _settings.block_threshold
        if sanitize_threshold is None:
            sanitize_threshold = _settings.sanitize_threshold

        try:

            # ── Step 1: Input guard ───────────────────────────
            input_result    = self._input_guard.inspect(request.input)
            effective_input = input_result.sanitized_text or request.input

            # ── Step 2: Rule detection (CPU-bound → thread) ──
            detection_failed = False
            try:
                if rule_enabled:
                    rule_result = await asyncio.to_thread(
                        self._rule_detector.detect, effective_input
                    )
                else:
                    rule_result = DetectionResult.clean("rule_detector")
            except Exception as e:
                logger.error(f"Rule detector failed: {e} trace_id={request.trace_id}")
                rule_result      = DetectionResult.clean("rule_detector")
                detection_failed = True

            # ── Step 3: ML detection (CPU-bound → thread) ────
            try:
                if ml_enabled:
                    ml_result = await asyncio.to_thread(
                        self._ml_detector.detect, effective_input
                    )
                else:
                    ml_result = DetectionResult.clean("ml_detector")
            except Exception as e:
                logger.error(f"ML detector failed: {e} trace_id={request.trace_id}")
                ml_result        = DetectionResult.clean("ml_detector")
                detection_failed = True

            # ── Step 3.5: Toxicity guardrail (after ML) ─────────
            # Toxicity signal is extracted from ML result — no new inference
            input_result = self._input_guard.inspect_toxicity(input_result, ml_result)

            # ── Step 4: LLM detection (async I/O → direct await)
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
                llm_enabled
                and request.detection_mode == DetectionMode.FULL
                and pre_score >= _settings.llm_trigger_threshold
            ):
                logger.debug(
                    f"LLM detector triggered — pre_score={pre_score:.2f} "
                    f"trace_id={request.trace_id}"
                )
                try:
                    llm_result = await self._llm_detector.detect_async(effective_input)
                except Exception as e:
                    logger.error(f"LLM detector failed: {e} trace_id={request.trace_id}")
                    llm_result       = DetectionResult.clean("llm_detector")
                    detection_failed = True

            # ── Step 5: Risk scoring ──────────────────────────
            scoring = self._risk_scorer.score(
                rule_result     = rule_result,
                ml_result       = ml_result,
                llm_result      = llm_result,
                pii_result      = input_result.pii_result,
                toxicity_result = input_result.toxicity_result,
            )

            # ── Step 6: Policy decision ───────────────────────
            policy = self._policy_engine.decide(
                risk_score                  = scoring.final_score,
                threats                     = scoring.threats,
                block_threshold             = block_threshold,
                sanitize_threshold          = sanitize_threshold,
                pii_score                   = scoring.pii_score,
                pii_block_threshold         = pii_block_threshold,
                pii_sanitize_threshold      = pii_sanitize_threshold,
                toxicity_score              = scoring.toxicity_score,
                toxicity_block_threshold    = toxicity_block_threshold,
                toxicity_sanitize_threshold = toxicity_sanitize_threshold,
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
                raw_output    = await self._call_llm_async(
                    prompt,
                    request.model or (llm_settings or {}).get("model") or _settings.llm_model,
                    llm_settings=llm_settings,
                )

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

            # Compute primary reason
            from engine.scoring.primary_reason import compute_primary_reason
            _pii_bt = pii_block_threshold    if pii_block_threshold    is not None else block_threshold
            _pii_st = pii_sanitize_threshold if pii_sanitize_threshold is not None else sanitize_threshold
            _tox_bt = toxicity_block_threshold    if toxicity_block_threshold    is not None else block_threshold
            _tox_st = toxicity_sanitize_threshold if toxicity_sanitize_threshold is not None else sanitize_threshold

            pii_guardrail_triggered = scoring.pii_score >= _pii_st
            toxicity_guardrail_triggered = (
                not pii_guardrail_triggered and
                scoring.toxicity_score >= _tox_st
            )
            guardrail_triggered = pii_guardrail_triggered or toxicity_guardrail_triggered

            primary_reason = compute_primary_reason(
                guardrail_triggered          = pii_guardrail_triggered,
                guardrail_decision           = policy.decision.value,
                rule_score                   = scoring.rule_score,
                ml_score                     = scoring.ml_score,
                llm_score                    = scoring.llm_score,
                pii_score                    = scoring.pii_score,
                block_threshold              = _pii_bt,
                sanitize_threshold           = _pii_st,
                detection_failed             = detection_failed,
                toxicity_score               = scoring.toxicity_score,
                toxicity_guardrail_triggered = toxicity_guardrail_triggered,
                toxicity_block_threshold     = _tox_bt,
            )

            # Compute confidence score
            from engine.scoring.confidence import compute_confidence
            confidence, confidence_band = compute_confidence(
                rule_score                   = scoring.rule_score,
                ml_score                     = scoring.ml_score,
                llm_score                    = scoring.llm_score,
                pii_score                    = scoring.pii_score,
                rule_enabled                 = rule_enabled,
                ml_enabled                   = ml_enabled,
                llm_invoked                  = llm_invoked,
                guardrail_triggered          = guardrail_triggered,
                block_threshold              = block_threshold,
                sanitize_threshold           = sanitize_threshold,
                toxicity_score               = scoring.toxicity_score,
                toxicity_guardrail_triggered = toxicity_guardrail_triggered,
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
                primary_reason  = primary_reason,
                confidence      = confidence,
                confidence_band = confidence_band,
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
            import traceback
            logger.error(f"GatewayService failed: {e} trace_id={request.trace_id}")
            logger.error(traceback.format_exc())
            latency_ms = (time.perf_counter() - start) * 1000

            gateway_decision = GatewayDecision(
                trace_id        = request.trace_id,
                decision        = DecisionType.BLOCK,
                risk_score      = RiskScore(1.0),
                threats         = [],
                llm_invoked     = False,
                detection_mode  = request.detection_mode,
                execution_mode  = request.execution_mode,
                latency_ms      = latency_ms,
                primary_reason  = "SYSTEM_ERROR",
                confidence      = 0.0,
                confidence_band = "LOW",
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