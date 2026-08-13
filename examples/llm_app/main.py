# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
WrapSec + LLM App Integration Example
=======================================

End-to-end LLM proxy that scans every user input with WrapSec
before forwarding to the configured LLM provider.

Supports two LLM providers (switchable via LLM_PROVIDER env var):
  - Ollama  (local, no API key required, default)
  - OpenAI  (or any OpenAI-compatible endpoint)

Architecture:
  User input -> WrapSec scan -> ALLOW/SANITIZE -> LLM -> response
                            -> BLOCK -> reject (LLM never called)

Setup:
  pip install -e ./sdk/python fastapi uvicorn httpx

  export WRAPSEC_API_KEY=wsk_live_...
  export WRAPSEC_BASE_URL=http://localhost:8000
  export WRAPSEC_DETECTION_MODE=fast
  export LLM_PROVIDER=ollama
  export LLM_TIMEOUT=60
"""

import logging
import os

import httpx
import wrapsec
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from wrapsec.exceptions import (
    WrapSecAuthError,
    WrapSecError,
    WrapSecRateLimitError,
)

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wrapsec.llm_app")

# ── Configuration ─────────────────────────────────────────────────────────────

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama").lower()
if LLM_PROVIDER not in ("ollama", "openai"):
    raise RuntimeError(f"Invalid LLM_PROVIDER={LLM_PROVIDER!r}. Allowed: ollama, openai")

WRAPSEC_DETECTION_MODE = os.environ.get("WRAPSEC_DETECTION_MODE", "fast")
if WRAPSEC_DETECTION_MODE not in ("fast", "full"):
    raise RuntimeError(f"Invalid WRAPSEC_DETECTION_MODE={WRAPSEC_DETECTION_MODE!r}. Allowed: fast, full")

LLM_TIMEOUT     = int(os.environ.get("LLM_TIMEOUT", "60"))
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL",    "llama3.2:latest")
OPENAI_API_KEY  = os.environ.get("OPENAI_API_KEY",  "")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL    = os.environ.get("OPENAI_MODEL",    "gpt-4o-mini")

wrapsec_client = wrapsec.Client()

# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "WrapSec LLM Proxy Example",
    description = "End-to-end LLM proxy with WrapSec input scanning",
    version     = "0.1.0",
)

# ── Models ────────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message:    str
    user_id:    str = "anonymous"
    system:     str = "You are a helpful assistant."
    max_tokens: int = 500

class ChatResponse(BaseModel):
    reply:          str
    trace_id:       str
    decision:       str
    primary_reason: str
    sanitized:      bool
    llm_provider:   str
    llm_model:      str

class BatchRequest(BaseModel):
    messages: list[str]
    user_id:  str = "anonymous"
    system:   str = "You are a helpful assistant."


def _error(code: str, message: str, trace_id: str | None = None, wrapsec_meta: dict | None = None) -> dict:
    """Build a standard WrapSec error response body."""
    body: dict = {
        "error": {
            "code":     code,
            "message":  message,
            "trace_id": trace_id,
        }
    }
    if wrapsec_meta:
        body["wrapsec"] = wrapsec_meta
    return body


# ── Chat endpoint ─────────────────────────────────────────────────────────────

@app.post("/chat", response_model=ChatResponse)
async def chat(body: ChatRequest):
    """
    End-to-end secured LLM chat.

    Flow:
      1. Scan with WrapSec
      2. BLOCK        -> 400, LLM never called
      3. SYSTEM_ERROR -> 503, LLM never called (fail closed)
      4. SANITIZE     -> call LLM with sanitized input
      5. ALLOW        -> call LLM with original input
      6. Return LLM response

    All error responses follow the standard WrapSec format:
      {"error": {"code": "...", "message": "...", "trace_id": "..."}, "wrapsec": {...}}
    """
    # Step 1: Scan
    try:
        scan_result = wrapsec_client.scan(
            body.message,
            mode = WRAPSEC_DETECTION_MODE,
            user = body.user_id,
        )
    except WrapSecAuthError:
        logger.error("WrapSec auth failed - check WRAPSEC_API_KEY")
        return JSONResponse(
            status_code = 500,
            content     = _error(
                code    = "system_error",
                message = "Security scanning unavailable - configuration error.",
            ),
        )
    except WrapSecRateLimitError:
        logger.warning("WrapSec rate limit exceeded")
        return JSONResponse(
            status_code = 429,
            content     = _error(
                code    = "system_error",
                message = "Security scan rate limit exceeded. Please retry.",
            ),
        )
    except WrapSecError as e:
        # Infrastructure failure - fail closed, never send unscanned input to LLM
        logger.error(f"WrapSec error: {e} - failing closed")
        return JSONResponse(
            status_code = 503,
            content     = _error(
                code    = "system_error",
                message = "Security scanning temporarily unavailable. Please retry.",
            ),
        )

    # Step 2: SYSTEM_ERROR - scanner ran but result unreliable (confidence = 0.0)
    # This is a valid scan result, not an exception. Fail closed.
    if scan_result.primary_reason == "SYSTEM_ERROR":
        logger.error(
            f"WrapSec SYSTEM_ERROR | trace_id={scan_result.trace_id} "
            f"decision={scan_result.decision} - failing closed"
        )
        return JSONResponse(
            status_code = 503,
            content     = _error(
                code     = "system_error",
                message  = "Security scanning temporarily unavailable. Please retry.",
                trace_id = scan_result.trace_id,
            ),
        )

    # Step 3: BLOCK
    if scan_result.decision == "BLOCK":
        logger.warning(
            f"Input BLOCKED | trace_id={scan_result.trace_id} "
            f"reason={scan_result.primary_reason} threats={scan_result.threats} user={body.user_id}"
        )
        return JSONResponse(
            status_code = 400,
            content     = _error(
                code     = "input_blocked",
                message  = "Your request was blocked by security policy.",
                trace_id = scan_result.trace_id,
                wrapsec_meta = {
                    "reason":  scan_result.primary_reason,
                    "threats": scan_result.threats,
                },
            ),
        )

    # Step 4: SANITIZE
    if scan_result.decision == "SANITIZE":
        message_to_send = scan_result.sanitized_input or body.message
        sanitized       = True
        logger.info(
            f"Input SANITIZED | trace_id={scan_result.trace_id} "
            f"reason={scan_result.primary_reason} user={body.user_id}"
        )
    else:
        # ALLOW
        message_to_send = body.message
        sanitized       = False
        logger.info(
            f"Input ALLOWED | trace_id={scan_result.trace_id} "
            f"confidence={scan_result.confidence} band={scan_result.confidence_band} user={body.user_id}"
        )

    # Step 5: Call LLM
    try:
        if LLM_PROVIDER == "openai":
            reply, model_used = await _call_openai(
                message    = message_to_send,
                system     = body.system,
                max_tokens = body.max_tokens,
            )
        else:
            reply, model_used = await _call_ollama(
                message = message_to_send,
                system  = body.system,
            )
    except Exception as e:
        logger.error(f"LLM call failed | trace_id={scan_result.trace_id} error={e}")
        return JSONResponse(
            status_code = 502,
            content     = _error(
                code     = "system_error",
                message  = "LLM provider error. Please retry.",
                trace_id = scan_result.trace_id,
            ),
        )

    return ChatResponse(
        reply          = reply,
        trace_id       = scan_result.trace_id,
        decision       = scan_result.decision,
        primary_reason = scan_result.primary_reason,
        sanitized      = sanitized,
        llm_provider   = LLM_PROVIDER,
        llm_model      = model_used,
    )


# ── Batch endpoint ────────────────────────────────────────────────────────────

@app.post("/chat/batch")
async def chat_batch(body: BatchRequest):
    """
    Scan and process multiple messages independently.
    BLOCK and SYSTEM_ERROR messages are skipped - others are sent to LLM.
    Returns per-message results including decision, reason, threats, and trace_id.
    """
    results = []

    for i, message in enumerate(body.messages):
        try:
            scan_result = wrapsec_client.scan(
                message,
                mode = WRAPSEC_DETECTION_MODE,
                user = body.user_id,
            )
        except WrapSecError:
            results.append({
                "index":          i,
                "message_length": len(message),
                "status":         "error",
                "error":          "system_error",
                "trace_id":       None,
                "reply":          None,
            })
            continue

        # SYSTEM_ERROR - skip, do not forward to LLM
        if scan_result.primary_reason == "SYSTEM_ERROR":
            logger.error(f"SYSTEM_ERROR in batch | index={i} trace_id={scan_result.trace_id}")
            results.append({
                "index":          i,
                "message_length": len(message),
                "status":         "error",
                "error":          "system_error",
                "trace_id":       scan_result.trace_id,
                "reply":          None,
            })
            continue

        if scan_result.decision == "BLOCK":
            results.append({
                "index":          i,
                "message_length": len(message),
                "decision":       "BLOCK",
                "reason":         scan_result.primary_reason,
                "threats":        scan_result.threats,
                "trace_id":       scan_result.trace_id,
                "reply":          None,
            })
            continue

        message_to_send = (
            scan_result.sanitized_input
            if scan_result.decision == "SANITIZE" and scan_result.sanitized_input
            else message
        )

        try:
            if LLM_PROVIDER == "openai":
                reply, _ = await _call_openai(message_to_send, body.system)
            else:
                reply, _ = await _call_ollama(message_to_send, body.system)
        except Exception as e:
            reply = None
            logger.error(f"LLM error in batch | index={i} trace_id={scan_result.trace_id} error={e}")

        results.append({
            "index":          i,
            "message_length": len(message),
            "decision":       scan_result.decision,
            "reason":         scan_result.primary_reason,
            "threats":        scan_result.threats,
            "trace_id":       scan_result.trace_id,
            "sanitized":      scan_result.decision == "SANITIZE",
            "reply":          reply,
        })

    blocked = sum(1 for r in results if r.get("decision") == "BLOCK")
    allowed = sum(1 for r in results if r.get("decision") in ("ALLOW", "SANITIZE"))

    return {
        "total":   len(results),
        "blocked": blocked,
        "allowed": allowed,
        "results": results,
    }


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    wrapsec_ok = wrapsec_client.health_live()
    llm_ok     = await _check_llm_health()
    return {
        "status":         "ok" if (wrapsec_ok and llm_ok) else "degraded",
        "wrapsec":        "reachable" if wrapsec_ok else "unreachable",
        "llm_provider":   LLM_PROVIDER,
        "llm":            "reachable" if llm_ok else "unreachable",
        "detection_mode": WRAPSEC_DETECTION_MODE,
    }


# ── LLM providers ─────────────────────────────────────────────────────────────

async def _call_ollama(message: str, system: str = "You are a helpful assistant.") -> tuple[str, str]:
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as http:
        resp = await http.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={"model": OLLAMA_MODEL, "stream": False, "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": message},
            ]},
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"], OLLAMA_MODEL


async def _call_openai(message: str, system: str = "You are a helpful assistant.", max_tokens: int = 500) -> tuple[str, str]:
    if not OPENAI_API_KEY:
        raise ValueError("OPENAI_API_KEY not set.")
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as http:
        resp = await http.post(
            f"{OPENAI_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json={"model": OPENAI_MODEL, "max_tokens": max_tokens, "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": message},
            ]},
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"], OPENAI_MODEL


async def _check_llm_health() -> bool:
    try:
        if LLM_PROVIDER == "openai":
            async with httpx.AsyncClient(timeout=5) as http:
                resp = await http.get(f"{OPENAI_BASE_URL}/models", headers={"Authorization": f"Bearer {OPENAI_API_KEY}"})
                return resp.is_success
        else:
            async with httpx.AsyncClient(timeout=5) as http:
                resp = await http.get(f"{OLLAMA_BASE_URL}/api/tags")
                return resp.is_success
    except Exception:
        return False
