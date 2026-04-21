"""
WrapSec Proxy Mode Example
===========================

Demonstrates how to use WrapSec as a drop-in replacement for the OpenAI API.

The only changes from a standard OpenAI SDK integration:
  1. api_key  → your WrapSec key (not your OpenAI key)
  2. base_url → your WrapSec instance
  3. model    → prefix with provider name (e.g. "openai/gpt-4o")

Setup:
  pip install -e ./sdk/python openai fastapi uvicorn httpx

  export WRAPSEC_API_KEY=wsk_live_...
  export WRAPSEC_BASE_URL=http://localhost:8000
  export LLM_MODEL=openai/gpt-4o-mini   # must match configured provider
"""

import os
import logging

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from openai import OpenAI, BadRequestError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("wrapsec.proxy_example")

WRAPSEC_API_KEY  = os.environ.get("WRAPSEC_API_KEY", "")
WRAPSEC_BASE_URL = os.environ.get("WRAPSEC_BASE_URL", "http://localhost:8000")
LLM_MODEL        = os.environ.get("LLM_MODEL", "openai/gpt-4o-mini")

if not WRAPSEC_API_KEY:
    raise RuntimeError("WRAPSEC_API_KEY not set. Set it with: export WRAPSEC_API_KEY=wsk_live_...")

# Point the OpenAI client at WrapSec — only change from standard integration
client = OpenAI(
    api_key  = WRAPSEC_API_KEY,
    base_url = f"{WRAPSEC_BASE_URL}/v1",
)

app = FastAPI(
    title       = "WrapSec Proxy Mode Example",
    description = "Drop-in OpenAI SDK replacement with WrapSec security enforcement",
    version     = "0.1.0",
)

class ChatRequest(BaseModel):
    message:    str
    user_id:    str = "anonymous"
    system:     str = "You are a helpful assistant."
    max_tokens: int = 500

class ChatResponse(BaseModel):
    reply:            str
    trace_id:         str | None   # null if header missing (should not happen on success)
    decision:         str | None   # input security verdict (canonical field)
    output_decision:  str | None
    execution_status: str | None
    input_sanitized:  bool
    output_sanitized: bool
    provider:         str | None
    model:            str
    latency_ms:       int | None   # total end-to-end latency (WrapSec + provider); null if header missing

class ConversationRequest(BaseModel):
    messages: list[dict]
    user_id:  str = "anonymous"


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
    Secured LLM chat via WrapSec proxy mode.
    Security enforced transparently on input and output.
    All decisions visible in X-WrapSec-* response headers.

    All error responses follow the standard WrapSec format:
      {"error": {"code": "...", "message": "...", "trace_id": "..."}, "wrapsec": {...}}
    """
    try:
        response = client.chat.completions.create(
            model      = LLM_MODEL,
            max_tokens = body.max_tokens,
            messages   = [
                {"role": "system", "content": body.system},
                {"role": "user",   "content": body.message},
            ],
            extra_body = {},
            # Note: headers are the primary observability mechanism.
            # Add X-WrapSec-Inline-Meta: true if you need metadata in the response body.
        )

        raw_response = response._raw_response
        # Use `or None` instead of "UNKNOWN" fallback — headers are always
        # present on successful responses. None signals a missing/unexpected value.
        input_dec    = raw_response.headers.get("x-wrapsec-input-decision")   or None
        output_dec   = raw_response.headers.get("x-wrapsec-output-decision")  or None
        exec_status  = raw_response.headers.get("x-wrapsec-execution-status") or None
        trace_id     = raw_response.headers.get("x-wrapsec-trace-id")         or None
        input_san    = raw_response.headers.get("x-wrapsec-input-sanitized",  "false") == "true"
        output_san   = raw_response.headers.get("x-wrapsec-output-sanitized", "false") == "true"
        provider     = raw_response.headers.get("x-wrapsec-provider")         or None
        model_used   = raw_response.headers.get("x-wrapsec-model")            or LLM_MODEL
        _latency_raw = raw_response.headers.get("x-wrapsec-latency-ms")
        latency_ms   = int(_latency_raw) if _latency_raw else None

        reply = response.choices[0].message.content

        logger.info(
            f"Chat completed | trace_id={trace_id} decision={input_dec} "
            f"output={output_dec} status={exec_status} latency={latency_ms}ms user={body.user_id}"
        )
        if input_san:
            logger.info(f"Input was sanitized (PII redacted) | trace_id={trace_id}")
        if output_san:
            logger.info(f"Output was sanitized (PII redacted) | trace_id={trace_id}")

        return ChatResponse(
            reply            = reply,
            trace_id         = trace_id,
            decision         = input_dec,
            output_decision  = output_dec,
            execution_status = exec_status,
            input_sanitized  = input_san,
            output_sanitized = output_san,
            provider         = provider,
            model            = model_used,
            latency_ms       = latency_ms,
        )

    except BadRequestError as e:
        error_body = e.response.json()
        error_code = error_body.get("error", {}).get("code", "unknown")
        trace_id   = error_body.get("error", {}).get("trace_id") or None
        wrapsec    = error_body.get("wrapsec", {})

        if error_code == "input_blocked":
            logger.warning(
                f"Input blocked | trace_id={trace_id} "
                f"reason={wrapsec.get('reason')} threats={wrapsec.get('threats')} user={body.user_id}"
            )
            return JSONResponse(
                status_code = 400,
                content     = _error(
                    code     = "input_blocked",
                    message  = "Your request was blocked by security policy.",
                    trace_id = trace_id,
                    wrapsec_meta = {
                        "reason":  wrapsec.get("reason"),
                        "threats": wrapsec.get("threats", []),
                    },
                ),
            )

        if error_code == "output_blocked":
            logger.warning(f"Output blocked | trace_id={trace_id} user={body.user_id}")
            return JSONResponse(
                status_code = 400,
                content     = _error(
                    code     = "output_blocked",
                    message  = "The model response was blocked by security policy.",
                    trace_id = trace_id,
                    wrapsec_meta = {
                        "reason":  wrapsec.get("reason"),
                        "threats": wrapsec.get("threats", []),
                    },
                ),
            )

        # Other known error codes (provider_timeout, provider_unreachable, etc.)
        # Pass through structured error from WrapSec preserving code and trace_id
        logger.warning(f"WrapSec error | code={error_code} trace_id={trace_id} user={body.user_id}")
        return JSONResponse(
            status_code = e.response.status_code,
            content     = _error(
                code     = error_code,
                message  = error_body.get("error", {}).get("message", str(e)),
                trace_id = trace_id,
                wrapsec_meta = wrapsec if wrapsec else None,
            ),
        )

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return JSONResponse(
            status_code = 500,
            content     = _error(
                code    = "system_error",
                message = "An unexpected error occurred. Please retry.",
            ),
        )


# ── Conversation endpoint ─────────────────────────────────────────────────────

@app.post("/chat/conversation")
async def conversation(body: ConversationRequest):
    """
    Multi-turn conversation with WrapSec proxy protection.
    WrapSec scans the last user message by default.
    """
    try:
        response = client.chat.completions.create(
            model    = LLM_MODEL,
            messages = body.messages,
            extra_headers = {
                "X-WrapSec-Scan-All-Messages": "false",  # scan last user message only
            },
        )
        raw_response = response._raw_response
        trace_id     = raw_response.headers.get("x-wrapsec-trace-id") or None
        input_dec    = raw_response.headers.get("x-wrapsec-input-decision") or None
        exec_status  = raw_response.headers.get("x-wrapsec-execution-status") or None

        return {
            "reply":            response.choices[0].message.content,
            "trace_id":         trace_id,
            "decision":         input_dec,
            "execution_status": exec_status,
        }

    except BadRequestError as e:
        error_body = e.response.json()
        error_code = error_body.get("error", {}).get("code", "unknown")
        trace_id   = error_body.get("error", {}).get("trace_id") or None
        wrapsec    = error_body.get("wrapsec", {})

        return JSONResponse(
            status_code = e.response.status_code,
            content     = _error(
                code     = error_code,
                message  = error_body.get("error", {}).get("message", str(e)),
                trace_id = trace_id,
                wrapsec_meta = wrapsec if wrapsec else None,
            ),
        )

    except Exception as e:
        logger.error(f"Conversation error: {e}")
        return JSONResponse(
            status_code = 500,
            content     = _error(
                code    = "system_error",
                message = "An unexpected error occurred. Please retry.",
            ),
        )


# ── Audit lookup ──────────────────────────────────────────────────────────────

@app.get("/audit/{trace_id}")
async def get_audit(trace_id: str):
    """
    Retrieve full security decision for a trace ID.
    Includes proxy lifecycle (provider, latency, output decision) when available.
    Note: input_raw/output_raw depend on DATA_STORAGE_MODE (may be masked or null).
    """
    async with httpx.AsyncClient() as http:
        resp = await http.get(
            f"{WRAPSEC_BASE_URL}/v1/ai/requests/{trace_id}",
            headers={"x-api-key": WRAPSEC_API_KEY},
        )
        if resp.status_code == 404:
            return JSONResponse(
                status_code = 404,
                content     = _error(
                    code     = "not_found",
                    message  = f"Trace {trace_id} not found.",
                    trace_id = trace_id,
                ),
            )
        resp.raise_for_status()
        return resp.json()


# ── Health ────────────────────────────────────────────────────────────────────

import wrapsec as _wrapsec

_wrapsec_client = _wrapsec.Client(api_key=WRAPSEC_API_KEY, base_url=WRAPSEC_BASE_URL)

@app.get("/health")
async def health():
    """Check WrapSec and provider connectivity."""
    async with httpx.AsyncClient() as http:
        try:
            resp = await http.get(
                f"{WRAPSEC_BASE_URL}/v1/settings/proxy/health",
                headers={"x-api-key": WRAPSEC_API_KEY},
                timeout=5,
            )
            proxy_health = resp.json() if resp.is_success else {"reachable": False}
        except Exception:
            proxy_health = {"reachable": False}

    wrapsec_ok  = _wrapsec_client.health_live()
    provider_ok = proxy_health.get("reachable", False)

    return {
        "status":           "ok" if (wrapsec_ok and provider_ok) else "degraded",
        "wrapsec":          "reachable" if wrapsec_ok else "unreachable",
        "provider":         proxy_health.get("provider") or None,
        "provider_status":  "reachable" if provider_ok else "unreachable",
        "provider_latency": proxy_health.get("latency_ms"),
        "model":            LLM_MODEL,
    }
