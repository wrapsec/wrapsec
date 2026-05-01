# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import json
import hashlib
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("wrapsec.idempotency")

# Paths that support idempotency
IDEMPOTENCY_PATHS = {"/v1/ai/request"}

# TTL for idempotency cache in seconds
IDEMPOTENCY_TTL = 60


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """
    Idempotency-Key header support for POST /v1/ai/request.

    If a request includes an Idempotency-Key header:
      First request  → process normally, cache response in Redis
      Repeat request → return cached response immediately

    Cache key: SHA-256(idempotency_key + body_hash)
    TTL:       60 seconds
    Storage:   Redis

    Prevents duplicate BLOCK/SANITIZE decisions on client retries.
    Returns X-Idempotency-Replayed: true header on cache hits.

    If Redis is unavailable → processes normally (fail open).
    Only caches non-5xx responses.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Only apply to supported paths and POST method
        if request.url.path not in IDEMPOTENCY_PATHS:
            return await call_next(request)

        if request.method != "POST":
            return await call_next(request)

        idempotency_key = request.headers.get("Idempotency-Key", "").strip()

        if not idempotency_key:
            return await call_next(request)

        # Read body for hashing
        body      = await request.body()
        body_hash = hashlib.sha256(body).hexdigest()[:16]

        # Scope idempotency to the authenticated API key.
        # Without this, two different keys using the same Idempotency-Key
        # value would collide — dept A could receive dept B's cached response.
        # key_id is always set by AuthMiddleware before this runs.
        key_id    = getattr(request.state, "key_id", None) or "anon"
        scope     = f"{key_id}:{idempotency_key}"
        idem_hash    = hashlib.sha256(scope.encode()).hexdigest()
        hash_key     = f"idempotency:{idem_hash}:hash"
        response_key = f"idempotency:{idem_hash}:resp"

        try:
            from cache.redis_client import get_redis
            redis = get_redis()

            # Atomically claim this idempotency slot before processing.
            # SET NX ensures only one concurrent request can claim the key —
            # eliminates the TOCTOU race between GET and later SET.
            claimed = await redis.set(hash_key, body_hash, nx=True, ex=IDEMPOTENCY_TTL)

            if not claimed:
                # Key exists — check for conflict or cached replay
                stored_hash = await redis.get(hash_key)
                if stored_hash and stored_hash != body_hash:
                    # Same idempotency key — different body → CONFLICT
                    logger.warning(
                        f"Idempotency conflict — "
                        f"key={idempotency_key[:12]}... "
                        f"body hash mismatch"
                    )
                    trace_id = getattr(request.state, "trace_id", "")
                    return JSONResponse(
                        status_code = 409,
                        content     = {
                            "error": {
                                "code":    "IDEMPOTENCY_CONFLICT",
                                "message": "Idempotency-Key was already used with a different request body.",
                                "trace_id": trace_id,
                            }
                        },
                    )

                # Same key + same body → return cached response if available
                cached = await redis.get(response_key)
                if cached:
                    logger.info(
                        f"Idempotency hit — "
                        f"key={idempotency_key[:12]}... "
                        f"path={request.url.path}"
                    )
                    cached_data = json.loads(cached)
                    response    = JSONResponse(
                        content     = cached_data["body"],
                        status_code = cached_data["status_code"],
                    )
                    response.headers["X-Idempotency-Replayed"] = "true"
                    return response

                # Concurrent in-flight request claimed the key but hasn't stored
                # a response yet — fall through and process normally.

        except Exception as e:
            logger.warning(f"Idempotency cache check failed: {e} — processing normally")

        # ── Process request ───────────────────────────────────
        # Reconstruct receive callable since we consumed the body
        async def receive():
            return {"type": "http.request", "body": body}

        request._receive = receive
        response         = await call_next(request)

        # ── Cache response ────────────────────────────────────
        # Only cache successful responses — not 5xx errors
        if response.status_code < 500:
            try:
                from cache.redis_client import get_redis
                redis = get_redis()

                # Consume body iterator to read response
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk

                response_data = json.loads(response_body)

                # hash_key was set atomically before processing via SET NX.
                # Only store the response — no hash_key race possible here.
                await redis.setex(response_key, IDEMPOTENCY_TTL, json.dumps({
                    "body":        response_data,
                    "status_code": response.status_code,
                }))

                logger.debug(
                    f"Idempotency cached — "
                    f"key={idempotency_key[:12]}... "
                    f"ttl={IDEMPOTENCY_TTL}s"
                )

                # Reconstruct response — body iterator was consumed
                return JSONResponse(
                    content     = response_data,
                    status_code = response.status_code,
                    headers     = dict(response.headers),
                )

            except Exception as e:
                logger.warning(f"Idempotency cache store failed: {e}")

        return response