from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from config.settings import get_settings

settings = get_settings()

PUBLIC_PATHS = {
    "/health",
    "/health/ready",
    "/health/live",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
}


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Validates API key on every protected request.
    Admin key — full access.
    Standard key (wsk_live_) — validated against DB.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in PUBLIC_PATHS:
            request.state.is_admin = False
            return await call_next(request)

        # Always capture network attribution
        request.state.ip_address = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
        request.state.user_agent = request.headers.get("user-agent", "")
        request.state.key_id     = None
        request.state.key_name   = None
        request.state.key_type   = "live"  # default — overridden below per key
        request.state.app_id     = None
        request.state.dept_id    = None
        request.state.tenant_id  = None

        api_key = request.headers.get("x-api-key", "")
        auth    = request.headers.get("authorization", "")

        # Admin API key
        if api_key == settings.admin_api_key:
            request.state.is_admin  = True
            request.state.key_type  = "live"  # admin key is always live
            request.state.key_id    = "admin"
            request.state.key_name  = "Admin Key"
            request.state.app_id    = None
            request.state.dept_id   = None
            request.state.tenant_id = None
            return await call_next(request)

        # Standard API key — validate against DB
        # Both wsk_live_ and wsk_trial_ go through the same DB validation.
        # key_type is read from the DB record — the prefix is display-only.
        if api_key.startswith("wsk_live_") or api_key.startswith("wsk_trial_"):
            key_record = await self._get_standard_key(api_key)
            if key_record:
                request.state.is_admin  = False
                request.state.key_type  = getattr(key_record, "key_type", "live") or "live"
                request.state.key_id    = key_record.key_id
                request.state.key_name  = key_record.name
                request.state.app_id    = str(key_record.app_id)    if key_record.app_id    else None
                request.state.dept_id   = str(key_record.dept_id)   if key_record.dept_id   else None
                request.state.tenant_id = str(key_record.tenant_id) if key_record.tenant_id else None
                return await call_next(request)
            else:
                trace_id = getattr(request.state, "trace_id", "")
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": {
                            "code":     "UNAUTHORIZED",
                            "message":  "Missing or invalid credentials",
                            "trace_id": trace_id,
                        }
                    },
                )

        # JWT auth not yet implemented.
        # Bearer tokens are rejected until JWT is live (Phase 2).

        # No valid credentials
        trace_id = getattr(request.state, "trace_id", "")
        return JSONResponse(
            status_code=401,
            content={
                "error": {
                    "code":     "UNAUTHORIZED",
                    "message":  "Missing or invalid credentials",
                    "trace_id": trace_id,
                }
            },
        )

    async def _get_standard_key(self, api_key: str):
        """Validate standard key, enforce grace period, update last_used_at."""
        try:
            import hashlib
            import logging
            from datetime import datetime
            from db.session import AsyncSessionFactory
            from db.repositories.api_key import ApiKeyRepository

            logger   = logging.getLogger("wrapsec.auth")
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()

            async with AsyncSessionFactory() as session:
                repo   = ApiKeyRepository(session)
                record = await repo.get_by_hash(key_hash)

                if not record or record.revoked:
                    return None

                # Check grace period expiry
                if record.expires_at is not None:
                    now = datetime.utcnow()
                    if now > record.expires_at:
                        return None  # Grace period over — key no longer valid

                # Update last_used_at on every successful auth
                try:
                    record.last_used_at = datetime.utcnow()
                    await session.commit()
                except Exception as e:
                    logger.warning(f"Failed to update last_used_at for {record.key_id}: {e}")

                return record

        except Exception as e:
            import logging
            logging.getLogger("wrapsec.auth").error(f"Key validation failed: {e}")
            return None