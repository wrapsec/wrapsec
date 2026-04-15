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
        request.state.app_id     = None
        request.state.dept_id    = None
        request.state.tenant_id  = None

        api_key = request.headers.get("x-api-key", "")
        auth    = request.headers.get("authorization", "")

        # Admin API key
        if api_key == settings.admin_api_key:
            request.state.is_admin  = True
            request.state.key_id    = "admin"
            request.state.key_name  = "Admin Key"
            request.state.app_id    = None
            request.state.dept_id   = None
            request.state.tenant_id = None
            return await call_next(request)

        # Standard API key — validate against DB
        if api_key.startswith("wsk_live_"):
            key_record = await self._get_standard_key(api_key)
            if key_record:
                request.state.is_admin  = False
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

        # JWT — placeholder for future
        if auth.startswith("Bearer "):
            request.state.is_admin = False
            return await call_next(request)

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
        """Validate standard key and return the record."""
        try:
            import hashlib
            from db.session import AsyncSessionFactory
            from db.repositories.api_key import ApiKeyRepository

            key_hash = hashlib.sha256(api_key.encode()).hexdigest()

            async with AsyncSessionFactory() as session:
                repo   = ApiKeyRepository(session)
                record = await repo.get_by_hash(key_hash)
                if record and not record.revoked:
                    # Check if key has expired (grace period ended)
                    if record.expires_at is not None:
                        from datetime import datetime
                        now = datetime.utcnow()
                        import logging
                        logging.getLogger("wrapsec.auth").warning(
                            f"Key {record.key_id} expires_at={record.expires_at} now={now} expired={now > record.expires_at}"
                        )
                        if now > record.expires_at:
                            return None  # Grace period over — key no longer valid
                    return record
                return None

        except Exception as e:
            import logging
            logging.getLogger("wrapsec.auth").error(f"Key validation failed: {e}")
            return None