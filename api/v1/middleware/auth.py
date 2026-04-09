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

        api_key = request.headers.get("x-api-key", "")
        auth    = request.headers.get("authorization", "")

        # Admin API key
        if api_key == settings.admin_api_key:
            request.state.is_admin = True
            return await call_next(request)

        # Standard API key — validate against DB
        if api_key.startswith("wsk_live_"):
            valid = await self._validate_standard_key(api_key)
            if valid:
                request.state.is_admin = False
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

    async def _validate_standard_key(self, api_key: str) -> bool:
        """Validate standard key against DB — check hash and revoked status."""
        try:
            import hashlib
            from db.session import AsyncSessionFactory
            from db.repositories.api_key import ApiKeyRepository

            key_hash = hashlib.sha256(api_key.encode()).hexdigest()

            async with AsyncSessionFactory() as session:
                repo   = ApiKeyRepository(session)
                record = await repo.get_by_hash(key_hash)
                return record is not None and not record.revoked

        except Exception as e:
            import logging
            logging.getLogger("wrapsec.auth").error(f"Key validation failed: {e}")
            # Fail closed — reject if DB unavailable
            return False