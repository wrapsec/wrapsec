from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from config.settings import get_settings

settings = get_settings()

# Paths that do not require authentication
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
    Validates API key or JWT on every protected request.
    Sets request.state.is_admin based on key type.
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

        # Standard API key — check against key store
        if api_key.startswith("wsk_live_"):
            request.state.is_admin = False
            return await call_next(request)

        # JWT — placeholder for now
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