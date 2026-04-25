from fastapi import Request
from starlette.responses import JSONResponse

from domain.entities.principal import (
    Principal,
    build_principal_from_api_key,
    build_principal_from_user,
)
from errors.exceptions import ForbiddenError, UnauthorizedError


def _get_principal_from_state(request: Request) -> Principal:
    """
    Builds a Principal from request.state populated by AuthMiddleware.
    Accepts both API key and JWT auth paths — all state fields are identical.

    Raises UnauthorizedError if request.state is not populated
    (should never happen in practice — middleware runs first).
    """
    principal_type = getattr(request.state, "principal_type", None)
    tenant_id      = getattr(request.state, "tenant_id", None)

    if not principal_type:
        raise UnauthorizedError()

    if principal_type == "user":
        # JWT path — build from state fields directly
        # (UserModel not available here — middleware already validated everything)
        return Principal(
            id          = getattr(request.state, "key_id", ""),       # "user:{uuid}"
            type        = __import__(
                              "domain.enums", fromlist=["PrincipalType"]
                          ).PrincipalType.USER,
            tenant_id   = tenant_id or "",
            dept_id     = getattr(request.state, "dept_id", None),
            roles       = [request.state.user_role] if request.state.user_role else [],
            permissions = __import__(
                              "domain.entities.principal", fromlist=["ROLE_PERMISSIONS"]
                          ).ROLE_PERMISSIONS.get(request.state.user_role or "", []),
            is_admin    = getattr(request.state, "is_admin", False),
            email       = getattr(request.state, "key_name", None),
        )
    else:
        # API key path — build from state fields directly
        return Principal(
            id          = getattr(request.state, "key_id", ""),       # "key:{key_id}"
            type        = __import__(
                              "domain.enums", fromlist=["PrincipalType"]
                          ).PrincipalType.API_KEY,
            tenant_id   = tenant_id or "",
            dept_id     = getattr(request.state, "dept_id", None),
            roles       = ["ADMIN"] if getattr(request.state, "is_admin", False) else ["DEVELOPER"],
            permissions = __import__(
                              "domain.entities.principal", fromlist=["ROLE_PERMISSIONS"]
                          ).ROLE_PERMISSIONS.get(
                              "ADMIN" if getattr(request.state, "is_admin", False) else "DEVELOPER",
                              [],
                          ),
            is_admin    = getattr(request.state, "is_admin", False),
        )


async def get_current_principal(request: Request) -> Principal:
    """
    FastAPI dependency — builds Principal from request.state.
    Accepts both API key and JWT auth.
    Use on endpoints that accept both (scan, audit, proxy).

    Usage:
        principal: Principal = Depends(get_current_principal)
    """
    return _get_principal_from_state(request)


async def require_jwt(request: Request) -> Principal:
    """
    FastAPI dependency — requires JWT specifically.
    Rejects API key auth with 403 FORBIDDEN.
    Use on all dashboard management endpoints.

    Usage:
        principal: Principal = Depends(require_jwt)
    """
    principal_type = getattr(request.state, "principal_type", None)
    if principal_type != "user":
        raise ForbiddenError("This endpoint requires dashboard (JWT) authentication.")
    return _get_principal_from_state(request)


def require_role(*roles: str):
    """
    FastAPI dependency factory — requires JWT + one of the given roles.
    Always implies require_jwt() — API keys get 403.

    Usage:
        Depends(require_role("ADMIN"))
        Depends(require_role("ADMIN", "DEVELOPER"))
    """
    async def _dependency(request: Request) -> Principal:
        # Must be JWT
        principal_type = getattr(request.state, "principal_type", None)
        if principal_type != "user":
            raise ForbiddenError("This endpoint requires dashboard (JWT) authentication.")

        principal = _get_principal_from_state(request)

        if not principal.has_role(*roles):
            raise ForbiddenError(
                f"Insufficient permissions. Required role: {' or '.join(roles)}."
            )
        return principal

    return _dependency


def require_admin():
    """
    Shorthand for Depends(require_role("ADMIN")).

    Usage:
        principal: Principal = Depends(require_admin())
    """
    return require_role("ADMIN")
