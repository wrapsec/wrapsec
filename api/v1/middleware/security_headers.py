# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Adds security headers to every API response. Mirrors the dashboard-side
next.config.ts headers block (pentest H11) so both planes have equivalent
defense-in-depth even when accessed directly.

Headers set:
  X-Content-Type-Options: nosniff
  X-Frame-Options:        DENY
  Referrer-Policy:        no-referrer
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Content-Security-Policy:   default-src 'none'; frame-ancestors 'none'
  Permissions-Policy:     camera=(), microphone=(), geolocation=(), payment=()

Rationale for a locked-down CSP: this middleware runs on the API surface
which returns JSON, never HTML. default-src 'none' prevents any accidental
inline HTML response from loading external resources; frame-ancestors 'none'
enforces the same anti-framing rule as X-Frame-Options for CSP-aware clients.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


_SECURITY_HEADERS = {
    "X-Content-Type-Options":    "nosniff",
    "X-Frame-Options":           "DENY",
    "Referrer-Policy":           "no-referrer",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
    "Permissions-Policy":        "camera=(), microphone=(), geolocation=(), payment=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            # Never overwrite a value that upstream middleware or a handler
            # deliberately set (e.g. a CSP nonce for a doc route).
            response.headers.setdefault(name, value)
        return response
