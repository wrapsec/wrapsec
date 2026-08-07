// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { NextRequest, NextResponse } from "next/server"

const API_BASE_URL     = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
const COOKIE_SECURE    = process.env.COOKIE_SECURE === "true"
// M5: BFF Path handshake. This BFF is reachable at /api/auth/*, so refresh
// cookies must be scoped to that Path. The backend defaults to /v1/auth
// (correct for direct callers like the SDK / browser extension). We send
// X-Refresh-Cookie-Path along with an Origin that must be in the backend's
// cors_allowed_origins for the header to be honored. If DASHBOARD_ORIGIN
// is unset (e.g. dev), the backend won't recognise the Origin and will
// fall back to its configured default - which for a dashboard deployment
// should be set via REFRESH_COOKIE_PATH=/api/auth in the api container env.
const DASHBOARD_ORIGIN = process.env.DASHBOARD_ORIGIN || ""
const BFF_COOKIE_PATH  = "/api/auth"
// The middleware routing indicator (wrapsec_session) must outlive the 30-min
// access token: it marks that a SESSION exists, and the session lives as long as
// the refresh token (default 30 days). If it expired with the access token, a
// page navigation in the window before an API call triggered a refresh would hit
// the middleware with no session cookie and get bounced to /login mid-session.
// Real access control stays on the JWT (validated on every proxied API call);
// this cookie only gates the app shell. Override to match the backend's
// jwt_refresh_token_expire_days if that is not the 30-day default.
const SESSION_MAX_AGE_S = Number(process.env.SESSION_COOKIE_MAX_AGE_S) || 60 * 60 * 24 * 30

/**
 * Copy every Set-Cookie header the backend emitted onto our BFF response,
 * unchanged. Preserves any attribute the backend adds now or later
 * (SameSite value, Partitioned for CHIPS, etc.) without re-parsing.
 * Uses getSetCookie() (Node 18+ / undici) which returns an array of
 * individual Set-Cookie header values; falls back to the legacy
 * comma-joined form only if the runtime is old enough not to have it.
 */
function forwardBackendSetCookies(backend: Response, out: NextResponse): void {
  const anyHeaders = backend.headers as unknown as { getSetCookie?: () => string[] }
  const cookies = typeof anyHeaders.getSetCookie === "function"
    ? anyHeaders.getSetCookie()
    : (backend.headers.get("set-cookie") ? [backend.headers.get("set-cookie") as string] : [])
  for (const c of cookies) {
    out.headers.append("Set-Cookie", c)
  }
}

/**
 * POST /api/auth/login
 *
 * Handles two auth modes:
 *
 * Mode A - API key (existing, unchanged):
 *   Body: { apiKey: "wrapsec_admin_key" }
 *   Validates against backend, sets wrapsec_api_key httpOnly cookie.
 *
 * Mode B - JWT email/password (new):
 *   Body: { email: "admin@example.com", password: "..." }
 *   Calls POST /v1/auth/login, receives JWT access token + refresh cookie.
 *   Stores access token in wrapsec_jwt httpOnly cookie (short-lived, 30 min).
 *   The refresh token cookie is set by the backend directly (Path=/v1/auth) -
 *   it cannot be read here, but it persists in the browser for /v1/auth/* calls.
 */
// Real client IP for forwarding to backend rate limiter.
// Next.js populates x-forwarded-for from the incoming request (set by the
// edge/proxy in front of the BFF). Fallback to x-real-ip, then unknown.
// The backend trusts this header only when TRUSTED_PROXY_IPS is configured.
function getClientIp(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    req.headers.get("x-real-ip") ||
    "unknown"
  )
}

export async function POST(request: NextRequest) {
  const body = await request.json()
  const clientIp = getClientIp(request)

  // ── Mode A: API key login (unchanged) ──────────────────────────────────
  if (body.apiKey) {
    const { apiKey } = body

    const response = await fetch(
      `${API_BASE_URL}/v1/audit/logs?limit=1&offset=0`,
      {
        headers: {
          "Content-Type":    "application/json",
          "x-api-key":       apiKey,
          "x-forwarded-for": clientIp,
        },
      }
    )

    if (!response.ok) {
      return NextResponse.json({ error: "Invalid API key" }, { status: 401 })
    }

    const res = NextResponse.json({ success: true, auth_type: "api_key" })
    res.cookies.set("wrapsec_api_key", apiKey, {
      httpOnly: true,
      secure:   COOKIE_SECURE,
      sameSite: "strict",
      maxAge:   60 * 60 * 8,   // 8 hours
      path:     "/",
    })
    // Clear any stale JWT credentials - only one auth mechanism active at a time
    res.cookies.set("wrapsec_jwt",     "", { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", maxAge: 0, path: "/" })
    res.cookies.set("wrapsec_session", "", { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", maxAge: 0, path: "/" })
    res.cookies.set("refresh_token",   "", { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", maxAge: 0, path: "/api/auth" })
    return res
  }

  // ── Mode B: JWT email/password login ───────────────────────────────────
  if (body.email && body.password) {
    const { email, password } = body

    const outgoingHeaders: Record<string, string> = {
      "Content-Type":            "application/json",
      "x-forwarded-for":         clientIp,
      "X-Refresh-Cookie-Path":   BFF_COOKIE_PATH,
    }
    if (DASHBOARD_ORIGIN) {
      // Backend gates the header on Origin ∈ cors_allowed_origins.
      // Without a matching Origin the backend falls back to its
      // configured default REFRESH_COOKIE_PATH.
      outgoingHeaders["Origin"] = DASHBOARD_ORIGIN
    }
    const response = await fetch(`${API_BASE_URL}/v1/auth/login`, {
      method:  "POST",
      headers: outgoingHeaders,
      body:    JSON.stringify({ email, password }),
    })

    const data = await response.json().catch(() => ({}))

    if (!response.ok) {
      // Forward the exact error from the backend (INVALID_CREDENTIALS,
      // ACCOUNT_LOCKED, ACCOUNT_DISABLED) so the client can handle them
      return NextResponse.json(data, { status: response.status })
    }

    // Store access token as httpOnly cookie so the proxy route can read it
    // and forward it as Authorization: Bearer
    const res = NextResponse.json({
      success:               true,
      auth_type:             "jwt",
      force_password_change: data.force_password_change,
      user:                  data.user,
    })

    res.cookies.set("wrapsec_jwt", data.access_token, {
      httpOnly: true,
      secure:   COOKIE_SECURE,
      sameSite: "strict",
      maxAge:   data.expires_in || 1800,   // match token expiry (30 min)
      path:     "/",
    })

    // Session indicator - httpOnly, used by middleware for route protection only.
    // Lives as long as the refresh token (not the access token) so an active
    // session is not bounced to /login the moment the access token lapses.
    res.cookies.set("wrapsec_session", "jwt", {
      httpOnly: true,
      secure:   COOKIE_SECURE,
      sameSite: "strict",
      maxAge:   SESSION_MAX_AGE_S,
      path:     "/",
    })

    // Forward backend's Set-Cookie headers (refresh_token with the negotiated
    // Path) unchanged. The BFF supplied X-Refresh-Cookie-Path=/api/auth so
    // the backend emitted Path=/api/auth if it recognised our Origin; if
    // not, the backend used its configured default and this dashboard's
    // refresh flow won't have a matching Path - deployment env
    // (DASHBOARD_ORIGIN + backend REFRESH_COOKIE_PATH / cors_allowed_origins)
    // must be aligned. This is a deploy-time contract, not a runtime parse.
    forwardBackendSetCookies(response, res)

    // Clear any stale API key credential - only one auth mechanism active at a time
    res.cookies.set("wrapsec_api_key", "", { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", maxAge: 0, path: "/" })
    return res
  }

  return NextResponse.json(
    { error: "Provide either apiKey or email+password" },
    { status: 400 }
  )
}
