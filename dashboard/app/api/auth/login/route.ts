// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { NextRequest, NextResponse } from "next/server"

const API_BASE_URL  = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true"

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

    const response = await fetch(`${API_BASE_URL}/v1/auth/login`, {
      method:  "POST",
      headers: {
        "Content-Type":    "application/json",
        "x-forwarded-for": clientIp,
      },
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

    // Session indicator - httpOnly, used by middleware for route protection only
    res.cookies.set("wrapsec_session", "jwt", {
      httpOnly: true,
      secure:   COOKIE_SECURE,
      sameSite: "strict",
      maxAge:   data.expires_in || 1800,
      path:     "/",
    })

    // Re-issue the refresh token cookie scoped to the BFF auth path.
    // The backend sets Path=/v1/auth - the browser won't send that cookie to
    // /api/auth/* routes. We parse the token value and max-age from the
    // backend set-cookie and re-store it with Path=/api/auth so the browser
    // includes it on /api/auth/refresh and /api/auth/logout requests.
    const setCookie = response.headers.get("set-cookie")
    if (setCookie) {
      const tokenMatch  = setCookie.match(/refresh_token=([^;]+)/)
      const maxAgeMatch = setCookie.match(/[Mm]ax-[Aa]ge=(\d+)/)
      if (tokenMatch) {
        res.cookies.set("refresh_token", tokenMatch[1], {
          httpOnly: true,
          secure:   COOKIE_SECURE,
          sameSite: "strict",
          maxAge:   maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 30 * 24 * 60 * 60,
          path:     "/api/auth",
        })
      }
    }

    // Clear any stale API key credential - only one auth mechanism active at a time
    res.cookies.set("wrapsec_api_key", "", { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", maxAge: 0, path: "/" })
    return res
  }

  return NextResponse.json(
    { error: "Provide either apiKey or email+password" },
    { status: 400 }
  )
}
