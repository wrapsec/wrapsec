// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { NextRequest, NextResponse } from "next/server"

const API_BASE_URL     = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
const COOKIE_SECURE    = process.env.COOKIE_SECURE === "true"
// M5: BFF Path handshake - see login/route.ts for the full explanation.
const DASHBOARD_ORIGIN = process.env.DASHBOARD_ORIGIN || ""
const BFF_COOKIE_PATH  = "/api/auth"
// See login/route.ts: the middleware session indicator must live as long as the
// refresh token (default 30 days), not the 30-min access token, or an active
// session is bounced to /login the moment the access token lapses.
const SESSION_MAX_AGE_S = Number(process.env.SESSION_COOKIE_MAX_AGE_S) || 60 * 60 * 24 * 30

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
 * POST /api/auth/refresh
 *
 * Relays the refresh token cookie to the backend and stores the
 * new access token as wrapsec_jwt httpOnly cookie.
 *
 * The browser's refresh_token cookie (Path=/v1/auth, httpOnly) is sent
 * automatically by the browser to this server-side route because Next.js
 * server actions run in the same origin. We forward it to the backend.
 */
export async function POST(request: NextRequest) {
  // Forward the refresh_token cookie from browser to backend
  const refreshCookie = request.cookies.get("refresh_token")?.value

  if (!refreshCookie) {
    return NextResponse.json({ error: "No refresh token" }, { status: 401 })
  }

  const outgoingHeaders: Record<string, string> = {
    "Cookie":                `refresh_token=${refreshCookie}`,
    "X-Refresh-Cookie-Path": BFF_COOKIE_PATH,
  }
  if (DASHBOARD_ORIGIN) {
    outgoingHeaders["Origin"] = DASHBOARD_ORIGIN
  }
  const response = await fetch(`${API_BASE_URL}/v1/auth/refresh`, {
    method:  "POST",
    headers: outgoingHeaders,
  })

  if (!response.ok) {
    // Clear JWT cookie on failed refresh
    const res = NextResponse.json({ error: "Session expired" }, { status: 401 })
    res.cookies.set("wrapsec_jwt", "", { maxAge: 0, path: "/" })
    res.cookies.set("wrapsec_session", "", { maxAge: 0, path: "/" })
    return res
  }

  const data = await response.json().catch(() => ({}))

  const res = NextResponse.json({ success: true })

  // Update access token cookie
  res.cookies.set("wrapsec_jwt", data.access_token, {
    httpOnly: true,
    secure:   COOKIE_SECURE,
    sameSite: "strict",
    maxAge:   data.expires_in || 1800,
    path:     "/",
  })

  // Keep session indicator alive - httpOnly matches login/route.ts. Lives as
  // long as the refresh token (not the access token), so navigating after the
  // access token lapses passes the middleware and the page's first API call
  // silently refreshes rather than redirecting to /login.
  res.cookies.set("wrapsec_session", "jwt", {
    httpOnly: true,
    secure:   COOKIE_SECURE,
    sameSite: "strict",
    maxAge:   SESSION_MAX_AGE_S,
    path:     "/",
  })

  // Re-resolve locale on every refresh: the backend re-runs User -> Tenant ->
  // System -> English, so a tenant/user preference change reaches a live session
  // without re-login. Set from the backend's resolved value, never a client
  // guess. (Older backends may omit resolved_locale; leave the cookie untouched.)
  if (data.resolved_locale) {
    res.cookies.set("wrapsec_locale", data.resolved_locale, {
      httpOnly: false,
      secure:   COOKIE_SECURE,
      sameSite: "strict",
      maxAge:   SESSION_MAX_AGE_S,
      path:     "/",
    })
  }

  // Forward backend's Set-Cookie headers (rotated refresh_token with the
  // negotiated Path) unchanged. See login/route.ts for the deploy-time
  // contract that keeps DASHBOARD_ORIGIN and backend cors_allowed_origins
  // aligned.
  forwardBackendSetCookies(response, res)

  return res
}
