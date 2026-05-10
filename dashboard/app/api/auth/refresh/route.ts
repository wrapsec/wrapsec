// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { NextRequest, NextResponse } from "next/server"

const API_BASE_URL  = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true"

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

  const response = await fetch(`${API_BASE_URL}/v1/auth/refresh`, {
    method:  "POST",
    headers: {
      "Cookie": `refresh_token=${refreshCookie}`,
    },
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

  // Keep session indicator alive — httpOnly matches login/route.ts
  // Middleware reads this server-side via request.cookies; JS never needs it.
  res.cookies.set("wrapsec_session", "jwt", {
    httpOnly: true,
    secure:   COOKIE_SECURE,
    sameSite: "strict",
    maxAge:   data.expires_in || 1800,
    path:     "/",
  })

  // Re-issue the rotated refresh token with Path=/api/auth (same as login/route.ts).
  // Backend returns Path=/v1/auth — rewrite to BFF path so browser sends it here.
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

  return res
}
