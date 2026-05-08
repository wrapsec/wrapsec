// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"

const API_BASE_URL  = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true"

/**
 * POST /api/auth/logout
 *
 * Clears all auth cookies (API key and JWT).
 * For JWT sessions: calls POST /v1/auth/logout to revoke refresh token.
 * Forwards reason from request body to backend for auth_events logging.
 *
 * Always clears cookies regardless of backend response — logout must
 * always succeed from the client's perspective.
 */
export async function POST(request: NextRequest) {
  const cookieStore = await cookies()
  const jwtToken    = cookieStore.get("wrapsec_jwt")?.value

  // Parse reason from request body (default: "manual")
  let reason = "manual"
  try {
    const body = await request.json()
    if (body?.reason && typeof body.reason === "string") {
      reason = body.reason
    }
  } catch {
    // No body or invalid JSON — use default reason
  }

  // If JWT session — call backend to revoke refresh token with reason
  if (jwtToken) {
    try {
      await fetch(`${API_BASE_URL}/v1/auth/logout`, {
        method:  "POST",
        headers: {
          "Authorization": `Bearer ${jwtToken}`,
          "Content-Type":  "application/json",
        },
        body: JSON.stringify({ reason }),
      })
    } catch {
      // Best effort — clear local cookies regardless
    }
  }

  const res = NextResponse.json({ success: true })

  // Clear all auth cookies — always, regardless of backend response
  const cookieOpts = {
    httpOnly: true,
    secure:   COOKIE_SECURE,
    sameSite: "strict" as const,
    maxAge:   0,
    path:     "/",
  }

  res.cookies.set("wrapsec_api_key", "", cookieOpts)
  res.cookies.set("wrapsec_jwt",     "", cookieOpts)
  res.cookies.set("wrapsec_session", "", cookieOpts)

  return res
}
