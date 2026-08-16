// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"

/**
 * Read the `role` claim from a JWT without verifying the signature. This is for
 * UI gating ONLY -- the backend re-validates the token and enforces authorization
 * on every request, so a forged claim here cannot grant access, only change what
 * buttons render. Returns null for a malformed token.
 */
function jwtRole(token: string | undefined): string | null {
  if (!token) return null
  const parts = token.split(".")
  if (parts.length < 2) return null
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))
    return typeof payload?.role === "string" ? payload.role : null
  } catch {
    return null
  }
}

/**
 * GET /api/auth/session
 *
 * Returns current auth mode by reading httpOnly cookies server-side.
 * Never exposes cookie values - only the auth type + the role (for UI gating).
 * Called once on mount by useAuthMode hook via fetch, not direct cookie read.
 */
export async function GET(_request: NextRequest) {
  const cookieStore = await cookies()
  const jwt         = cookieStore.get("wrapsec_jwt")?.value
  const hasJwt      = !!jwt
  const hasApiKey   = !!cookieStore.get("wrapsec_api_key")?.value

  if (!hasJwt && !hasApiKey) {
    return NextResponse.json({ authenticated: false, auth_type: null })
  }

  // Admin-resource mutations require the ADMIN role (not merely a JWT session), so
  // the UI gates write actions on is_admin. The backend stays authoritative.
  const role    = hasJwt ? jwtRole(jwt) : null
  const isAdmin = role === "ADMIN"

  return NextResponse.json({
    authenticated: true,
    auth_type:     hasJwt ? "jwt" : "api_key",
    role,
    is_admin:      isAdmin,
    can_write:     hasJwt,   // has a JWT session (distinct from admin-write ability)
  })
}
