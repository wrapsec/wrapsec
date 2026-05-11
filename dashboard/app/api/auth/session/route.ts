// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"

/**
 * GET /api/auth/session
 *
 * Returns current auth mode by reading httpOnly cookies server-side.
 * Never exposes cookie values - only returns the auth type.
 * Called once on mount by useAuthMode hook via fetch, not direct cookie read.
 */
export async function GET(_request: NextRequest) {
  const cookieStore = await cookies()
  const hasJwt      = !!cookieStore.get("wrapsec_jwt")?.value
  const hasApiKey   = !!cookieStore.get("wrapsec_api_key")?.value

  if (!hasJwt && !hasApiKey) {
    return NextResponse.json({ authenticated: false, auth_type: null })
  }

  return NextResponse.json({
    authenticated: true,
    auth_type:     hasJwt ? "jwt" : "api_key",
    can_write:     hasJwt,   // write endpoints require JWT
  })
}
