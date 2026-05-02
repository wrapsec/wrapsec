// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

/**
 * dashboard/middleware.ts
 *
 * Route guard. Checks for any valid session cookie before allowing access.
 *
 * CRITICAL: /api/* paths must NEVER be intercepted by this middleware.
 * API routes handle their own auth and return JSON 401 — not HTML redirects.
 * Intercepting /api/* causes HTML to be returned instead of JSON, breaking
 * all error handling in the frontend (JSON.parse crash).
 *
 * Two valid session states:
 *   wrapsec_api_key — API key auth (existing flow)
 *   wrapsec_session — JWT auth indicator (httpOnly, set on JWT login)
 *
 * wrapsec_jwt is httpOnly and cannot be read here.
 * wrapsec_session is httpOnly and used only by server-side routes.
 * Both are checked via request.cookies (server-side readable in middleware).
 */

const PUBLIC_PATHS = [
  "/login",
  "/change-password",
  "/_next",
  "/favicon.ico",
]

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // MUST skip all /api/* routes — they handle own auth, return JSON
  if (pathname.startsWith("/api/")) {
    return NextResponse.next()
  }

  // Allow public UI paths
  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) {
    return NextResponse.next()
  }

  // Check for any valid session cookie (both readable server-side)
  const hasApiKey  = !!request.cookies.get("wrapsec_api_key")?.value
  const hasSession = !!request.cookies.get("wrapsec_session")?.value

  if (!hasApiKey && !hasSession) {
    const loginUrl = new URL("/login", request.url)
    return NextResponse.redirect(loginUrl)
  }

  return NextResponse.next()
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
}
