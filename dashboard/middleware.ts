import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

/**
 * dashboard/middleware.ts
 *
 * Route guard. Checks for any valid session cookie before allowing access.
 * Two valid session states:
 *   wrapsec_api_key — API key auth (existing flow)
 *   wrapsec_session — JWT auth indicator (set on JWT login, non-httpOnly)
 *
 * Note: wrapsec_jwt is httpOnly so cannot be read here, but
 * wrapsec_session (non-httpOnly) is set alongside it as an indicator.
 * The actual token validation happens server-side in the proxy route.
 */

const PUBLIC_PATHS = [
  "/login",
  "/change-password",
  "/api/auth",
  "/_next",
  "/favicon.ico",
]

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Allow public paths
  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) {
    return NextResponse.next()
  }

  // Check for any valid session
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
