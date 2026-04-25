import { NextRequest, NextResponse } from "next/server"

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

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
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   data.expires_in || 1800,
    path:     "/",
  })

  // Keep session indicator alive
  res.cookies.set("wrapsec_session", "jwt", {
    httpOnly: false,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   data.expires_in || 1800,
    path:     "/",
  })

  // Forward the new refresh_token cookie from backend if present
  const setCookie = response.headers.get("set-cookie")
  if (setCookie) {
    res.headers.append("set-cookie", setCookie)
  }

  return res
}
