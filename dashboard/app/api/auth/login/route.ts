import { NextRequest, NextResponse } from "next/server"

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

/**
 * POST /api/auth/login
 *
 * Handles two auth modes:
 *
 * Mode A — API key (existing, unchanged):
 *   Body: { apiKey: "wrapsec_admin_key" }
 *   Validates against backend, sets wrapsec_api_key httpOnly cookie.
 *
 * Mode B — JWT email/password (new):
 *   Body: { email: "admin@example.com", password: "..." }
 *   Calls POST /v1/auth/login, receives JWT access token + refresh cookie.
 *   Stores access token in wrapsec_jwt httpOnly cookie (short-lived, 30 min).
 *   The refresh token cookie is set by the backend directly (Path=/v1/auth) —
 *   it cannot be read here, but it persists in the browser for /v1/auth/* calls.
 */
export async function POST(request: NextRequest) {
  const body = await request.json()

  // ── Mode A: API key login (unchanged) ──────────────────────────────────
  if (body.apiKey) {
    const { apiKey } = body

    const response = await fetch(
      `${API_BASE_URL}/v1/audit/logs?limit=1&offset=0`,
      {
        headers: {
          "Content-Type": "application/json",
          "x-api-key":    apiKey,
        },
      }
    )

    if (!response.ok) {
      return NextResponse.json({ error: "Invalid API key" }, { status: 401 })
    }

    const res = NextResponse.json({ success: true, auth_type: "api_key" })
    res.cookies.set("wrapsec_api_key", apiKey, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge:   60 * 60 * 8,   // 8 hours
      path:     "/",
    })
    return res
  }

  // ── Mode B: JWT email/password login ───────────────────────────────────
  if (body.email && body.password) {
    const { email, password } = body

    const response = await fetch(`${API_BASE_URL}/v1/auth/login`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
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
      secure:   process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge:   data.expires_in || 1800,   // match token expiry (30 min)
      path:     "/",
    })

    // Session indicator — httpOnly, used by middleware for route protection only
    res.cookies.set("wrapsec_session", "jwt", {
      httpOnly: true,
      secure:   process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge:   data.expires_in || 1800,
      path:     "/",
    })

    // Forward the refresh token cookie from the backend response
    // The backend sets: refresh_token=...; HttpOnly; Path=/v1/auth
    // We need to relay it to the browser since this is a server-side fetch
    const setCookie = response.headers.get("set-cookie")
    if (setCookie) {
      res.headers.append("set-cookie", setCookie)
    }

    return res
  }

  return NextResponse.json(
    { error: "Provide either apiKey or email+password" },
    { status: 400 }
  )
}
