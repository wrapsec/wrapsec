import { NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

/**
 * POST /api/auth/logout
 *
 * Clears all auth cookies (API key and JWT).
 * For JWT sessions: also calls POST /v1/auth/logout to revoke the refresh token.
 */
export async function POST(request: NextRequest) {
  const cookieStore = await cookies()
  const jwtToken    = cookieStore.get("wrapsec_jwt")?.value

  // If JWT session — call backend logout to revoke refresh token
  if (jwtToken) {
    try {
      await fetch(`${API_BASE_URL}/v1/auth/logout`, {
        method:  "POST",
        headers: { "Authorization": `Bearer ${jwtToken}` },
      })
    } catch {
      // Best effort — clear local cookies regardless
    }
  }

  const res = NextResponse.json({ success: true })

  // Clear API key cookie
  res.cookies.set("wrapsec_api_key", "", {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   0,
    path:     "/",
  })

  // Clear JWT cookie
  res.cookies.set("wrapsec_jwt", "", {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   0,
    path:     "/",
  })

  // Clear session indicator
  res.cookies.set("wrapsec_session", "", {
    httpOnly: false,
    secure:   process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge:   0,
    path:     "/",
  })

  return res
}
