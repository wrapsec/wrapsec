import { NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

/**
 * Catch-all proxy route.
 *
 * Reads auth from httpOnly cookies (never from client JS):
 *   wrapsec_api_key → forwarded as x-api-key header
 *   wrapsec_jwt     → forwarded as Authorization: Bearer header
 *
 * API key takes precedence if both are somehow present (matches backend rule).
 * Returns 401 if neither cookie is present.
 */
async function handler(request: NextRequest) {
  const cookieStore = await cookies()
  const apiKey      = cookieStore.get("wrapsec_api_key")?.value
  const jwtToken    = cookieStore.get("wrapsec_jwt")?.value

  if (!apiKey && !jwtToken) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "Not authenticated" } },
      { status: 401 }
    )
  }

  // Build auth header — JWT wins if both present (required for admin write endpoints)
  // JWT users need Authorization: Bearer to satisfy require_admin() on PUT /v1/settings/*
  // API key used only when no JWT session exists (legacy API key dashboard sessions)
  const authHeaders: Record<string, string> = jwtToken
    ? { "Authorization": `Bearer ${jwtToken}` }
    : { "x-api-key": apiKey! }

  // Extract path after /api/proxy
  const url    = new URL(request.url)
  const path   = url.pathname.replace(/^\/api\/proxy/, "")
  const search = url.search
  const target = `${API_BASE_URL}${path}${search}`

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...authHeaders,
  }

  const options: RequestInit = {
    method: request.method,
    headers,
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    const body = await request.text()
    if (body) options.body = body
  }

  const response = await fetch(target, options)

  // Handle CSV export — return raw response, not JSON
  const contentType = response.headers.get("content-type") || ""
  if (contentType.includes("text/csv")) {
    const blob = await response.blob()
    return new NextResponse(blob, {
      status:  response.status,
      headers: {
        "Content-Type":        "text/csv",
        "Content-Disposition": response.headers.get("Content-Disposition") || "attachment",
      },
    })
  }

  // JWT token expired — clear cookie and return 401 so client redirects to login
  if (response.status === 401 && jwtToken && !apiKey) {
    const res = NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "Session expired" } },
      { status: 401 }
    )
    res.cookies.set("wrapsec_jwt", "", { maxAge: 0, path: "/" })
    res.cookies.set("wrapsec_session", "", { maxAge: 0, path: "/" })
    return res
  }

  const data = await response.json().catch(() => ({}))
  return NextResponse.json(data, { status: response.status })
}

export const GET    = handler
export const POST   = handler
export const PUT    = handler
export const PATCH  = handler
export const DELETE = handler
