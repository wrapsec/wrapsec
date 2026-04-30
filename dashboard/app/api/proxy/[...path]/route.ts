import { NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

/**
 * Catch-all proxy route.
 *
 * GUARANTEE: this route ALWAYS returns JSON — never HTML.
 * All error paths are wrapped in try/catch with explicit JSON responses.
 * This prevents JSON.parse crashes in the frontend when sessions expire.
 *
 * Reads auth from httpOnly cookies (never from client JS):
 *   wrapsec_api_key → forwarded as x-api-key header
 *   wrapsec_jwt     → forwarded as Authorization: Bearer header
 *
 * JWT wins if both present (required for admin write endpoints).
 * Returns 401 JSON if neither cookie is present.
 */
async function handler(request: NextRequest) {
  try {
    const cookieStore = await cookies()
    const apiKey      = cookieStore.get("wrapsec_api_key")?.value
    const jwtToken    = cookieStore.get("wrapsec_jwt")?.value

    if (!apiKey && !jwtToken) {
      return NextResponse.json(
        { error: { code: "UNAUTHORIZED", message: "Not authenticated" } },
        { status: 401 }
      )
    }

    // JWT wins if both present — required for admin write endpoints
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

    // JWT token expired — clear cookies and return JSON 401
    if (response.status === 401 && jwtToken && !apiKey) {
      const res = NextResponse.json(
        { error: { code: "UNAUTHORIZED", message: "Session expired" } },
        { status: 401 }
      )
      res.cookies.set("wrapsec_jwt",     "", { maxAge: 0, path: "/" })
      res.cookies.set("wrapsec_session", "", { maxAge: 0, path: "/" })
      return res
    }

    // Parse response as JSON — if backend returns non-JSON, return 502
    const data = await response.json().catch(() => null)
    if (data === null) {
      return NextResponse.json(
        { error: { code: "UPSTREAM_ERROR", message: "Invalid response from server" } },
        { status: 502 }
      )
    }

    return NextResponse.json(data, { status: response.status })

  } catch (error) {
    // Catch-all — network failure, timeout, etc.
    // Always return JSON — never let an exception bubble as HTML
    console.error("Proxy handler error:", error)
    return NextResponse.json(
      { error: { code: "INTERNAL_ERROR", message: "Internal proxy error" } },
      { status: 500 }
    )
  }
}

export const GET    = handler
export const POST   = handler
export const PUT    = handler
export const PATCH  = handler
export const DELETE = handler
