import { NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

async function handler(request: NextRequest) {
  const cookieStore = await cookies()
  const apiKey = cookieStore.get("wrapsec_api_key")?.value

  if (!apiKey) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "Not authenticated" } },
      { status: 401 }
    )
  }

  // Extract path after /api/proxy/
  const url      = new URL(request.url)
  const path     = url.pathname.replace(/^\/api\/proxy/, "")
  const search   = url.search
  const target   = `${API_BASE_URL}${path}${search}`

  // Forward request
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "x-api-key":    apiKey,
  }

  const options: RequestInit = {
    method:  request.method,
    headers,
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    const body = await request.text()
    if (body) options.body = body
  }

  const response = await fetch(target, options)
  const data     = await response.json().catch(() => ({}))

  return NextResponse.json(data, { status: response.status })
}

export const GET    = handler
export const POST   = handler
export const PUT    = handler
export const DELETE = handler