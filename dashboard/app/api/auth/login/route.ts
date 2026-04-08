import { NextRequest, NextResponse } from "next/server"

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

export async function POST(request: NextRequest) {
  const { apiKey } = await request.json()

  if (!apiKey) {
    return NextResponse.json(
      { error: "API key required" },
      { status: 400 }
    )
  }

  // Validate key against backend
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
    return NextResponse.json(
      { error: "Invalid API key" },
      { status: 401 }
    )
  }

  // Set HttpOnly cookie
  const res = NextResponse.json({ success: true })
  res.cookies.set("wrapsec_api_key", apiKey, {
    httpOnly:  true,
    secure:    process.env.NODE_ENV === "production",
    sameSite:  "strict",
    maxAge:    60 * 60 * 24,    // 24 hours
    path:      "/",
  })

  return res
}