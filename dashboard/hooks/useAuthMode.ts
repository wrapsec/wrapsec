// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
/**
 * useAuthMode — detects current auth mode via server-side API route.
 *
 * Calls GET /api/auth/session which reads httpOnly cookies server-side.
 * Never reads document.cookie — all cookies remain httpOnly and JS-inaccessible.
 *
 * Returns:
 *   isJwt     — logged in with JWT (email/password), write endpoints allowed
 *   isApiKey  — logged in with API key only, write endpoints rejected
 *   canWrite  — alias for isJwt
 *   loading   — true during initial fetch
 */
import { useState, useEffect } from "react"

interface SessionResponse {
  authenticated: boolean
  auth_type:     "jwt" | "api_key" | null
  can_write:     boolean
}

export function useAuthMode() {
  const [session, setSession] = useState<SessionResponse>({
    authenticated: false,
    auth_type:     null,
    can_write:     false,
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch("/api/auth/session")
      .then(r => r.json())
      .then((data: SessionResponse) => setSession(data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return {
    isJwt:    session.auth_type === "jwt",
    isApiKey: session.auth_type === "api_key",
    canWrite: session.can_write,
    loading,
  }
}
