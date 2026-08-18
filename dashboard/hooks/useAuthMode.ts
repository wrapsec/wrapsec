// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
/**
 * useAuthMode - detects current auth mode via server-side API route.
 *
 * Calls GET /api/auth/session which reads httpOnly cookies server-side.
 * Never reads document.cookie - all cookies remain httpOnly and JS-inaccessible.
 *
 * Returns:
 *   isJwt     - logged in with JWT (email/password); required for user-scoped
 *               actions like changing locale, but NOT sufficient for admin writes
 *   isApiKey  - logged in with API key only
 *   isAdmin   - JWT session whose role claim is ADMIN; gate admin-resource writes
 *               (create/edit keys, departments, applications, settings) on this.
 *               The backend re-validates the role; this only shapes the UI.
 *   canWrite  - legacy alias for isJwt; prefer isAdmin for admin-write gating
 *   loading   - true during initial fetch
 */
import { useState, useEffect } from "react"

interface SessionResponse {
  authenticated: boolean
  auth_type:     "jwt" | "api_key" | null
  role?:         string | null
  is_admin?:     boolean
  can_write:     boolean
}

export function useAuthMode() {
  const [session, setSession] = useState<SessionResponse>({
    authenticated: false,
    auth_type:     null,
    is_admin:      false,
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
    // Admin-resource writes require the ADMIN role; gate write actions on this,
    // not isJwt (a VIEWER/DEVELOPER JWT is not an admin).
    isAdmin:  session.is_admin === true,
    canWrite: session.can_write,
    loading,
  }
}
