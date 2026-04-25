/**
 * dashboard/lib/auth.ts
 *
 * Auth utilities for the WrapSec dashboard.
 * Supports two auth modes that coexist:
 *
 * Mode A — API key (existing flow, unchanged):
 *   login(apiKey) → POST /api/auth/login with { apiKey }
 *   Sets wrapsec_api_key httpOnly cookie server-side.
 *
 * Mode B — JWT email/password (new):
 *   loginWithCredentials(email, password) → POST /api/auth/login with { email, password }
 *   Sets wrapsec_jwt httpOnly cookie server-side (access token).
 *   Backend sets refresh_token httpOnly cookie (Path=/v1/auth).
 *
 * Both modes share the same logout() function.
 * All tokens live in httpOnly cookies — never in JS memory or localStorage.
 */

// ── Mode A: API key login (existing — unchanged) ──────────────────────────

export async function login(apiKey: string): Promise<boolean> {
  const response = await fetch("/api/auth/login", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ apiKey }),
  })
  return response.ok
}

// ── Mode B: JWT email/password login (new) ────────────────────────────────

export interface JWTLoginResult {
  force_password_change: boolean
  user: {
    id:        string
    email:     string
    role:      "ADMIN" | "DEVELOPER" | "VIEWER"
    dept_id:   string | null
    tenant_id: string
  }
}

export async function loginWithCredentials(
  email:    string,
  password: string
): Promise<JWTLoginResult> {
  const response = await fetch("/api/auth/login", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ email, password }),
  })

  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    const code = data?.error?.code || "UNKNOWN"
    if (response.status === 429) {
      throw new AuthError("ACCOUNT_LOCKED", data?.error?.message || "Too many failed attempts")
    }
    if (code === "ACCOUNT_DISABLED") {
      throw new AuthError("ACCOUNT_DISABLED", "This account has been disabled.")
    }
    throw new AuthError("INVALID_CREDENTIALS", "Invalid email or password.")
  }

  return {
    force_password_change: data.force_password_change,
    user:                  data.user,
  }
}

// ── Refresh JWT (called by AuthProvider on page load) ─────────────────────

export async function refreshJWT(): Promise<boolean> {
  /**
   * Calls the backend refresh endpoint directly.
   * The browser automatically sends the refresh_token httpOnly cookie
   * (Path=/v1/auth) to the backend.
   *
   * On success: backend issues new access token. We store it via
   * the server-side route handler which sets wrapsec_jwt cookie.
   *
   * Note: we can't call POST /v1/auth/refresh through /api/proxy because
   * the proxy reads wrapsec_jwt — which doesn't exist yet on page load.
   * We call it through a dedicated route handler instead.
   */
  const response = await fetch("/api/auth/refresh", { method: "POST" })
  return response.ok
}

// ── Change password ───────────────────────────────────────────────────────

export async function changePassword(
  currentPassword: string,
  newPassword:     string
): Promise<void> {
  const response = await fetch("/api/proxy/v1/auth/change-password", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      current_password: currentPassword,
      new_password:     newPassword,
    }),
  })

  if (!response.ok) {
    const data = await response.json().catch(() => ({}))
    throw new AuthError(
      data?.error?.code || "INVALID_REQUEST",
      data?.error?.message || "Password change failed."
    )
  }
}

// ── Logout (shared by both modes) ─────────────────────────────────────────

export async function logout(): Promise<void> {
  await fetch("/api/auth/logout", { method: "POST" })
}

// ── AuthError ─────────────────────────────────────────────────────────────

export class AuthError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message)
    this.name = "AuthError"
  }
}
