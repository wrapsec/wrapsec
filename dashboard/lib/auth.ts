// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
/**
 * dashboard/lib/auth.ts
 *
 * Auth utilities for the WrapSec dashboard.
 * Supports two auth modes that coexist:
 *
 * Mode A - API key (existing flow, unchanged):
 *   login(apiKey) -> POST /api/auth/login with { apiKey }
 *   Sets wrapsec_api_key httpOnly cookie server-side.
 *
 * Mode B - JWT email/password (new):
 *   loginWithCredentials(email, password) -> POST /api/auth/login with { email, password }
 *   Sets wrapsec_jwt httpOnly cookie server-side (access token).
 *   Backend sets refresh_token httpOnly cookie (Path=/v1/auth).
 *
 * Both modes share the same logout() function.
 * All tokens live in httpOnly cookies - never in JS memory or localStorage.
 */

// ── isLoggingOut flag ────────────────────────────────────────────────────
// Set to true before logout() fetch - prevents concurrent silent refresh
// from succeeding after logout decision is made.
// Checked in api.ts request() before any refresh attempt.
// See session_management.md Convention 42.
export let isLoggingOut = false

// ── Single-flight token refresh ───────────────────────────────────────────
// The backend ROTATES the refresh token on every /auth/refresh (the presented
// token is revoked and a new one issued). If two refreshes run concurrently
// with the same token, the second presents an already-rotated token, gets a
// 401, and forces a spurious logout even though the first refresh succeeded.
// An actively-browsing user fires several parallel API calls, so when the
// 30-min access token expires they all 401 at once. Sharing ONE in-flight
// promise (and routing initAuth/refreshJWT/api.ts through it) guarantees a
// single rotation per expiry, after which every waiter retries with the new
// token. Module singletons are shared across the whole client bundle.
let inflightRefresh: Promise<boolean> | null = null

export function refreshSession(): Promise<boolean> {
  if (!inflightRefresh) {
    inflightRefresh = fetch("/api/auth/refresh", { method: "POST" })
      .then(r => r.ok)
      .catch(() => false)
      .finally(() => { inflightRefresh = null })
  }
  return inflightRefresh
}

// ── Mode A: API key login ───────────────────────────────────────────────────
// Use loginWithApiKey() for API key auth from login page.

export async function loginWithApiKey(apiKey: string): Promise<boolean> {
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
  user: AuthUser
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
   * the proxy reads wrapsec_jwt - which doesn't exist yet on page load.
   * We call it through a dedicated route handler instead.
   */
  return refreshSession()
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

export async function logout(
  reason: "manual" | "inactivity" | "expired" = "manual"
): Promise<void> {
  isLoggingOut = true   // set BEFORE fetch - prevents concurrent refresh
  await fetch("/api/auth/logout", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ reason }),
  })
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

// ── login(email, password) - used by AuthProvider ────────────────────────
// AuthProvider imports this as authLogin(email, password) -> LoginResponse
// Wraps loginWithCredentials to match AuthProvider's expected signature.

export async function login(
  email:    string,
  password: string
): Promise<LoginResponse> {
  const result = await loginWithCredentials(email, password)
  return {
    force_password_change: result.force_password_change,
    user:                  result.user,
  }
}

// ── Types ─────────────────────────────────────────────────────────────────

export interface AuthUser {
  id:                    string
  email:                 string
  role:                  "ADMIN" | "DEVELOPER" | "VIEWER" | "AUDITOR"
  dept_id:               string | null
  tenant_id:             string
  is_active:             boolean
  force_password_change: boolean
  last_login_at:         string | null
  // Stored preference and the backend-resolved effective locale (User -> Tenant
  // -> System -> English). AuthProvider uses resolved_locale to reconcile the
  // rendered locale after an out-of-band (SDK/API) change.
  locale?:               string | null
  resolved_locale?:      string
}

export interface LoginResponse {
  force_password_change: boolean
  user: AuthUser
}

// ── initAuth - silent session restore on page load ────────────────────────
// Called by AuthProvider on mount to restore session from httpOnly cookie.
// Attempts refresh via /api/auth/refresh, then fetches current user.
// Returns AuthUser on success, throws on failure.

export async function initAuth(): Promise<AuthUser> {
  isLoggingOut = false  // clear flag - a new session is being established
  const refreshed = await refreshSession()
  if (!refreshed) {
    throw new Error("No active session")
  }
  return getMe()
}

// ── getMe - fetch current user profile ────────────────────────────────────

export async function getMe(): Promise<AuthUser> {
  const response = await fetch("/api/proxy/v1/auth/me", {
    headers: { "Content-Type": "application/json" },
  })
  if (!response.ok) {
    throw new Error("Failed to fetch user")
  }
  const data = await response.json()
  return data as AuthUser
}

// ── getToken - not used (tokens in httpOnly cookies) ─────────────────────
// Kept for backward compatibility with AuthProvider import.
// Always returns null - tokens are never accessible to JS.

export function getToken(): null {
  return null
}
