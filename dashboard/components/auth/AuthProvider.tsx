// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

/**
 * dashboard/components/auth/AuthProvider.tsx
 *
 * Manages JWT session state for the entire dashboard.
 * Wraps the app in a context that exposes:
 *   - currentUser  — the authenticated AuthUser or null
 *   - isLoading    — true while initAuth() is running on mount
 *   - login()      — authenticate + store token
 *   - logout()     — revoke refresh token + clear state
 *
 * Token is stored in memory (never localStorage). On page refresh,
 * initAuth() silently restores the session via the httpOnly cookie.
 * If the cookie is gone or expired, user is redirected to /login.
 */

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from "react"
import { useRouter } from "next/navigation"
import {
  login as authLogin,
  logout as authLogout,
  initAuth,
  getToken,
  type AuthUser,
  type LoginResponse,
} from "@/lib/auth"

// ── Context shape ──────────────────────────────────────────────────────────

interface AuthContextValue {
  currentUser:  AuthUser | null
  isLoading:    boolean
  isAdmin:      boolean
  isDeveloper:  boolean
  login:        (email: string, password: string) => Promise<LoginResponse>
  logout:       () => Promise<void>
  refreshUser:  () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

// ── Provider ───────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null)
  const [isLoading,   setIsLoading]   = useState(true)
  const router = useRouter()

  // On mount: silent refresh to restore session from httpOnly cookie
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const user = await initAuth()
        if (!cancelled) setCurrentUser(user)
      } catch {
        if (!cancelled) setCurrentUser(null)
      } finally {
        if (!cancelled) setIsLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const login = useCallback(async (
    email:    string,
    password: string
  ): Promise<LoginResponse> => {
    const data = await authLogin(email, password)
    setCurrentUser(data.user)
    return data
  }, [])

  const logout = useCallback(async () => {
    await authLogout()
    setCurrentUser(null)
    router.push("/login")
  }, [router])

  const refreshUser = useCallback(async () => {
    try {
      const { getMe } = await import("@/lib/auth")
      const user = await getMe()
      setCurrentUser(user)
    } catch {
      setCurrentUser(null)
    }
  }, [])

  const isAdmin     = currentUser?.role === "ADMIN"
  const isDeveloper = currentUser?.role === "DEVELOPER" || isAdmin

  return (
    <AuthContext.Provider value={{
      currentUser,
      isLoading,
      isAdmin,
      isDeveloper,
      login,
      logout,
      refreshUser,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

// ── Hook ───────────────────────────────────────────────────────────────────

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>")
  return ctx
}

// Safe variant for components that may render outside AuthProvider during SSR.
// Returns null when context is not available — callers must guard against null.
export function useAuthOptional(): AuthContextValue | null {
  return useContext(AuthContext)
}
