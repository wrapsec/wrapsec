// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

/**
 * dashboard/components/auth/ProtectedRoute.tsx
 *
 * Wraps any page that requires authentication.
 * - Shows a loading spinner while initAuth() resolves on mount
 * - Redirects to /login if no session is found
 * - Redirects to /change-password if force_password_change = true
 * - Optionally enforces a minimum role (adminOnly, developerOnly)
 * - Renders children only when user is confirmed + authorised
 */

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "./AuthProvider"

interface ProtectedRouteProps {
  children:       React.ReactNode
  adminOnly?:     boolean
  developerOnly?: boolean
}

export function ProtectedRoute({
  children,
  adminOnly     = false,
  developerOnly = false,
}: ProtectedRouteProps) {
  const { currentUser, isLoading, isAdmin, isDeveloper } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (isLoading) return

    // No session — go to login
    if (!currentUser) {
      router.replace("/login")
      return
    }

    // Must change password — only /change-password is allowed
    if (currentUser.force_password_change) {
      router.replace("/change-password")
      return
    }

    // Role checks
    if (adminOnly && !isAdmin) {
      router.replace("/")
      return
    }

    if (developerOnly && !isDeveloper) {
      router.replace("/")
      return
    }
  }, [isLoading, currentUser, isAdmin, isDeveloper, adminOnly, developerOnly, router])

  // Loading — show nothing (or a spinner)
  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-blue-600 border-t-transparent" />
      </div>
    )
  }

  // Not authenticated or wrong role — render nothing while redirect fires
  if (!currentUser) return null
  if (currentUser.force_password_change) return null
  if (adminOnly && !isAdmin) return null
  if (developerOnly && !isDeveloper) return null

  return <>{children}</>
}
