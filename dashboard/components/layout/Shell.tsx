// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { Sidebar } from "./Sidebar"
import { TopBar } from "./TopBar"
import { useInactivityTimer } from "@/hooks/useInactivityTimer"
import { InactivityWarning } from "./InactivityWarning"
import { useAuthOptional } from "@/components/auth/AuthProvider"

interface ShellProps {
  title:    string
  children: React.ReactNode
}

export function Shell({ title, children }: ShellProps) {
  const auth    = useAuthOptional()
  const router  = useRouter()
  const { showWarning, secondsRemaining, resetTimer, logoutNow } = useInactivityTimer()

  // Force-password-change users must change password before accessing any page.
  // This mirrors ProtectedRoute - catches JWT users who navigate directly to a
  // Shell-wrapped page without going through ProtectedRoute first.
  // Guard against null: useAuthOptional() returns null during static prerendering.
  useEffect(() => {
    if (auth && !auth.isLoading && auth.currentUser?.force_password_change) {
      router.replace("/change-password")
    }
  }, [auth, router])

  if (auth && !auth.isLoading && auth.currentUser?.force_password_change) return null

  return (
    <div className="flex h-screen" style={{ background: "var(--page-bg)" }}>
      {showWarning && (
        <InactivityWarning
          secondsRemaining={secondsRemaining}
          onStay={resetTimer}
          onLogout={logoutNow}
        />
      )}
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 min-h-0">
        <TopBar title={title} />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
