"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { StatusDot } from "@/components/ui/StatusDot"
import { getHealth } from "@/lib/api"
import { logout } from "@/lib/auth"

export function TopBar({ title }: { title: string }) {
  const [status,      setStatus]      = useState<"ok" | "degraded" | "down">("ok")
  const [userEmail,   setUserEmail]   = useState<string | null>(null)
  const [userRole,    setUserRole]    = useState<string | null>(null)
  const [menuOpen,    setMenuOpen]    = useState(false)
  const router = useRouter()

  useEffect(() => {
    const loadUser = async () => {
      try {
        const res = await fetch("/api/proxy/v1/auth/me")
        if (res.ok) {
          const data = await res.json()
          setUserEmail(data.email ?? null)
          setUserRole(data.role ?? null)
        } else if (res.status === 403) {
          // API key session — /me requires JWT
          setUserEmail("Admin Key")
          setUserRole("API KEY")
        }
      } catch {
        setUserEmail(null)
      }
    }
    loadUser()
  }, [])

  useEffect(() => {
    const check = async () => {
      try {
        const health = await getHealth()
        const allOk  = Object.values(health.checks).every(v => v === "ok")
        setStatus(allOk ? "ok" : "degraded")
      } catch {
        setStatus("down")
      }
    }
    check()
    const interval = setInterval(check, 30000)
    return () => clearInterval(interval)
  }, [])

  const handleLogout = async () => {
    setMenuOpen(false)
    await logout()
    router.push("/login")
  }

  const initials = userEmail && userEmail !== "Admin Key"
    ? userEmail.slice(0, 2).toUpperCase()
    : "AK"

  return (
    <header className="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-6 flex-shrink-0">
      <h1 className="text-base font-semibold text-slate-900">{title}</h1>

      <div className="flex items-center gap-5">
        <StatusDot
          status={status}
          label={
            status === "ok"       ? "All systems operational" :
            status === "degraded" ? "Degraded" :
                                    "API unavailable"
          }
        />

        {/* User avatar + dropdown */}
        <div className="relative">
          <button
            onClick={() => setMenuOpen(prev => !prev)}
            className="flex items-center gap-2.5 hover:opacity-80 transition-opacity"
          >
            <div className="h-7 w-7 rounded-full bg-blue-800 flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-semibold text-white">{initials}</span>
            </div>
            {userEmail && (
              <div className="hidden sm:block text-left">
                <p className="text-xs font-medium text-slate-900 leading-none">{userEmail}</p>
                {userRole && (
                  <p className="text-xs text-slate-400 leading-none mt-0.5">{userRole}</p>
                )}
              </div>
            )}
            <svg className="h-3.5 w-3.5 text-slate-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {menuOpen && (
            <>
              {/* Backdrop */}
              <div
                className="fixed inset-0 z-10"
                onClick={() => setMenuOpen(false)}
              />
              {/* Menu — fixed to viewport so it renders above all layout */}
              <div className="fixed right-4 top-14 w-48 bg-white border border-slate-200 rounded-lg shadow-lg z-50 py-1">
                <Link
                  href="/profile"
                  onClick={() => setMenuOpen(false)}
                  className="flex items-center gap-2 px-4 py-2 text-xs text-slate-700 hover:bg-slate-50"
                >
                  <svg className="h-3.5 w-3.5 text-slate-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                  Profile
                </Link>
                <div className="border-t border-slate-100 my-1" />
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-2 w-full px-4 py-2 text-xs text-red-600 hover:bg-red-50"
                >
                  <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                  </svg>
                  Sign out
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
