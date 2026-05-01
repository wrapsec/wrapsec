"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { getHealth } from "@/lib/api"
import { logout } from "@/lib/auth"

export function TopBar({ title }: { title: string }) {
  const [status,    setStatus]    = useState<"ok" | "degraded" | "down">("ok")
  const [checks,    setChecks]    = useState<Record<string, string>>({})
  const [userEmail, setUserEmail] = useState<string | null>(null)
  const [userRole,  setUserRole]  = useState<string | null>(null)
  const [menuOpen,  setMenuOpen]  = useState(false)
  const router = useRouter()

  useEffect(() => {
    fetch("/api/proxy/v1/auth/me").then(async res => {
      if (res.ok) {
        const d = await res.json()
        setUserEmail(d.email ?? null)
        setUserRole(d.role ?? null)
      } else if (res.status === 403) {
        // API key session — /me requires JWT, 403 is expected and handled
        setUserEmail("Admin Key")
        setUserRole("API KEY")
      }
    }).catch(() => {})
  }, [])

  useEffect(() => {
    const check = async () => {
      try {
        const health = await getHealth()
        const c      = health.checks ?? {}
        setChecks(c)
        const allOk  = Object.keys(c).length > 0 && Object.values(c).every(v => v === "ok")
        setStatus(allOk ? "ok" : "degraded")
      } catch { setStatus("down") }
    }
    check()
    const t = setInterval(check, 30000)
    return () => clearInterval(t)
  }, [])

  const handleLogout = async () => {
    setMenuOpen(false)
    try {
      await logout()
    } catch {
      // Best effort — cookies are cleared server-side regardless
    }
    router.push("/login")
  }

  const initials = userEmail && userEmail !== "Admin Key"
    ? userEmail.slice(0, 2).toUpperCase()
    : "AK"

  const statusColor = status === "ok" ? "#00E1FF" : status === "degraded" ? "#d97706" : "#dc2626"
  const failed      = Object.entries(checks).filter(([, v]) => v !== "ok").map(([k]) => k)
  const statusLabel = status === "ok"
    ? "All systems operational"
    : status === "degraded"
    ? `Degraded${failed.length ? `: ${failed.join(", ")}` : ""}`
    : "API unavailable"

  return (
    <header style={{
      height:       "56px",
      background:   "var(--topbar-bg)",
      borderBottom: "none",
      display:      "flex",
      alignItems:   "center",
      justifyContent: "space-between",
      padding:      "0 24px",
      flexShrink:   0,
      position:     "relative",
    }}>
      {/* Purple accent line at bottom */}
      <div style={{
        position:   "absolute",
        bottom:     0,
        left:       0,
        right:      0,
        height:     "2px",
        background: "linear-gradient(90deg, #670FEF 0%, #CD00FF 40%, #00E1FF 80%, #00B1FF 100%)",
      }} />

      <h1 style={{ fontSize: "15px", fontWeight: 600, color: "var(--text-primary)", margin: 0 }}>
        {title}
      </h1>

      <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
        {/* Health status */}
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <span style={{
            width: "7px", height: "7px", borderRadius: "50%",
            background: statusColor,
            display: "inline-block",
            boxShadow: status === "ok" ? `0 0 0 2px rgba(0,225,255,0.20)` : "none",
          }} />
          <span style={{ fontSize: "12px", color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
            {statusLabel}
          </span>
        </div>

        {/* User menu */}
        <div style={{ position: "relative" }}>
          <button
            onClick={() => setMenuOpen(v => !v)}
            style={{
              display:    "flex",
              alignItems: "center",
              gap:        "8px",
              background: "none",
              border:     "none",
              cursor:     "pointer",
              padding:    "4px",
              borderRadius: "6px",
            }}
          >
            <div style={{
              height: "30px", width: "30px", borderRadius: "50%",
              background: "linear-gradient(135deg, #670FEF, #CD00FF)",
              display: "flex", alignItems: "center", justifyContent: "center",
              flexShrink: 0,
            }}>
              <span style={{ fontSize: "11px", fontWeight: 600, color: "#fff" }}>{initials}</span>
            </div>
            {userEmail && (
              <div style={{ textAlign: "left" }}>
                <p style={{ fontSize: "12px", fontWeight: 500, color: "var(--text-primary)", lineHeight: 1, margin: 0 }}>
                  {userEmail}
                </p>
                {userRole && (
                  <p style={{ fontSize: "11px", color: "var(--text-tertiary)", lineHeight: 1, marginTop: "2px" }}>
                    {userRole}
                  </p>
                )}
              </div>
            )}
            <svg style={{ width: "12px", height: "12px", color: "var(--text-tertiary)" }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/>
            </svg>
          </button>

          {menuOpen && (
            <>
              <div style={{ position: "fixed", inset: 0, zIndex: 10 }} onClick={() => setMenuOpen(false)} />
              <div style={{
                position:   "fixed",
                right:      "16px",
                top:        "60px",
                width:      "180px",
                background: "#ffffff",
                border:     "1px solid var(--card-border)",
                borderRadius: "8px",
                boxShadow:  "0 4px 16px rgba(0,0,0,0.10)",
                zIndex:     50,
                padding:    "4px",
              }}>
                <Link
                  href="/profile"
                  onClick={() => setMenuOpen(false)}
                  style={{
                    display: "flex", alignItems: "center", gap: "8px",
                    padding: "8px 10px", borderRadius: "6px",
                    fontSize: "13px", color: "var(--text-primary)",
                    textDecoration: "none",
                  }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "#f4f5f7"}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = "none"}
                >
                  <svg style={{ width: "14px", height: "14px", color: "var(--text-tertiary)" }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                  </svg>
                  Profile
                </Link>
                <div style={{ height: "1px", background: "var(--card-border)", margin: "4px 0" }} />
                <button
                  onClick={handleLogout}
                  style={{
                    display: "flex", alignItems: "center", gap: "8px",
                    padding: "8px 10px", borderRadius: "6px", width: "100%",
                    fontSize: "13px", color: "#dc2626",
                    background: "none", border: "none", cursor: "pointer",
                  }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "#fef2f2"}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = "none"}
                >
                  <svg style={{ width: "14px", height: "14px" }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
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
