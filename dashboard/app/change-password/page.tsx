"use client"

import React, { useState, FormEvent } from "react"
import { useRouter } from "next/navigation"
import { changePassword, logout, AuthError } from "@/lib/auth"

const REQUIREMENTS = [
  { label: "At least 8 characters", test: (p: string) => p.length >= 8 },
  { label: "One uppercase letter",  test: (p: string) => /[A-Z]/.test(p) },
  { label: "One lowercase letter",  test: (p: string) => /[a-z]/.test(p) },
  { label: "One digit",             test: (p: string) => /\d/.test(p) },
]

function LogoMark({ size = 36 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 249 221" fill="none">
      <g transform="matrix(1,0,0,1,-375.623461,-389.613053)">
        <g transform="matrix(1,0,0,1,-0,22.207172)">
          <g transform="matrix(1.835477,-1.386843,2.13606,2.827061,252.359105,497.387654)">
            <path d="M160,35C160,37.76 156.549,40 152.299,40L107.701,40C103.451,40 100,37.76 100,35C100,32.24 103.451,30 107.701,30L152.299,30C156.549,30 160,32.24 160,35Z" fill="#670FEF"/>
          </g>
          <g transform="matrix(-0.81495,1.114041,-2.859803,-2.09202,653.361273,461.347338)">
            <path d="M160,35C160,37.76 154.249,40 147.165,40L112.835,40C105.751,40 100,37.76 100,35C100,32.24 105.751,30 112.835,30L147.165,30C154.249,30 160,32.24 160,35Z" fill="#CD00FF"/>
          </g>
          <g transform="matrix(0.975083,1.240032,-2.785324,2.190204,674.397302,330.426277)">
            <path d="M90,65C90,67.76 84.968,70 78.769,70L31.231,70C25.032,70 20,67.76 20,65C20,62.24 25.032,60 31.231,60L78.769,60C84.968,60 90,62.24 90,65Z" fill="#00E1FF"/>
          </g>
          <g transform="matrix(2.248397,1.601761,-2.055903,2.885877,265.218885,33.107289)">
            <path d="M150,65C150,67.76 147.124,70 143.582,70L116.418,70C112.876,70 110,67.76 110,65C110,62.24 112.876,60 116.418,60L143.582,60C147.124,60 150,62.24 150,65Z" fill="#00B1FF"/>
          </g>
        </g>
      </g>
    </svg>
  )
}

const INPUT: React.CSSProperties = {
  width: "100%", height: "42px", padding: "0 14px",
  fontSize: "13px", borderRadius: "8px",
  border: "1px solid rgba(255,255,255,0.12)",
  background: "rgba(255,255,255,0.06)",
  color: "#fff", outline: "none",
  transition: "border-color 0.15s",
  boxSizing: "border-box",
}

const LABEL: React.CSSProperties = {
  display: "block", fontSize: "11px", fontWeight: 600,
  color: "rgba(255,255,255,0.5)", letterSpacing: "0.06em",
  textTransform: "uppercase", marginBottom: "6px",
}

export default function ChangePasswordPage() {
  const router = useRouter()

  const [current, setCurrent] = useState("")
  const [next,    setNext]    = useState("")
  const [confirm, setConfirm] = useState("")
  const [error,   setError]   = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)

  const reqsMet        = REQUIREMENTS.every(r => r.test(next))
  const passwordsMatch = next === confirm && next.length > 0

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (!reqsMet)        { setError("New password does not meet requirements."); return }
    if (!passwordsMatch) { setError("Passwords do not match."); return }
    setLoading(true)
    try {
      await changePassword(current, next)
      setSuccess(true)
      setTimeout(async () => { await logout(); router.replace("/login") }, 2000)
    } catch (err) {
      if (err instanceof AuthError) {
        setError(err.code === "INVALID_PASSWORD" ? "Current password is incorrect." : err.message || "Password change failed.")
      } else {
        setError("Something went wrong. Please try again.")
      }
    } finally {
      setLoading(false)
    }
  }

  const PAGE_STYLE: React.CSSProperties = {
    minHeight: "100vh",
    background: "#0d1526",
    backgroundImage: "radial-gradient(ellipse at 20% 20%, rgba(103,15,239,0.20) 0%, transparent 50%), radial-gradient(ellipse at 80% 80%, rgba(0,177,255,0.10) 0%, transparent 50%)",
    display: "flex", alignItems: "center", justifyContent: "center", padding: "24px",
  }

  if (success) {
    return (
      <div style={PAGE_STYLE}>
        <div style={{
          background: "#111d35", borderRadius: "16px", padding: "48px 40px",
          textAlign: "center", width: "100%", maxWidth: "400px",
          boxShadow: "0 25px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.08)",
        }}>
          <div style={{
            width: 52, height: 52, borderRadius: "50%", margin: "0 auto 20px",
            background: "rgba(16,185,129,0.15)", border: "1px solid rgba(16,185,129,0.3)",
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <svg width={24} height={24} fill="none" stroke="#10b981" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <p style={{ fontSize: "16px", fontWeight: 700, color: "#fff", margin: "0 0 8px 0" }}>
            Password changed
          </p>
          <p style={{ fontSize: "13px", color: "rgba(255,255,255,0.40)", margin: 0 }}>
            All sessions signed out. Redirecting to login…
          </p>
        </div>
      </div>
    )
  }

  return (
    <div style={PAGE_STYLE}>
      <div style={{ width: "100%", maxWidth: "400px" }}>

        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "32px", justifyContent: "center" }}>
          <LogoMark size={36} />
          <div>
            <p style={{ fontSize: "18px", fontWeight: 700, color: "#fff", margin: 0, letterSpacing: "-0.02em" }}>WrapSec</p>
            <p style={{ fontSize: "10px", color: "rgba(255,255,255,0.35)", margin: 0, letterSpacing: "0.07em", textTransform: "uppercase" }}>AI Security Gateway</p>
          </div>
        </div>

        {/* Card */}
        <div style={{
          background: "#111d35", borderRadius: "16px", padding: "36px 40px",
          boxShadow: "0 25px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.08)",
        }}>
          <p style={{ fontSize: "18px", fontWeight: 700, color: "#fff", margin: "0 0 6px 0" }}>
            Change password
          </p>
          <p style={{ fontSize: "12px", color: "rgba(255,255,255,0.35)", margin: "0 0 28px 0" }}>
            Choose a new password to continue.
          </p>

          {error && (
            <div style={{
              marginBottom: "16px", padding: "10px 14px", fontSize: "12px",
              color: "#fca5a5", background: "rgba(220,38,38,0.15)",
              border: "1px solid rgba(220,38,38,0.30)", borderRadius: "8px",
            }}>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "18px" }}>
            <div>
              <label style={LABEL}>Current password</label>
              <input type="password" value={current} onChange={e => setCurrent(e.target.value)}
                required disabled={loading} autoComplete="current-password" style={INPUT}
                onFocus={e => (e.target as HTMLInputElement).style.borderColor = "#670FEF"}
                onBlur={e  => (e.target as HTMLInputElement).style.borderColor = "rgba(255,255,255,0.12)"}
              />
            </div>

            <div>
              <label style={LABEL}>New password</label>
              <input type="password" value={next} onChange={e => setNext(e.target.value)}
                required disabled={loading} autoComplete="new-password" style={INPUT}
                onFocus={e => (e.target as HTMLInputElement).style.borderColor = "#670FEF"}
                onBlur={e  => (e.target as HTMLInputElement).style.borderColor = "rgba(255,255,255,0.12)"}
              />
              {next.length > 0 && (
                <ul style={{ margin: "8px 0 0 0", padding: 0, listStyle: "none", display: "flex", flexDirection: "column", gap: "4px" }}>
                  {REQUIREMENTS.map(r => (
                    <li key={r.label} style={{ display: "flex", alignItems: "center", gap: "6px",
                      fontSize: "11px", color: r.test(next) ? "#10b981" : "rgba(255,255,255,0.30)" }}>
                      <span style={{ fontSize: "10px" }}>{r.test(next) ? "✓" : "○"}</span>
                      {r.label}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <label style={LABEL}>Confirm new password</label>
              <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)}
                required disabled={loading} autoComplete="new-password"
                style={{ ...INPUT, borderColor: confirm.length > 0 && !passwordsMatch ? "#dc2626" : "rgba(255,255,255,0.12)" }}
                onFocus={e => (e.target as HTMLInputElement).style.borderColor = confirm.length > 0 && !passwordsMatch ? "#dc2626" : "#670FEF"}
                onBlur={e  => (e.target as HTMLInputElement).style.borderColor = confirm.length > 0 && !passwordsMatch ? "#dc2626" : "rgba(255,255,255,0.12)"}
              />
              {confirm.length > 0 && !passwordsMatch && (
                <p style={{ fontSize: "11px", color: "#fca5a5", margin: "5px 0 0 0" }}>Passwords do not match</p>
              )}
            </div>

            <div style={{ display: "flex", gap: "10px", paddingTop: "4px" }}>
              <button type="button" onClick={logout} disabled={loading} style={{
                flex: 1, height: "42px", fontSize: "13px", fontWeight: 500,
                background: "transparent", border: "1px solid rgba(255,255,255,0.12)",
                color: "rgba(255,255,255,0.55)", borderRadius: "8px", cursor: "pointer",
                transition: "border-color 0.15s, color 0.15s",
              }}
                onMouseEnter={e => { (e.target as HTMLElement).style.borderColor = "rgba(255,255,255,0.25)"; (e.target as HTMLElement).style.color = "rgba(255,255,255,0.8)" }}
                onMouseLeave={e => { (e.target as HTMLElement).style.borderColor = "rgba(255,255,255,0.12)"; (e.target as HTMLElement).style.color = "rgba(255,255,255,0.55)" }}
              >
                Sign out
              </button>
              <button type="submit" disabled={loading || !reqsMet || !passwordsMatch} style={{
                flex: 1, height: "42px", fontSize: "13px", fontWeight: 600,
                background: "linear-gradient(135deg, #670FEF, #CD00FF)",
                color: "#fff", border: "none", borderRadius: "8px", cursor: "pointer",
                opacity: (loading || !reqsMet || !passwordsMatch) ? 0.45 : 1,
                transition: "opacity 0.15s",
                boxShadow: "0 4px 16px rgba(103,15,239,0.35)",
              }}>
                {loading ? "Saving…" : "Change password"}
              </button>
            </div>
          </form>
        </div>

        <p style={{ fontSize: "11px", color: "rgba(255,255,255,0.18)", textAlign: "center", marginTop: "24px" }}>
          WrapSec v1.5 · AI Security Gateway
        </p>
      </div>
      <style>{`input::placeholder { color: rgba(255,255,255,0.20) !important }`}</style>
    </div>
  )
}
