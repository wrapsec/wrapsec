// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { getSetupStatus, completeSetup } from "@/lib/api"

function LogoMark({ size = 48 }: { size?: number }) {
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

export default function SetupPage() {
  const router = useRouter()

  const [email,    setEmail]    = useState("")
  const [password, setPassword] = useState("")
  const [confirm,  setConfirm]  = useState("")
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState<string | null>(null)

  // If already initialized, redirect to login immediately
  useEffect(() => {
    getSetupStatus().then(({ initialized }) => {
      if (initialized) {
        router.replace("/login")
      } else {
        setLoading(false)
      }
    }).catch(() => setLoading(false))
  }, [router])

  async function handleSetup() {
    setError(null)

    if (!email.trim() || !password || !confirm) return

    if (password !== confirm) {
      setError("Passwords do not match.")
      return
    }

    setLoading(true)
    try {
      await completeSetup(email.trim().toLowerCase(), password)
      router.replace("/login?setup=done")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed. Please try again.")
    } finally {
      setLoading(false)
    }
  }

  const INPUT = {
    width: "100%", height: "42px", padding: "0 14px",
    fontSize: "13px", borderRadius: "8px",
    border: "1px solid rgba(255,255,255,0.12)",
    background: "rgba(255,255,255,0.06)",
    color: "#fff", outline: "none",
    transition: "border-color 0.15s",
  } as React.CSSProperties

  const LABEL = {
    display: "block", fontSize: "11px", fontWeight: 600,
    color: "rgba(255,255,255,0.5)", letterSpacing: "0.06em",
    textTransform: "uppercase" as const, marginBottom: "6px",
  }

  return (
    <div style={{
      minHeight: "100vh",
      background: "#0d1526",
      backgroundImage: "radial-gradient(ellipse at 20% 20%, rgba(103,15,239,0.20) 0%, transparent 50%), radial-gradient(ellipse at 80% 80%, rgba(0,177,255,0.10) 0%, transparent 50%)",
      display: "flex", alignItems: "center", justifyContent: "center",
      padding: "24px",
    }}>

      <div style={{
        width: "100%", maxWidth: "880px",
        display: "grid", gridTemplateColumns: "1fr 1fr",
        minHeight: "520px",
        borderRadius: "16px", overflow: "hidden",
        boxShadow: "0 25px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.08)",
      }}>

        {/* Left panel - brand */}
        <div style={{
          background: "linear-gradient(135deg, #0d1526 0%, #1a0a3d 100%)",
          backgroundImage: "radial-gradient(ellipse at 30% 40%, rgba(103,15,239,0.30) 0%, transparent 60%)",
          padding: "52px 48px",
          display: "flex", flexDirection: "column", justifyContent: "space-between",
          borderRight: "1px solid rgba(255,255,255,0.06)",
          position: "relative", overflow: "hidden",
        }}>
          <div style={{
            position: "absolute", top: -80, right: -80,
            width: 280, height: 280, borderRadius: "50%",
            background: "radial-gradient(circle, rgba(103,15,239,0.15) 0%, transparent 70%)",
            pointerEvents: "none",
          }} />
          <div style={{
            position: "absolute", bottom: -60, left: -60,
            width: 200, height: 200, borderRadius: "50%",
            background: "radial-gradient(circle, rgba(0,177,255,0.10) 0%, transparent 70%)",
            pointerEvents: "none",
          }} />

          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "14px", marginBottom: "40px" }}>
              <LogoMark size={44} />
              <div>
                <p style={{ fontSize: "22px", fontWeight: 700, color: "#fff", margin: 0, letterSpacing: "-0.02em" }}>
                  WrapSec
                </p>
                <p style={{ fontSize: "11px", color: "rgba(255,255,255,0.4)", margin: 0, letterSpacing: "0.06em", textTransform: "uppercase" }}>
                  AI Security Gateway
                </p>
              </div>
            </div>

            <h2 style={{ fontSize: "26px", fontWeight: 700, color: "#fff", margin: "0 0 12px 0", lineHeight: 1.2, letterSpacing: "-0.02em" }}>
              Welcome to<br />WrapSec.
            </h2>
            <p style={{ fontSize: "13px", color: "rgba(255,255,255,0.45)", margin: 0, lineHeight: 1.6 }}>
              Create your admin account to get started. This setup runs once - the page is disabled after your first login.
            </p>
          </div>

          <div>
            <span style={{
              fontSize: "10px", fontWeight: 600, color: "#a78bfa",
              background: "rgba(103,15,239,0.18)",
              border: "1px solid rgba(103,15,239,0.30)",
              borderRadius: "20px", padding: "3px 10px",
              letterSpacing: "0.03em",
            }}>
              v1.0.0
            </span>
          </div>
        </div>

        {/* Right panel - form */}
        <div style={{
          background: "#111d35",
          padding: "52px 48px",
          display: "flex", flexDirection: "column", justifyContent: "center",
        }}>
          <h3 style={{ fontSize: "18px", fontWeight: 700, color: "#fff", margin: "0 0 6px 0" }}>
            Create admin account
          </h3>
          <p style={{ fontSize: "12px", color: "rgba(255,255,255,0.35)", margin: "0 0 28px 0" }}>
            This is the only admin account. You can create more users from the dashboard.
          </p>

          {error && (
            <div style={{
              marginBottom: "16px", padding: "10px 14px",
              fontSize: "12px", color: "#fca5a5",
              background: "rgba(220,38,38,0.15)", border: "1px solid rgba(220,38,38,0.30)",
              borderRadius: "8px",
            }}>
              {error}
            </div>
          )}

          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            <div>
              <label style={LABEL}>Email</label>
              <input
                type="email" value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@example.com"
                autoFocus autoComplete="off" disabled={loading}
                style={INPUT}
                onFocus={e => (e.target as HTMLInputElement).style.borderColor = "#670FEF"}
                onBlur={e  => (e.target as HTMLInputElement).style.borderColor = "rgba(255,255,255,0.12)"}
              />
            </div>
            <div>
              <label style={LABEL}>Password</label>
              <input
                type="password" value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder=""
                autoComplete="new-password" disabled={loading}
                style={INPUT}
                onFocus={e => (e.target as HTMLInputElement).style.borderColor = "#670FEF"}
                onBlur={e  => (e.target as HTMLInputElement).style.borderColor = "rgba(255,255,255,0.12)"}
              />
            </div>
            <div>
              <label style={LABEL}>Confirm password</label>
              <input
                type="password" value={confirm}
                onChange={e => setConfirm(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleSetup()}
                placeholder=""
                autoComplete="new-password" disabled={loading}
                style={INPUT}
                onFocus={e => (e.target as HTMLInputElement).style.borderColor = "#670FEF"}
                onBlur={e  => (e.target as HTMLInputElement).style.borderColor = "rgba(255,255,255,0.12)"}
              />
            </div>
            <button
              onClick={handleSetup}
              disabled={!email.trim() || !password || !confirm || loading}
              style={{
                width: "100%", height: "42px", marginTop: "4px",
                background: "linear-gradient(135deg, #670FEF, #CD00FF)",
                color: "#fff", fontSize: "13px", fontWeight: 600,
                border: "none", borderRadius: "8px", cursor: "pointer",
                opacity: (!email.trim() || !password || !confirm || loading) ? 0.5 : 1,
                display: "flex", alignItems: "center", justifyContent: "center", gap: "8px",
                transition: "opacity 0.15s",
                boxShadow: "0 4px 16px rgba(103,15,239,0.35)",
              }}
            >
              {loading && (
                <svg style={{ width: 14, height: 14, animation: "spin 1s linear infinite" }} fill="none" viewBox="0 0 24 24">
                  <circle style={{ opacity: 0.25 }} cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path style={{ opacity: 0.75 }} fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              )}
              {loading ? "Setting up" : "Create admin account"}
            </button>
          </div>

          <p style={{ fontSize: "11px", color: "rgba(255,255,255,0.20)", marginTop: "32px", textAlign: "center" }}>
            WrapSec v1.0 · AI Security Gateway
          </p>
        </div>
      </div>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg) } to { transform: rotate(360deg) } }
        input::placeholder { color: rgba(255,255,255,0.20) !important }
      `}</style>
    </div>
  )
}
