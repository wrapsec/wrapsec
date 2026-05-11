// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
/**
 * dashboard/components/layout/InactivityWarning.tsx
 *
 * Blocking modal shown 2 minutes before inactivity logout.
 * Cannot be dismissed by clicking outside or pressing Escape.
 * Timer continues accurately while modal is open.
 *
 * Props:
 *   secondsRemaining - countdown value from useInactivityTimer
 *   onStay           - resets timer, closes modal
 *   onLogout         - logout("manual"), redirect /login
 */
"use client"

import React from "react"

interface InactivityWarningProps {
  secondsRemaining: number
  onStay:           () => void
  onLogout:         () => void
}

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${s.toString().padStart(2, "0")}`
}

export function InactivityWarning({
  secondsRemaining,
  onStay,
  onLogout,
}: InactivityWarningProps) {
  return (
    // Backdrop - blocks all interaction, cannot dismiss by clicking
    <div style={{
      position:        "fixed",
      inset:           0,
      zIndex:          9999,
      background:      "rgba(0,0,0,0.55)",
      display:         "flex",
      alignItems:      "center",
      justifyContent:  "center",
      backdropFilter:  "blur(2px)",
    }}>
      <div style={{
        background:   "#fff",
        borderRadius: "12px",
        padding:      "32px 36px",
        maxWidth:     "400px",
        width:        "100%",
        boxShadow:    "0 20px 60px rgba(0,0,0,0.3)",
        textAlign:    "center",
      }}>
        {/* Icon */}
        <div style={{
          width:          "52px",
          height:         "52px",
          borderRadius:   "50%",
          background:     "#fffbeb",
          border:         "1px solid #fde68a",
          display:        "flex",
          alignItems:     "center",
          justifyContent: "center",
          margin:         "0 auto 20px",
        }}>
          <svg width={24} height={24} fill="none" stroke="#d97706" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round"
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>

        {/* Heading */}
        <p style={{ fontSize: "16px", fontWeight: 700, color: "#111827", margin: "0 0 8px 0" }}>
          Session expiring soon
        </p>

        {/* Countdown */}
        <p style={{ fontSize: "13px", color: "#6b7280", margin: "0 0 6px 0" }}>
          You will be logged out due to inactivity in
        </p>
        <p style={{
          fontSize:   "32px",
          fontWeight: 700,
          color:      secondsRemaining <= 30 ? "#dc2626" : "#d97706",
          margin:     "0 0 24px 0",
          fontVariantNumeric: "tabular-nums",
          transition: "color 0.3s",
        }}>
          {formatTime(secondsRemaining)}
        </p>

        {/* Buttons */}
        <div style={{ display: "flex", gap: "10px" }}>
          <button
            onClick={onLogout}
            style={{
              flex:         1,
              height:       "40px",
              fontSize:     "13px",
              fontWeight:   500,
              background:   "transparent",
              border:       "1px solid #e5e7eb",
              borderRadius: "8px",
              color:        "#6b7280",
              cursor:       "pointer",
              transition:   "border-color 0.15s, color 0.15s",
            }}
            onMouseEnter={e => {
              (e.target as HTMLElement).style.borderColor = "#9ca3af"
              ;(e.target as HTMLElement).style.color = "#374151"
            }}
            onMouseLeave={e => {
              (e.target as HTMLElement).style.borderColor = "#e5e7eb"
              ;(e.target as HTMLElement).style.color = "#6b7280"
            }}
          >
            Log out now
          </button>
          <button
            onClick={onStay}
            style={{
              flex:         1,
              height:       "40px",
              fontSize:     "13px",
              fontWeight:   600,
              background:   "linear-gradient(135deg, #670FEF, #CD00FF)",
              border:       "none",
              borderRadius: "8px",
              color:        "#fff",
              cursor:       "pointer",
              boxShadow:    "0 4px 12px rgba(103,15,239,0.30)",
              transition:   "opacity 0.15s",
            }}
            onMouseEnter={e => (e.target as HTMLElement).style.opacity = "0.88"}
            onMouseLeave={e => (e.target as HTMLElement).style.opacity = "1"}
          >
            Stay logged in
          </button>
        </div>
      </div>
    </div>
  )
}
