// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useEffect } from "react"
import { useTranslations } from "next-intl"

function LogoMark({ size = 40 }: { size?: number }) {
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

interface Props {
  onClose: () => void
}

export function AboutModal({ onClose }: Props) {
  const t = useTranslations("common")
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    document.addEventListener("keydown", handler)
    return () => document.removeEventListener("keydown", handler)
  }, [onClose])

  return (
    <div
      onClick={onClose}
      style={{
        position:       "fixed",
        inset:          0,
        zIndex:         100,
        background:     "rgba(0,0,0,0.55)",
        display:        "flex",
        alignItems:     "center",
        justifyContent: "center",
        padding:        "24px",
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background:   "#0f1623",
          border:       "1px solid rgba(255,255,255,0.08)",
          borderRadius: "12px",
          width:        "100%",
          maxWidth:     "380px",
          overflow:     "hidden",
          boxShadow:    "0 24px 64px rgba(0,0,0,0.6)",
        }}
      >
        {/* Header */}
        <div style={{
          background:    "linear-gradient(135deg, rgba(103,15,239,0.2) 0%, rgba(0,177,255,0.08) 100%)",
          borderBottom:  "1px solid rgba(255,255,255,0.07)",
          padding:       "28px 28px 24px",
          textAlign:     "center",
          position:      "relative",
        }}>
          <button
            onClick={onClose}
            style={{
              position:     "absolute",
              top:          "14px",
              right:        "14px",
              background:   "none",
              border:       "none",
              cursor:       "pointer",
              color:        "rgba(255,255,255,0.35)",
              padding:      "4px",
              borderRadius: "4px",
              lineHeight:   0,
            }}
            onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.7)"}
            onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.35)"}
          >
            <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>

          <div style={{ display: "flex", justifyContent: "center", marginBottom: "14px" }}>
            <LogoMark size={44} />
          </div>
          <p style={{ fontSize: "18px", fontWeight: 700, color: "#ffffff", margin: "0 0 4px" }}>{t("app_name")}</p>
          <p style={{ fontSize: "12px", color: "rgba(255,255,255,0.45)", margin: "0 0 12px" }}>{t("tagline")}</p>
          <span style={{
            display:      "inline-block",
            fontSize:     "11px",
            fontWeight:   600,
            color:        "#a78bfa",
            background:   "rgba(103,15,239,0.18)",
            border:       "1px solid rgba(103,15,239,0.35)",
            borderRadius: "20px",
            padding:      "3px 12px",
            letterSpacing:"0.03em",
          }}>
            {t("version")}
          </span>
        </div>

        {/* Body */}
        <div style={{ padding: "20px 28px 8px" }}>
          <p style={{ fontSize: "12px", color: "rgba(255,255,255,0.5)", lineHeight: 1.65, margin: "0 0 20px", textAlign: "center" }}>
            {t("about.mission")}
          </p>

          <a
            href="https://wrapsec.com"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display:        "flex",
              alignItems:     "center",
              justifyContent: "center",
              gap:            "8px",
              padding:        "9px 10px",
              borderRadius:   "6px",
              textDecoration: "none",
              color:          "rgba(255,255,255,0.5)",
              transition:     "background 0.15s, color 0.15s",
            }}
            onMouseEnter={e => {
              (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.05)"
              ;(e.currentTarget as HTMLElement).style.color = "#ffffff"
            }}
            onMouseLeave={e => {
              (e.currentTarget as HTMLElement).style.background = "transparent"
              ;(e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.5)"
            }}
          >
            <svg width="13" height="13" fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/>
            </svg>
            <span style={{ fontSize: "12px" }}>{t("website")}</span>
          </a>
        </div>

        {/* Footer */}
        <div style={{ padding: "12px 28px 18px", textAlign: "center" }}>
          <p style={{ fontSize: "11px", color: "rgba(255,255,255,0.18)", margin: 0 }}>
            {t("about.copyright")}
          </p>
        </div>
      </div>
    </div>
  )
}
