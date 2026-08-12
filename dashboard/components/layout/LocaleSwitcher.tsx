// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useLocale, useTranslations } from "next-intl"
import { useSetLocale } from "@/hooks/useSetLocale"
import { useAuthMode } from "@/hooks/useAuthMode"
import { SUPPORTED_LOCALES, LOCALE_LABELS } from "@/lib/locale"

/**
 * Header language switcher. Options + labels come from the generated
 * locale-config (derived from _meta.json); the current selection is the active
 * next-intl locale. Selecting calls useSetLocale -> PATCH /me -> the backend's
 * resolved locale is written to the cookie and server components re-render.
 *
 * Hidden when there is only one locale, or for API-key sessions: those cannot
 * persist a user preference (PATCH /me returns 403).
 */
export function LocaleSwitcher() {
  const current = useLocale()
  const t       = useTranslations("common")
  const setLocale = useSetLocale()
  const { isJwt } = useAuthMode()
  const [open,    setOpen]    = useState(false)
  const [pending, setPending] = useState<string | null>(null)
  const [failed,  setFailed]  = useState(false)

  if (SUPPORTED_LOCALES.length < 2 || !isJwt) return null

  const choose = async (loc: string) => {
    if (loc === current || pending) { setOpen(false); return }
    setPending(loc)
    setFailed(false)
    try {
      await setLocale(loc)   // PATCH /me -> resolved cookie -> router.refresh()
      setOpen(false)
    } catch {
      setFailed(true)
    } finally {
      setPending(null)
    }
  }

  return (
    <div style={{ position: "relative" }}>
      <button
        onClick={() => setOpen(v => !v)}
        aria-label={t("aria.language")}
        title={t("language")}
        style={{
          display:      "flex",
          alignItems:   "center",
          gap:          "6px",
          background:   "none",
          border:       "none",
          cursor:       "pointer",
          padding:      "4px 6px",
          borderRadius: "6px",
          color:        "var(--text-secondary)",
        }}
      >
        <svg style={{ width: "16px", height: "16px" }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9 9 0 100-18 9 9 0 000 18zm0 0c2.5-2.5 3.5-6 3.5-9S14.5 5.5 12 3M12 21c-2.5-2.5-3.5-6-3.5-9S9.5 5.5 12 3M3.5 12h17" />
        </svg>
        <span style={{ fontSize: "12px", fontWeight: 500 }}>{LOCALE_LABELS[current] ?? current}</span>
        <svg style={{ width: "11px", height: "11px", color: "var(--text-tertiary)" }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <>
          <div style={{ position: "fixed", inset: 0, zIndex: 10 }} onClick={() => setOpen(false)} />
          <div style={{
            position:     "absolute",
            top:          "calc(100% + 6px)",
            right:        0,
            minWidth:     "160px",
            background:   "#ffffff",
            border:       "1px solid var(--card-border)",
            borderRadius: "8px",
            boxShadow:    "0 4px 16px rgba(0,0,0,0.10)",
            zIndex:       50,
            padding:      "4px",
          }}>
            {SUPPORTED_LOCALES.map(loc => {
              const active = loc === current
              return (
                <button
                  key={loc}
                  onClick={() => choose(loc)}
                  disabled={!!pending}
                  style={{
                    display:      "flex",
                    alignItems:   "center",
                    justifyContent: "space-between",
                    gap:          "8px",
                    width:        "100%",
                    padding:      "8px 10px",
                    borderRadius: "6px",
                    fontSize:     "13px",
                    fontWeight:   active ? 600 : 400,
                    color:        active ? "var(--ws-violet, #670FEF)" : "var(--text-primary)",
                    background:   "none",
                    border:       "none",
                    cursor:       pending ? "default" : "pointer",
                    opacity:      pending && pending !== loc ? 0.5 : 1,
                    textAlign:    "left",
                  }}
                  onMouseEnter={e => { if (!pending) (e.currentTarget as HTMLElement).style.background = "#f4f5f7" }}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = "none"}
                >
                  <span>{LOCALE_LABELS[loc] ?? loc}</span>
                  {active && (
                    <svg style={{ width: "14px", height: "14px", flexShrink: 0 }} fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  )}
                </button>
              )
            })}
            {failed && (
              <p style={{ fontSize: "11px", color: "#dc2626", padding: "6px 10px", margin: 0 }}>
                {t("unexpected_error")}
              </p>
            )}
          </div>
        </>
      )}
    </div>
  )
}
