// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useEffect, useState, useCallback } from "react"

/**
 * Right-side slide-in drawer: the dashboard's standard "peek" surface for a
 * resource's detail while the list stays visible behind it. Open/close is
 * URL-driven by the caller (mount = open); this component owns only the overlay,
 * the slide animation, and the ESC / overlay-click / close-button affordances.
 *
 * header and footer are pinned (flex-shrink-0); children scroll between them.
 */
export function Drawer({ onClose, header, footer, children, width = 720, label = "Detail" }: {
  onClose:   () => void
  header?:   React.ReactNode
  footer?:   React.ReactNode
  children:  React.ReactNode
  width?:    number
  label?:    string
}) {
  const [shown, setShown] = useState(false)

  // Animate in on mount; animate out before the parent unmounts us.
  const requestClose = useCallback(() => {
    setShown(false)
    setTimeout(onClose, 200)
  }, [onClose])

  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(true))
    return () => cancelAnimationFrame(id)
  }, [])

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") requestClose() }
    document.addEventListener("keydown", h)
    return () => document.removeEventListener("keydown", h)
  }, [requestClose])

  return (
    <div className="fixed inset-0 z-50">
      <div
        className={`absolute inset-0 bg-black/40 transition-opacity duration-200 ${shown ? "opacity-100" : "opacity-0"}`}
        onClick={requestClose}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={label}
        className={`absolute top-0 right-0 h-full bg-white shadow-xl border-l border-slate-200 flex flex-col transition-transform duration-200 ${shown ? "translate-x-0" : "translate-x-full"}`}
        style={{ width: `min(${width}px, 100vw)` }}
      >
        <div className="flex-shrink-0 relative border-b border-slate-100">
          {header}
          <button
            onClick={requestClose}
            aria-label="Close"
            className="absolute top-4 right-4 text-slate-400 hover:text-slate-600 transition-colors"
          >
            <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">{children}</div>

        {footer && <div className="flex-shrink-0 border-t border-slate-100">{footer}</div>}
      </div>
    </div>
  )
}
