// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import Link from "next/link"

/**
 * The top-of-page KPI/summary card shared by Overview and Analytics, so both
 * rows have identical label / value / sub typography, accent, and spacing. The
 * only per-card variation is the data: an optional accent value color (Overview
 * tints by decision), an optional icon (Analytics), and an optional link.
 */
export function KpiCard({ label, value, sub, accent, icon, valueColor, href }: {
  label:       React.ReactNode
  value:       React.ReactNode
  sub?:        React.ReactNode
  accent?:     string      // hex; drives the top border and icon tint
  icon?:       string      // svg path `d`
  valueColor?: string      // hex; defaults to the neutral value color
  href?:       string
}) {
  const inner = (
    <div
      className="px-5 py-4 h-full"
      style={{
        background:    "var(--card-bg)",
        border:        "1px solid var(--card-border)",
        borderTop:     accent ? `3px solid ${accent}` : "1px solid var(--card-border)",
        borderRadius:  "8px",
      }}
    >
      <div className="flex items-start justify-between gap-2 mb-2.5">
        <span className="text-[10px] font-bold uppercase tracking-[0.08em] text-slate-400 leading-tight">
          {label}
        </span>
        {icon && accent && (
          <span
            className="flex items-center justify-center w-8 h-8 rounded-lg shrink-0"
            style={{ background: accent + "12" }}
          >
            <svg className="w-4 h-4" fill="none" stroke={accent} strokeWidth={1.75} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d={icon} />
            </svg>
          </span>
        )}
      </div>
      <div
        className="text-[28px] font-bold leading-none tabular-nums mb-1.5"
        style={{ color: valueColor ?? "#111827" }}
      >
        {value}
      </div>
      {sub != null && <div className="text-[11px] text-slate-400">{sub}</div>}
    </div>
  )

  if (href) {
    return (
      <Link href={href} className="block no-underline rounded-lg transition-shadow hover:shadow-md">
        {inner}
      </Link>
    )
  }
  return inner
}
