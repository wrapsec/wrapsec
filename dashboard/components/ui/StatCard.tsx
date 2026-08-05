// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { cn } from "@/lib/utils"

/**
 * The label + value stat block repeated across the monitoring pages (Overview
 * KPIs, the Sources per-source grid, Analytics numbers). One presentation for
 * all of them. Presentational only -- the caller supplies formatted values.
 */
export function StatCard({ label, value, sub, className }: {
  label: React.ReactNode
  value: React.ReactNode
  sub?:  React.ReactNode
  className?: string
}) {
  return (
    <div className={className}>
      <div className="text-[10px] font-semibold uppercase tracking-[0.05em] text-slate-400">{label}</div>
      <div className="text-lg font-bold text-slate-900 tabular-nums">{value}</div>
      {sub != null && <div className="text-xs text-slate-400 mt-0.5">{sub}</div>}
    </div>
  )
}
