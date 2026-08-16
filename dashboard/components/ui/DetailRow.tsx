// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { cn } from "@/lib/utils"

/**
 * Uniform label/value grid used across detail surfaces. Replaces the ad-hoc
 * chip strips so every drawer/section renders label + value the same way.
 */
export function DetailGrid({ children, cols = 2, className }: {
  children:   React.ReactNode
  cols?:      1 | 2
  className?: string
}) {
  return (
    <div className={cn("grid gap-x-6 gap-y-3.5", cols === 2 ? "grid-cols-2" : "grid-cols-1", className)}>
      {children}
    </div>
  )
}

export function DetailRow({ label, children, mono, span }: {
  label:     string
  children:  React.ReactNode
  mono?:     boolean
  span?:     boolean
}) {
  return (
    <div className={cn("flex flex-col gap-0.5 min-w-0", span && "col-span-2")}>
      <span className="text-[11px] text-slate-600">{label}</span>
      <span className={cn("text-xs text-slate-700 break-words", mono && "font-mono")}>{children}</span>
    </div>
  )
}

/** Uppercase section label used above a DetailGrid or list within a tab. */
export function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-3">
      {children}
    </p>
  )
}
