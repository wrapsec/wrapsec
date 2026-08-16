// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { cn } from "@/lib/utils"

/**
 * The time-range segmented control duplicated inline on Overview / Analytics /
 * Sources. One implementation of the active-pill look.
 */
export function RangeTabs<T extends string>({ options, value, onChange, format }: {
  options:  readonly T[]
  value:    T
  onChange:  (v: T) => void
  format?:  (o: T) => string
}) {
  return (
    <div className="flex gap-0.5 bg-slate-100 rounded-lg p-[3px]">
      {options.map(o => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={cn(
            "text-xs px-3 py-1.5 rounded-md border-none cursor-pointer transition-all",
            value === o
              ? "bg-white text-slate-900 font-semibold shadow-sm"
              : "bg-transparent text-slate-600 font-normal",
          )}
        >
          {format ? format(o) : o}
        </button>
      ))}
    </div>
  )
}
