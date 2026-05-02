// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
interface StatusDotProps {
  status: "ok" | "degraded" | "down"
  label?: string
}

export function StatusDot({ status, label }: StatusDotProps) {
  const colors = {
    ok:       "bg-green-500",
    degraded: "bg-yellow-500",
    down:     "bg-red-500",
  }

  return (
    <div className="flex items-center gap-1.5">
      <span
        className={`inline-block h-2 w-2 rounded-full ${colors[status]}`}
      />
      {label && (
        <span className="text-xs text-slate-600">{label}</span>
      )}
    </div>
  )
}