// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

interface EmptyStateProps {
  title:    string
  message?: string
  icon?:    React.ReactNode
  action?:  React.ReactNode
}

/**
 * The single empty-state used across the dashboard, replacing the ad-hoc
 * "no rows / no results" blocks each page used to hand-roll.
 */
export function EmptyState({ title, message, icon, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-12 px-6">
      {icon && <div className="mb-3 text-slate-300">{icon}</div>}
      <p className="text-sm font-semibold text-slate-700 mb-1">{title}</p>
      {message && <p className="text-xs text-slate-400 max-w-sm">{message}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
