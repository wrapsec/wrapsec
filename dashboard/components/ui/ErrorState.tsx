// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

interface ErrorStateProps {
  title?:   string
  message?: string
  action?:  React.ReactNode
}

/**
 * The single error-state used across the dashboard. Renders only a safe,
 * caller-supplied message (the API already returns a generic message + trace_id
 * for 5xx -- no internal detail leaks through here).
 */
export function ErrorState({ title = "Something went wrong", message, action }: ErrorStateProps) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-12 px-6">
      <p className="text-sm font-semibold text-red-700 mb-1">{title}</p>
      {message && <p className="text-xs text-slate-400 max-w-sm">{message}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
