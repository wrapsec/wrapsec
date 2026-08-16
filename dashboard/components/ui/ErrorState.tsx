// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

type Severity = "ERROR" | "WARNING" | "INFO"

interface ErrorStateProps {
  title?:    string
  message?:  string
  severity?: Severity
  action?:   React.ReactNode
}

// Error severity drives the title color (distinct from threat severity). The
// message resolver (useErrorMessage) supplies both the localized message and the
// severity from the error envelope.
const TITLE_COLOR: Record<Severity, string> = {
  ERROR:   "text-red-700",
  WARNING: "text-amber-700",
  INFO:    "text-sky-700",
}

/**
 * The single error-state used across the dashboard. Presentational only: it
 * renders a caller-supplied (already localized) message. Callers resolve the
 * message + severity via useErrorMessage so there is one localized error path.
 */
export function ErrorState({ title = "Something went wrong", message, severity = "ERROR", action }: ErrorStateProps) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-12 px-6">
      <p className={`text-sm font-semibold mb-1 ${TITLE_COLOR[severity]}`}>{title}</p>
      {message && <p className="text-xs text-slate-600 max-w-sm">{message}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
