// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { cn } from "@/lib/utils"

// Shared icon - import this wherever you need a + in a button
export function PlusIcon() {
  return (
    <svg style={{ width: 13, height: 13 }} fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4"/>
    </svg>
  )
}

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost"
  size?:    "sm" | "md" | "lg"
  loading?: boolean
  children: React.ReactNode
}

const V: Record<string, React.CSSProperties> = {
  primary:   { background: "var(--ws-violet)", color: "#fff",                        border: "1px solid var(--ws-violet)" },
  secondary: { background: "#fff",             color: "var(--text-primary)",          border: "1px solid var(--card-border)" },
  danger:    { background: "#dc2626",           color: "#fff",                        border: "1px solid #dc2626" },
  ghost:     { background: "transparent",       color: "var(--text-secondary)",       border: "1px solid transparent" },
}

const S: Record<string, React.CSSProperties> = {
  sm: { padding: "5px 10px",  fontSize: "12px", gap: "5px" },
  md: { padding: "7px 14px",  fontSize: "13px", gap: "6px" },
  lg: { padding: "9px 18px",  fontSize: "13px", gap: "6px" },
}

export function Button({ variant = "primary", size = "md", loading = false, children, disabled, className, style, ...props }: ButtonProps) {
  return (
    <button
      disabled={disabled || loading}
      className={className}
      style={{
        display:        "inline-flex",
        alignItems:     "center",
        justifyContent: "center",
        fontWeight:     500,
        borderRadius:   "6px",
        cursor:         "pointer",
        transition:     "opacity 0.15s, background 0.15s",
        fontFamily:     "inherit",
        opacity:        (disabled || loading) ? 0.5 : 1,
        ...V[variant],
        ...S[size],
        ...style,
      }}
      onMouseEnter={e => {
        if (!disabled && !loading) (e.currentTarget as HTMLElement).style.opacity = "0.85"
      }}
      onMouseLeave={e => {
        if (!disabled && !loading) (e.currentTarget as HTMLElement).style.opacity = "1"
      }}
      {...props}
    >
      {loading && (
        <svg style={{ width: "13px", height: "13px", animation: "spin 1s linear infinite" }} fill="none" viewBox="0 0 24 24">
          <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
          <circle style={{ opacity: 0.25 }} cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
          <path style={{ opacity: 0.75 }} fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
        </svg>
      )}
      {children}
    </button>
  )
}
