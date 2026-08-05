// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useEffect } from "react"
import { Button } from "@/components/ui/Button"

interface Props {
  title:         string
  message:       string
  confirmLabel?: string
  danger?:       boolean
  loading?:      boolean
  error?:        string | null
  onConfirm:     () => void
  onClose:       () => void
}

/**
 * Reusable confirmation dialog. Replaces the browser's window.confirm so
 * destructive actions get a consistent, styled prompt and can surface a
 * backend error inline instead of failing silently. Closes on Escape or a
 * backdrop click (never while an action is in flight).
 */
export function ConfirmModal({
  title, message, confirmLabel = "Confirm", danger = false,
  loading = false, error = null, onConfirm, onClose,
}: Props) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape" && !loading) onClose() }
    document.addEventListener("keydown", h)
    return () => document.removeEventListener("keydown", h)
  }, [onClose, loading])

  return (
    <div
      className="fixed inset-0 bg-black/40 flex items-center justify-center z-50"
      onClick={() => { if (!loading) onClose() }}
    >
      <div
        className="bg-white rounded-lg border border-slate-200 w-full max-w-sm p-6 shadow-lg"
        onClick={e => e.stopPropagation()}
      >
        <h2 className="text-base font-semibold text-slate-900 mb-1">{title}</h2>
        <p className="text-sm text-slate-500 mb-4">{message}</p>
        {error && <p className="text-xs text-red-600 mb-4">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button size="sm" variant="secondary" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            size="sm"
            variant={danger ? "danger" : "primary"}
            loading={loading}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  )
}
