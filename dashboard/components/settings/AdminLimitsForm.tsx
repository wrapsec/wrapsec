// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Button } from "@/components/ui/Button"
import { updateAdminLimits } from "@/lib/api"

interface AdminLimitsFormProps {
  adminWrite:  number
  exportLimit: number
  source:      string
  onUpdated:   (adminWrite: number, exportLimit: number, source: string) => void
}

export function AdminLimitsForm({
  adminWrite,
  exportLimit,
  source,
  onUpdated,
}: AdminLimitsFormProps) {
  const [write,  setWrite]  = useState(adminWrite)
  const [exp,    setExp]    = useState(exportLimit)
  const [saving, setSaving] = useState(false)
  const [saved,  setSaved]  = useState(false)
  const [error,  setError]  = useState<string | null>(null)
  const { isJwt } = useAuthMode()

  const writeValid = write >= 5  && write <= 200
  const expValid   = exp   >= 1  && exp   <= 60
  const isValid    = writeValid && expValid

  const handleSave = async () => {
    if (!isValid) return
    setSaving(true)
    setError(null)
    try {
      const updated = await updateAdminLimits({
        admin_write_rate_limit:  write,
        audit_export_rate_limit: exp,
      })
      onUpdated(updated.admin_write_rate_limit, updated.audit_export_rate_limit, updated.source)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">

      <div className="grid grid-cols-2 gap-5">

        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">
            Admin write operations
          </label>
          <input
            type="number"
            min={5}
            max={200}
            value={write}
            onChange={(e) => {
              const val = parseInt(e.target.value)
              if (!isNaN(val)) setWrite(val)
            }}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-400">
            Applies to user create, update, and password reset. Min: 5, Max: 200.
          </p>
          {!writeValid && (
            <p className="text-xs text-red-600">
              {write < 5 ? "Minimum is 5 - lower values may lock out legitimate admins" : "Maximum is 200"}
            </p>
          )}
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">
            Audit export
          </label>
          <input
            type="number"
            min={1}
            max={60}
            value={exp}
            onChange={(e) => {
              const val = parseInt(e.target.value)
              if (!isNaN(val)) setExp(val)
            }}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-400">
            Applies to CSV export (up to 10,000 rows per call). Min: 1, Max: 60.
          </p>
          {!expValid && (
            <p className="text-xs text-red-600">
              {exp < 1 ? "Minimum is 1" : "Maximum is 60"}
            </p>
          )}
        </div>

      </div>

      <div className="flex items-center gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2.5">
        <svg className="w-3.5 h-3.5 text-amber-600 shrink-0" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
        </svg>
        <p className="text-xs text-amber-700">
          These are security controls. Setting values too high reduces protection against compromised admin credentials.
          Changes are recorded in the audit log.
        </p>
      </div>

      <div className="flex items-center gap-2 text-xs text-slate-400">
        <span>Source:</span>
        <span className="font-mono bg-slate-100 px-1.5 py-0.5 rounded text-slate-600">{source}</span>
        {source === "database" && (
          <span>- overrides environment default, takes effect within 60 seconds</span>
        )}
      </div>

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3">
        {isJwt ? (
          <Button size="sm" onClick={handleSave} loading={saving} disabled={!isValid}>
            Save limits
          </Button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Button size="sm" disabled>Save limits</Button>
            <span style={{ fontSize: "11px", color: "#9ca3af" }}>
              Requires admin login -{" "}
              <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>sign in with email</a>
            </span>
          </div>
        )}
        {saved && (
          <span className="text-xs text-green-600">Saved - takes effect within 60 seconds</span>
        )}
      </div>

    </div>
  )
}
