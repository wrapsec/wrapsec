"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { updateRetentionSettings } from "@/lib/api"

interface RetentionSettingsFormProps {
  retentionDays:      number
  source:             string
  proxyRetentionDays: number
  storageMode:        string
  onUpdated:          (days: number) => void
}

const STORAGE_MODE_LABELS: Record<string, { label: string; description: string; color: string }> = {
  full: {
    label:       "Full",
    description: "Raw input and output stored as-is. Use for development and debugging.",
    color:       "bg-amber-50 text-amber-700 border-amber-200",
  },
  masked: {
    label:       "Masked",
    description: "PII is redacted before storing (e.g. emails, phone numbers). Recommended for production.",
    color:       "bg-green-50 text-green-700 border-green-200",
  },
  none: {
    label:       "None",
    description: "Input and output text is never stored. Only metadata is retained. For strict compliance.",
    color:       "bg-slate-50 text-slate-600 border-slate-200",
  },
}

export function RetentionSettingsForm({
  retentionDays,
  source,
  proxyRetentionDays,
  storageMode,
  onUpdated,
}: RetentionSettingsFormProps) {
  const [days,   setDays]   = useState(retentionDays)
  const [saving, setSaving] = useState(false)
  const [saved,  setSaved]  = useState(false)
  const [error,  setError]  = useState<string | null>(null)

  const isValid = days >= 7 && days <= 3650

  const handleSave = async () => {
    if (!isValid) return
    setSaving(true)
    setError(null)
    try {
      const updated = await updateRetentionSettings(days)
      onUpdated(updated.retention_days)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const modeInfo = STORAGE_MODE_LABELS[storageMode] ?? STORAGE_MODE_LABELS["masked"]

  return (
    <div className="space-y-6">

      {/* Storage mode -- read only, set via .env */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          Storage Mode
        </p>
        <div className="flex items-start gap-3">
          <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold border ${modeInfo.color}`}>
            {modeInfo.label}
          </span>
          <p className="text-xs text-slate-500 mt-0.5">{modeInfo.description}</p>
        </div>
        <p className="text-xs text-slate-400 mt-2">
          Configured via <code className="font-mono bg-slate-100 px-1 rounded">DATA_STORAGE_MODE</code> in your environment.
          Options: <code className="font-mono bg-slate-100 px-1 rounded">full</code> · <code className="font-mono bg-slate-100 px-1 rounded">masked</code> · <code className="font-mono bg-slate-100 px-1 rounded">none</code>
        </p>
      </div>

      <div className="border-t border-slate-100" />

      {/* Audit logs retention -- editable */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          Audit Log Retention
        </p>
        <div className="grid grid-cols-2 gap-5">
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              Retention period (days)
            </label>
            <input
              type="number"
              min={7}
              max={3650}
              value={days}
              onChange={(e) => {
                const val = parseInt(e.target.value)
                if (!isNaN(val)) setDays(val)
              }}
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
            />
            <p className="text-xs text-slate-400">
              Audit logs older than {days} days will be deleted. Min: 7, Max: 3650.
            </p>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              Setting source
            </label>
            <div className="h-9 px-3 text-sm rounded-md border border-slate-100 bg-slate-50 flex items-center text-slate-600">
              {source}
            </div>
            <p className="text-xs text-slate-400">
              Where the current value was read from
            </p>
          </div>
        </div>

        {!isValid && (
          <p className="text-xs text-red-600 mt-2">
            {days < 7 ? "Minimum retention is 7 days" : "Maximum retention is 3650 days"}
          </p>
        )}
      </div>

      {/* Proxy interactions retention -- read only, set via .env */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          Proxy Interaction Text Retention
        </p>
        <div className="grid grid-cols-2 gap-5">
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              Text retention period (days)
            </label>
            <div className="h-9 px-3 text-sm rounded-md border border-slate-100 bg-slate-50 flex items-center text-slate-600 font-mono">
              {proxyRetentionDays} days
            </div>
            <p className="text-xs text-slate-400">
              Input and output text is nulled after {proxyRetentionDays} days. Metadata is kept permanently.
            </p>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              What is retained permanently
            </label>
            <div className="h-9 px-3 text-sm rounded-md border border-slate-100 bg-slate-50 flex items-center text-slate-500 text-xs">
              decisions · threats · scores · latency · status
            </div>
            <p className="text-xs text-slate-400">
              Security audit trail is never deleted.
            </p>
          </div>
        </div>
        <p className="text-xs text-slate-400 mt-2">
          Configured via <code className="font-mono bg-slate-100 px-1 rounded">DATA_RETENTION_DAYS_PROXY</code> in your environment.
          Run <code className="font-mono bg-slate-100 px-1 rounded">python scripts/cleanup_audit_logs.py</code> daily to enforce.
        </p>
      </div>

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3">
        <Button onClick={handleSave} loading={saving} disabled={!isValid}>
          Save audit retention
        </Button>
        {saved && (
          <span className="text-xs text-green-600">Saved successfully</span>
        )}
      </div>

    </div>
  )
}