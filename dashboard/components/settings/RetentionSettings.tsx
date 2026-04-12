"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { updateRetentionSettings } from "@/lib/api"

interface RetentionSettingsFormProps {
  retentionDays: number
  source:        string
  onUpdated:     (days: number) => void
}

export function RetentionSettingsForm({
  retentionDays, source, onUpdated
}: RetentionSettingsFormProps) {
  const [days,    setDays]    = useState(retentionDays)
  const [saving,  setSaving]  = useState(false)
  const [saved,   setSaved]   = useState(false)
  const [error,   setError]   = useState<string | null>(null)

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

  return (
    <div className="space-y-4">
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
            Audit logs older than {days} days will be deleted. Min: 7, Max: 3650 (10 years).
          </p>
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">
            Estimated storage impact
          </label>
          <div className="h-9 px-3 text-sm rounded-md border border-slate-100 bg-slate-50 flex items-center text-slate-600">
            {days} days of audit history retained
          </div>
          <p className="text-xs text-slate-400">
            Setting from: {source}
          </p>
        </div>
      </div>

      {!isValid && (
        <p className="text-xs text-red-600">
          {days < 7 ? "Minimum retention is 7 days" : "Maximum retention is 3650 days (10 years)"}
        </p>
      )}

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3">
        <Button onClick={handleSave} loading={saving} disabled={!isValid}>
          Save retention settings
        </Button>
        {saved && (
          <span className="text-xs text-green-600">Saved successfully</span>
        )}
      </div>
    </div>
  )
}