"use client"

import { useState } from "react"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Button } from "@/components/ui/Button"
import { updateRateLimitSettings } from "@/lib/api"

interface RateLimitSettingsFormProps {
  perMinute:  number
  source:     string
  trialLimit?: number  // trial key rate limit — live limit must not go below this
  onUpdated:  (perMinute: number, source: string) => void
}

export function RateLimitSettingsForm({
  perMinute,
  source,
  trialLimit = 10,
  onUpdated,
}: RateLimitSettingsFormProps) {
  const [limit,  setLimit]  = useState(perMinute)
  const [saving, setSaving] = useState(false)
  const [saved,  setSaved]  = useState(false)
  const { isJwt } = useAuthMode()
  const [error,  setError]  = useState<string | null>(null)

  const isBelowTrialLimit = limit < trialLimit
  const isValid = limit >= 1 && limit <= 10000 && !isBelowTrialLimit

  const handleSave = async () => {
    if (!isValid) return
    setSaving(true)
    setError(null)
    try {
      const updated = await updateRateLimitSettings(limit)
      onUpdated(updated.per_minute, updated.source)
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

      {/* Live key rate limit — editable, DB-backed */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          Live Key Rate Limit
        </p>
        <div className="grid grid-cols-2 gap-5">
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              Requests per minute
            </label>
            <input
              type="number"
              min={1}
              max={10000}
              value={limit}
              onChange={(e) => {
                const val = parseInt(e.target.value)
                if (!isNaN(val)) setLimit(val)
              }}
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
            />
            <p className="text-xs text-slate-400">
              Applies to all <code className="font-mono bg-slate-100 px-1 rounded">wsk_live_</code> keys globally. Min: 1, Max: 10,000.
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
              Once saved, database value overrides environment default.
              Takes effect within 5 minutes.
            </p>
          </div>
        </div>
        {isBelowTrialLimit && (
          <p className="text-xs text-red-600 mt-2">
            Live key limit cannot be less than the trial key limit ({trialLimit} req/min).
            Live keys must always have equal or higher limits than trial keys.
          </p>
        )}
        {!isBelowTrialLimit && !isValid && (
          <p className="text-xs text-red-600 mt-2">
            {limit < 1 ? "Minimum is 1 request per minute" : "Maximum is 10,000 requests per minute"}
          </p>
        )}
      </div>

      <div className="border-t border-slate-100" />

      {/* Trial key limits — read-only, env-configured */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          Trial Key Limits
          <span className="ml-2 text-xs font-normal text-slate-400 normal-case">— read-only, configured via environment</span>
        </p>
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-slate-50 rounded-lg px-3 py-2.5">
            <p className="text-xs text-slate-400 mb-0.5">Rate limit</p>
            <p className="text-xs font-mono text-slate-700">
              {process.env.NEXT_PUBLIC_TRIAL_RATE_LIMIT ?? "10"} req/min
            </p>
          </div>
          <div className="bg-slate-50 rounded-lg px-3 py-2.5">
            <p className="text-xs text-slate-400 mb-0.5">Max input</p>
            <p className="text-xs font-mono text-slate-700">500 chars</p>
          </div>
          <div className="bg-slate-50 rounded-lg px-3 py-2.5">
            <p className="text-xs text-slate-400 mb-0.5">Proxy mode</p>
            <p className="text-xs font-mono text-slate-700">Disabled</p>
          </div>
        </div>
        <p className="text-xs text-slate-400 mt-2">
          Configured via <code className="font-mono bg-slate-100 px-1 rounded">TRIAL_RATE_LIMIT_PER_MINUTE</code>,{" "}
          <code className="font-mono bg-slate-100 px-1 rounded">TRIAL_MAX_INPUT_CHARS</code> in your environment.
        </p>
      </div>

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3">
        {isJwt ? (
          <Button size="sm" onClick={handleSave} loading={saving} disabled={!isValid}>
            Save rate limit
          </Button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Button size="sm" disabled>Save rate limit</Button>
            <span style={{ fontSize: "11px", color: "#9ca3af" }}>
              Requires admin login —{" "}
              <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>sign in with email</a>
            </span>
          </div>
        )}
        {saved && (
          <span className="text-xs text-green-600">Saved — takes effect within 5 minutes</span>
        )}
      </div>

    </div>
  )
}
