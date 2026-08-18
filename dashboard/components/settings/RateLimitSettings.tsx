// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useTranslations } from "next-intl"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Button } from "@/components/ui/Button"
import { updateRateLimitSettings } from "@/lib/api"
import { errorMessage } from "@/lib/apiError"

interface RateLimitSettingsFormProps {
  perMinute:  number
  source:     string
  trialLimit?: number  // trial key rate limit - live limit must not go below this
  onUpdated:  (perMinute: number, source: string) => void
}

export function RateLimitSettingsForm({
  perMinute,
  source,
  trialLimit = 10,
  onUpdated,
}: RateLimitSettingsFormProps) {
  const t  = useTranslations("pages.settings")
  const tc = useTranslations("common")
  const code = (chunks: React.ReactNode) => <code className="font-mono bg-slate-100 px-1 rounded">{chunks}</code>
  const [limit,  setLimit]  = useState(perMinute)
  const [saving, setSaving] = useState(false)
  const [saved,  setSaved]  = useState(false)
  const { isAdmin } = useAuthMode()
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
    } catch (e: unknown) {
      setError(errorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">

      {/* Live key rate limit - editable, DB-backed */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          {t("rate_limit.live_title")}
        </p>
        <div className="grid grid-cols-2 gap-5">
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              {t("rate_limit.per_minute")}
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
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
            />
            <p className="text-xs text-slate-600">
              {t.rich("rate_limit.live_hint", { code })}
            </p>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              {t("rate_limit.setting_source")}
            </label>
            <div className="h-9 px-3 text-sm rounded-md border border-slate-100 bg-slate-50 flex items-center text-slate-600">
              {source}
            </div>
            <p className="text-xs text-slate-600">
              {t("rate_limit.source_hint")}
            </p>
          </div>
        </div>
        {isBelowTrialLimit && (
          <p className="text-xs text-red-600 mt-2">
            {t("rate_limit.below_trial", { limit: trialLimit })}
          </p>
        )}
        {!isBelowTrialLimit && !isValid && (
          <p className="text-xs text-red-600 mt-2">
            {limit < 1 ? t("rate_limit.err_min") : t("rate_limit.err_max")}
          </p>
        )}
      </div>

      <div className="border-t border-slate-100" />

      {/* Trial key limits - read-only, env-configured */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          {t("rate_limit.trial_title")}
          <span className="ml-2 text-xs font-normal text-slate-600 normal-case">{t("rate_limit.trial_note")}</span>
        </p>
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-slate-50 rounded-lg px-3 py-2.5">
            <p className="text-xs text-slate-600 mb-0.5">{t("rate_limit.trial_rate_limit")}</p>
            <p className="text-xs font-mono text-slate-700">
              {t("rate_limit.trial_rate_value", { value: process.env.NEXT_PUBLIC_TRIAL_RATE_LIMIT ?? "10" })}
            </p>
          </div>
          <div className="bg-slate-50 rounded-lg px-3 py-2.5">
            <p className="text-xs text-slate-600 mb-0.5">{t("rate_limit.trial_max_input")}</p>
            <p className="text-xs font-mono text-slate-700">{t("rate_limit.trial_max_input_value")}</p>
          </div>
          <div className="bg-slate-50 rounded-lg px-3 py-2.5">
            <p className="text-xs text-slate-600 mb-0.5">{t("rate_limit.trial_proxy_mode")}</p>
            <p className="text-xs font-mono text-slate-700">{t("rate_limit.trial_proxy_value")}</p>
          </div>
        </div>
        <p className="text-xs text-slate-600 mt-2">
          {t.rich("rate_limit.trial_config_note", { code })}
        </p>
      </div>

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3">
        {isAdmin ? (
          <Button size="sm" onClick={handleSave} loading={saving} disabled={!isValid}>
            {t("rate_limit.save")}
          </Button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Button size="sm" disabled>{t("rate_limit.save")}</Button>
            <span style={{ fontSize: "11px", color: "#9ca3af" }}>
              {tc.rich("requires_admin", {
                link: (chunks) => <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>{chunks}</a>,
              })}
            </span>
          </div>
        )}
        {saved && (
          <span className="text-xs text-green-600">{t("rate_limit.saved_note")}</span>
        )}
      </div>

    </div>
  )
}
