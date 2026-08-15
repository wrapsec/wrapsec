// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useTranslations } from "next-intl"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Button } from "@/components/ui/Button"
import { updateRetentionSettings } from "@/lib/api"
import { errorMessage } from "@/lib/apiError"

interface RetentionSettingsFormProps {
  retentionDays:      number
  source:             string
  proxyRetentionDays: number
  storageMode:        string
  onUpdated:          (days: number) => void
}

const STORAGE_MODE_COLORS: Record<string, string> = {
  full:   "bg-amber-50 text-amber-700 border-amber-200",
  masked: "bg-green-50 text-green-700 border-green-200",
  none:   "bg-slate-50 text-slate-600 border-slate-200",
}

export function RetentionSettingsForm({
  retentionDays,
  source,
  proxyRetentionDays,
  storageMode,
  onUpdated,
}: RetentionSettingsFormProps) {
  const t  = useTranslations("pages.settings")
  const tc = useTranslations("common")
  const code = (chunks: React.ReactNode) => <code className="font-mono bg-slate-100 px-1 rounded">{chunks}</code>
  const [days,   setDays]   = useState(retentionDays)
  const [saving, setSaving] = useState(false)
  const [saved,  setSaved]  = useState(false)
  const { isJwt } = useAuthMode()
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
    } catch (e: unknown) {
      setError(errorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  const modeKey   = STORAGE_MODE_COLORS[storageMode] ? storageMode : "masked"
  const modeColor = STORAGE_MODE_COLORS[modeKey]

  return (
    <div className="space-y-6">

      {/* Storage mode -- read only, set via .env */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          {t("retention.storage_mode_title")}
        </p>
        <div className="flex items-start gap-3">
          <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold border ${modeColor}`}>
            {t(`retention.mode_${modeKey}_label`)}
          </span>
          <p className="text-xs text-slate-500 mt-0.5">{t(`retention.mode_${modeKey}_desc`)}</p>
        </div>
        <p className="text-xs text-slate-400 mt-2">
          {t.rich("retention.storage_config_note", { code })}
        </p>
      </div>

      <div className="border-t border-slate-100" />

      {/* Audit logs retention -- editable */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          {t("retention.audit_title")}
        </p>
        <div className="grid grid-cols-2 gap-5">
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              {t("retention.period_label")}
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
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
            />
            <p className="text-xs text-slate-400">
              {t("retention.period_hint", { days })}
            </p>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              {t("retention.setting_source")}
            </label>
            <div className="h-9 px-3 text-sm rounded-md border border-slate-100 bg-slate-50 flex items-center text-slate-600">
              {source}
            </div>
            <p className="text-xs text-slate-400">
              {t("retention.source_hint")}
            </p>
          </div>
        </div>

        {!isValid && (
          <p className="text-xs text-red-600 mt-2">
            {days < 7 ? t("retention.err_min") : t("retention.err_max")}
          </p>
        )}
      </div>

      {/* Proxy interactions retention -- read only, set via .env */}
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          {t("retention.proxy_title")}
        </p>
        <div className="grid grid-cols-2 gap-5">
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              {t("retention.text_period_label")}
            </label>
            <div className="h-9 px-3 text-sm rounded-md border border-slate-100 bg-slate-50 flex items-center text-slate-600 font-mono">
              {t("retention.proxy_days_value", { days: proxyRetentionDays })}
            </div>
            <p className="text-xs text-slate-400">
              {t("retention.proxy_text_hint", { days: proxyRetentionDays })}
            </p>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">
              {t("retention.permanent_label")}
            </label>
            <div className="h-9 px-3 text-sm rounded-md border border-slate-100 bg-slate-50 flex items-center text-slate-500 text-xs">
              {t("retention.permanent_value")}
            </div>
            <p className="text-xs text-slate-400">
              {t("retention.permanent_hint")}
            </p>
          </div>
        </div>
        <p className="text-xs text-slate-400 mt-2">
          {t.rich("retention.proxy_config_note", { code })}
        </p>
      </div>

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3">
        {isJwt ? (
          <Button size="sm" onClick={handleSave} loading={saving} disabled={!isValid}>
            {t("retention.save")}
          </Button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Button size="sm" disabled>{t("retention.save")}</Button>
            <span style={{ fontSize: "11px", color: "#9ca3af" }}>
              {tc.rich("requires_admin", {
                link: (chunks) => <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>{chunks}</a>,
              })}
            </span>
          </div>
        )}
        {saved && (
          <span className="text-xs text-green-600">{t("saved")}</span>
        )}
      </div>

    </div>
  )
}