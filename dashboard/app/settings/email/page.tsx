// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useEffect, useState } from "react"
import { useTranslations } from "next-intl"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState } from "@/components/ui/ErrorState"
import { PageSpinner } from "@/components/ui/Spinner"
import { Button } from "@/components/ui/Button"
import { useAuthMode } from "@/hooks/useAuthMode"
import { useErrorMessage } from "@/hooks/useErrorMessage"
import { getEmailSettings, updateEmailSettings } from "@/lib/api"
import type { EmailSettings } from "@/lib/types"

function fmtInterval(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${Math.round(seconds / 3600)}h`
}

export default function EmailSettingsPage() {
  const t   = useTranslations("pages.email_settings")
  const tc  = useTranslations("common")
  const { isAdmin } = useAuthMode()
  const { resolve } = useErrorMessage()
  const { data, isLoading, error, mutate } = useSWR<EmailSettings>("email-settings", getEmailSettings)

  const [enabled,   setEnabled]   = useState(true)
  const [attempts,  setAttempts]  = useState(8)
  const [retention, setRetention] = useState(30)
  const [saving, setSaving] = useState(false)
  const [saved,  setSaved]  = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  // Seed the form once settings arrive (and after a successful save re-fetch).
  useEffect(() => {
    // Intentional: seed the form state from the fetched settings once they arrive (guarded by
    // if(data), keyed on [data]); this is initialization from async data, not a render loop.
    /* eslint-disable react-hooks/set-state-in-effect */
    if (data) {
      setEnabled(data.notifications_enabled)
      setAttempts(data.max_attempts)
      setRetention(data.retention_days)
    }
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [data])

  if (isLoading && !data) return <Shell title={t("title")}><PageSpinner /></Shell>
  if (error || !data) {
    return (
      <Shell title={t("title")}>
        <PageHeader description={t("description")} />
        <ErrorState title={t("load_error")} message={error ? resolve(error).message : ""} />
      </Shell>
    )
  }

  const ceiling = data.retry_schedule.max_attempts_ceiling
  const minAtt  = data.retry_schedule.min_attempts
  const attemptsValid  = attempts >= minAtt && attempts <= ceiling
  const retentionValid = retention >= 1
  const canSave = attemptsValid && retentionValid

  const handleSave = async () => {
    if (!canSave) return
    setSaving(true)
    setSaveError(null)
    try {
      const updated = await updateEmailSettings({
        notifications_enabled: enabled,
        max_attempts:          attempts,
        retention_days:        retention,
      })
      await mutate(updated, { revalidate: false })
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e) {
      setSaveError(resolve(e).message)
    } finally {
      setSaving(false)
    }
  }

  const intervals = data.retry_schedule.intervals_seconds.map(fmtInterval).join(", ")

  return (
    <Shell title={t("title")}>
      <PageHeader description={t("description")} />

      <div className="max-w-2xl flex flex-col gap-8 bg-white border border-slate-200 rounded-lg p-6">

        {/* General */}
        <section className="flex flex-col gap-3">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">{t("general_title")}</p>
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <span className="text-sm font-medium text-slate-800">{t("notifications_label")}</span>
              <span className="text-xs text-slate-600 max-w-md">{t("notifications_hint")}</span>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={enabled}
              disabled={!isAdmin}
              onClick={() => setEnabled(v => !v)}
              className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${
                enabled ? "bg-purple-700" : "bg-slate-300"
              } ${isAdmin ? "cursor-pointer" : "cursor-not-allowed opacity-60"}`}
            >
              <span className={`inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${enabled ? "translate-x-5" : "translate-x-1"}`} />
            </button>
          </div>
        </section>

        <div className="border-t border-slate-100" />

        {/* Delivery */}
        <section className="flex flex-col gap-4">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">{t("delivery_title")}</p>

          <div className="grid grid-cols-2 gap-5">
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-slate-700">{t("max_attempts_label")}</label>
              <input
                type="number" min={minAtt} max={ceiling} value={attempts}
                disabled={!isAdmin}
                onChange={e => { const v = parseInt(e.target.value); if (!isNaN(v)) setAttempts(v) }}
                className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 disabled:bg-slate-50"
              />
              <p className="text-xs text-slate-600">{t("max_attempts_hint", { max: ceiling })}</p>
              {!attemptsValid && <p className="text-xs text-red-600">{t("err_max_attempts", { min: minAtt, max: ceiling })}</p>}
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-slate-700">{t("retention_label")}</label>
              <div className="flex items-center gap-2">
                <input
                  type="number" min={1} value={retention}
                  disabled={!isAdmin}
                  onChange={e => { const v = parseInt(e.target.value); if (!isNaN(v)) setRetention(v) }}
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 disabled:bg-slate-50 w-28"
                />
                <span className="text-xs text-slate-600">{t("days")}</span>
              </div>
              <p className="text-xs text-slate-600">{t("retention_hint")}</p>
              {!retentionValid && <p className="text-xs text-red-600">{t("err_retention")}</p>}
            </div>
          </div>

          {/* Retry policy -- read only (fixed schedule) */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-slate-700">{t("retry_policy_label")}</label>
            <div className="h-9 px-3 text-sm rounded-md border border-slate-100 bg-slate-50 flex items-center text-slate-600 font-mono">
              {t("retry_intervals", { intervals })}
            </div>
            <p className="text-xs text-slate-600">{t("retry_policy_hint")}</p>
          </div>
        </section>

        {saveError && <p className="text-xs text-red-600">{saveError}</p>}

        <div className="flex items-center gap-3">
          {isAdmin ? (
            <Button size="sm" onClick={handleSave} loading={saving} disabled={!canSave}>{t("save")}</Button>
          ) : (
            <div className="flex items-center gap-2">
              <Button size="sm" disabled>{t("save")}</Button>
              <span className="text-xs text-slate-600">
                {tc.rich("requires_admin", {
                  link: (chunks) => <a href="/login" className="text-purple-700 underline">{chunks}</a>,
                })}
              </span>
            </div>
          )}
          {saved && <span className="text-xs text-green-600">{t("saved")}</span>}
        </div>
      </div>
    </Shell>
  )
}
