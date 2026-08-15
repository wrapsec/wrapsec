// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useTranslations } from "next-intl"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Button } from "@/components/ui/Button"
import { Thresholds } from "@/lib/types"
import { updateThresholds } from "@/lib/api"
import { errorMessage } from "@/lib/apiError"

interface ThresholdFormProps {
  thresholds:  Thresholds
  onUpdated:   (t: Thresholds) => void
}

export function ThresholdForm({ thresholds, onUpdated }: ThresholdFormProps) {
  const t  = useTranslations("pages.settings")
  const tc = useTranslations("common")
  const [block,    setBlock]    = useState(thresholds.block_threshold)
  const [sanitize, setSanitize] = useState(thresholds.sanitize_threshold)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState<string | null>(null)
  const [saved,    setSaved]    = useState(false)
  const { isJwt } = useAuthMode()

  const valid = (
    block > 0.0 &&
    block <= 1.0 &&
    sanitize >= 0.0 &&
    sanitize < 1.0 &&
    block > sanitize
  )

  const handleSave = async () => {
    if (!valid) return
    setLoading(true)
    setError(null)
    try {
      const updated = await updateThresholds({
        block_threshold:    block,
        sanitize_threshold: sanitize,
      })
      onUpdated(updated)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e: unknown) {
      setError(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-6">
        <div>
          <label className="block text-xs font-medium text-slate-700 mb-1.5">
            {t("threshold.block")}
          </label>
          <input
            type="number"
            min={0} max={1} step={0.05}
            value={block}
            onChange={(e) => setBlock(parseFloat(e.target.value))}
            className="h-9 w-full px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-400 mt-1">
            {t("threshold.block_hint", { value: block })}
          </p>
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-700 mb-1.5">
            {t("threshold.sanitize")}
          </label>
          <input
            type="number"
            min={0} max={1} step={0.05}
            value={sanitize}
            onChange={(e) => setSanitize(parseFloat(e.target.value))}
            className="h-9 w-full px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-400 mt-1">
            {t("threshold.sanitize_hint", { value: sanitize })}
          </p>
        </div>
      </div>

      {!valid && (
        <p className="text-xs text-red-600">
          {block <= 0.0
            ? t("threshold.err_block_min")
            : block > 1.0
            ? t("threshold.err_block_max")
            : sanitize < 0.0
            ? t("threshold.err_sanitize_neg")
            : sanitize >= 1.0
            ? t("threshold.err_sanitize_max")
            : t("threshold.err_order")}
        </p>
      )}
      {error && (
        <p className="text-xs text-red-600">{error}</p>
      )}

      <div className="flex items-center gap-3">
        {isJwt ? (
          <Button size="sm"onClick={handleSave} loading={loading} disabled={!valid}>
            {t("threshold.save")}
          </Button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Button size="sm" disabled>{t("threshold.save")}</Button>
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