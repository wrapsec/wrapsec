// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState, useEffect } from "react"
import { useTranslations } from "next-intl"
import { swrKeys } from "@/lib/swrKeys"
import useSWR from "swr"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { ApiKeyCreated } from "@/lib/types"
import { createApiKey, getDepartments, getApplicationsByDept } from "@/lib/api"
import { errorMessage } from "@/lib/apiError"

interface CreateKeyModalProps {
  onCreated: (key: ApiKeyCreated) => void
  onClose:   () => void
}

export function CreateKeyModal({ onCreated, onClose }: CreateKeyModalProps) {
  const t = useTranslations("pages.keys.create_modal")
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    document.addEventListener("keydown", handler)
    return () => document.removeEventListener("keydown", handler)
  }, [onClose])

  const [name,    setName]    = useState("")
  const [deptId,  setDeptId]  = useState("")
  const [appId,   setAppId]   = useState("")
  const [keyType, setKeyType] = useState<"live" | "trial">("live")
  const [loading, setLoading] = useState(false)
  const [created, setCreated] = useState<ApiKeyCreated | null>(null)
  const [error,   setError]   = useState<string | null>(null)

  // Load departments for selector
  const { data: deptsData } = useSWR(swrKeys.departments, getDepartments)
  const departments = deptsData?.departments ?? []

  // Load applications when dept is selected
  const { data: appsData } = useSWR(
    deptId ? `apps-dept-${deptId}` : null,
    () => getApplicationsByDept(deptId)
  )
  const applications = appsData?.applications ?? []

  const handleDeptChange = (id: string) => {
    setDeptId(id)
    setAppId("") // reset app when dept changes
  }

  const handleCreate = async () => {
    if (!name.trim()) return
    setLoading(true)
    setError(null)
    try {
      const key = await createApiKey(
        name.trim(),
        appId   || undefined,
        deptId  || undefined,
        keyType,
      )
      setCreated(key)
      onCreated(key)
    } catch (e: unknown) {
      setError(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  const selectClass = "h-9 w-full px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700"

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg border border-slate-200 w-full max-w-md p-6 shadow-lg">
        <h2 className="text-base font-semibold text-slate-900 mb-4">
          {t("title")}
        </h2>

        {!created ? (
          <div className="space-y-4">
            {/* Name */}
            <Input
              label={t("name")}
              placeholder={t("name_placeholder")}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />

            {/* Department */}
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-slate-700">
                {t("department")} <span className="text-slate-400">{t("required")}</span>
              </label>
              <select
                value={deptId}
                onChange={(e) => handleDeptChange(e.target.value)}
                className={selectClass}
              >
                <option value="">{t("select_dept")}</option>
                {departments.map(d => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
              <p className="text-xs text-slate-400">
                {t("dept_hint")}
              </p>
            </div>

            {/* Key type */}
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-slate-700">{t("key_type")}</label>
              <select
                value={keyType}
                onChange={(e) => setKeyType(e.target.value as "live" | "trial")}
                className={selectClass}
              >
                <option value="live">{t("type_live")}</option>
                <option value="trial">{t("type_trial")}</option>
              </select>
              {keyType === "trial" && (
                <p className="text-xs text-amber-600">
                  {t("trial_hint")}
                </p>
              )}
            </div>

            {/* Application - optional, only shown when dept is selected */}
            {deptId && (
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">
                  {t("application")} <span className="text-slate-400">{t("optional")}</span>
                </label>
                <select
                  value={appId}
                  onChange={(e) => setAppId(e.target.value)}
                  className={selectClass}
                >
                  <option value="">{t("no_app")}</option>
                  {applications.map(a => (
                    <option key={a.id} value={a.id}>{a.name}</option>
                  ))}
                </select>
                <p className="text-xs text-slate-400">
                  {t("app_hint")}
                </p>
              </div>
            )}

            {error && (
              <p className="text-xs text-red-600">{error}</p>
            )}
            <div className="flex justify-end gap-3">
              <Button size="sm" variant="secondary" onClick={onClose}>{t("cancel")}</Button>
              <Button
                size="sm"
                loading={loading}
                disabled={!name.trim() || !deptId}
                onClick={handleCreate}
              >
                {t("submit")}
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg">
              <p className="text-xs font-medium text-amber-800 mb-2">
                {t("copy_now")}
              </p>
              <div className="flex items-center gap-2">
                <p className="font-mono text-xs text-amber-900 break-all flex-1">
                  {created.api_key}
                </p>
                <button
                  onClick={() => navigator.clipboard.writeText(created.api_key)}
                  className="shrink-0 text-xs font-medium text-amber-700 hover:text-amber-900 border border-amber-300 rounded px-2 py-1 bg-amber-100 hover:bg-amber-200 transition-colors"
                >
                  {t("copy")}
                </button>
              </div>
            </div>
            {/* Show scoping info */}
            <div className="grid grid-cols-2 gap-2 text-xs text-slate-500">
              <div>
                <span className="text-slate-400">{t("type_label")}</span>{" "}
                <span className={`font-medium ${created.key_type === "trial" ? "text-amber-600" : "text-emerald-600"}`}>
                  {created.key_type === "trial" ? t("trial") : t("live")}
                </span>
              </div>
              {created.dept_id && (
                <div>
                  <span className="text-slate-400">{t("dept_label")}</span>{" "}
                  <span className="font-mono">{created.dept_id.slice(0, 8)}...</span>
                </div>
              )}
              {created.app_id && (
                <div>
                  <span className="text-slate-400">{t("app_label")}</span>{" "}
                  <span className="font-mono">{created.app_id.slice(0, 8)}...</span>
                </div>
              )}
            </div>
            <div className="flex justify-end">
              <Button size="sm" onClick={onClose}>{t("done")}</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
