// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useTranslations } from "next-intl"
import { useAuthMode } from "@/hooks/useAuthMode"
import { useParams } from "next/navigation"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { Button } from "@/components/ui/Button"
import { PageSpinner } from "@/components/ui/Spinner"
import {
  getApplication, getDepartment, getKeysByApp,
  getApplicationPolicy, setApplicationPolicy, resetApplicationPolicy,
  updateAppLLMOverride, updateAppProxyOverride,
} from "@/lib/api"
import Link from "next/link"
import { PageHeader } from "@/components/ui/PageHeader"
import { useBackNav } from "@/hooks/useBackNav"

const PROVIDERS = ["openai", "ollama", "custom"] as const

export default function ApplicationDetailPage() {
  const { id } = useParams<{ id: string }>()
  const t  = useTranslations("pages.detail")
  const ta = useTranslations("pages.app_detail")
  const tp = useTranslations("pages.settings.providers")

  const { data: app, isLoading, mutate: mutateApp } = useSWR(
    `application-${id}`, () => getApplication(id)
  )
  const { data: dept } = useSWR(
    app ? `department-${app.dept_id}` : null,
    () => getDepartment(app!.dept_id)
  )
  const { data: keysData } = useSWR(
    `keys-app-${id}`, () => getKeysByApp(id)
  )
  const { data: policyData, mutate: mutatePolicy } = useSWR(
    `app-policy-${id}`, () => getApplicationPolicy(id)
  )

  const appKeys = (keysData?.keys ?? []).filter(k => k.app_id === id)

  const [confirmReset,      setConfirmReset]      = useState(false)
  const [confirmLlmClear,   setConfirmLlmClear]   = useState(false)
  const [confirmProxyClear, setConfirmProxyClear] = useState(false)

  // Policy editor state
  const [editing,     setEditing]     = useState(false)
  const [blockVal,    setBlockVal]    = useState("")
  const [sanitizeVal, setSanitizeVal] = useState("")
  const [saving,      setSaving]      = useState(false)
  const [resetting,   setResetting]   = useState(false)
  const [saved,       setSaved]       = useState(false)
  const [error,       setError]       = useState<string | null>(null)

  // LLM override form
  const [llmEditing,  setLlmEditing]  = useState(false)
  const [llmProvider, setLlmProvider] = useState("")
  const [llmModel,    setLlmModel]    = useState("")
  const [llmBaseUrl,  setLlmBaseUrl]  = useState("")
  const [llmApiKey,   setLlmApiKey]   = useState("")
  const [llmTimeout,  setLlmTimeout]  = useState("")
  const [llmSaving,   setLlmSaving]   = useState(false)
  const [llmSaved,    setLlmSaved]    = useState(false)
  const [llmError,    setLlmError]    = useState<string | null>(null)

  // Proxy provider override form
  const [proxyEditing,  setProxyEditing]  = useState(false)
  const [proxyProvider, setProxyProvider] = useState("")
  const [proxyBaseUrl,  setProxyBaseUrl]  = useState("")
  const [proxyModel,    setProxyModel]    = useState("")
  const [proxyApiKey,   setProxyApiKey]   = useState("")
  const [proxyTimeout,  setProxyTimeout]  = useState("")
  const [proxySaving,   setProxySaving]   = useState(false)
  const [proxySaved,    setProxySaved]    = useState(false)
  const [proxyError,    setProxyError]    = useState<string | null>(null)

  const { isJwt } = useAuthMode()

  const handleEditStart = () => {
    const override = policyData?.policy_override
    setBlockVal(override?.thresholds?.block?.toString()    ?? "")
    setSanitizeVal(override?.thresholds?.sanitize?.toString() ?? "")
    setEditing(true)
  }

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    try {
      const block    = blockVal    ? parseFloat(blockVal)    : null
      const sanitize = sanitizeVal ? parseFloat(sanitizeVal) : null

      const policy_override = (block !== null || sanitize !== null)
        ? { thresholds: {
              ...(block    !== null ? { block }    : {}),
              ...(sanitize !== null ? { sanitize } : {}),
            }
          }
        : null

      await setApplicationPolicy(id, policy_override)
      mutatePolicy()
      setEditing(false)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleReset = async () => {
    setConfirmReset(false)
    setResetting(true)
    setError(null)
    try {
      await resetApplicationPolicy(id)
      mutatePolicy()
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setResetting(false)
    }
  }

  const handleLlmEditStart = () => {
    const llm = app?.policy_override?.llm
    setLlmProvider(llm?.provider ?? "openai")
    setLlmModel(llm?.model ?? "")
    setLlmBaseUrl(llm?.base_url ?? "")
    setLlmTimeout(llm?.timeout?.toString() ?? "")
    setLlmApiKey("")
    setLlmEditing(true)
  }

  const handleLlmSave = async () => {
    setLlmSaving(true)
    setLlmError(null)
    try {
      const payload: any = {}
      if (llmProvider)      payload.provider = llmProvider
      if (llmModel)         payload.model    = llmModel
      if (llmBaseUrl)       payload.base_url = llmBaseUrl
      if (llmTimeout)       payload.timeout  = parseInt(llmTimeout)
      if (llmApiKey.trim()) payload.api_key  = llmApiKey.trim()
      const updated = await updateAppLLMOverride(id, payload)
      mutateApp(updated, false)
      setLlmApiKey("")
      setLlmEditing(false)
      setLlmSaved(true)
      setTimeout(() => setLlmSaved(false), 3000)
    } catch (e: any) {
      setLlmError(e.message)
    } finally {
      setLlmSaving(false)
    }
  }

  const handleLlmClear = async () => {
    setConfirmLlmClear(false)
    setLlmSaving(true)
    try {
      const updated = await updateAppLLMOverride(id, { clear: true })
      mutateApp(updated, false)
      setLlmEditing(false)
    } catch (e: any) {
      setLlmError(e.message)
    } finally {
      setLlmSaving(false)
    }
  }

  const handleProxyEditStart = () => {
    const proxy = app?.policy_override?.proxy_provider
    setProxyProvider(proxy?.provider ?? "openai")
    setProxyBaseUrl(proxy?.base_url ?? "")
    setProxyModel(proxy?.default_model ?? "")
    setProxyTimeout(proxy?.timeout_seconds?.toString() ?? "")
    setProxyApiKey("")
    setProxyEditing(true)
  }

  const handleProxySave = async () => {
    setProxySaving(true)
    setProxyError(null)
    try {
      const payload: any = {}
      if (proxyProvider)      payload.provider        = proxyProvider
      if (proxyBaseUrl)       payload.base_url        = proxyBaseUrl
      if (proxyModel)         payload.default_model   = proxyModel
      if (proxyTimeout)       payload.timeout_seconds = parseInt(proxyTimeout)
      if (proxyApiKey.trim()) payload.api_key         = proxyApiKey.trim()
      const updated = await updateAppProxyOverride(id, payload)
      mutateApp(updated, false)
      setProxyApiKey("")
      setProxyEditing(false)
      setProxySaved(true)
      setTimeout(() => setProxySaved(false), 3000)
    } catch (e: any) {
      setProxyError(e.message)
    } finally {
      setProxySaving(false)
    }
  }

  const handleProxyClear = async () => {
    setConfirmProxyClear(false)
    setProxySaving(true)
    try {
      const updated = await updateAppProxyOverride(id, { clear: true })
      mutateApp(updated, false)
      setProxyEditing(false)
    } catch (e: any) {
      setProxyError(e.message)
    } finally {
      setProxySaving(false)
    }
  }

  const goBack = useBackNav("/applications")

  if (isLoading) return <Shell title={ta("title")}><PageSpinner /></Shell>
  if (!app)      return <Shell title={ta("title")}><p className="text-sm text-slate-500">{ta("not_found")}</p></Shell>

  const override     = policyData?.policy_override
  const hasOverride  = override !== null && override !== undefined
  const deptName     = dept?.name || ta("parent_department")

  return (
    <Shell title={app.name}>
      <div className="max-w-2xl space-y-5">

        <PageHeader
          breadcrumb={[
            { label: ta("breadcrumb"), href: "/applications" },
            { label: app.name },
          ]}
          onBack={goBack}
        />

        {/* Application info */}
        <Card>
          <CardHeader title={ta("info_title")} />
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: ta("info_name"),        value: app.name },
              { label: ta("info_slug"),        value: app.slug },
              { label: ta("info_department"),  value: dept?.name || app.dept_id },
              { label: ta("info_environment"), value: app.environment },
              { label: ta("info_owner"),       value: app.owner_name  || "-" },
              { label: ta("info_email"),       value: app.owner_email || "-" },
              { label: ta("info_description"), value: app.description || "-" },
              { label: ta("info_status"),      value: app.is_active ? t("active") : t("inactive") },
              { label: ta("info_created"),     value: new Date(app.created_at).toLocaleDateString() },
            ].map(({ label, value }) => (
              <div key={label} className="bg-slate-50 rounded-lg px-3 py-2.5">
                <p className="text-xs text-slate-400 mb-0.5">{label}</p>
                <p className="text-xs font-mono text-slate-700">{value}</p>
              </div>
            ))}
          </div>
        </Card>

        {/* Policy Override */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title={t("policy_title")}
              subtitle={ta("policy_subtitle", { dept: deptName })}
            />
            {!editing && isJwt && (
              <Button onClick={handleEditStart} variant="secondary">{t("edit")}</Button>
            )}
          </div>

          {!editing ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2 border-b border-slate-50">
                <span className="text-sm text-slate-600">{t("block_threshold")}</span>
                <span className="text-sm font-mono text-slate-900">
                  {override?.thresholds?.block ?? (
                    <span className="text-slate-400">
                      {ta("inherits_from", { dept: deptName, value: policyData?.resolved_policy?.thresholds?.block ?? "0.7" })}
                    </span>
                  )}
                </span>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-slate-50">
                <span className="text-sm text-slate-600">{t("sanitize_threshold")}</span>
                <span className="text-sm font-mono text-slate-900">
                  {override?.thresholds?.sanitize ?? (
                    <span className="text-slate-400">
                      {ta("inherits_from", { dept: deptName, value: policyData?.resolved_policy?.thresholds?.sanitize ?? "0.4" })}
                    </span>
                  )}
                </span>
              </div>

              <div className="flex items-center justify-between pt-1 flex-wrap gap-2">
                {hasOverride ? (
                  <p className="text-xs text-amber-600">
                    {ta("override_active")}
                  </p>
                ) : (
                  <p className="text-xs text-slate-400">
                    {ta("no_overrides", { dept: deptName })}
                  </p>
                )}
                {hasOverride && isJwt && (
                  confirmReset ? (
                    <div className="flex items-center gap-2 ml-4 flex-shrink-0">
                      <span className="text-xs text-red-600 whitespace-nowrap">{ta("reset_q")}</span>
                      <button
                        onClick={handleReset}
                        disabled={resetting}
                        className="text-xs font-medium text-red-600 hover:text-red-800 disabled:opacity-50 whitespace-nowrap"
                      >
                        {resetting ? ta("resetting") : t("confirm")}
                      </button>
                      <button
                        onClick={() => setConfirmReset(false)}
                        className="text-xs text-slate-500 hover:text-slate-700"
                      >
                        {t("cancel")}
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setConfirmReset(true)}
                      disabled={resetting}
                      className="text-xs text-red-500 hover:text-red-700 disabled:opacity-50 whitespace-nowrap ml-4"
                    >
                      {ta("reset")}
                    </button>
                  )
                )}
              </div>
              {saved && <p className="text-xs text-emerald-600">{t("saved_success")}</p>}
              {error  && <p className="text-xs text-red-600">{error}</p>}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">{t("block_threshold")}</label>
                  <input
                    type="number"
                    min={0.01} max={1.0} step={0.05}
                    value={blockVal}
                    onChange={e => setBlockVal(e.target.value)}
                    placeholder={ta("block_ph", { value: policyData?.resolved_policy?.thresholds?.block ?? "0.7" })}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                  />
                  <p className="text-xs text-slate-400">{ta("leave_blank", { dept: deptName })}</p>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">{t("sanitize_threshold")}</label>
                  <input
                    type="number"
                    min={0.0} max={0.99} step={0.05}
                    value={sanitizeVal}
                    onChange={e => setSanitizeVal(e.target.value)}
                    placeholder={ta("sanitize_ph", { value: policyData?.resolved_policy?.thresholds?.sanitize ?? "0.4" })}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                  />
                  <p className="text-xs text-slate-400">{ta("leave_blank", { dept: deptName })}</p>
                </div>
              </div>
              {error && <p className="text-xs text-red-600">{error}</p>}
              <div className="flex items-center gap-3">
                {isJwt
                  ? <Button onClick={handleSave} loading={saving}>{t("save_overrides")}</Button>
                  : <Button disabled>{t("save_overrides")}</Button>
                }
                <button
                  onClick={() => { setEditing(false); setError(null) }}
                  className="text-sm text-slate-500 hover:text-slate-700"
                >
                  {t("cancel")}
                </button>
                {saved && <span className="text-xs text-emerald-600">{t("saved")}</span>}
              </div>
            </div>
          )}
        </Card>

        {/* LLM Detection Override */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title={t("llm_title")}
              subtitle={ta("llm_subtitle", { dept: deptName })}
            />
            {!llmEditing && isJwt && (
              <Button onClick={handleLlmEditStart} variant="secondary">{t("edit")}</Button>
            )}
          </div>

          {!llmEditing ? (
            <div className="space-y-2">
              {app.policy_override?.llm ? (
                <>
                  {[
                    [t("provider"), app.policy_override.llm.provider],
                    [t("model"),    app.policy_override.llm.model],
                    [t("base_url"), app.policy_override.llm.base_url],
                    [t("timeout"),  app.policy_override.llm.timeout ? `${app.policy_override.llm.timeout}s` : undefined],
                    [t("api_key"),  app.policy_override.llm.api_key_masked ?? t("using_env")],
                  ].filter(([, v]) => v).map(([label, value]) => (
                    <div key={label as string} className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
                      <span className="text-sm text-slate-600">{label}</span>
                      <span className="text-xs font-mono text-slate-700">{value as string}</span>
                    </div>
                  ))}
                </>
              ) : (
                <p className="text-xs text-slate-400">{ta("llm_inherits", { dept: deptName })}</p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">{t("provider")}</label>
                  <select value={llmProvider} onChange={(e) => setLlmProvider(e.target.value)}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700">
                    {PROVIDERS.map((p) => <option key={p} value={p}>{tp(p)}</option>)}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">{t("model")}</label>
                  <input type="text" value={llmModel} onChange={(e) => setLlmModel(e.target.value)}
                    placeholder={t("model_ph")}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
                <div className="flex flex-col gap-1 col-span-2">
                  <label className="text-xs font-medium text-slate-700">{t("base_url")}</label>
                  <input type="text" value={llmBaseUrl} onChange={(e) => setLlmBaseUrl(e.target.value)}
                    placeholder={t("base_url_ph")}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
                {llmProvider !== "ollama" && (
                  <div className="flex flex-col gap-1 col-span-2">
                    <label className="text-xs font-medium text-slate-700">
                      {t("api_key")}
                      {app.policy_override?.llm?.api_key_masked && (
                        <span className="ml-2 font-normal text-slate-400">{t("api_key_current", { masked: app.policy_override.llm.api_key_masked })}</span>
                      )}
                    </label>
                    <input type="password" value={llmApiKey} onChange={(e) => setLlmApiKey(e.target.value)}
                      placeholder={app.policy_override?.llm?.api_key_masked ? t("api_key_keep") : t("api_key_new")}
                      className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                    <p className="text-xs text-slate-400">{ta("llm_encrypted")}</p>
                  </div>
                )}
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">{t("timeout")}</label>
                  <input type="number" min={5} max={120} value={llmTimeout} onChange={(e) => setLlmTimeout(e.target.value)}
                    placeholder={t("timeout_ph")}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
              </div>
              {llmError && <p className="text-xs text-red-600">{llmError}</p>}
              <div className="flex items-center gap-3 flex-wrap">
                <Button onClick={handleLlmSave} loading={llmSaving}>{t("save_override")}</Button>
                {app.policy_override?.llm && (
                  confirmLlmClear ? (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-red-600">{t("remove_override_q")}</span>
                      <Button variant="danger" size="sm" onClick={handleLlmClear} loading={llmSaving}>{t("confirm")}</Button>
                      <button onClick={() => setConfirmLlmClear(false)}
                        className="text-sm text-slate-500 hover:text-slate-700">{t("cancel")}</button>
                    </div>
                  ) : (
                    <Button variant="danger" onClick={() => setConfirmLlmClear(true)}>{t("clear_override")}</Button>
                  )
                )}
                {!confirmLlmClear && (
                  <button onClick={() => { setLlmEditing(false); setLlmError(null); setConfirmLlmClear(false) }}
                    className="text-sm text-slate-500 hover:text-slate-700">{t("cancel")}</button>
                )}
                {llmSaved && <span className="text-xs text-green-600">{t("saved")}</span>}
              </div>
            </div>
          )}
        </Card>

        {/* Proxy Provider Override */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title={t("proxy_title")}
              subtitle={ta("proxy_subtitle", { dept: deptName })}
            />
            {!proxyEditing && isJwt && (
              <Button onClick={handleProxyEditStart} variant="secondary">{t("edit")}</Button>
            )}
          </div>

          {!proxyEditing ? (
            <div className="space-y-2">
              {app.policy_override?.proxy_provider ? (
                <>
                  {[
                    [t("provider"),      app.policy_override.proxy_provider.provider],
                    [t("default_model"), app.policy_override.proxy_provider.default_model],
                    [t("base_url"),      app.policy_override.proxy_provider.base_url],
                    [t("timeout"),       app.policy_override.proxy_provider.timeout_seconds ? `${app.policy_override.proxy_provider.timeout_seconds}s` : undefined],
                    [t("api_key"),       app.policy_override.proxy_provider.api_key_masked ?? t("using_env")],
                  ].filter(([, v]) => v).map(([label, value]) => (
                    <div key={label as string} className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
                      <span className="text-sm text-slate-600">{label}</span>
                      <span className="text-xs font-mono text-slate-700">{value as string}</span>
                    </div>
                  ))}
                </>
              ) : (
                <p className="text-xs text-slate-400">{ta("proxy_inherits", { dept: deptName })}</p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">{t("provider")}</label>
                  <select value={proxyProvider} onChange={(e) => setProxyProvider(e.target.value)}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700">
                    {PROVIDERS.map((p) => <option key={p} value={p}>{tp(p)}</option>)}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">{t("default_model")}</label>
                  <input type="text" value={proxyModel} onChange={(e) => setProxyModel(e.target.value)}
                    placeholder={t("model_ph_proxy")}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
                <div className="flex flex-col gap-1 col-span-2">
                  <label className="text-xs font-medium text-slate-700">{t("base_url")}</label>
                  <input type="text" value={proxyBaseUrl} onChange={(e) => setProxyBaseUrl(e.target.value)}
                    placeholder={t("base_url_ph")}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
                {proxyProvider !== "ollama" && (
                  <div className="flex flex-col gap-1 col-span-2">
                    <label className="text-xs font-medium text-slate-700">
                      {t("api_key")}
                      {app.policy_override?.proxy_provider?.api_key_masked && (
                        <span className="ml-2 font-normal text-slate-400">{t("api_key_current", { masked: app.policy_override.proxy_provider.api_key_masked })}</span>
                      )}
                    </label>
                    <input type="password" value={proxyApiKey} onChange={(e) => setProxyApiKey(e.target.value)}
                      placeholder={app.policy_override?.proxy_provider?.api_key_masked ? t("api_key_keep") : t("api_key_new")}
                      className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                    <p className="text-xs text-slate-400">{t("proxy_encrypted")}</p>
                  </div>
                )}
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">{t("timeout")}</label>
                  <input type="number" min={1} max={300} value={proxyTimeout} onChange={(e) => setProxyTimeout(e.target.value)}
                    placeholder={t("timeout_ph_proxy")}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
              </div>
              {proxyError && <p className="text-xs text-red-600">{proxyError}</p>}
              <div className="flex items-center gap-3 flex-wrap">
                <Button onClick={handleProxySave} loading={proxySaving}>{t("save_override")}</Button>
                {app.policy_override?.proxy_provider && (
                  confirmProxyClear ? (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-red-600">{t("remove_override_q")}</span>
                      <Button variant="danger" size="sm" onClick={handleProxyClear} loading={proxySaving}>{t("confirm")}</Button>
                      <button onClick={() => setConfirmProxyClear(false)}
                        className="text-sm text-slate-500 hover:text-slate-700">{t("cancel")}</button>
                    </div>
                  ) : (
                    <Button variant="danger" onClick={() => setConfirmProxyClear(true)}>{t("clear_override")}</Button>
                  )
                )}
                {!confirmProxyClear && (
                  <button onClick={() => { setProxyEditing(false); setProxyError(null); setConfirmProxyClear(false) }}
                    className="text-sm text-slate-500 hover:text-slate-700">{t("cancel")}</button>
                )}
                {proxySaved && <span className="text-xs text-green-600">{t("saved")}</span>}
              </div>
            </div>
          )}
        </Card>

        {/* API Keys */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title={ta("keys_title")}
              subtitle={ta("keys_subtitle")}
            />
            <Link href="/settings/keys" className="text-xs text-blue-700 hover:underline whitespace-nowrap">
              {ta("manage_keys")}
            </Link>
          </div>
          {appKeys.length === 0 ? (
            <p className="text-sm text-slate-400">
              {ta("no_keys")}{" "}
              <Link href="/settings/keys" className="text-blue-700 hover:underline">
                {ta("create_one")}
              </Link>
            </p>
          ) : (
            <div className="space-y-2">
              {appKeys.map(key => (
                <div
                  key={key.key_id}
                  className="flex items-center justify-between px-3 py-2.5 bg-slate-50 rounded-lg border border-slate-100"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-slate-900">{key.name}</p>
                    <p className="text-xs text-slate-400 font-mono">{key.key_id}</p>
                    {key.last_used_at && (
                      <p className="text-xs text-slate-400">
                        {ta("last_used", { date: new Date(key.last_used_at).toLocaleDateString() })}
                      </p>
                    )}
                  </div>
                  <span className="text-xs text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-full">
                    {t("active")}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>

      </div>
    </Shell>
  )
}