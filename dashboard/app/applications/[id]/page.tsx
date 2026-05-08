// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
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

const PROVIDERS = [
  { value: "openai", label: "OpenAI / OpenAI-compatible" },
  { value: "ollama", label: "Ollama (Local)" },
  { value: "custom", label: "Custom (OpenAI-compatible)" },
]

export default function ApplicationDetailPage() {
  const { id } = useParams<{ id: string }>()

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
    if (!confirm("Remove all application policy overrides? It will inherit from the department.")) return
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
    if (!confirm("Remove LLM detection override? This application will inherit from the department.")) return
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
    if (!confirm("Remove proxy provider override? This application will fall back to the department proxy configuration.")) return
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

  if (isLoading) return <Shell title="Application"><PageSpinner /></Shell>
  if (!app)      return <Shell title="Application"><p className="text-sm text-slate-500">Application not found.</p></Shell>

  const override     = policyData?.policy_override
  const hasOverride  = override !== null && override !== undefined
  const deptName     = dept?.name || "parent department"

  return (
    <Shell title={app.name}>
      <div className="max-w-2xl space-y-5">

        {/* Back */}
        <Link
          href="/applications"
          className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-900"
        >
          <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Back to applications
        </Link>

        {/* Application info */}
        <Card>
          <CardHeader title="Application Info" />
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Name",        value: app.name },
              { label: "Slug",        value: app.slug },
              { label: "Department",  value: dept?.name || app.dept_id },
              { label: "Environment", value: app.environment },
              { label: "Owner",       value: app.owner_name  || "—" },
              { label: "Email",       value: app.owner_email || "—" },
              { label: "Description", value: app.description || "—" },
              { label: "Status",      value: app.is_active ? "Active" : "Inactive" },
              { label: "Created",     value: new Date(app.created_at).toLocaleDateString() },
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
              title="Policy Override"
              subtitle={`Override thresholds for this application. Leave blank to inherit from ${deptName}.`}
            />
            {!editing && isJwt && (
              <Button onClick={handleEditStart} variant="secondary">Edit</Button>
            )}
          </div>

          {!editing ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2 border-b border-slate-50">
                <span className="text-sm text-slate-600">Block threshold</span>
                <span className="text-sm font-mono text-slate-900">
                  {override?.thresholds?.block ?? (
                    <span className="text-slate-400">
                      Inherits from {deptName} ({policyData?.resolved_policy?.thresholds?.block ?? "0.7"})
                    </span>
                  )}
                </span>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-slate-50">
                <span className="text-sm text-slate-600">Sanitize threshold</span>
                <span className="text-sm font-mono text-slate-900">
                  {override?.thresholds?.sanitize ?? (
                    <span className="text-slate-400">
                      Inherits from {deptName} ({policyData?.resolved_policy?.thresholds?.sanitize ?? "0.4"})
                    </span>
                  )}
                </span>
              </div>

              <div className="flex items-center justify-between pt-1">
                {hasOverride ? (
                  <p className="text-xs text-amber-600">
                    ⚠ Application-level override active — this application uses different thresholds than the department.
                  </p>
                ) : (
                  <p className="text-xs text-slate-400">
                    No overrides set — inheriting policy from {deptName}.
                  </p>
                )}
                {hasOverride && isJwt && (
                  <button
                    onClick={handleReset}
                    disabled={resetting}
                    className="text-xs text-red-500 hover:text-red-700 disabled:opacity-50 whitespace-nowrap ml-4"
                  >
                    {resetting ? "Resetting..." : "Reset to department"}
                  </button>
                )}
              </div>
              {saved && <p className="text-xs text-emerald-600">Saved successfully</p>}
              {error  && <p className="text-xs text-red-600">{error}</p>}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Block threshold</label>
                  <input
                    type="number"
                    min={0.01} max={1.0} step={0.05}
                    value={blockVal}
                    onChange={e => setBlockVal(e.target.value)}
                    placeholder={`e.g. 0.5 (dept: ${policyData?.resolved_policy?.thresholds?.block ?? "0.7"})`}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800"
                  />
                  <p className="text-xs text-slate-400">Leave blank to inherit from {deptName}</p>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Sanitize threshold</label>
                  <input
                    type="number"
                    min={0.0} max={0.99} step={0.05}
                    value={sanitizeVal}
                    onChange={e => setSanitizeVal(e.target.value)}
                    placeholder={`e.g. 0.3 (dept: ${policyData?.resolved_policy?.thresholds?.sanitize ?? "0.4"})`}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800"
                  />
                  <p className="text-xs text-slate-400">Leave blank to inherit from {deptName}</p>
                </div>
              </div>
              {error && <p className="text-xs text-red-600">{error}</p>}
              <div className="flex items-center gap-3">
                {isJwt
                  ? <Button onClick={handleSave} loading={saving}>Save overrides</Button>
                  : <Button disabled>Save overrides</Button>
                }
                <button
                  onClick={() => { setEditing(false); setError(null) }}
                  className="text-sm text-slate-500 hover:text-slate-700"
                >
                  Cancel
                </button>
                {saved && <span className="text-xs text-emerald-600">Saved</span>}
              </div>
            </div>
          )}
        </Card>

        {/* LLM Detection Override */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title="LLM Detection Override"
              subtitle={`Override the LLM provider used for threat detection. Inherits from ${deptName} if not set.`}
            />
            {!llmEditing && isJwt && (
              <Button onClick={handleLlmEditStart} variant="secondary">Edit</Button>
            )}
          </div>

          {!llmEditing ? (
            <div className="space-y-2">
              {app.policy_override?.llm ? (
                <>
                  {[
                    ["Provider", app.policy_override.llm.provider],
                    ["Model",    app.policy_override.llm.model],
                    ["Base URL", app.policy_override.llm.base_url],
                    ["Timeout",  app.policy_override.llm.timeout ? `${app.policy_override.llm.timeout}s` : undefined],
                    ["API key",  app.policy_override.llm.api_key_masked ?? "Using env var"],
                  ].filter(([, v]) => v).map(([label, value]) => (
                    <div key={label as string} className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
                      <span className="text-sm text-slate-600">{label}</span>
                      <span className="text-xs font-mono text-slate-700">{value as string}</span>
                    </div>
                  ))}
                </>
              ) : (
                <p className="text-xs text-slate-400">Inherits LLM configuration from {deptName}.</p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Provider</label>
                  <select value={llmProvider} onChange={(e) => setLlmProvider(e.target.value)}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800">
                    {PROVIDERS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Model</label>
                  <input type="text" value={llmModel} onChange={(e) => setLlmModel(e.target.value)}
                    placeholder="gpt-4o-mini"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800" />
                </div>
                <div className="flex flex-col gap-1 col-span-2">
                  <label className="text-xs font-medium text-slate-700">Base URL</label>
                  <input type="text" value={llmBaseUrl} onChange={(e) => setLlmBaseUrl(e.target.value)}
                    placeholder="https://api.openai.com/v1"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800" />
                </div>
                {llmProvider !== "ollama" && (
                  <div className="flex flex-col gap-1 col-span-2">
                    <label className="text-xs font-medium text-slate-700">
                      API key
                      {app.policy_override?.llm?.api_key_masked && (
                        <span className="ml-2 font-normal text-slate-400">current: {app.policy_override.llm.api_key_masked}</span>
                      )}
                    </label>
                    <input type="password" value={llmApiKey} onChange={(e) => setLlmApiKey(e.target.value)}
                      placeholder={app.policy_override?.llm?.api_key_masked ? "Leave blank to keep current key" : "sk-..."}
                      className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800" />
                    <p className="text-xs text-slate-400">Stored encrypted. Falls back to department key if blank.</p>
                  </div>
                )}
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Timeout (seconds)</label>
                  <input type="number" min={5} max={120} value={llmTimeout} onChange={(e) => setLlmTimeout(e.target.value)}
                    placeholder="30"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800" />
                </div>
              </div>
              {llmError && <p className="text-xs text-red-600">{llmError}</p>}
              <div className="flex items-center gap-3 flex-wrap">
                <Button onClick={handleLlmSave} loading={llmSaving}>Save override</Button>
                {app.policy_override?.llm && (
                  <Button variant="danger" onClick={handleLlmClear} loading={llmSaving}>Clear override</Button>
                )}
                <button onClick={() => { setLlmEditing(false); setLlmError(null) }}
                  className="text-sm text-slate-500 hover:text-slate-700">Cancel</button>
                {llmSaved && <span className="text-xs text-green-600">Saved</span>}
              </div>
            </div>
          )}
        </Card>

        {/* Proxy Provider Override */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title="Proxy Provider Override"
              subtitle={`Override the proxy completion provider for this application. Falls back to ${deptName} if not set.`}
            />
            {!proxyEditing && isJwt && (
              <Button onClick={handleProxyEditStart} variant="secondary">Edit</Button>
            )}
          </div>

          {!proxyEditing ? (
            <div className="space-y-2">
              {app.policy_override?.proxy_provider ? (
                <>
                  {[
                    ["Provider",      app.policy_override.proxy_provider.provider],
                    ["Default model", app.policy_override.proxy_provider.default_model],
                    ["Base URL",      app.policy_override.proxy_provider.base_url],
                    ["Timeout",       app.policy_override.proxy_provider.timeout_seconds ? `${app.policy_override.proxy_provider.timeout_seconds}s` : undefined],
                    ["API key",       app.policy_override.proxy_provider.api_key_masked ?? "Using env var"],
                  ].filter(([, v]) => v).map(([label, value]) => (
                    <div key={label as string} className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
                      <span className="text-sm text-slate-600">{label}</span>
                      <span className="text-xs font-mono text-slate-700">{value as string}</span>
                    </div>
                  ))}
                </>
              ) : (
                <p className="text-xs text-slate-400">Inherits proxy provider from {deptName}.</p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Provider</label>
                  <select value={proxyProvider} onChange={(e) => setProxyProvider(e.target.value)}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800">
                    {PROVIDERS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Default model</label>
                  <input type="text" value={proxyModel} onChange={(e) => setProxyModel(e.target.value)}
                    placeholder="gpt-4o"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800" />
                </div>
                <div className="flex flex-col gap-1 col-span-2">
                  <label className="text-xs font-medium text-slate-700">Base URL</label>
                  <input type="text" value={proxyBaseUrl} onChange={(e) => setProxyBaseUrl(e.target.value)}
                    placeholder="https://api.openai.com/v1"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800" />
                </div>
                {proxyProvider !== "ollama" && (
                  <div className="flex flex-col gap-1 col-span-2">
                    <label className="text-xs font-medium text-slate-700">
                      API key
                      {app.policy_override?.proxy_provider?.api_key_masked && (
                        <span className="ml-2 font-normal text-slate-400">current: {app.policy_override.proxy_provider.api_key_masked}</span>
                      )}
                    </label>
                    <input type="password" value={proxyApiKey} onChange={(e) => setProxyApiKey(e.target.value)}
                      placeholder={app.policy_override?.proxy_provider?.api_key_masked ? "Leave blank to keep current key" : "sk-..."}
                      className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800" />
                    <p className="text-xs text-slate-400">Stored encrypted. Masked after save.</p>
                  </div>
                )}
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Timeout (seconds)</label>
                  <input type="number" min={1} max={300} value={proxyTimeout} onChange={(e) => setProxyTimeout(e.target.value)}
                    placeholder="60"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800" />
                </div>
              </div>
              {proxyError && <p className="text-xs text-red-600">{proxyError}</p>}
              <div className="flex items-center gap-3 flex-wrap">
                <Button onClick={handleProxySave} loading={proxySaving}>Save override</Button>
                {app.policy_override?.proxy_provider && (
                  <Button variant="danger" onClick={handleProxyClear} loading={proxySaving}>Clear override</Button>
                )}
                <button onClick={() => { setProxyEditing(false); setProxyError(null) }}
                  className="text-sm text-slate-500 hover:text-slate-700">Cancel</button>
                {proxySaved && <span className="text-xs text-green-600">Saved</span>}
              </div>
            </div>
          )}
        </Card>

        {/* API Keys */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title="API Keys"
              subtitle="Keys scoped to this application"
            />
            <Link href="/settings/keys" className="text-xs text-blue-700 hover:underline whitespace-nowrap">
              Manage keys →
            </Link>
          </div>
          {appKeys.length === 0 ? (
            <p className="text-sm text-slate-400">
              No keys for this application.{" "}
              <Link href="/settings/keys" className="text-blue-700 hover:underline">
                Create one in API Keys
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
                        Last used {new Date(key.last_used_at).toLocaleDateString()}
                      </p>
                    )}
                  </div>
                  <span className="text-xs text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-full">
                    Active
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