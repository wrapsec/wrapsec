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
  getDepartment, updateDepartment, getApplicationsByDept, getDepartmentStats,
  updateDeptLLMOverride, updateDeptProxyOverride,
} from "@/lib/api"
import Link from "next/link"
import { Breadcrumb } from "@/components/ui/Breadcrumb"
import { formatNumber } from "@/lib/format"

const PROVIDERS = [
  { value: "openai", label: "OpenAI / OpenAI-compatible" },
  { value: "ollama", label: "Ollama (Local)" },
  { value: "custom", label: "Custom (OpenAI-compatible)" },
]

export default function DepartmentDetailPage() {
  const { id } = useParams<{ id: string }>()

  const { data: dept, isLoading, mutate } = useSWR(
    `department-${id}`, () => getDepartment(id)
  )
  const { data: appsData } = useSWR(
    `apps-dept-${id}`, () => getApplicationsByDept(id)
  )
  const { data: stats } = useSWR(
    `dept-stats-${id}`, () => getDepartmentStats(id)
  )

  const [editing,     setEditing]     = useState(false)
  const [blockVal,    setBlockVal]    = useState("")
  const [sanitizeVal, setSanitizeVal] = useState("")
  const [saving,      setSaving]      = useState(false)
  const [saved,       setSaved]       = useState(false)
  const [error,       setError]       = useState<string | null>(null)

  // LLM override form
  const [confirmLlmClear,   setConfirmLlmClear]   = useState(false)
  const [confirmProxyClear, setConfirmProxyClear] = useState(false)

  const [llmEditing,   setLlmEditing]   = useState(false)
  const [llmProvider,  setLlmProvider]  = useState("")
  const [llmModel,     setLlmModel]     = useState("")
  const [llmBaseUrl,   setLlmBaseUrl]   = useState("")
  const [llmApiKey,    setLlmApiKey]    = useState("")
  const [llmTimeout,   setLlmTimeout]   = useState("")
  const [llmSaving,    setLlmSaving]    = useState(false)
  const [llmSaved,     setLlmSaved]     = useState(false)
  const [llmError,     setLlmError]     = useState<string | null>(null)

  // Proxy provider override form
  const [proxyEditing,   setProxyEditing]   = useState(false)
  const [proxyProvider,  setProxyProvider]  = useState("")
  const [proxyBaseUrl,   setProxyBaseUrl]   = useState("")
  const [proxyModel,     setProxyModel]     = useState("")
  const [proxyApiKey,    setProxyApiKey]    = useState("")
  const [proxyTimeout,   setProxyTimeout]   = useState("")
  const [proxySaving,    setProxySaving]    = useState(false)
  const [proxySaved,     setProxySaved]     = useState(false)
  const [proxyError,     setProxyError]     = useState<string | null>(null)

  const { isJwt } = useAuthMode()

  const handleEditStart = () => {
    const override = dept?.policy_override
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
        ? {
            thresholds: {
              ...(block    !== null ? { block }    : {}),
              ...(sanitize !== null ? { sanitize } : {}),
            }
          }
        : null

      await updateDepartment(id, { policy_override })
      mutate()
      setEditing(false)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleLlmEditStart = () => {
    const llm = dept?.policy_override?.llm
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
      if (llmProvider) payload.provider = llmProvider
      if (llmModel)    payload.model    = llmModel
      if (llmBaseUrl)  payload.base_url = llmBaseUrl
      if (llmTimeout)  payload.timeout  = parseInt(llmTimeout)
      if (llmApiKey.trim()) payload.api_key = llmApiKey.trim()
      const updated = await updateDeptLLMOverride(id, payload)
      mutate(updated, false)
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
      const updated = await updateDeptLLMOverride(id, { clear: true })
      mutate(updated, false)
      setLlmEditing(false)
    } catch (e: any) {
      setLlmError(e.message)
    } finally {
      setLlmSaving(false)
    }
  }

  const handleProxyEditStart = () => {
    const proxy = dept?.policy_override?.proxy_provider
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
      if (proxyProvider) payload.provider       = proxyProvider
      if (proxyBaseUrl)  payload.base_url        = proxyBaseUrl
      if (proxyModel)    payload.default_model   = proxyModel
      if (proxyTimeout)  payload.timeout_seconds = parseInt(proxyTimeout)
      if (proxyApiKey.trim()) payload.api_key = proxyApiKey.trim()
      const updated = await updateDeptProxyOverride(id, payload)
      mutate(updated, false)
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
      const updated = await updateDeptProxyOverride(id, { clear: true })
      mutate(updated, false)
      setProxyEditing(false)
    } catch (e: any) {
      setProxyError(e.message)
    } finally {
      setProxySaving(false)
    }
  }

  if (isLoading) return <Shell title="Department"><PageSpinner /></Shell>
  if (!dept)     return <Shell title="Department"><p className="text-sm text-slate-500">Department not found.</p></Shell>

  return (
    <Shell title={dept.name}>
      <div className="max-w-2xl space-y-5">
        <Breadcrumb items={[
          { label: "Departments", href: "/departments" },
          { label: dept.name },
        ]} />

        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: "Total requests", value: formatNumber(stats.total) },
              {
                label: "Block rate",
                value: `${Math.round(stats.block_rate * 100)}%`,
                color: stats.block_rate > 0.3 ? "text-red-600" : "text-slate-900",
              },
              { label: "Avg latency", value: `${stats.avg_latency_ms.toFixed(1)}ms` },
              { label: "Top threat",  value: stats.top_threats[0]?.category ?? "None" },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-white rounded-xl border border-slate-200 px-4 py-3">
                <p className="text-xs text-slate-400 mb-1">{label}</p>
                <p className={`text-lg font-semibold ${color ?? "text-slate-900"}`}>{value}</p>
              </div>
            ))}
          </div>
        )}

        {/* Decision breakdown */}
        {stats && stats.total > 0 && (
          <div className="bg-white rounded-xl border border-slate-200 p-4">
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Decision breakdown</p>
            <div className="flex gap-3">
              {Object.entries(stats.decisions).map(([decision, count]) => {
                const pct   = Math.round((count / stats.total) * 100)
                const color = decision === "BLOCK"    ? "#f87171" :
                              decision === "SANITIZE" ? "#fbbf24" : "#10b981"
                return (
                  <div key={decision} className="flex-1 bg-slate-50 rounded-lg px-3 py-2.5">
                    <p className="text-xs text-slate-400 mb-1">{decision}</p>
                    <p className="text-sm font-semibold text-slate-900">{formatNumber(count)}</p>
                    <div className="mt-1.5 h-1.5 bg-slate-200 rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{pct}%</p>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Department info */}
        <Card>
          <CardHeader title="Department Info" />
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Name",          value: dept.name },
              { label: "Slug",          value: dept.slug },
              { label: "Description",   value: dept.description   || "-" },
              { label: "Contact email", value: dept.contact_email || "-" },
              { label: "Status",        value: dept.is_active ? "Active" : "Inactive" },
              { label: "Created",       value: new Date(dept.created_at).toLocaleDateString() },
            ].map(({ label, value }) => (
              <div key={label} className="bg-slate-50 rounded-lg px-3 py-2.5">
                <p className="text-xs text-slate-400 mb-0.5">{label}</p>
                <p className="text-xs font-mono text-slate-700">{value}</p>
              </div>
            ))}
          </div>
        </Card>

        {/* Policy overrides */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title="Policy Override"
              subtitle="Override global thresholds for this department. Leave blank to inherit."
            />
            {!editing && isJwt && (
              <Button onClick={handleEditStart} variant="secondary">
                Edit
              </Button>
            )}
          </div>

          {!editing ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2 border-b border-slate-50">
                <span className="text-sm text-slate-600">Block threshold</span>
                <span className="text-sm font-mono text-slate-900">
                  {dept.policy_override?.thresholds?.block ?? (
                    <span className="text-slate-400">Inherits global (0.7)</span>
                  )}
                </span>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-sm text-slate-600">Sanitize threshold</span>
                <span className="text-sm font-mono text-slate-900">
                  {dept.policy_override?.thresholds?.sanitize ?? (
                    <span className="text-slate-400">Inherits global (0.4)</span>
                  )}
                </span>
              </div>
              {dept.policy_override === null && (
                <p className="text-xs text-slate-400 pt-1">
                  No overrides set - this department uses the global policy.
                </p>
              )}
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
                    onChange={(e) => setBlockVal(e.target.value)}
                    placeholder="e.g. 0.5 (global: 0.7)"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                  />
                  <p className="text-xs text-slate-400">Leave blank to inherit global</p>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Sanitize threshold</label>
                  <input
                    type="number"
                    min={0.0} max={0.99} step={0.05}
                    value={sanitizeVal}
                    onChange={(e) => setSanitizeVal(e.target.value)}
                    placeholder="e.g. 0.3 (global: 0.4)"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                  />
                  <p className="text-xs text-slate-400">Leave blank to inherit global</p>
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
                {saved && <span className="text-xs text-green-600">Saved</span>}
              </div>
            </div>
          )}
        </Card>

        {/* LLM Detection Override */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title="LLM Detection Override"
              subtitle="Use a department-specific LLM provider for threat detection. Inherits global config if not set."
            />
            {!llmEditing && isJwt && (
              <Button onClick={handleLlmEditStart} variant="secondary">Edit</Button>
            )}
          </div>

          {!llmEditing ? (
            <div className="space-y-2">
              {dept.policy_override?.llm ? (
                <>
                  {[
                    ["Provider",    dept.policy_override.llm.provider],
                    ["Model",       dept.policy_override.llm.model],
                    ["Base URL",    dept.policy_override.llm.base_url],
                    ["Timeout",     dept.policy_override.llm.timeout ? `${dept.policy_override.llm.timeout}s` : undefined],
                    ["API key",     dept.policy_override.llm.api_key_masked ?? "Using env var"],
                  ].filter(([, v]) => v).map(([label, value]) => (
                    <div key={label as string} className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
                      <span className="text-sm text-slate-600">{label}</span>
                      <span className="text-xs font-mono text-slate-700">{value as string}</span>
                    </div>
                  ))}
                </>
              ) : (
                <p className="text-xs text-slate-400">Inherits global LLM configuration.</p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Provider</label>
                  <select
                    value={llmProvider}
                    onChange={(e) => setLlmProvider(e.target.value)}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700"
                  >
                    {PROVIDERS.map((p) => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Model</label>
                  <input type="text" value={llmModel} onChange={(e) => setLlmModel(e.target.value)}
                    placeholder="gpt-4o-mini"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
                <div className="flex flex-col gap-1 col-span-2">
                  <label className="text-xs font-medium text-slate-700">Base URL</label>
                  <input type="text" value={llmBaseUrl} onChange={(e) => setLlmBaseUrl(e.target.value)}
                    placeholder="https://api.openai.com/v1"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
                {llmProvider !== "ollama" && (
                  <div className="flex flex-col gap-1 col-span-2">
                    <label className="text-xs font-medium text-slate-700">
                      API key
                      {dept.policy_override?.llm?.api_key_masked && (
                        <span className="ml-2 font-normal text-slate-400">current: {dept.policy_override.llm.api_key_masked}</span>
                      )}
                    </label>
                    <input type="password" value={llmApiKey} onChange={(e) => setLlmApiKey(e.target.value)}
                      placeholder={dept.policy_override?.llm?.api_key_masked ? "Leave blank to keep current key" : "sk-..."}
                      className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                    <p className="text-xs text-slate-400">Stored encrypted. Falls back to global key if blank.</p>
                  </div>
                )}
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Timeout (seconds)</label>
                  <input type="number" min={5} max={120} value={llmTimeout} onChange={(e) => setLlmTimeout(e.target.value)}
                    placeholder="30"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
              </div>
              {llmError && <p className="text-xs text-red-600">{llmError}</p>}
              <div className="flex items-center gap-3 flex-wrap">
                <Button onClick={handleLlmSave} loading={llmSaving}>Save override</Button>
                {dept.policy_override?.llm && (
                  confirmLlmClear ? (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-red-600">Remove override?</span>
                      <Button variant="danger" size="sm" onClick={handleLlmClear} loading={llmSaving}>Confirm</Button>
                      <button onClick={() => setConfirmLlmClear(false)}
                        className="text-sm text-slate-500 hover:text-slate-700">Cancel</button>
                    </div>
                  ) : (
                    <Button variant="danger" onClick={() => setConfirmLlmClear(true)}>Clear override</Button>
                  )
                )}
                {!confirmLlmClear && (
                  <button onClick={() => { setLlmEditing(false); setLlmError(null); setConfirmLlmClear(false) }}
                    className="text-sm text-slate-500 hover:text-slate-700">Cancel</button>
                )}
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
              subtitle="Department-level fallback provider for proxy mode when no per-key config exists."
            />
            {!proxyEditing && isJwt && (
              <Button onClick={handleProxyEditStart} variant="secondary">Edit</Button>
            )}
          </div>

          {!proxyEditing ? (
            <div className="space-y-2">
              {dept.policy_override?.proxy_provider ? (
                <>
                  {[
                    ["Provider",      dept.policy_override.proxy_provider.provider],
                    ["Default model", dept.policy_override.proxy_provider.default_model],
                    ["Base URL",      dept.policy_override.proxy_provider.base_url],
                    ["Timeout",       dept.policy_override.proxy_provider.timeout_seconds ? `${dept.policy_override.proxy_provider.timeout_seconds}s` : undefined],
                    ["API key",       dept.policy_override.proxy_provider.api_key_masked ?? "Using env var"],
                  ].filter(([, v]) => v).map(([label, value]) => (
                    <div key={label as string} className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
                      <span className="text-sm text-slate-600">{label}</span>
                      <span className="text-xs font-mono text-slate-700">{value as string}</span>
                    </div>
                  ))}
                </>
              ) : (
                <p className="text-xs text-slate-400">No override - API keys must have their own proxy configuration.</p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Provider</label>
                  <select
                    value={proxyProvider}
                    onChange={(e) => setProxyProvider(e.target.value)}
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700"
                  >
                    {PROVIDERS.map((p) => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </select>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Default model</label>
                  <input type="text" value={proxyModel} onChange={(e) => setProxyModel(e.target.value)}
                    placeholder="gpt-4o"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
                <div className="flex flex-col gap-1 col-span-2">
                  <label className="text-xs font-medium text-slate-700">Base URL</label>
                  <input type="text" value={proxyBaseUrl} onChange={(e) => setProxyBaseUrl(e.target.value)}
                    placeholder="https://api.openai.com/v1"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
                {proxyProvider !== "ollama" && (
                  <div className="flex flex-col gap-1 col-span-2">
                    <label className="text-xs font-medium text-slate-700">
                      API key
                      {dept.policy_override?.proxy_provider?.api_key_masked && (
                        <span className="ml-2 font-normal text-slate-400">current: {dept.policy_override.proxy_provider.api_key_masked}</span>
                      )}
                    </label>
                    <input type="password" value={proxyApiKey} onChange={(e) => setProxyApiKey(e.target.value)}
                      placeholder={dept.policy_override?.proxy_provider?.api_key_masked ? "Leave blank to keep current key" : "sk-..."}
                      className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                    <p className="text-xs text-slate-400">Stored encrypted. Masked after save.</p>
                  </div>
                )}
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">Timeout (seconds)</label>
                  <input type="number" min={1} max={300} value={proxyTimeout} onChange={(e) => setProxyTimeout(e.target.value)}
                    placeholder="60"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                </div>
              </div>
              {proxyError && <p className="text-xs text-red-600">{proxyError}</p>}
              <div className="flex items-center gap-3 flex-wrap">
                <Button onClick={handleProxySave} loading={proxySaving}>Save override</Button>
                {dept.policy_override?.proxy_provider && (
                  confirmProxyClear ? (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-red-600">Remove override?</span>
                      <Button variant="danger" size="sm" onClick={handleProxyClear} loading={proxySaving}>Confirm</Button>
                      <button onClick={() => setConfirmProxyClear(false)}
                        className="text-sm text-slate-500 hover:text-slate-700">Cancel</button>
                    </div>
                  ) : (
                    <Button variant="danger" onClick={() => setConfirmProxyClear(true)}>Clear override</Button>
                  )
                )}
                {!confirmProxyClear && (
                  <button onClick={() => { setProxyEditing(false); setProxyError(null); setConfirmProxyClear(false) }}
                    className="text-sm text-slate-500 hover:text-slate-700">Cancel</button>
                )}
                {proxySaved && <span className="text-xs text-green-600">Saved</span>}
              </div>
            </div>
          )}
        </Card>

        {/* Applications */}
        <Card>
          <CardHeader
            title="Applications"
            subtitle="Systems registered under this department"
          />
          {(appsData?.applications ?? []).length === 0 ? (
            <p className="text-sm text-slate-400">No applications registered.</p>
          ) : (
            <div className="space-y-2">
              {(appsData?.applications ?? []).map((app) => (
                <div
                  key={app.id}
                  className="flex items-center justify-between px-3 py-2.5 bg-slate-50 rounded-lg border border-slate-100"
                >
                  <div>
                    <p className="text-sm font-medium text-slate-900">{app.name}</p>
                    <p className="text-xs text-slate-400">{app.slug} · {app.environment}</p>
                  </div>
                  <a
                    href={`/applications/${app.id}`}
                    className="text-xs text-blue-700 hover:underline"
                  >
                    Manage
                  </a>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </Shell>
  )
}
